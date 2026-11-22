package demo

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
)

// fixedScenarios implements the four scenarios atomically: either a single
// conditional statement enforces the rule, or the check and the write share
// one transaction. The store has a single connection, so a database/sql
// transaction excludes every other statement until it ends.
type fixedScenarios struct {
	st *store
}

// applyCoupon inserts the discount in a single statement that requires the
// cart to exist and lets UNIQUE(cart_id, code) reject a duplicate.
func (f *fixedScenarios) applyCoupon(ctx context.Context, cartID, owner, code string, amountCents int64) error {
	err := f.st.insertDiscount(ctx, cartID, owner, code, amountCents)
	if isConstraint(err) {
		return errCouponApplied
	}
	return err
}

// transfer debits the sender only if the balance covers the amount, then
// credits the recipient and records the transfer, all in one transaction.
func (f *fixedScenarios) transfer(ctx context.Context, from, to string, amountCents int64) (int64, error) {
	tx, err := f.st.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE users SET balance_cents = balance_cents - ? WHERE name = ? AND balance_cents >= ?`,
		amountCents, from, amountCents)
	if err != nil {
		return 0, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return 0, err
	} else if n != 1 {
		return 0, errInsufficientFunds
	}

	res, err = tx.ExecContext(ctx,
		`UPDATE users SET balance_cents = balance_cents + ? WHERE name = ?`, amountCents, to)
	if err != nil {
		return 0, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return 0, err
	} else if n != 1 {
		return 0, errRecipientNotFound
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO transfers (sender, recipient, amount_cents) VALUES (?, ?, ?)`, from, to, amountCents); err != nil {
		return 0, err
	}
	var bal int64
	if err := tx.QueryRowContext(ctx,
		`SELECT balance_cents FROM users WHERE name = ?`, from).Scan(&bal); err != nil {
		return 0, err
	}
	return bal, tx.Commit()
}

// verify2FA reserves an attempt with a conditional update before comparing
// the code, so no more than twofaLimit codes are ever compared.
func (f *fixedScenarios) verify2FA(ctx context.Context, user, code string) (bool, int, error) {
	tx, err := f.st.db.BeginTx(ctx, nil)
	if err != nil {
		return false, 0, err
	}
	defer tx.Rollback()

	var (
		attempts int
		want     string
	)
	err = tx.QueryRowContext(ctx,
		`UPDATE twofa SET attempts = attempts + 1 WHERE user = ? AND attempts < ? RETURNING attempts, code`,
		user, twofaLimit).Scan(&attempts, &want)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, errTooManyAttempts
	}
	if err != nil {
		return false, 0, err
	}

	ok := subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1
	if _, err := tx.ExecContext(ctx,
		`UPDATE twofa SET checks = checks + 1 WHERE user = ?`, user); err != nil {
		return false, 0, err
	}
	return ok, attempts, tx.Commit()
}

// redeemGiftCard flips the redeemed flag with a conditional update and
// credits the caller in the same transaction.
func (f *fixedScenarios) redeemGiftCard(ctx context.Context, user, code string) (int64, int64, error) {
	tx, err := f.st.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	var value int64
	err = tx.QueryRowContext(ctx,
		`UPDATE giftcards SET redeemed = 1, redeemed_by = ? WHERE code = ? AND redeemed = 0 RETURNING value_cents`,
		user, code).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM giftcards WHERE code = ?`, code).Scan(&n); err != nil {
			return 0, 0, err
		}
		if n == 0 {
			return 0, 0, errGiftCardNotFound
		}
		return 0, 0, errGiftCardRedeemed
	}
	if err != nil {
		return 0, 0, err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET balance_cents = balance_cents + ? WHERE name = ?`, value, user); err != nil {
		return 0, 0, err
	}
	var bal int64
	if err := tx.QueryRowContext(ctx,
		`SELECT balance_cents FROM users WHERE name = ?`, user).Scan(&bal); err != nil {
		return 0, 0, err
	}
	return value, bal, tx.Commit()
}
