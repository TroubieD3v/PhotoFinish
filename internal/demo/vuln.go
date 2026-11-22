package demo

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

// vulnScenarios implements the four scenarios as check-then-act sequences of
// separate statements. Every operation reads state, decides, optionally
// pauses for the configured window and then writes. Concurrent requests can
// all pass the check before any of them writes: these are the intentional
// race conditions of the /vuln variant.
type vulnScenarios struct {
	st     *store
	window time.Duration
	// beforeWrite, if set, runs at the start of every pause, after the check
	// and before the write. Tests use it to hold requests between the two
	// and so make the race deterministic. It is never set outside tests.
	beforeWrite func()
}

// pause widens the gap between the check and the write.
func (v *vulnScenarios) pause() {
	if v.beforeWrite != nil {
		v.beforeWrite()
	}
	if v.window > 0 {
		time.Sleep(v.window)
	}
}

// applyCoupon checks that code is not yet applied to the cart, then inserts
// it. The insert itself still requires the cart to exist, so a concurrent
// reset cannot leave an orphan discount; the duplicate-code race is the
// intentional bug.
func (v *vulnScenarios) applyCoupon(ctx context.Context, cartID, owner, code string, amountCents int64) error {
	var n int
	if err := v.st.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cart_discounts WHERE cart_id = ? AND code = ?`, cartID, code).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errCouponApplied
	}
	v.pause()
	return v.st.insertDiscount(ctx, cartID, owner, code, amountCents)
}

// transfer checks the sender balance, then debits, credits and records the
// transfer in separate statements without a transaction.
func (v *vulnScenarios) transfer(ctx context.Context, from, to string, amountCents int64) (int64, error) {
	bal, err := v.st.balance(ctx, from)
	if err != nil {
		return 0, err
	}
	if bal < amountCents {
		return 0, errInsufficientFunds
	}
	v.pause()
	if _, err := v.st.db.ExecContext(ctx,
		`UPDATE users SET balance_cents = balance_cents - ? WHERE name = ?`, amountCents, from); err != nil {
		return 0, err
	}
	if _, err := v.st.db.ExecContext(ctx,
		`UPDATE users SET balance_cents = balance_cents + ? WHERE name = ?`, amountCents, to); err != nil {
		return 0, err
	}
	if _, err := v.st.db.ExecContext(ctx,
		`INSERT INTO transfers (sender, recipient, amount_cents) VALUES (?, ?, ?)`, from, to, amountCents); err != nil {
		return 0, err
	}
	return v.st.balance(ctx, from)
}

// verify2FA checks the attempt counter, then compares the code and bumps the
// counters afterwards.
func (v *vulnScenarios) verify2FA(ctx context.Context, user, code string) (bool, int, error) {
	var (
		attempts int
		want     string
	)
	err := v.st.db.QueryRowContext(ctx,
		`SELECT attempts, code FROM twofa WHERE user = ?`, user).Scan(&attempts, &want)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, errUnauthorized
	}
	if err != nil {
		return false, 0, err
	}
	if attempts >= twofaLimit {
		return false, attempts, errTooManyAttempts
	}
	v.pause()
	ok := subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1
	err = v.st.db.QueryRowContext(ctx,
		`UPDATE twofa SET attempts = attempts + 1, checks = checks + 1 WHERE user = ? RETURNING attempts`,
		user).Scan(&attempts)
	if err != nil {
		return false, 0, err
	}
	return ok, attempts, nil
}

// redeemGiftCard checks the redeemed flag, then credits the caller and marks
// the card as redeemed in separate statements.
func (v *vulnScenarios) redeemGiftCard(ctx context.Context, user, code string) (int64, int64, error) {
	var value, redeemed int64
	err := v.st.db.QueryRowContext(ctx,
		`SELECT value_cents, redeemed FROM giftcards WHERE code = ?`, code).Scan(&value, &redeemed)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, errGiftCardNotFound
	}
	if err != nil {
		return 0, 0, err
	}
	if redeemed == 1 {
		return 0, 0, errGiftCardRedeemed
	}
	v.pause()
	if _, err := v.st.db.ExecContext(ctx,
		`UPDATE users SET balance_cents = balance_cents + ? WHERE name = ?`, value, user); err != nil {
		return 0, 0, err
	}
	if _, err := v.st.db.ExecContext(ctx,
		`UPDATE giftcards SET redeemed = 1, redeemed_by = ? WHERE code = ?`, user, code); err != nil {
		return 0, 0, err
	}
	bal, err := v.st.balance(ctx, user)
	if err != nil {
		return 0, 0, err
	}
	return value, bal, nil
}
