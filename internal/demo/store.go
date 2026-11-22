package demo

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Seed values shared by both variants. Reset restores exactly this state.
const (
	seedBalanceCents   = 10000
	cartTotalCents     = 8100
	twofaLimit         = 3
	twofaSeedCode      = "482913"
	welcomeCouponCode  = "WELCOME10"
	welcomeCouponPct   = 10
	giftCardValueCents = 5000
	maxTransferCents   = 1000000
	cartIDRandomBytes  = 4
	cartIDPrefix       = "c_"
	cartCreateAttempts = 5
)

// Business outcomes reported by the stores. Their messages are the exact
// error strings sent to clients; statusOf maps them to HTTP status codes.
var (
	errUnauthorized      = errors.New("unauthorized")
	errCartNotFound      = errors.New("cart not found")
	errCouponNotFound    = errors.New("coupon not found")
	errCouponApplied     = errors.New("coupon already applied")
	errRecipientNotFound = errors.New("recipient not found")
	errInsufficientFunds = errors.New("insufficient funds")
	errTooManyAttempts   = errors.New("too many attempts")
	errGiftCardNotFound  = errors.New("gift card not found")
	errGiftCardRedeemed  = errors.New("gift card already redeemed")
)

// commonSchema is created in both stores.
var commonSchema = []string{
	`CREATE TABLE users (
		name TEXT PRIMARY KEY,
		token TEXT UNIQUE NOT NULL,
		balance_cents INTEGER NOT NULL
	)`,
	`CREATE TABLE carts (
		id TEXT PRIMARY KEY,
		owner TEXT NOT NULL,
		total_cents INTEGER NOT NULL
	)`,
	`CREATE TABLE coupons (
		code TEXT PRIMARY KEY,
		percent INTEGER NOT NULL
	)`,
	`CREATE TABLE transfers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender TEXT,
		recipient TEXT,
		amount_cents INTEGER
	)`,
	`CREATE TABLE twofa (
		user TEXT PRIMARY KEY,
		attempts INTEGER NOT NULL,
		checks INTEGER NOT NULL,
		code TEXT NOT NULL
	)`,
	`CREATE TABLE giftcards (
		code TEXT PRIMARY KEY,
		value_cents INTEGER NOT NULL,
		redeemed INTEGER NOT NULL,
		redeemed_by TEXT
	)`,
}

// vulnDiscountsTable has no uniqueness guarantee: the vulnerable handler
// relies on a separate check, which is the bug.
const vulnDiscountsTable = `CREATE TABLE cart_discounts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	cart_id TEXT NOT NULL,
	code TEXT NOT NULL,
	amount_cents INTEGER NOT NULL
)`

// fixedDiscountsTable lets the database enforce one discount per code.
const fixedDiscountsTable = `CREATE TABLE cart_discounts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	cart_id TEXT NOT NULL,
	code TEXT NOT NULL,
	amount_cents INTEGER NOT NULL,
	UNIQUE(cart_id, code)
)`

// seedStatements restore the seed state. They run inside one transaction.
var seedStatements = []struct {
	query string
	args  []any
}{
	{`DELETE FROM cart_discounts`, nil},
	{`DELETE FROM carts`, nil},
	{`DELETE FROM transfers`, nil},
	{`DELETE FROM twofa`, nil},
	{`DELETE FROM giftcards`, nil},
	{`DELETE FROM coupons`, nil},
	{`DELETE FROM users`, nil},
	{`DELETE FROM sqlite_sequence`, nil},
	{`INSERT INTO users (name, token, balance_cents) VALUES (?, ?, ?), (?, ?, ?)`,
		[]any{"alice", "demo-alice", seedBalanceCents, "bob", "demo-bob", seedBalanceCents}},
	{`INSERT INTO coupons (code, percent) VALUES (?, ?)`,
		[]any{welcomeCouponCode, welcomeCouponPct}},
	{`INSERT INTO twofa (user, attempts, checks, code) VALUES (?, 0, 0, ?), (?, 0, 0, ?)`,
		[]any{"alice", twofaSeedCode, "bob", twofaSeedCode}},
	{`INSERT INTO giftcards (code, value_cents, redeemed, redeemed_by) VALUES (?, ?, 0, NULL), (?, ?, 0, NULL)`,
		[]any{"GIFT-ALICE-50", giftCardValueCents, "GIFT-BOB-50", giftCardValueCents}},
}

// store is one variant's in-memory SQLite database.
//
// The pool is pinned to a single connection that is never closed, so the
// in-memory data lives as long as the store. With one connection, separate
// statements issued by concurrent requests interleave: a check in one
// statement and a write in another is a real race, while a single
// conditional statement or a transaction is atomic.
type store struct {
	db *sql.DB
}

// openStore creates, migrates and seeds the store for variant v.
func openStore(v Variant) (*store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("open %s store: %w", v, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	st := &store{db: db}
	if err := st.migrate(v); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s store: %w", v, err)
	}
	if err := st.reset(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("seed %s store: %w", v, err)
	}
	return st, nil
}

func (st *store) migrate(v Variant) error {
	stmts := append([]string{}, commonSchema...)
	if v == Fixed {
		stmts = append(stmts, fixedDiscountsTable)
	} else {
		stmts = append(stmts, vulnDiscountsTable)
	}
	ctx := context.Background()
	for _, q := range stmts {
		if _, err := st.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// reset restores the seed state atomically.
func (st *store) reset(ctx context.Context) error {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, s := range seedStatements {
		if _, err := tx.ExecContext(ctx, s.query, s.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (st *store) close() error {
	return st.db.Close()
}

// userByToken returns the user owning token, or errUnauthorized.
func (st *store) userByToken(ctx context.Context, token string) (string, error) {
	var name string
	err := st.db.QueryRowContext(ctx, `SELECT name FROM users WHERE token = ?`, token).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errUnauthorized
	}
	return name, err
}

// userExists reports whether a user called name exists.
func (st *store) userExists(ctx context.Context, name string) (bool, error) {
	var n int
	err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE name = ?`, name).Scan(&n)
	return n > 0, err
}

// balance returns the balance of user name.
func (st *store) balance(ctx context.Context, name string) (int64, error) {
	var b int64
	err := st.db.QueryRowContext(ctx, `SELECT balance_cents FROM users WHERE name = ?`, name).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errUnauthorized
	}
	return b, err
}

// discount is one coupon applied to a cart.
type discount struct {
	Code        string `json:"code"`
	AmountCents int64  `json:"amount_cents"`
}

// cart is the client view of a cart.
type cart struct {
	ID           string     `json:"id"`
	Owner        string     `json:"owner"`
	TotalCents   int64      `json:"total_cents"`
	Discounts    []discount `json:"discounts"`
	PayableCents int64      `json:"payable_cents"`
}

// newCartID returns "c_" followed by 8 lowercase hex characters.
func newCartID() (string, error) {
	b := make([]byte, cartIDRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return cartIDPrefix + hex.EncodeToString(b), nil
}

// createCart creates an empty cart owned by owner.
func (st *store) createCart(ctx context.Context, owner string) (cart, error) {
	for range cartCreateAttempts {
		id, err := newCartID()
		if err != nil {
			return cart{}, err
		}
		_, err = st.db.ExecContext(ctx,
			`INSERT INTO carts (id, owner, total_cents) VALUES (?, ?, ?)`, id, owner, cartTotalCents)
		if isConstraint(err) {
			continue // id collision; draw again
		}
		if err != nil {
			return cart{}, err
		}
		return st.cart(ctx, id, owner)
	}
	return cart{}, errors.New("could not allocate a unique cart id")
}

// cart loads cart id if it is owned by owner; otherwise errCartNotFound.
func (st *store) cart(ctx context.Context, id, owner string) (cart, error) {
	c := cart{Discounts: []discount{}}
	err := st.db.QueryRowContext(ctx,
		`SELECT id, owner, total_cents FROM carts WHERE id = ? AND owner = ?`, id, owner).
		Scan(&c.ID, &c.Owner, &c.TotalCents)
	if errors.Is(err, sql.ErrNoRows) {
		return cart{}, errCartNotFound
	}
	if err != nil {
		return cart{}, err
	}

	rows, err := st.db.QueryContext(ctx,
		`SELECT code, amount_cents FROM cart_discounts WHERE cart_id = ? ORDER BY id`, id)
	if err != nil {
		return cart{}, err
	}
	defer rows.Close()
	var discounted int64
	for rows.Next() {
		var d discount
		if err := rows.Scan(&d.Code, &d.AmountCents); err != nil {
			return cart{}, err
		}
		discounted += d.AmountCents
		c.Discounts = append(c.Discounts, d)
	}
	if err := rows.Err(); err != nil {
		return cart{}, err
	}
	c.PayableCents = max(c.TotalCents-discounted, 0)
	return c, nil
}

// insertDiscount adds a discount row to cart cartID in one statement that
// also requires the cart to exist and belong to owner. A reset that lands
// after the handler looked the cart up therefore cannot leave a discount for
// a cart that no longer exists: the insert matches no row and the result is
// errCartNotFound.
func (st *store) insertDiscount(ctx context.Context, cartID, owner, code string, amountCents int64) error {
	res, err := st.db.ExecContext(ctx,
		`INSERT INTO cart_discounts (cart_id, code, amount_cents)
		 SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM carts WHERE id = ? AND owner = ?)`,
		cartID, code, amountCents, cartID, owner)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errCartNotFound
	}
	return nil
}

// couponPercent returns the percentage of coupon code, or errCouponNotFound.
func (st *store) couponPercent(ctx context.Context, code string) (int64, error) {
	var pct int64
	err := st.db.QueryRowContext(ctx, `SELECT percent FROM coupons WHERE code = ?`, code).Scan(&pct)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errCouponNotFound
	}
	return pct, err
}

// twofaStatus returns the attempt and check counters of user.
func (st *store) twofaStatus(ctx context.Context, user string) (attempts, checks int, err error) {
	err = st.db.QueryRowContext(ctx,
		`SELECT attempts, checks FROM twofa WHERE user = ?`, user).Scan(&attempts, &checks)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, errUnauthorized
	}
	return attempts, checks, err
}

// isConstraint reports whether err is an SQLite constraint violation.
func isConstraint(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_CONSTRAINT
}
