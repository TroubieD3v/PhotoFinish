// Package store keeps the history of runs made through the local server in
// SQLite: one row per run with the summary columns the history views filter
// on, and the masked report as JSON. Reports are masked by the runner before
// they get here; the store adds nothing and never sees a secret.
//
// The database uses one connection, so database/sql serializes every access
// and a Store is safe for concurrent use. File databases run in WAL mode.
// The schema version is kept in PRAGMA user_version and migrated on Open.
package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/TroubieD3v/photofinish/internal/runner"
)

// FileName is the database file inside the data directory.
const FileName = "photofinish.db"

// Memory is the path that keeps the runs in memory, lost on Close.
const Memory = ":memory:"

// List limits.
const (
	// DefaultLimit is the number of runs List returns for a limit of 0 or
	// less.
	DefaultLimit = 100
	// MaxLimit is the most runs List returns.
	MaxLimit = 1000
)

// idBytes is the number of random bytes in a run id (12 hex digits).
const idBytes = 6

// busyTimeout is how long a write waits for another process holding the
// database (a second photofinish serve on the same data directory).
const busyTimeout = 5 * time.Second

// ErrNotFound is returned when a run does not exist.
var ErrNotFound = errors.New("run not found")

// Run is one stored run.
type Run struct {
	// ID is 12 lowercase hex digits.
	ID string `json:"id"`
	// Scenario is the scenario name, File the workspace-relative file it
	// came from ("" for a scenario that was not saved).
	Scenario string `json:"scenario"`
	File     string `json:"file"`
	// Engine is the engine used.
	Engine  string         `json:"engine"`
	Verdict runner.Verdict `json:"verdict"`
	// Summary is the report's one-sentence summary.
	Summary string `json:"summary"`
	// Trials is the number of trials that ran, Violated how many of them
	// were VIOLATED, Copies the number of requests per race.
	Trials     int       `json:"trials"`
	Violated   int       `json:"violated"`
	Copies     int       `json:"copies"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	// Report is the masked report as JSON. List leaves it nil; it is not
	// part of the JSON form of a Run.
	Report []byte `json:"-"`
}

// FromReport returns a run with a new id for a finished report, with the
// report encoded as compact JSON.
func FromReport(rep *runner.Report) (*Run, error) {
	if rep == nil {
		return nil, errors.New("store: nil report")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep invariants such as "a <= 1" readable
	if err := enc.Encode(rep); err != nil {
		return nil, fmt.Errorf("store: encode report: %w", err)
	}
	return &Run{
		ID:         NewID(),
		Scenario:   rep.Scenario,
		File:       rep.File,
		Engine:     string(rep.Engine),
		Verdict:    rep.Verdict,
		Summary:    rep.Summary,
		Trials:     rep.Stats.Ran,
		Violated:   rep.Stats.Violated,
		Copies:     rep.Copies,
		StartedAt:  rep.StartedAt,
		FinishedAt: rep.FinishedAt,
		Report:     bytes.TrimSuffix(buf.Bytes(), []byte("\n")),
	}, nil
}

// NewID returns a random run id of 12 lowercase hex digits.
func NewID() string {
	b := make([]byte, idBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

// ValidID reports whether id has the form of a run id.
func ValidID(id string) bool {
	if len(id) != 2*idBytes {
		return false
	}
	for _, c := range []byte(id) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Path returns the database path for a data directory: Memory for "" or
// ":memory:", otherwise FileName inside dir.
func Path(dir string) string {
	if dir == "" || dir == Memory {
		return Memory
	}
	return filepath.Join(dir, FileName)
}

// Store is the run history.
type Store struct {
	db *sql.DB
}

// migrations[i] moves the schema from version i to i+1.
var migrations = [][]string{
	{
		`CREATE TABLE runs (
			id          TEXT PRIMARY KEY,
			scenario    TEXT NOT NULL,
			file        TEXT NOT NULL,
			engine      TEXT NOT NULL,
			verdict     TEXT NOT NULL,
			summary     TEXT NOT NULL,
			trials      INTEGER NOT NULL,
			violated    INTEGER NOT NULL,
			copies      INTEGER NOT NULL,
			started_at  INTEGER NOT NULL, -- Unix nanoseconds, 0 for none
			finished_at INTEGER NOT NULL, -- Unix nanoseconds, 0 for none
			report      BLOB              -- masked report JSON
		) STRICT`,
		`CREATE INDEX runs_started ON runs(started_at DESC)`,
		`CREATE INDEX runs_scenario ON runs(scenario, started_at DESC)`,
	},
}

// SchemaVersion is the schema version this package writes; migrations
// has one entry per version.
const SchemaVersion = 1

// Open opens the database at path, creating it and its directory if
// needed, and migrates the schema. "" and ":memory:" keep the runs in
// memory.
func Open(path string) (*Store, error) {
	memory := path == "" || path == Memory
	dsn := Memory
	if !memory {
		if strings.Contains(path, "?") {
			return nil, fmt.Errorf("store: database path %q must not contain '?'", path)
		}
		if err := prepareFile(path); err != nil {
			return nil, err
		}
		q := url.Values{}
		q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeout.Milliseconds()))
		q.Add("_pragma", "synchronous(NORMAL)")
		dsn = path + "?" + q.Encode()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One connection: writes never contend inside the process, and an
	// in-memory database lives exactly as long as its connection.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	s := &Store{db: db}
	if err := s.migrate(memory); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: %s: %w", valueOr(path, Memory), err)
	}
	return s, nil
}

// prepareFile creates the directory of the database and the database file
// itself, readable by the owner only, if they do not exist.
func prepareFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return f.Close()
}

// sqliteBusy is the primary result code SQLITE_BUSY.
const sqliteBusy = 5

// migrate switches a file database to WAL and brings the schema to
// SchemaVersion. Two processes may open a new data directory at the same
// time: the migration runs inside BEGIN IMMEDIATE and reads the version
// again once it holds the write lock, so that the second one finds the
// schema in place. SQLITE_BUSY answers that SQLite gives without waiting
// for the busy timeout (while another connection changes the journal mode,
// for one) are retried for up to busyTimeout.
func (s *Store) migrate(memory bool) error {
	ctx := context.Background()
	deadline := time.Now().Add(busyTimeout)
	for attempt := 1; ; attempt++ {
		err := s.migrateOnce(ctx, memory)
		if err == nil || !isBusy(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(min(time.Duration(attempt)*10*time.Millisecond, 100*time.Millisecond))
	}
}

// migrateOnce is one attempt of migrate.
func (s *Store) migrateOnce(ctx context.Context, memory bool) error {
	if !memory {
		var mode string
		if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode = WAL`).Scan(&mode); err != nil {
			return fmt.Errorf("switch to WAL: %w", err)
		}
	}
	version, err := schemaVersion(ctx, s.db)
	if err != nil || version == SchemaVersion {
		return err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// database/sql transactions begin DEFERRED, and a deferred transaction
	// that reads and then writes can fail with SQLITE_BUSY at once when
	// another connection writes first; IMMEDIATE takes the write lock up
	// front and waits for it.
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("lock the database for the migration: %w", err)
	}
	if err := migrateLocked(ctx, conn); err != nil {
		_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		return fmt.Errorf("migrate to version %d: %w", SchemaVersion, err)
	}
	return nil
}

// migrateLocked runs the missing migrations; the caller holds the write
// lock, so the version it reads cannot change underneath.
func migrateLocked(ctx context.Context, conn *sql.Conn) error {
	version, err := schemaVersion(ctx, conn)
	if err != nil {
		return err
	}
	for v := version; v < SchemaVersion; v++ {
		for _, stmt := range migrations[v] {
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migrate to version %d: %w", v+1, err)
			}
		}
		// PRAGMA does not take parameters; v+1 is a constant of this package.
		if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			return fmt.Errorf("migrate to version %d: %w", v+1, err)
		}
	}
	return nil
}

// rowQuerier is a *sql.DB or a *sql.Conn.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// schemaVersion reads PRAGMA user_version and refuses a version newer than
// this package writes.
func schemaVersion(ctx context.Context, q rowQuerier) (int, error) {
	var version int
	if err := q.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	if version > SchemaVersion {
		return 0, fmt.Errorf("schema version %d is newer than this photofinish supports (%d)", version, SchemaVersion)
	}
	return version, nil
}

// isBusy reports whether err is SQLITE_BUSY or one of its extended codes.
func isBusy(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqliteBusy
}

// Close closes the database. An in-memory history is lost.
func (s *Store) Close() error { return s.db.Close() }

// Save inserts r or replaces the stored run with the same id. An empty
// r.ID is set to a new id.
func (s *Store) Save(r *Run) error {
	if r == nil {
		return errors.New("store: nil run")
	}
	if r.ID == "" {
		r.ID = NewID()
	}
	if !ValidID(r.ID) {
		return fmt.Errorf("store: invalid run id %q (want 12 lowercase hex digits)", r.ID)
	}
	_, err := s.db.Exec(`INSERT INTO runs
		(id, scenario, file, engine, verdict, summary, trials, violated, copies, started_at, finished_at, report)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			scenario = excluded.scenario, file = excluded.file, engine = excluded.engine,
			verdict = excluded.verdict, summary = excluded.summary, trials = excluded.trials,
			violated = excluded.violated, copies = excluded.copies, started_at = excluded.started_at,
			finished_at = excluded.finished_at, report = excluded.report`,
		r.ID, r.Scenario, r.File, r.Engine, string(r.Verdict), r.Summary,
		r.Trials, r.Violated, r.Copies, toNanos(r.StartedAt), toNanos(r.FinishedAt), r.Report)
	if err != nil {
		return fmt.Errorf("store: save run %s: %w", r.ID, err)
	}
	return nil
}

// columns are the summary columns, in the order scanRun reads them.
const columns = `id, scenario, file, engine, verdict, summary, trials, violated, copies, started_at, finished_at`

// scanner is a *sql.Row or *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

// scanRun reads the summary columns, followed by extra destinations.
func scanRun(sc scanner, extra ...any) (Run, error) {
	var r Run
	var verdict string
	var started, finished int64
	dest := append([]any{&r.ID, &r.Scenario, &r.File, &r.Engine, &verdict, &r.Summary,
		&r.Trials, &r.Violated, &r.Copies, &started, &finished}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return Run{}, err
	}
	r.Verdict = runner.Verdict(verdict)
	r.StartedAt, r.FinishedAt = fromNanos(started), fromNanos(finished)
	return r, nil
}

// Get returns the run with the given id, report included, or ErrNotFound.
func (s *Store) Get(id string) (*Run, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	var report []byte
	r, err := scanRun(s.db.QueryRow(`SELECT `+columns+`, report FROM runs WHERE id = ?`, id), &report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get run %s: %w", id, err)
	}
	r.Report = report
	return &r, nil
}

// List returns up to limit runs, newest first, without their reports. A
// limit of 0 or less means DefaultLimit; limits above MaxLimit are capped.
// A non-empty scenario keeps only the runs of that scenario name.
func (s *Store) List(limit int, scenario string) ([]Run, error) {
	return s.Query(Filter{Limit: limit, Scenario: scenario})
}

// Filter selects the runs Query returns.
type Filter struct {
	// Limit is the most runs returned; 0 or less means DefaultLimit, and
	// limits above MaxLimit are capped.
	Limit int
	// Scenario, when set, keeps the runs of that scenario name only.
	Scenario string
	// Verdict, when set, keeps the runs with that verdict only.
	Verdict runner.Verdict
}

// Query returns the runs that match f, newest first, without their
// reports. The filters apply before the limit, so old runs of a scenario
// are found however many newer runs other scenarios have.
func (s *Store) Query(f Filter) ([]Run, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	limit = min(limit, MaxLimit)
	var where []string
	args := []any{}
	if f.Scenario != "" {
		where = append(where, `scenario = ?`)
		args = append(args, f.Scenario)
	}
	if f.Verdict != "" {
		where = append(where, `verdict = ?`)
		args = append(args, string(f.Verdict))
	}
	query := `SELECT ` + columns + ` FROM runs`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY started_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit)
	return s.collect(`list runs`, query, args...)
}

// LatestByFile returns the newest run of every scenario file, keyed by the
// workspace-relative file; runs without a file are left out.
func (s *Store) LatestByFile() (map[string]Run, error) {
	runs, err := s.collect(`latest runs`, `SELECT `+columns+` FROM (
		SELECT `+columns+`, ROW_NUMBER() OVER (PARTITION BY file ORDER BY started_at DESC, rowid DESC) AS n
		FROM runs WHERE file != ''
	) WHERE n = 1`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Run, len(runs))
	for _, r := range runs {
		out[r.File] = r
	}
	return out, nil
}

// Scenarios returns the distinct scenario names of the stored runs, sorted.
func (s *Store) Scenarios() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT scenario FROM runs WHERE scenario != '' ORDER BY scenario`)
	if err != nil {
		return nil, fmt.Errorf("store: list scenario names: %w", err)
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: list scenario names: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list scenario names: %w", err)
	}
	return names, nil
}

// collect runs a query of the summary columns; what names it in errors.
func (s *Store) collect(what, query string, args ...any) ([]Run, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: %s: %w", what, err)
	}
	defer rows.Close()
	runs := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("store: %s: %w", what, err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: %s: %w", what, err)
	}
	return runs, nil
}

// Delete removes the run with the given id, or returns ErrNotFound.
func (s *Store) Delete(id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	res, err := s.db.Exec(`DELETE FROM runs WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete run %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// toNanos stores t as Unix nanoseconds, 0 for the zero time.
func toNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// fromNanos is the inverse of toNanos, in UTC.
func fromNanos(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// valueOr returns v, or def when v is empty.
func valueOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
