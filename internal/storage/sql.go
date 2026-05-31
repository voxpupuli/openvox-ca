// Copyright (C) 2026 Chris Boot
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package storage

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
	"github.com/uptrace/bun/dialect/mysqldialect"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/uptrace/bun/migrate"
	"github.com/uptrace/bun/schema"
)

// SQLDialect selects which SQL engine an SQLBackend talks to. The same backend
// implementation drives every dialect; only DSN/driver selection, a few
// dialect-specific SQL clauses (upsert, row locking), and the distributed-lock
// mechanism differ.
type SQLDialect string

const (
	// SQLitePure targets a single SQLite database file via the pure-Go
	// modernc.org/sqlite driver (no CGO). SQLite is single-node, so it does
	// not provide a distributed lock.
	SQLitePure SQLDialect = "sqlite"
	// SQLPostgres targets PostgreSQL.
	SQLPostgres SQLDialect = "postgres"
	// SQLMySQL targets MySQL or MariaDB.
	SQLMySQL SQLDialect = "mysql"

	// sqlBusyTimeoutMS is the SQLite busy-timeout (milliseconds) appended to
	// the DSN when the caller has not set one. It makes a writer wait for a
	// concurrent writer to finish instead of failing immediately with
	// "database is locked".
	sqlBusyTimeoutMS = 10000

	sqlDefaultTimeout = 10 * time.Second
)

// SQLConfig configures an SQLBackend.
type SQLConfig struct {
	// Dialect selects the SQL engine. Required.
	Dialect SQLDialect

	// DSN is the driver-specific data source name. For SQLite it is a file
	// path or "file:" URI; for PostgreSQL/MySQL it is the connection string
	// understood by the respective driver.
	DSN string

	// TLS, if non-nil, configures TLS for the networked dialects (PostgreSQL,
	// MySQL). Ignored by SQLite.
	TLS *tls.Config

	// RequestTimeout bounds each individual operation. Zero uses 10s.
	RequestTimeout time.Duration

	// MaxOpenConns / MaxIdleConns tune the underlying database/sql pool. Zero
	// leaves the database/sql defaults in place, except SQLite which is pinned
	// to a single open connection (see NewSQLBackend).
	MaxOpenConns int
	MaxIdleConns int
}

func (c *SQLConfig) applyDefaults() {
	if c.RequestTimeout == 0 {
		c.RequestTimeout = sqlDefaultTimeout
	}
}

// sqlBlob is the single table backing every logical key. The key column is
// named blob_key (not "key") to avoid clashing with the reserved word KEY in
// MySQL/MariaDB. modified_at is a real column, so unlike the etcd/redis
// backends there is no need to prefix the payload with an mtime.
type sqlBlob struct {
	bun.BaseModel `bun:"table:puppet_ca_blobs,alias:b"`

	Key        string    `bun:"blob_key,pk,type:varchar(512)"`
	Data       []byte    `bun:"data"`
	Kind       int       `bun:"kind,notnull"`
	ModifiedAt time.Time `bun:"modified_at,notnull"`
}

// SQLBackend is a Backend implementation backed by a SQL database (SQLite,
// PostgreSQL, or MySQL/MariaDB). It stores every logical key as one row in a
// single key-value table and runs bun migrations on EnsureReady to create and
// version the schema.
//
// AppendLine is made atomic with a per-process mutex plus a row-locking
// transaction (SELECT ... FOR UPDATE on engines that support it), so
// concurrent appenders — including separate replicas sharing one database —
// never lose lines. Distributed locking is provided per dialect via AcquireLock
// (PostgreSQL advisory locks, MySQL GET_LOCK); SQLite, being single-node,
// reports ErrDistributedLockingUnsupported so StorageService falls back to a
// process-local mutex.
type SQLBackend struct {
	db      *bun.DB
	owned   bool // true when Close should close the underlying *sql.DB
	timeout time.Duration

	appendMu sync.Mutex // serialises AppendLine within this process

	// localLocks holds a *sync.Mutex per lock name, serialising intra-process
	// contention before the distributed lock is taken so that goroutines in
	// this process do not each hold a blocked connection waiting on the same
	// lock. Same pattern as the etcd and Redis backends.
	localLocks sync.Map
}

// sqlTLSConfigSeq names the per-backend TLS configs the MySQL driver requires
// to be registered globally. A monotonic counter keeps each registration name
// unique across backends in the process.
var sqlTLSConfigSeq atomic.Int64

// NewSQLBackend opens a database connection according to cfg and returns a
// ready backend. The caller must call Close to release the connection pool.
func NewSQLBackend(cfg SQLConfig) (*SQLBackend, error) {
	cfg.applyDefaults()

	sqldb, bunDialect, err := openSQLDB(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Dialect == SQLitePure {
		// A single SQLite file tolerates only one writer at a time; pinning the
		// pool to one connection avoids spurious "database is locked" errors
		// and keeps WAL/rollback semantics predictable.
		sqldb.SetMaxOpenConns(1)
	} else {
		if cfg.MaxOpenConns > 0 {
			sqldb.SetMaxOpenConns(cfg.MaxOpenConns)
		}
		if cfg.MaxIdleConns > 0 {
			sqldb.SetMaxIdleConns(cfg.MaxIdleConns)
		}
	}

	return newSQLBackend(bun.NewDB(sqldb, bunDialect), true, cfg.RequestTimeout), nil
}

// NewSQLBackendFromDB wraps an existing *bun.DB. The backend does not take
// ownership and Close leaves the handle open. Used by tests that want to share
// a single database across backends to simulate multiple replicas.
func NewSQLBackendFromDB(db *bun.DB, requestTimeout time.Duration) *SQLBackend {
	if requestTimeout == 0 {
		requestTimeout = sqlDefaultTimeout
	}
	return newSQLBackend(db, false, requestTimeout)
}

func newSQLBackend(db *bun.DB, owned bool, timeout time.Duration) *SQLBackend {
	return &SQLBackend{db: db, owned: owned, timeout: timeout}
}

// openSQLDB opens the database/sql handle and matching bun dialect for cfg.
// PostgreSQL and MySQL support is added in later changes; selecting them here
// returns a clear error until then.
func openSQLDB(cfg SQLConfig) (*sql.DB, schema.Dialect, error) {
	switch cfg.Dialect {
	case SQLitePure:
		dsn := sqliteDSNWithDefaults(cfg.DSN)
		sqldb, err := sql.Open(sqliteshim.ShimName, dsn)
		if err != nil {
			return nil, nil, fmt.Errorf("opening sqlite database: %w", err)
		}
		return sqldb, sqlitedialect.New(), nil
	case SQLPostgres:
		opts := []pgdriver.Option{pgdriver.WithDSN(cfg.DSN)}
		if cfg.TLS != nil {
			opts = append(opts, pgdriver.WithTLSConfig(cfg.TLS))
		}
		sqldb := sql.OpenDB(pgdriver.NewConnector(opts...))
		return sqldb, pgdialect.New(), nil
	case SQLMySQL:
		mycfg, err := mysqldriver.ParseDSN(cfg.DSN)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing mysql dsn: %w", err)
		}
		// ParseTime is required so DATETIME columns scan into time.Time
		// (otherwise the driver returns raw bytes and ModTime scanning fails).
		mycfg.ParseTime = true
		if cfg.TLS != nil {
			name := fmt.Sprintf("puppet-ca-%d", sqlTLSConfigSeq.Add(1))
			if err := mysqldriver.RegisterTLSConfig(name, cfg.TLS); err != nil {
				return nil, nil, fmt.Errorf("registering mysql tls config: %w", err)
			}
			mycfg.TLSConfig = name
		}
		connector, err := mysqldriver.NewConnector(mycfg)
		if err != nil {
			return nil, nil, fmt.Errorf("creating mysql connector: %w", err)
		}
		return sql.OpenDB(connector), mysqldialect.New(), nil
	default:
		return nil, nil, fmt.Errorf("unknown SQL dialect %q", cfg.Dialect)
	}
}

// sqliteDSNWithDefaults adds connection parameters that make SQLite behave well
// under the CA's concurrent access pattern, unless the caller has already set
// them:
//
//   - _txlock=immediate makes every transaction start with BEGIN IMMEDIATE so a
//     read-then-write transaction (AppendLine) takes the write lock up front.
//     Without it two writers can each hold a shared read lock and deadlock when
//     they try to upgrade — a deadlock busy_timeout cannot resolve.
//   - busy_timeout makes a writer wait for a peer to finish rather than failing
//     immediately with SQLITE_BUSY.
//   - journal_mode=WAL lets readers proceed without blocking the single writer.
func sqliteDSNWithDefaults(dsn string) string {
	add := func(s, param, kv string) string {
		if strings.Contains(s, param) {
			return s
		}
		sep := "?"
		if strings.Contains(s, "?") {
			sep = "&"
		}
		return s + sep + kv
	}
	dsn = add(dsn, "_txlock", "_txlock=immediate")
	dsn = add(dsn, "busy_timeout", fmt.Sprintf("_pragma=busy_timeout(%d)", sqlBusyTimeoutMS))
	dsn = add(dsn, "journal_mode", "_pragma=journal_mode(WAL)")
	return dsn
}

// validateKey rejects obviously unsafe logical keys. The key is stored verbatim
// as the primary key, so this mostly guards against caller bugs.
func validateKey(key string) error {
	if key == "" {
		return fmt.Errorf("empty key")
	}
	if strings.Contains(key, "..") {
		return fmt.Errorf("invalid key %q: must not contain ..", key)
	}
	return nil
}

// callCtx layers the backend's per-call timeout on top of the caller's context.
// Caller cancellation always wins; with no caller deadline b.timeout bounds the
// call.
func (b *SQLBackend) callCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, b.timeout)
}

// EnsureReady verifies connectivity and brings the schema up to date by running
// the bun migrations. Safe to call multiple times: the migrator records applied
// versions and serialises concurrent runners with its lock table.
func (b *SQLBackend) EnsureReady(ctx context.Context) error {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	if err := b.db.PingContext(ctx); err != nil {
		return fmt.Errorf("sql database not reachable: %w", err)
	}

	migrator := migrate.NewMigrator(b.db, sqlMigrations)
	if err := migrator.Init(ctx); err != nil {
		return fmt.Errorf("initialising migrations: %w", err)
	}
	if _, err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// Get returns the blob at key, wrapping fs.ErrNotExist when absent.
func (b *SQLBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	row := new(sqlBlob)
	err := b.db.NewSelect().Model(row).Column("data").Where("blob_key = ?", key).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	// Normalise NULL/empty to a non-nil empty slice so callers can distinguish
	// "present but empty" (e.g. a freshly touched inventory) from absent.
	if row.Data == nil {
		return []byte{}, nil
	}
	return row.Data, nil
}

// Put stores data at key, inserting or replacing the row. The BlobKind hint is
// recorded in the kind column but does not affect access control, which is
// managed by the database server.
func (b *SQLBackend) Put(ctx context.Context, key string, data []byte, kind BlobKind) error {
	if err := validateKey(key); err != nil {
		return err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	return b.upsert(ctx, b.db, &sqlBlob{
		Key:        key,
		Data:       data,
		Kind:       int(kind),
		ModifiedAt: time.Now(),
	})
}

// upsert inserts row or, on primary-key conflict, updates the existing row. The
// ON-conflict clause differs between dialects, so it branches on the dialect
// name; idb is either the *bun.DB or an in-flight bun.Tx.
func (b *SQLBackend) upsert(ctx context.Context, idb bun.IDB, row *sqlBlob) error {
	q := idb.NewInsert().Model(row)
	switch b.db.Dialect().Name() {
	case dialect.MySQL:
		q = q.On("DUPLICATE KEY UPDATE").
			Set("data = VALUES(data)").
			Set("kind = VALUES(kind)").
			Set("modified_at = VALUES(modified_at)")
	default: // PostgreSQL, SQLite
		q = q.On("CONFLICT (blob_key) DO UPDATE").
			Set("data = EXCLUDED.data").
			Set("kind = EXCLUDED.kind").
			Set("modified_at = EXCLUDED.modified_at")
	}
	_, err := q.Exec(ctx)
	return err
}

// Delete removes key, wrapping fs.ErrNotExist when the key is absent.
func (b *SQLBackend) Delete(ctx context.Context, key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	res, err := b.db.NewDelete().Model((*sqlBlob)(nil)).Where("blob_key = ?", key).Exec(ctx)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return &fs.PathError{Op: "delete", Path: key, Err: fs.ErrNotExist}
	}
	return nil
}

// Exists reports whether key is present.
func (b *SQLBackend) Exists(ctx context.Context, key string) (bool, error) {
	if err := validateKey(key); err != nil {
		return false, err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	return b.db.NewSelect().Model((*sqlBlob)(nil)).Where("blob_key = ?", key).Exists(ctx)
}

// List returns the logical keys sharing prefix. Only csrPrefix and certPrefix
// are supported, matching the other backends.
func (b *SQLBackend) List(ctx context.Context, prefix string) ([]string, error) {
	switch prefix {
	case csrPrefix, certPrefix:
	default:
		return nil, fmt.Errorf("unsupported list prefix %q", prefix)
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	var keys []string
	err := b.db.NewSelect().
		Model((*sqlBlob)(nil)).
		Column("blob_key").
		Where("blob_key LIKE ?", prefix+"%").
		Order("blob_key").
		Scan(ctx, &keys)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// AppendLine atomically appends data to key, creating it if absent. Appends
// from this process are serialised on appendMu; cross-replica concurrency is
// resolved by a row-locking transaction that reads, appends, and writes back
// the blob in one atomic step.
//
// On MySQL/MariaDB the FOR UPDATE-then-insert pattern can raise an InnoDB
// deadlock (1213) when two connections race to create the same not-yet-existing
// row; InnoDB rolls one back as the victim. That is the expected, transient
// outcome, so the transaction is retried a bounded number of times.
func (b *SQLBackend) AppendLine(ctx context.Context, key string, data []byte, kind BlobKind) error {
	if err := validateKey(key); err != nil {
		return err
	}
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	const maxAttempts = 10
	for attempt := 0; ; attempt++ {
		err := b.appendLineOnce(ctx, key, data, kind)
		if err == nil {
			return nil
		}
		if attempt+1 >= maxAttempts || !isRetryableSQLError(err) {
			return err
		}
		// Brief, growing backoff so a deadlock victim does not immediately
		// re-collide with the winner. Honour caller cancellation while waiting.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 5 * time.Millisecond):
		}
	}
}

func (b *SQLBackend) appendLineOnce(ctx context.Context, key string, data []byte, kind BlobKind) error {
	return b.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		row := new(sqlBlob)
		q := tx.NewSelect().Model(row).Column("data").Where("blob_key = ?", key)
		// SQLite has no row-level locks (its write transaction is already
		// exclusive), and rejects FOR UPDATE; other engines take the row lock
		// so a concurrent appender on another connection blocks here.
		if b.db.Dialect().Name() != dialect.SQLite {
			q = q.For("UPDATE")
		}
		existing := []byte(nil)
		switch err := q.Scan(ctx); {
		case err == nil:
			existing = row.Data
		case errors.Is(err, sql.ErrNoRows):
			// First append: row created below.
		default:
			return err
		}

		combined := make([]byte, 0, len(existing)+len(data))
		combined = append(combined, existing...)
		combined = append(combined, data...)

		return b.upsert(ctx, tx, &sqlBlob{
			Key:        key,
			Data:       combined,
			Kind:       int(kind),
			ModifiedAt: time.Now(),
		})
	})
}

// isRetryableSQLError reports whether err is a transient MySQL/MariaDB locking
// error that warrants retrying the transaction: 1213 (deadlock) or 1205 (lock
// wait timeout). Other dialects do not surface these, so they fall through.
func isRetryableSQLError(err error) bool {
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == 1213 || myErr.Number == 1205
	}
	return false
}

// ModTime returns the timestamp recorded when the blob was last written,
// wrapping fs.ErrNotExist when the key is absent.
func (b *SQLBackend) ModTime(ctx context.Context, key string) (time.Time, error) {
	if err := validateKey(key); err != nil {
		return time.Time{}, err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	row := new(sqlBlob)
	err := b.db.NewSelect().Model(row).Column("modified_at").Where("blob_key = ?", key).Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, &fs.PathError{Op: "modtime", Path: key, Err: fs.ErrNotExist}
		}
		return time.Time{}, err
	}
	return row.ModifiedAt, nil
}

// AcquireLock obtains a cross-node distributed mutex named name. The mechanism
// is dialect-specific; SQLite is single-node and reports
// ErrDistributedLockingUnsupported so StorageService falls back to a
// process-local mutex.
func (b *SQLBackend) AcquireLock(ctx context.Context, name string) (Unlocker, error) {
	switch b.db.Dialect().Name() {
	case dialect.PG:
		return b.acquirePostgresLock(ctx, name)
	case dialect.MySQL:
		return b.acquireMySQLLock(ctx, name)
	default:
		// SQLite is single-node: fall back to the process-local mutex.
		return nil, ErrDistributedLockingUnsupported
	}
}

// acquirePostgresLock takes a session-level PostgreSQL advisory lock on a
// dedicated connection. The lock name is hashed to the bigint key
// pg_advisory_lock requires; lock and unlock must run on the same session, so
// the connection is held until Unlock. A process-local mutex serialises
// in-process callers first so they do not each tie up a connection blocked in
// pg_advisory_lock. pg_advisory_lock itself blocks until granted or the context
// is cancelled.
func (b *SQLBackend) acquirePostgresLock(ctx context.Context, name string) (Unlocker, error) {
	local := b.localLockFor(name)
	local.Lock()

	conn, err := b.db.Conn(ctx)
	if err != nil {
		local.Unlock()
		return nil, fmt.Errorf("acquiring connection for lock %q: %w", name, err)
	}

	key := advisoryLockKey(name)
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock(?)", key); err != nil {
		_ = conn.Close()
		local.Unlock()
		return nil, fmt.Errorf("acquiring postgres advisory lock %q: %w", name, err)
	}

	return &pgUnlocker{conn: conn, key: key, local: local, timeout: b.timeout}, nil
}

// localLockFor returns the process-local mutex for lock name, creating it on
// first use. Mutexes are never removed; the namespace is small and bounded.
func (b *SQLBackend) localLockFor(name string) *sync.Mutex {
	if v, ok := b.localLocks.Load(name); ok {
		return v.(*sync.Mutex)
	}
	v, _ := b.localLocks.LoadOrStore(name, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// advisoryLockKey hashes a lock name to the int64 key that PostgreSQL's
// pg_advisory_lock family requires. FNV-1a gives a stable mapping across
// processes and replicas, which is what matters for cross-node coordination.
func advisoryLockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64()) // wraps to a signed bigint; the bit pattern is stable
}

// pgUnlocker releases a PostgreSQL advisory lock on the same connection that
// acquired it, then returns the connection to the pool and releases the
// process-local mutex. The local mutex is always released even if the advisory
// unlock fails, so a transient error cannot wedge later in-process callers.
type pgUnlocker struct {
	conn    bun.Conn
	key     int64
	local   *sync.Mutex
	timeout time.Duration
}

func (u *pgUnlocker) Unlock() error {
	ctx, cancel := context.WithTimeout(context.Background(), u.timeout)
	defer cancel()
	_, err := u.conn.ExecContext(ctx, "SELECT pg_advisory_unlock(?)", u.key)
	_ = u.conn.Close()
	u.local.Unlock()
	return err
}

// acquireMySQLLock takes a named MySQL/MariaDB lock via GET_LOCK on a dedicated
// connection (GET_LOCK is session-scoped, so lock and release must share one
// connection). The lock name is hashed to a short, stable string to stay within
// MySQL's 64-character GET_LOCK name limit. GET_LOCK is polled with a 1-second
// server-side wait so caller-context cancellation is honoured between attempts;
// a process-local mutex serialises in-process callers first.
func (b *SQLBackend) acquireMySQLLock(ctx context.Context, name string) (Unlocker, error) {
	local := b.localLockFor(name)
	local.Lock()

	conn, err := b.db.Conn(ctx)
	if err != nil {
		local.Unlock()
		return nil, fmt.Errorf("acquiring connection for lock %q: %w", name, err)
	}

	lockName := mysqlLockName(name)
	for {
		var got sql.NullInt64
		if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 1)", lockName).Scan(&got); err != nil {
			_ = conn.Close()
			local.Unlock()
			return nil, fmt.Errorf("acquiring mysql lock %q: %w", name, err)
		}
		if got.Valid && got.Int64 == 1 {
			return &mysqlUnlocker{conn: conn, lockName: lockName, local: local, timeout: b.timeout}, nil
		}
		if !got.Valid {
			// NULL means an error occurred (e.g. the session was killed).
			_ = conn.Close()
			local.Unlock()
			return nil, fmt.Errorf("acquiring mysql lock %q: GET_LOCK returned NULL", name)
		}
		// got == 0: the 1-second wait elapsed without the lock. Honour caller
		// cancellation, then retry.
		select {
		case <-ctx.Done():
			_ = conn.Close()
			local.Unlock()
			return nil, fmt.Errorf("acquiring mysql lock %q: %w", name, ctx.Err())
		default:
		}
	}
}

// mysqlLockName maps a lock name to a stable, short identifier within MySQL's
// 64-character GET_LOCK name limit.
func mysqlLockName(name string) string {
	return fmt.Sprintf("puppet-ca:%016x", uint64(advisoryLockKey(name)))
}

// mysqlUnlocker releases a GET_LOCK on the same connection that acquired it,
// then returns the connection to the pool and releases the process-local mutex.
// The local mutex is always released even if RELEASE_LOCK fails.
type mysqlUnlocker struct {
	conn     bun.Conn
	lockName string
	local    *sync.Mutex
	timeout  time.Duration
}

func (u *mysqlUnlocker) Unlock() error {
	ctx, cancel := context.WithTimeout(context.Background(), u.timeout)
	defer cancel()
	_, err := u.conn.ExecContext(ctx, "SELECT RELEASE_LOCK(?)", u.lockName)
	_ = u.conn.Close()
	u.local.Unlock()
	return err
}

// Close releases the underlying connection pool when owned by this backend.
func (b *SQLBackend) Close() error {
	if !b.owned || b.db == nil {
		return nil
	}
	return b.db.Close()
}
