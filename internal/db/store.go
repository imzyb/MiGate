package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db                        *sql.DB
	trafficCleanupMu          sync.Mutex
	nextTrafficSamplesCleanup time.Time
}

func Open(ctx context.Context, path string) (*Store, error) {
	database, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	configureSQLitePool(database, path)
	if err := verifyForeignKeysEnabled(ctx, database); err != nil {
		database.Close()
		return nil, err
	}
	if err := configureSQLitePragmas(ctx, database); err != nil {
		database.Close()
		return nil, err
	}
	store := &Store{db: database}
	if err := store.migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func configureSQLitePool(database *sql.DB, path string) {
	if isInMemorySQLitePath(path) {
		database.SetMaxOpenConns(1)
		database.SetMaxIdleConns(1)
		return
	}
	database.SetMaxOpenConns(4)
	database.SetMaxIdleConns(4)
	database.SetConnMaxLifetime(30 * time.Minute)
}

func configureSQLitePragmas(ctx context.Context, database *sql.DB) error {
	pragmas := []string{
		`PRAGMA busy_timeout=5000`,
		`PRAGMA synchronous=NORMAL`,
		`PRAGMA temp_store=MEMORY`,
	}
	for _, pragma := range pragmas {
		if _, err := database.ExecContext(ctx, pragma); err != nil {
			return err
		}
	}
	return nil
}

func sqliteDSN(path string) string {
	dsn := path
	pragmas := []string{
		"foreign_keys(1)",
		"busy_timeout(5000)",
		"synchronous(NORMAL)",
		"temp_store(MEMORY)",
	}
	if !isInMemorySQLitePath(path) {
		pragmas = append(pragmas, "journal_mode(WAL)")
	}
	for _, pragma := range pragmas {
		if !strings.Contains(dsn, "_pragma="+url.QueryEscape(pragma)) && !strings.Contains(dsn, "_pragma="+pragma) {
			dsn = appendSQLiteQueryParam(dsn, "_pragma", pragma)
		}
	}
	return dsn
}

func isInMemorySQLitePath(path string) bool {
	return path == ":memory:" || strings.Contains(path, "mode=memory")
}

func appendSQLiteQueryParam(dsn, key, value string) string {
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	return dsn + separator + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}

func verifyForeignKeysEnabled(ctx context.Context, database *sql.DB) error {
	var enabled int
	if err := database.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&enabled); err != nil {
		return err
	}
	if enabled != 1 {
		return fmt.Errorf("sqlite foreign_keys pragma is disabled")
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}

func randomHexToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newSecret(byteLen int) string {
	token, err := randomHexToken(byteLen)
	if err != nil {
		panic(err)
	}
	return token
}
