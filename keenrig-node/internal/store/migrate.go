package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrate chạy migration embed mặc định.
func migrate(db *sql.DB) error {
	return migrateFS(db, migrationsFS, "migrations")
}

// migrateFS chạy tuần tự <dir>/*.sql trong fsys (sort theo tên), track bằng PRAGMA user_version.
// Idempotent: gọi lại chỉ chạy các migration có số thứ tự > user_version hiện tại.
// Mỗi migration chạy trong 1 transaction — SQL hỏng → rollback, user_version giữ nguyên.
// Tách khỏi migrate(db) để test inject fs.FS chứa SQL hỏng.
func migrateFS(db *sql.DB, fsys fs.FS, dir string) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}

	for i, name := range names {
		v := i + 1
		if v <= version {
			continue
		}
		if err := applyMigration(db, fsys, dir, name, v); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration chạy 1 file migration + cập nhật user_version trong cùng transaction.
func applyMigration(db *sql.DB, fsys fs.FS, dir, name string, version int) error {
	ddl, err := fs.ReadFile(fsys, dir+"/"+name)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(string(ddl)); err != nil {
		tx.Rollback()
		return fmt.Errorf("migrate %s: %w", name, err)
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		tx.Rollback()
		return fmt.Errorf("migrate %s: set user_version: %w", name, err)
	}
	return tx.Commit()
}
