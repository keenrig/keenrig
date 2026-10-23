// Package store_test — external test package: gọi được storetest mà không
// tạo import cycle (storetest import store).
package store_test

import (
	"path/filepath"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
	"github.com/keenrig/keenrig/keenrig-node/internal/store/storetest"
)

func TestSQLiteConformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) store.Store {
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	})
}
