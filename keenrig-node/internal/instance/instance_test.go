package instance_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/instance"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

func newConfig(t *testing.T) (*instance.Config, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return instance.New(st), st
}

// Cloud thắng local ở CẢ HAI thứ tự — local trước rồi cloud đè; cloud trước
// rồi local bị bỏ qua. Đây là luật chủ dự án 2026-09-07 viết thành máy kiểm.
func TestCloudWinsInBothOrders(t *testing.T) {
	ctx := context.Background()

	t.Run("local rồi cloud", func(t *testing.T) {
		cfg, _ := newConfig(t)
		if ok, err := cfg.ApplyLocal(ctx, "home.example.com"); err != nil || !ok {
			t.Fatalf("ApplyLocal = (%v, %v)", ok, err)
		}
		if err := cfg.SetFromCloud(ctx, "demo.acme.keenrig.com", instance.ModeKeenrig); err != nil {
			t.Fatal(err)
		}
		info, _ := cfg.Info(ctx)
		if info != (instance.Info{ParentDomain: "demo.acme.keenrig.com", Source: instance.SourceCloud, Mode: "keenrig"}) {
			t.Errorf("Info = %+v", info)
		}
	})

	t.Run("cloud rồi local", func(t *testing.T) {
		cfg, _ := newConfig(t)
		if err := cfg.SetFromCloud(ctx, "demo.acme.keenrig.com", instance.ModeKeenrig); err != nil {
			t.Fatal(err)
		}
		if ok, err := cfg.ApplyLocal(ctx, "home.example.com"); err != nil || ok {
			t.Fatalf("ApplyLocal trên box đã có tên cloud = (%v, %v), muốn (false, nil)", ok, err)
		}
		info, _ := cfg.Info(ctx)
		if info.ParentDomain != "demo.acme.keenrig.com" || info.Source != instance.SourceCloud {
			t.Errorf("KEENRIG_DOMAIN đè được tên của cloud: %+v", info)
		}
	})
}

// Tên hỏng bị chặn bằng ErrInvalidDomain (→ 400 ở nodeapi) và KHÔNG chạm store.
func TestInvalidNamesAreRejectedTyped(t *testing.T) {
	ctx := context.Background()
	cfg, st := newConfig(t)
	for _, bad := range []string{"", "*.iot.keenrig.com", "a..b", "nodots", "-x.example.com"} {
		if err := cfg.SetFromCloud(ctx, bad, instance.ModeKeenrig); !errors.Is(err, instance.ErrInvalidDomain) {
			t.Errorf("SetFromCloud(%q) = %v, muốn ErrInvalidDomain", bad, err)
		}
	}
	if err := cfg.SetFromCloud(ctx, "x.example.com", "magic"); !errors.Is(err, instance.ErrInvalidDomain) {
		t.Errorf("mode lạ = %v, muốn ErrInvalidDomain", err)
	}
	if _, err := cfg.ApplyLocal(ctx, "*.example.com"); !errors.Is(err, instance.ErrInvalidDomain) {
		t.Errorf("ApplyLocal wildcard = %v, muốn ErrInvalidDomain", err)
	}
	if v, err := st.GetSetting(ctx, instance.SettingParentDomain); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("store có parent_domain=%q sau toàn tên hỏng (err=%v)", v, err)
	}
	// Không có gì → Info sạch, không lỗi.
	if info, err := cfg.Info(ctx); err != nil || info != (instance.Info{}) {
		t.Errorf("Info trên box trắng = (%+v, %v)", info, err)
	}
}

// Đổi tên gốc thì app dời TRƯỚC, tên mới ghi SAU: dời hỏng thì tên cũ còn nguyên
// để lần sync sau dời tiếp. Lần gán đầu (chưa có tên) không dời gì.
func TestParentChangeMovesAppsBeforeWriting(t *testing.T) {
	ctx := context.Background()
	cfg, _ := newConfig(t)
	var calls [][2]string
	fail := true
	cfg.OnParentChanged = func(_ context.Context, old, new string) error {
		calls = append(calls, [2]string{old, new})
		if fail {
			return errors.New("boom")
		}
		return nil
	}
	if err := cfg.SetFromCloud(ctx, "shop.acme.keenrig.com", instance.ModeKeenrig); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("lần gán đầu đã gọi dời app: %v", calls)
	}
	if err := cfg.SetFromCloud(ctx, "cuahangacme.com", instance.ModeKeenrig); err == nil {
		t.Fatal("dời hỏng mà SetFromCloud vẫn trả nil — agent sẽ không thử lại")
	}
	if info, _ := cfg.Info(ctx); info.ParentDomain != "shop.acme.keenrig.com" {
		t.Fatalf("dời hỏng mà tên đã đổi thành %q — app bị bỏ lại ở địa chỉ cũ", info.ParentDomain)
	}
	fail = false
	if err := cfg.SetFromCloud(ctx, "cuahangacme.com", instance.ModeKeenrig); err != nil {
		t.Fatal(err)
	}
	if info, _ := cfg.Info(ctx); info.ParentDomain != "cuahangacme.com" {
		t.Fatalf("ParentDomain = %q", info.ParentDomain)
	}
	if len(calls) != 2 || calls[1] != [2]string{"shop.acme.keenrig.com", "cuahangacme.com"} {
		t.Fatalf("calls = %v", calls)
	}
}
