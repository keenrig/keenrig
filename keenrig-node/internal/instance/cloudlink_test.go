package instance_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/instance"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// AD-12 — trạng thái pair là thứ AGENT báo, box chỉ ghi và tính. Ba ca: chưa
// có gì → standalone (không lỗi); vừa báo → synced; quá 5 phút → stale.

// Báo cáo hỏng bị chặn bằng ErrInvalidCloudLink (→ 400 ở nodeapi) và KHÔNG
// chạm store: một URL không phải URL lọt vào là một link hỏng trên Admin UI.
func TestCloudLinkRejectsBadReportsTyped(t *testing.T) {
	ctx := context.Background()
	cfg, st := newConfig(t)
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, url, env string
		at             time.Time
	}{
		{"url rỗng", "", "env-1", now},
		{"url không scheme", "keenrig.com", "env-1", now},
		{"scheme lạ", "ftp://keenrig.com", "env-1", now},
		{"không host", "https://", "env-1", now},
		{"env rỗng", "https://keenrig.com", "  ", now},
		{"mốc zero", "https://keenrig.com", "env-1", time.Time{}},
	} {
		if err := cfg.SetCloudLink(ctx, tc.url, tc.env, tc.at); !errors.Is(err, instance.ErrInvalidCloudLink) {
			t.Errorf("%s: SetCloudLink = %v, muốn ErrInvalidCloudLink", tc.name, err)
		}
	}
	if v, err := st.GetSetting(ctx, instance.SettingCloudLinkURL); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("store có cloud_link_url=%q sau toàn báo cáo hỏng (err=%v)", v, err)
	}
	info, err := cfg.CloudLink(ctx, now)
	if err != nil || info.Paired || info.State != instance.StateStandalone {
		t.Errorf("box trắng → (%+v, %v), muốn standalone không lỗi", info, err)
	}
}

// synced ↔ stale quanh đúng mốc 5 phút, với đồng hồ tiêm vào — không ngủ.
func TestCloudLinkStateFlipsToStaleAfterFiveMinutes(t *testing.T) {
	ctx := context.Background()
	cfg, _ := newConfig(t)
	synced := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if err := cfg.SetCloudLink(ctx, "https://keenrig.com", "env-1", synced); err != nil {
		t.Fatal(err)
	}
	if instance.StaleAfter != 5*time.Minute {
		t.Fatalf("StaleAfter = %s, hợp đồng instance.yaml nói 5 phút", instance.StaleAfter)
	}
	for _, tc := range []struct {
		name string
		now  time.Time
		want string
	}{
		{"ngay lúc báo", synced, instance.StateSynced},
		{"1 giây trước mốc", synced.Add(instance.StaleAfter - time.Second), instance.StateSynced},
		{"đúng mốc", synced.Add(instance.StaleAfter), instance.StateSynced},
		{"1 giây sau mốc", synced.Add(instance.StaleAfter + time.Second), instance.StateStale},
		{"năm ngày sau", synced.Add(5 * 24 * time.Hour), instance.StateStale},
	} {
		info, err := cfg.CloudLink(ctx, tc.now)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if info.State != tc.want {
			t.Errorf("%s: state = %q, muốn %q", tc.name, info.State, tc.want)
		}
		// Ba trường đi kèm ở CẢ hai trạng thái: stale vẫn là đã pair, UI vẫn
		// cần URL/env để vẽ thẻ và lệnh chẩn đoán.
		if !info.Paired || info.CloudURL != "https://keenrig.com" || info.EnvID != "env-1" || !info.LastSyncAt.Equal(synced) {
			t.Errorf("%s: info = %+v, mất trường đi kèm", tc.name, info)
		}
	}
}

// Agent báo lại → mốc mới, trạng thái quay về synced (idempotent theo giá trị,
// và không cần xoá gì).
func TestCloudLinkReportAgainRefreshesTheMark(t *testing.T) {
	ctx := context.Background()
	cfg, _ := newConfig(t)
	t0 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	if err := cfg.SetCloudLink(ctx, "https://keenrig.com", "env-1", t0); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(time.Hour)
	if info, _ := cfg.CloudLink(ctx, later); info.State != instance.StateStale {
		t.Fatalf("một giờ không báo mà state = %q", info.State)
	}
	if err := cfg.SetCloudLink(ctx, "https://keenrig.com", "env-1", later); err != nil {
		t.Fatal(err)
	}
	info, _ := cfg.CloudLink(ctx, later.Add(time.Second))
	if info.State != instance.StateSynced || !info.LastSyncAt.Equal(later) {
		t.Errorf("sau khi báo lại: %+v, muốn synced với mốc mới", info)
	}
}
