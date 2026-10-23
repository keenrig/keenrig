package reconciler

// Cấp phát addon trong vòng hội tụ (AD-01..04).
//
// # Thứ tự là một phần của thiết kế
//
// Cấp phát addon chạy TRƯỚC runtime.Apply, và biến môi trường được tiêm vào
// desired trước khi container được tạo. Đảo lại thì container khởi động không có
// KEENRIG_POSTGRES_URL, app chết vì thiếu cấu hình, và triệu chứng nằm trong log
// của APP chứ không trong log của ta.
//
// Hệ quả: addon chưa sẵn sàng nghĩa là app KHÔNG được deploy ở tick này —
// reconciler backoff và thử lại. Deploy một app biết trước là sẽ chết chỉ để
// "làm gì đó" là tệ hơn không làm gì.
//
// # Reconciler ghi `app_addons`, driver KHÔNG
//
// Bảng đó có khoá ngoại tới `apps` và là state vòng đời app. Driver chỉ ghi
// `secrets` (credential của chính nó). Ranh giới này lộ ra khi chạy conformance:
// suite cấp phát cho một app id không có row trong `apps`, và `PutAppAddon` trả
// ErrNotFound. Xem godoc driver postgres.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// AddonProvisioner — phần internal/addons mà reconciler cần.
//
// Interface HẸP thay vì map[Kind]addons.Addon: reconciler không cần biết có bao
// nhiêu driver, và không cần quyền mở driver mới giữa vòng hội tụ.
type AddonProvisioner interface {
	// Setup cấp phát và trả biến môi trường để tiêm vào container.
	Setup(ctx context.Context, kind addons.Kind, appID string) (map[string]string, error)
	// Teardown dọn phần của app này.
	Teardown(ctx context.Context, kind addons.Kind, appID string) error
}

// WithAddons gắn tầng cấp phát addon. Gọi sau New, trước Run.
//
// nil = TẮT. Khi tắt, app khai addon vẫn deploy được nhưng KHÔNG có biến môi
// trường — và điều đó phải ồn ào, không im lặng (xem provisionAddons).
func (r *Reconciler) WithAddons(p AddonProvisioner) *Reconciler {
	r.addons = p
	return r
}

// wantedAddons đọc desired và trả danh sách addon app BẬT, thứ tự ổn định.
//
// Thứ tự ổn định để log và event không đổi giữa các lần chạy — một dòng log nhảy
// thứ tự mỗi tick làm việc so sánh hai lần chạy thành không làm được.
func wantedAddons(d contracts.DesiredApp) []addons.Kind {
	if d.Addons == nil {
		return nil
	}
	var out []addons.Kind
	if d.Addons.Postgres != nil && d.Addons.Postgres.Enabled {
		out = append(out, addons.KindPostgres)
	}
	if d.Addons.Redis != nil && d.Addons.Redis.Enabled {
		out = append(out, addons.KindRedis)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// provisionAddons cấp phát mọi addon app bật và trả bộ biến để tiêm.
//
// Trả error nghĩa là KHÔNG deploy ở tick này. Cụ thể với ErrInfraNotReady: đó là
// "chưa xong", không phải "hỏng" — caller phải backoff chứ không đánh dấu app
// lỗi, vì postgres mất tới một phút để initdb lần đầu và mọi app đầu tiên trên
// một máy mới sẽ vào trạng thái error.
func (r *Reconciler) provisionAddons(ctx context.Context, app *store.App, d contracts.DesiredApp) (map[string]string, error) {
	want := wantedAddons(d)
	if len(want) == 0 {
		return nil, nil
	}
	if r.addons == nil {
		// KÊU TO. Deploy im lặng một app thiếu biến kết nối DB nghĩa là app khởi
		// động rồi chết, và người dùng đi tìm lỗi trong app của họ.
		log.Printf("reconciler: app %s declares addons %v but the addon layer is not configured — "+
			"the container will NOT receive connection variables", app.ID, want)
		data, _ := json.Marshal(map[string]any{"addons": want})
		if err := r.st.AppendEvent(ctx, "app.addons_unavailable", "reconciler", app.ID, data); err != nil && ctx.Err() == nil {
			log.Printf("reconciler: appending event: %v", err)
		}
		return nil, nil
	}

	env := map[string]string{}
	for _, kind := range want {
		got, err := r.addons.Setup(ctx, kind, app.ID)
		if err != nil {
			r.markAddon(ctx, app.ID, kind, store.AddonError, err.Error())
			return nil, fmt.Errorf("addon %s: %w", kind, err)
		}
		for k, v := range got {
			if prev, dup := env[k]; dup && prev != v {
				// Hai addon cùng đặt một biến to different values: một trong
				// hai app sẽ nối sai chỗ, và không có gì báo. Namespace
				// KEENRIG_<KIND>_* làm điều này gần như không thể — nên nếu nó
				// xảy ra thì có một driver đang vi phạm quy ước đặt tên.
				return nil, fmt.Errorf("addon %s and another addon both set variable %s "+
					"to different values", kind, k)
			}
			env[k] = v
		}
		r.markAddon(ctx, app.ID, kind, store.AddonReady, "")
	}
	return env, nil
}

// injectAddonEnv trộn biến addon vào desired.Env.
//
// Biến của NGƯỜI DÙNG thắng biến của addon.
//
// Ngược lại nghe an toàn hơn nhưng sai: một người vận hành trỏ app sang một
// PostgreSQL bên ngoài bằng KEENRIG_POSTGRES_URL của riêng họ phải làm được điều
// đó, và nếu addon ghi đè thì họ không có cách nào — kể cả tắt addon, vì lúc đó
// biến biến mất hoàn toàn thay vì mang giá trị họ đặt.
//
// Trả về BẢN SAO: sửa desired tại chỗ nghĩa là bộ biến addon lọt vào thứ ta so
// sánh để biết "desired có đổi không", và mọi tick sẽ thấy một desired khác.
func injectAddonEnv(d contracts.DesiredApp, addonEnv map[string]string) contracts.DesiredApp {
	if len(addonEnv) == 0 {
		return d
	}
	merged := make(map[string]string, len(addonEnv)+len(d.Env))
	for k, v := range addonEnv {
		merged[k] = v
	}
	for k, v := range d.Env { // người dùng thắng
		merged[k] = v
	}
	out := d
	out.Env = merged
	return out
}

// teardownAddons dọn addon của app ở PHA 2 của xoá.
//
// Chạy SAU runtime.Remove (container còn chạy là còn ghi vào DB) và TRƯỚC
// PurgeApp (không còn row thì không còn gì nhắc rằng DB đó thuộc về ai).
//
// Lỗi ở đây KHÔNG chặn Purge — cùng lý lẽ với RemoveAppData: một DB sót lại là
// rác tốn đĩa, còn một app kẹt mãi ở "đang xoá" thì giữ luôn slug và người dùng
// không tạo lại được app cùng tên.
//
// Dọn theo BẢNG app_addons, không theo desired: desired có thể đã bị sửa để tắt
// addon TRƯỚC khi app bị xoá, và lúc đó DB vẫn còn nhưng không ai biết.
func (r *Reconciler) teardownAddons(ctx context.Context, appID string) {
	if r.addons == nil {
		return
	}
	recs, err := r.st.ListAppAddons(ctx, appID)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("reconciler: reading app_addons for %s: %v", appID, err)
		}
		return
	}
	for _, rec := range recs {
		kind := addons.Kind(rec.Addon)
		if err := r.addons.Teardown(ctx, kind, appID); err != nil {
			data, _ := json.Marshal(map[string]any{"addon": rec.Addon, "error": err.Error()})
			if aerr := r.st.AppendEvent(ctx, "app.addon_teardown_failed", "reconciler", appID, data); aerr != nil && ctx.Err() == nil {
				log.Printf("reconciler: appending event: %v", aerr)
			}
			log.Printf("reconciler: could not tear down addon %s for %s (%v) — continuing with deletion",
				rec.Addon, appID, err)
			continue
		}
		if err := r.st.DeleteAppAddon(ctx, appID, rec.Addon); err != nil &&
			!errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
			log.Printf("reconciler: deleting addon record %s for %s: %v", rec.Addon, appID, err)
		}
	}
}

// markAddon ghi state addon vào app_addons.
//
// Lỗi ghi KHÔNG làm thất bại việc cấp phát: bản ghi này là sổ sách, còn DB thì
// đã được tạo thật. Đánh dấu app lỗi vì không ghi được sổ sách là biến một sự cố
// store tạm thời thành một app không deploy được.
func (r *Reconciler) markAddon(ctx context.Context, appID string, kind addons.Kind, state, lastErr string) {
	err := r.st.PutAppAddon(ctx, &store.AppAddon{
		AppID: appID, Addon: string(kind), State: state, LastError: lastErr,
	})
	if err != nil && ctx.Err() == nil {
		log.Printf("reconciler: writing app_addons %s/%s: %v", appID, kind, err)
	}
}
