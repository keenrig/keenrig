// Package reconciler — vòng lặp hội tụ: apps có desired_rev > applied_rev
// được đưa qua runtime.Apply cho tới khi khớp. Đơn luồng, tuần tự;
// backoff lỗi per-app giữ in-memory (mất khi restart — chấp nhận được,
// tối đa tốn 1 lần Apply lại).
//
// Reconciler là nơi DUY NHẤT chạm runtime, kể cả khi xoá: store.DeleteApp chỉ
// đánh dấu deleted_at, mỗi tick reconciler dọn danh sách pending-delete trước
// (runtime.Remove → store.PurgeApp) rồi mới hội tụ phần còn lại.
package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/certs"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/health"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

type Options struct {
	Interval        time.Duration // tick reconcile; zero → 1s
	RefreshInterval time.Duration // tick refresh status app đã hội tụ; zero → 15s
	BackoffBase     time.Duration // zero → 1s
	BackoffCap      time.Duration // zero → 60s

	// Holder — định danh tiến trình cho lease; zero → DefaultHolder() (hostname/pid).
	Holder string
	// LeaseTTL — hạn lease reconciler; zero → DefaultLeaseTTL.
	// ĐỌC phần "số học của TTL" trong lease.go trước khi đặt giá trị khác.
	LeaseTTL time.Duration
	// LeaseDisabled tắt hẳn việc giành lease. CHỈ dành cho test đơn vị muốn
	// chạy tick mà không dựng lease; đặt true trong sản xuất là mở lại đúng lỗ
	// hổng hai-chủ mà T6b bịt.
	LeaseDisabled bool
}

type backoffState struct {
	attempt int
	nextAt  time.Time
}

type Reconciler struct {
	st   store.Store
	rt   runtime.Runtime
	opts Options
	// backoff per-app — chỉ đọc/ghi từ goroutine Run (đơn luồng, không cần lock).
	backoff map[string]*backoffState
	// ls — lease đang giữ; cũng chỉ goroutine Run đụng tới.
	ls            leaseState
	defaultHolder string
	// proxy — gateway seam #7 (T8); nil = chưa cấu hình, box vẫn chạy.
	proxy proxy.Controller
	// lastSites — tập site đã đẩy sang gateway thành công gần nhất, để bỏ qua
	// Apply khi không có gì đổi. nil nghĩa là "chưa biết", buộc Apply lần sau.
	lastSites []proxy.Site
	// platformHosts/platformUp — tên miền + upstream của Admin chính box.
	platformHosts PlatformHosts
	platformUp    proxy.Upstream
	// certs — cấp chứng chỉ khi gateway KHÔNG có CapACME (T9); nil = không có.
	certs *certs.Manager
	// caps/capsAt — năng lực gateway đã hỏi, kèm mốc để hỏi lại (xem capsTTL).
	caps           proxy.Caps
	capsAt         time.Time
	noIssuerWarnAt time.Time
	// drain — cờ tạm dừng cho ota (T9b). Xem drain.go.
	drain drainState
	// health — probe HTTP bổ sung (nil = tắt). Xem health.go.
	health *health.Monitor
	// lastHealth — health đã công bố lần trước, để chỉ ghi event khi ĐỔI.
	lastHealth map[string]string
	// addons — cấp phát addon (M2). nil = TẮT; app khai addon vẫn deploy nhưng
	// KHÔNG có biến kết nối, và điều đó được ghi event chứ không im lặng.
	addons AddonProvisioner
	// priv — thao tác cần root, qua sudo + script. nil = không có (dev, test,
	// hoặc sudoers chưa cài): reconciler vẫn chạy, chỉ không dọn được thư mục
	// dữ liệu. Bắt buộc phải có ở đây sẽ làm mọi test cần một sudoers thật.
	priv PrivOps
}

// PrivOps — phần internal/privops mà reconciler cần. Interface hẹp thay vì
// nhận thẳng *privops.Ops: reconciler chỉ được xoá dữ liệu, không được reboot
// máy hay restart dịch vụ, và cách chắc chắn nhất để giữ điều đó là không đưa
// cho nó những hàm kia.
type PrivOps interface {
	RemoveAppData(ctx context.Context, appID string) error
}

// WithRuntime gắn (hoặc thay) driver runtime.
//
// Có nó vì driver docker được tạo BÊN TRONG hàm supervisor: dockerd chưa lên
// chỉ nên làm supervisor retry, không nên làm cả tiến trình chết. Nhưng
// Reconciler phải được tạo TRƯỚC đó và giữ nguyên identity qua mọi lần restart,
// vì node API cầm con trỏ này cho /drain — ota drain xong mà box thay bằng một
// reconciler khác chưa drain thì cả cơ chế vô nghĩa.
func (r *Reconciler) WithRuntime(rt runtime.Runtime) *Reconciler {
	r.rt = rt
	return r
}

// WithProxy gắn controller gateway. Gọi sau New, trước Run.
//
// Tách khỏi New thay vì thêm tham số: phần lớn test không cần gateway, và một
// tham số nil bắt buộc ở mọi chỗ gọi là mời gọi truyền nhầm.
func (r *Reconciler) WithProxy(ctl proxy.Controller) *Reconciler {
	r.proxy = ctl
	return r
}

// WithPrivOps gắn tầng thao tác đặc quyền. Gọi sau New, trước Run.
func (r *Reconciler) WithPrivOps(p PrivOps) *Reconciler {
	r.priv = p
	return r
}

func New(st store.Store, rt runtime.Runtime, opts Options) *Reconciler {
	if opts.Interval <= 0 {
		opts.Interval = time.Second
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = 15 * time.Second
	}
	if opts.BackoffBase <= 0 {
		opts.BackoffBase = time.Second
	}
	if opts.BackoffCap <= 0 {
		opts.BackoffCap = 60 * time.Second
	}
	return &Reconciler{
		st: st, rt: rt, opts: opts,
		backoff:       map[string]*backoffState{},
		lastHealth:    map[string]string{},
		defaultHolder: DefaultHolder(),
	}
}

// Run — vòng lặp chính, block tới khi ctx done (trả nil — kết thúc sạch).
//
// MỌI lối đi chạm runtime đều nằm sau ensureLease (T6b): tiến trình không giữ
// lease thì đứng im, không Apply, không Remove, không Status. Nó vẫn sống và
// vẫn chờ — mất lease là trạng thái bình thường của box thua cuộc trong cửa sổ
// OTA, không phải sự cố.
//
// Trả lỗi ≠ nil chỉ khi có app PANIC trong tick: panic đã được recover và quy
// về lỗi của riêng app đó (status + event + backoff, các app còn lại trong tick
// vẫn chạy), nhưng vẫn báo lên để supervisor (§2.1.1) tái tạo module — panic
// nghĩa là driver ở trạng thái không rõ, không nên nuốt im lặng.
func (r *Reconciler) Run(ctx context.Context) error {
	tick := time.NewTicker(r.opts.Interval)
	defer tick.Stop()
	refresh := time.NewTicker(r.opts.RefreshInterval)
	defer refresh.Stop()
	// Nhả lease trên MỌI đường ra, kể cả đường trả lỗi panic: giữ lease sau khi
	// module đã chết là bắt box còn lại chờ hết TTL mà chẳng ai làm việc.
	defer r.releaseOnExit()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			// Cổng drain đứng TRƯỚC cổng lease: đang drain thì đừng cả giành
			// lease — box sắp bị thay bin mà lại đi giành quyền lái Docker là
			// đúng thứ drain sinh ra để chặn.
			if r.Paused() || !r.leaseOK(ctx) {
				continue
			}
			if err := r.reconcileTick(ctx); err != nil {
				return err
			}
		case <-refresh.C:
			if r.Paused() || !r.leaseOK(ctx) {
				continue
			}
			r.reclaimJobs(ctx)
			r.refreshTick(ctx)
			// syncProxy SAU refreshTick: refresh vừa cập nhật endpoint, nên
			// tập site dựng ở đây là ảnh mới nhất chứ không phải ảnh cũ một nhịp.
			r.syncProxy(ctx)
		}
	}
}

// leaseOK — cổng duy nhất dẫn tới runtime.
func (r *Reconciler) leaseOK(ctx context.Context) bool {
	if r.opts.LeaseDisabled {
		return true
	}
	return r.ensureLease(ctx)
}

// releaseOnExit nhả lease với ctx RIÊNG: ctx của Run đã done lúc này, dùng lại
// nó thì câu DELETE bị huỷ ngay và lease ở lại tới hết TTL.
func (r *Reconciler) releaseOnExit() {
	if r.opts.LeaseDisabled || r.ls.lease == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
	defer cancel()
	r.releaseLease(ctx)
}

// releaseTimeout — nhả lease là một câu DELETE theo primary key; quá 5 giây
// nghĩa là store đã hỏng nặng và chờ thêm cũng không cứu được ai.
const releaseTimeout = 5 * time.Second

// runGuarded chạy fn và biến panic thành error (stack vào log). Không có nó,
// MỘT app làm driver panic sẽ cắt ngang cả vòng lặp: các app còn lại trong tick
// không được xử lý và app gây panic cũng không được ghi nhận/backoff.
func runGuarded(appID string, fn func()) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("reconciler: PANIC while processing app %s: %v\n%s", appID, rec, debug.Stack())
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	fn()
	return nil
}

// deleteTick xử lý app đã đánh dấu xoá (pha 2 của xoá 2 pha): runtime.Remove
// dọn container rồi PurgeApp xoá hẳn row. Chạy TRƯỚC reconcileTick mỗi tick.
// Crash giữa chừng an toàn: row vẫn còn deleted_at nên tick sau dọn tiếp;
// Remove idempotent nên dọn lại không sao.
// Trả lỗi ≠ nil chỉ khi có app panic (đã recover, xem runGuarded).
func (r *Reconciler) deleteTick(ctx context.Context) error {
	apps, err := r.st.ListAppsPendingDelete(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("reconciler: list apps pending delete: %v", err)
		}
		return nil
	}
	var panicErr error
	now := time.Now()
	for _, app := range apps {
		if ctx.Err() != nil {
			return panicErr
		}
		if bs, ok := r.backoff[app.ID]; ok && now.Before(bs.nextAt) {
			continue
		}
		// enterWork/leaveWork bao QUANH lời gọi chạm runtime, không bao quanh cả
		// tick: Drain cần biết "có Apply/Remove nào đang dở" chứ không phải "có
		// tick nào đang chạy" — tick phần lớn thời gian chỉ đang đọc DB.
		r.enterWork()
		perr := runGuarded(app.ID, func() { r.deleteApp(ctx, app) })
		r.leaveWork()
		if perr != nil {
			r.failDelete(ctx, app, perr) // panic = lỗi xoá của app này, tick sau thử lại
			if panicErr == nil {
				panicErr = fmt.Errorf("app %s: %w", app.ID, perr)
			}
		}
	}
	return panicErr
}

func (r *Reconciler) deleteApp(ctx context.Context, app *store.App) {
	if err := r.rt.Remove(ctx, app.ID); err != nil {
		r.failDelete(ctx, app, err)
		return
	}
	// Addon dọn SAU runtime.Remove, TRƯỚC PurgeApp — cùng lý do với thư mục dữ
	// liệu: container còn chạy là còn ghi vào DB, và không còn row thì không
	// còn gì nhắc rằng DB đó thuộc về ai. Xem addons.go.
	r.teardownAddons(ctx, app.ID)

	// Thư mục dữ liệu dọn SAU runtime.Remove, TRƯỚC PurgeApp.
	//
	// Sau Remove vì container còn chạy là còn ghi vào đó — xoá trước là xoá
	// dưới chân một tiến trình đang sống. Trước Purge vì Purge xoá row, và
	// không còn row thì không còn gì nhắc rằng thư mục đó cần dọn: nó thành
	// rác vĩnh viễn mà không ai biết nó thuộc về ai.
	//
	// Lỗi ở đây KHÔNG chặn Purge. Dữ liệu sót lại là rác tốn đĩa; một app kẹt
	// mãi ở trạng thái "đang xoá" vì không dọn được thư mục thì tệ hơn — nó
	// giữ luôn slug và người dùng không tạo lại được app cùng tên.
	if r.priv != nil {
		if err := r.priv.RemoveAppData(ctx, app.ID); err != nil {
			data, _ := json.Marshal(map[string]any{"error": err.Error()})
			if aerr := r.st.AppendEvent(ctx, "app.data_cleanup_failed", "reconciler", app.ID, data); aerr != nil && ctx.Err() == nil {
				log.Printf("reconciler: append event %s: %v", app.ID, aerr)
			}
			log.Printf("reconciler: could not clean up data for app %s (%v) — continuing with deletion", app.ID, err)
		}
	}
	// Container đã sạch → giải phóng row (và slug).
	if err := r.st.PurgeApp(ctx, app.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		r.failDelete(ctx, app, fmt.Errorf("purge: %w", err))
		return
	}
	if err := r.st.AppendEvent(ctx, "app.deleted", "reconciler", app.ID, nil); err != nil && ctx.Err() == nil {
		log.Printf("reconciler: append event %s: %v", app.ID, err)
	}
	delete(r.backoff, app.ID)
	r.forgetHealth(app.ID)
	// Purge đã CASCADE xoá app_domains → route phải biến mất khỏi gateway ngay.
	// Chờ nhịp refresh nghĩa là có một cửa sổ gateway còn trỏ tới container vừa
	// bị gỡ, tức là 502 cho tới 15 giây sau khi xoá xong.
	r.syncProxy(ctx)
}

// failDelete — không writeStatus (app đã bị đánh dấu xoá, SetStatus sẽ NotFound):
// chỉ ghi event + backoff để tick sau thử lại.
func (r *Reconciler) failDelete(ctx context.Context, app *store.App, cause error) {
	data, _ := json.Marshal(map[string]any{"error": cause.Error()})
	if err := r.st.AppendEvent(ctx, "app.delete_failed", "reconciler", app.ID, data); err != nil && ctx.Err() == nil {
		log.Printf("reconciler: append event %s: %v", app.ID, err)
	}
	r.bumpBackoff(app.ID)
}

// reconcileTick — 1 vòng hội tụ. Trả lỗi ≠ nil chỉ khi có app panic (đã
// recover và quy về lỗi của app đó; lỗi trả về để Run báo lên supervisor).
func (r *Reconciler) reconcileTick(ctx context.Context) error {
	panicErr := r.deleteTick(ctx) // dọn app bị xoá TRƯỚC — đừng vừa dựng vừa xoá
	if ctx.Err() != nil {
		return panicErr
	}
	apps, err := r.st.ListAppsNeedingReconcile(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("reconciler: list apps: %v", err)
		}
		return panicErr
	}
	now := time.Now()
	for _, app := range apps {
		if ctx.Err() != nil {
			return panicErr
		}
		if bs, ok := r.backoff[app.ID]; ok && now.Before(bs.nextAt) {
			continue // đang trong cửa sổ backoff — bỏ qua tick này
		}
		r.enterWork()
		perr := runGuarded(app.ID, func() { r.reconcileApp(ctx, app) })
		r.leaveWork()
		if perr != nil {
			r.failPanic(ctx, app, perr)
			if panicErr == nil {
				panicErr = fmt.Errorf("app %s: %w", app.ID, perr)
			}
		}
	}
	return panicErr
}

func (r *Reconciler) reconcileApp(ctx context.Context, app *store.App) {
	// Đánh dấu deploying — GIỮ appliedRev cũ (chưa apply xong rev mới).
	r.writeStatus(ctx, app, runtime.Observed{
		Phase:  contracts.AppStateDeploying,
		Health: contracts.HealthUnknown,
	}, app.AppliedRev)

	var desired contracts.DesiredApp
	if err := json.Unmarshal(app.Desired, &desired); err != nil {
		r.fail(ctx, app, fmt.Errorf("desired could not be parsed: %w", err))
		return
	}

	// Addon cấp phát TRƯỚC Apply, và biến được tiêm vào desired trước khi
	// container được tạo. Đảo lại thì container khởi động thiếu
	// KEENRIG_POSTGRES_URL, app chết vì thiếu cấu hình, và triệu chứng nằm
	// trong log của APP chứ không trong log của ta.
	addonEnv, aerr := r.provisionAddons(ctx, app, desired)
	if aerr != nil {
		// ErrInfraNotReady là "CHƯA XONG", không phải "hỏng": postgres mất tới
		// một phút để initdb lần đầu. Đánh dấu app lỗi ở đây nghĩa là mọi app
		// đầu tiên trên một máy mới đều vào trạng thái error rồi tự khỏi — một
		// cảnh báo giả mà người vận hành sẽ học cách phớt lờ.
		if errors.Is(aerr, addons.ErrInfraNotReady) {
			r.bumpBackoff(app.ID)
			return
		}
		r.fail(ctx, app, aerr)
		return
	}

	obs, err := r.rt.Apply(ctx, runtime.AppSpec{
		ID:         app.ID,
		Slug:       app.Slug,
		Desired:    injectAddonEnv(desired, addonEnv),
		DesiredRev: app.DesiredRev,
	})
	if err != nil {
		r.fail(ctx, app, err)
		return
	}

	// Hội tụ: applied = desired. Ghi THẤT BẠI → app vẫn nằm trong
	// ListAppsNeedingReconcile nên tick sau Apply lại NGAY: lỗi ghi kéo dài =
	// gọi runtime 1 lần/tick vô hạn (Interval mặc định 1s). Backoff chặn
	// hot-loop đó, nhưng nhẹ tay hơn lỗi Apply vì runtime vẫn ĐÚNG — chỉ sổ
	// sách hỏng: mốc khởi điểm là nhịp tick và trần là statusBackoffTicks tick,
	// đủ để ghi lại sớm ngay khi store lành.
	// ErrNotFound là ngoại lệ lành: app vừa bị xoá → đã rời danh sách, deleteTick lo.
	if err := r.writeStatus(ctx, app, obs, app.DesiredRev); err != nil && !errors.Is(err, store.ErrNotFound) {
		r.bumpBackoffFrom(app.ID, r.opts.Interval, r.statusBackoffCap())
		return
	}
	r.writeEndpoints(ctx, app.ID, obs.Endpoints)
	data, _ := json.Marshal(map[string]int64{"rev": app.DesiredRev})
	if err := r.st.AppendEvent(ctx, "app.reconciled", "reconciler", app.ID, data); err != nil && ctx.Err() == nil {
		log.Printf("reconciler: append event %s: %v", app.ID, err)
	}
	delete(r.backoff, app.ID)
	// App vừa hội tụ → endpoint đã đổi → gateway phải biết NGAY, không đợi
	// nhịp refresh: chờ 15 giây mới định tuyến được là 15 giây người dùng thấy
	// 404 sau khi deploy báo thành công.
	r.syncProxy(ctx)
}

func (r *Reconciler) fail(ctx context.Context, app *store.App, cause error) {
	r.writeStatus(ctx, app, runtime.Observed{
		Phase:   contracts.AppStateError,
		Health:  contracts.HealthUnknown,
		Message: cause.Error(),
	}, app.AppliedRev) // lỗi → applied_rev GIỮ NGUYÊN

	data, _ := json.Marshal(map[string]any{"rev": app.DesiredRev, "error": cause.Error()})
	if err := r.st.AppendEvent(ctx, "app.reconcile_failed", "reconciler", app.ID, data); err != nil && ctx.Err() == nil {
		log.Printf("reconciler: append event %s: %v", app.ID, err)
	}

	r.bumpBackoff(app.ID)
}

// failPanic — app panic giữa lúc reconcile: panic đã được recover, quy về lỗi
// CỦA RIÊNG app đó (status error + event + backoff) đúng như một lỗi Apply
// thường, để các app khác không bị vạ lây và app này không bị thử lại ngay.
func (r *Reconciler) failPanic(ctx context.Context, app *store.App, cause error) {
	r.writeStatus(ctx, app, runtime.Observed{
		Phase:   contracts.AppStateError,
		Health:  contracts.HealthUnknown,
		Message: cause.Error(),
	}, app.AppliedRev)

	data, _ := json.Marshal(map[string]any{"rev": app.DesiredRev, "error": cause.Error()})
	if err := r.st.AppendEvent(ctx, "app.reconcile_panicked", "reconciler", app.ID, data); err != nil && ctx.Err() == nil {
		log.Printf("reconciler: append event %s: %v", app.ID, err)
	}

	r.bumpBackoff(app.ID)
}

// statusBackoffTicks — trần backoff cho lỗi ghi status, tính bằng số tick.
const statusBackoffTicks = 10

// statusBackoffCap = min(statusBackoffTicks * Interval, BackoffCap).
func (r *Reconciler) statusBackoffCap() time.Duration {
	if d := statusBackoffTicks * r.opts.Interval; d < r.opts.BackoffCap {
		return d
	}
	return r.opts.BackoffCap
}

// bumpBackoff tăng attempt và đặt nextAt = now + min(Base<<(attempt-1), Cap).
func (r *Reconciler) bumpBackoff(appID string) {
	r.bumpBackoffFrom(appID, r.opts.BackoffBase, r.opts.BackoffCap)
}

// bumpBackoffFrom — như bumpBackoff nhưng chọn được mốc khởi điểm và trần
// riêng (đường lỗi ghi status dùng mốc/trần nhẹ hơn — xem reconcileApp).
func (r *Reconciler) bumpBackoffFrom(appID string, base, maxDelay time.Duration) {
	if base <= 0 {
		base = r.opts.BackoffBase
	}
	if maxDelay <= 0 {
		maxDelay = r.opts.BackoffCap
	}
	bs := r.backoff[appID]
	if bs == nil {
		bs = &backoffState{}
		r.backoff[appID] = bs
	}
	bs.attempt++
	d := base
	for i := 1; i < bs.attempt && d < maxDelay; i++ {
		d <<= 1 // min(base << (attempt-1), maxDelay) — nhân dần tránh overflow shift lớn
	}
	if d > maxDelay {
		d = maxDelay
	}
	bs.nextAt = time.Now().Add(d)
}

// refreshTick cập nhật health/status cho app ĐÃ hội tụ (applied >= desired).
func (r *Reconciler) refreshTick(ctx context.Context) {
	apps, err := r.st.ListApps(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("reconciler: refresh list apps: %v", err)
		}
		return
	}
	for _, app := range apps {
		if ctx.Err() != nil {
			return
		}
		if app.DesiredRev > app.AppliedRev {
			continue // app đang lệch — tick reconcile lo
		}
		obs, err := r.rt.Status(ctx, app.ID)
		if err != nil {
			continue // Status lỗi thoáng qua — thử lại tick sau
		}
		// Probe HTTP chỉ ở nhịp refresh (15s), không ở tick hội tụ (1s): probe
		// là lời gọi mạng tới TỪNG replica, làm mỗi giây là tự tạo tải lên
		// chính app mình đang theo dõi.
		r.applyHealthProbe(ctx, app, &obs)
		r.writeStatus(ctx, app, obs, app.AppliedRev)
		// Cập nhật endpoint cả ở nhịp refresh: container tự restart (Docker
		// restart-policy) sẽ đổi IP mà desired_rev KHÔNG đổi, nên vòng hội tụ
		// không bao giờ chạy lại. Không refresh ở đây thì gateway giữ upstream
		// trỏ vào IP cũ và app "đang chạy" mà trả 502.
		r.writeEndpoints(ctx, app.ID, obs.Endpoints)
	}
}

// writeEndpoints ghi tập endpoint quan sát được vào store (T6c).
//
// Reconciler là nơi DUY NHẤT ghi cột này — httpd chỉ đọc, và httpd không được
// import runtime (luật §2.1). Vì vậy chuyển đổi runtime.Endpoint →
// store.Endpoint nằm ở đây chứ không phải ở một trong hai package đó.
//
// Lỗi ghi KHÔNG bump backoff và KHÔNG chặn hội tụ: endpoint là cache dẫn xuất,
// tick refresh sau ghi lại. Coi nó là lỗi hội tụ sẽ biến một sự cố hiển thị
// thành một app không deploy được.
func (r *Reconciler) writeEndpoints(ctx context.Context, appID string, eps []runtime.Endpoint) {
	converted := make([]store.Endpoint, 0, len(eps))
	for _, e := range eps {
		if e.Host == "" || e.Port <= 0 {
			continue // endpoint không dùng được thì đừng đẩy sang gateway
		}
		converted = append(converted, store.Endpoint{Host: e.Host, Port: e.Port})
	}
	if err := r.st.SetEndpoints(ctx, appID, converted); err != nil {
		if ctx.Err() == nil && !errors.Is(err, store.ErrNotFound) {
			log.Printf("reconciler: writing endpoints for %s: %v", appID, err)
		}
	}
}

// writeStatus ghi contracts.AppStatus JSON vào store. Trả lỗi để caller quyết
// định (đường hội tụ dùng nó để backoff — xem reconcileApp); caller nào không
// quan tâm bỏ qua được vì lỗi đã được log tại đây.
func (r *Reconciler) writeStatus(ctx context.Context, app *store.App, obs runtime.Observed, appliedRev int64) error {
	status := contracts.AppStatus{
		AppID:      app.ID,
		State:      obs.Phase,
		Health:     obs.Health,
		Message:    obs.Message,
		DesiredRev: app.DesiredRev,
		AppliedRev: appliedRev,
	}
	data, err := json.Marshal(status)
	if err != nil {
		log.Printf("reconciler: marshal status %s: %v", app.ID, err)
		return err
	}
	if err := r.st.SetStatus(ctx, app.ID, data, appliedRev); err != nil {
		if ctx.Err() == nil {
			// NotFound: app vừa bị xoá; Conflict: rev đã nhảy tiếp — tick sau xử lý.
			log.Printf("reconciler: set status %s: %v", app.ID, err)
		}
		return err
	}
	return nil
}
