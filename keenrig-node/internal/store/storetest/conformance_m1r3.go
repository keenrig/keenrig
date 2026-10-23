package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// Phần conformance thêm ở vòng 3 (T6b/T6c/T6d): endpoints, domains, addons,
// lease reconciler (LS-01/02) và visibility timeout của job queue (LS-03).

// --- T6c: endpoints -----------------------------------------------------------

func testEndpoints(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")

	if got, err := st.GetApp(ctx, "app-1"); err != nil || len(got.Endpoints) != 0 {
		t.Fatalf("Endpoints lúc mới tạo = (%v, %v), muốn rỗng", got.Endpoints, err)
	}

	eps := []store.Endpoint{{Host: "172.17.0.2", Port: 8080}, {Host: "172.17.0.3", Port: 8080}}
	if err := st.SetEndpoints(ctx, "app-1", eps); err != nil {
		t.Fatalf("SetEndpoints: %v", err)
	}
	got, err := st.GetApp(ctx, "app-1")
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	if len(got.Endpoints) != 2 || got.Endpoints[0] != eps[0] || got.Endpoints[1] != eps[1] {
		t.Fatalf("Endpoints = %+v, muốn %+v", got.Endpoints, eps)
	}

	// Thay NGUYÊN KHỐI: scale 2 → 1 phải mất endpoint thừa, không để lại
	// upstream ma cho gateway.
	if err := st.SetEndpoints(ctx, "app-1", eps[:1]); err != nil {
		t.Fatalf("SetEndpoints thu hẹp: %v", err)
	}
	if got, err := st.GetApp(ctx, "app-1"); err != nil || len(got.Endpoints) != 1 {
		t.Fatalf("Endpoints sau thu hẹp = %+v (err %v), muốn đúng 1", got.Endpoints, err)
	}

	if err := st.SetEndpoints(ctx, "app-1", nil); err != nil {
		t.Fatalf("SetEndpoints(nil): %v", err)
	}
	if got, err := st.GetApp(ctx, "app-1"); err != nil || len(got.Endpoints) != 0 {
		t.Fatalf("Endpoints sau nil = %+v (err %v), muốn rỗng", got.Endpoints, err)
	}

	if err := st.SetEndpoints(ctx, "không-có", eps); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetEndpoints app lạ: muốn ErrNotFound, nhận %v", err)
	}
	// App đã đánh dấu xoá coi như không tồn tại — reconciler không được ghi
	// endpoint cho app đang bị gỡ.
	if err := st.DeleteApp(ctx, "app-1"); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if err := st.SetEndpoints(ctx, "app-1", eps); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetEndpoints app pending-delete: muốn ErrNotFound, nhận %v", err)
	}
}

// --- T6d: domains -------------------------------------------------------------

func testDomains(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")
	mustCreate(t, st, "app-2", "world")

	primary := &store.Domain{AppID: "app-1", FQDN: "a.keenrig.com", IsPrimary: true}
	if err := st.AddDomain(ctx, primary); err != nil {
		t.Fatalf("AddDomain primary: %v", err)
	}
	if err := st.AddDomain(ctx, &store.Domain{AppID: "app-1", FQDN: "b.keenrig.com"}); err != nil {
		t.Fatalf("AddDomain phụ: %v", err)
	}

	// UNIQUE(fqdn) TOÀN CỤC — app khác không được cướp tên miền đã có chủ.
	// Đây là ràng buộc ở tầng DB, không phải chỉ ở tầng service: hai request
	// song song đều "thấy trống" nếu chỉ SELECT rồi INSERT.
	if err := st.AddDomain(ctx, &store.Domain{AppID: "app-2", FQDN: "a.keenrig.com"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("AddDomain FQDN app khác đang giữ: muốn ErrConflict, nhận %v", err)
	}
	if err := st.AddDomain(ctx, &store.Domain{AppID: "app-1", FQDN: "a.keenrig.com"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("AddDomain trùng chính mình: muốn ErrConflict, nhận %v", err)
	}
	// Một app chỉ có ĐÚNG MỘT domain chính.
	if err := st.AddDomain(ctx, &store.Domain{AppID: "app-1", FQDN: "c.keenrig.com", IsPrimary: true}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("AddDomain primary thứ hai: muốn ErrConflict, nhận %v", err)
	}
	if err := st.AddDomain(ctx, &store.Domain{AppID: "không-có", FQDN: "x.keenrig.com"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AddDomain app lạ: muốn ErrNotFound, nhận %v", err)
	}

	ds, err := st.ListDomains(ctx, "app-1")
	if err != nil || len(ds) != 2 {
		t.Fatalf("ListDomains = (%d, %v), muốn 2", len(ds), err)
	}
	if !ds[0].IsPrimary || ds[0].FQDN != "a.keenrig.com" {
		t.Errorf("ListDomains phải xếp primary lên đầu, nhận %+v", ds[0])
	}

	if err := st.SetDomainCertRef(ctx, "a.keenrig.com", "cert/a"); err != nil {
		t.Fatalf("SetDomainCertRef: %v", err)
	}
	ds, _ = st.ListDomains(ctx, "app-1")
	if ds[0].CertRef != "cert/a" {
		t.Errorf("CertRef = %q, muốn %q", ds[0].CertRef, "cert/a")
	}
	if err := st.SetDomainCertRef(ctx, "không-có.keenrig.com", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetDomainCertRef FQDN lạ: muốn ErrNotFound, nhận %v", err)
	}

	// ListAllDomains là nguồn dựng desired cho proxy (level-triggered), nên app
	// đang chờ xoá phải rời danh sách NGAY — route biến mất trước khi container bị gỡ.
	if err := st.AddDomain(ctx, &store.Domain{AppID: "app-2", FQDN: "z.keenrig.com"}); err != nil {
		t.Fatalf("AddDomain app-2: %v", err)
	}
	all, err := st.ListAllDomains(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListAllDomains = (%d, %v), muốn 3", len(all), err)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].FQDN > all[i].FQDN {
			t.Fatalf("ListAllDomains không xếp theo fqdn: %v", domainFQDNs(all))
		}
	}
	if err := st.DeleteApp(ctx, "app-2"); err != nil {
		t.Fatalf("DeleteApp app-2: %v", err)
	}
	all, err = st.ListAllDomains(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListAllDomains sau soft-delete = (%v, %v), muốn còn 2", domainFQDNs(all), err)
	}
	// …nhưng FQDN vẫn CHƯA được giải phóng: app-2 chưa purge, container còn đó.
	if err := st.AddDomain(ctx, &store.Domain{AppID: "app-1", FQDN: "z.keenrig.com"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("AddDomain FQDN của app chờ xoá: muốn ErrConflict, nhận %v", err)
	}

	if err := st.DeleteDomain(ctx, "b.keenrig.com"); err != nil {
		t.Fatalf("DeleteDomain: %v", err)
	}
	if err := st.DeleteDomain(ctx, "b.keenrig.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeleteDomain lần 2: muốn ErrNotFound, nhận %v", err)
	}
}

// testDomainsCascadeOnPurge — PurgeApp (pha 2) phải dọn cả domain lẫn addon,
// nếu không FQDN sẽ bị giữ vĩnh viễn bởi một app không còn tồn tại.
func testDomainsCascadeOnPurge(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")
	if err := st.AddDomain(ctx, &store.Domain{AppID: "app-1", FQDN: "a.keenrig.com", IsPrimary: true}); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	if err := st.PutAppAddon(ctx, &store.AppAddon{AppID: "app-1", Addon: "postgres"}); err != nil {
		t.Fatalf("PutAppAddon: %v", err)
	}

	if err := st.DeleteApp(ctx, "app-1"); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if err := st.PurgeApp(ctx, "app-1"); err != nil {
		t.Fatalf("PurgeApp: %v", err)
	}

	if ds, err := st.ListDomains(ctx, "app-1"); err != nil || len(ds) != 0 {
		t.Errorf("ListDomains sau purge = (%v, %v), muốn rỗng", domainFQDNs(ds), err)
	}
	if as, err := st.ListAppAddons(ctx, "app-1"); err != nil || len(as) != 0 {
		t.Errorf("ListAppAddons sau purge = (%d, %v), muốn rỗng", len(as), err)
	}
	// FQDN đã được giải phóng thật sự — app mới dùng lại được.
	mustCreate(t, st, "app-2", "world")
	if err := st.AddDomain(ctx, &store.Domain{AppID: "app-2", FQDN: "a.keenrig.com"}); err != nil {
		t.Errorf("AddDomain dùng lại FQDN sau purge: %v", err)
	}
}

func domainFQDNs(ds []*store.Domain) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.FQDN
	}
	return out
}

// --- T6d: addons --------------------------------------------------------------

func testAppAddons(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")

	a := &store.AppAddon{AppID: "app-1", Addon: "postgres"}
	if err := st.PutAppAddon(ctx, a); err != nil {
		t.Fatalf("PutAppAddon: %v", err)
	}
	if a.State != store.AddonPending {
		t.Errorf("State mặc định = %q, muốn %q", a.State, store.AddonPending)
	}
	if err := st.PutAppAddon(ctx, &store.AppAddon{AppID: "app-1", Addon: "redis"}); err != nil {
		t.Fatalf("PutAppAddon redis: %v", err)
	}

	// Upsert: cùng (app, addon) thì cập nhật chứ không sinh dòng thứ hai.
	if err := st.PutAppAddon(ctx, &store.AppAddon{
		AppID: "app-1", Addon: "postgres", State: store.AddonReady, ConfigRef: "addon/pg/app-1",
	}); err != nil {
		t.Fatalf("PutAppAddon upsert: %v", err)
	}
	as, err := st.ListAppAddons(ctx, "app-1")
	if err != nil || len(as) != 2 {
		t.Fatalf("ListAppAddons = (%d, %v), muốn 2", len(as), err)
	}
	if as[0].Addon != "postgres" || as[0].State != store.AddonReady || as[0].ConfigRef != "addon/pg/app-1" {
		t.Errorf("addon sau upsert = %+v", as[0])
	}
	// created_at KHÔNG được reset khi upsert — mốc "cấp từ bao giờ" phải giữ.
	if as[0].CreatedAt.After(as[0].UpdatedAt) {
		t.Errorf("CreatedAt (%v) sau UpdatedAt (%v)", as[0].CreatedAt, as[0].UpdatedAt)
	}

	if err := st.PutAppAddon(ctx, &store.AppAddon{AppID: "không-có", Addon: "redis"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("PutAppAddon app lạ: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.DeleteAppAddon(ctx, "app-1", "redis"); err != nil {
		t.Fatalf("DeleteAppAddon: %v", err)
	}
	if err := st.DeleteAppAddon(ctx, "app-1", "redis"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeleteAppAddon lần 2: muốn ErrNotFound, nhận %v", err)
	}
}

// --- T6b: lease ---------------------------------------------------------------

// LS-01 — hai box cùng chạy thì chỉ một giữ được lease.
func testLeaseSingleHolder(t *testing.T, st store.Store) {
	ctx := context.Background()

	l1, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-A", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease box-A: %v", err)
	}
	if l1.Holder != "box-A" || l1.Token != 1 {
		t.Fatalf("lease đầu tiên = %+v, muốn holder=box-A token=1", l1)
	}

	if _, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-B", time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("AcquireLease box-B khi box-A đang giữ: muốn ErrConflict, nhận %v", err)
	}

	// Gia hạn của chính chủ KHÔNG được làm token nhảy — token nhảy nghĩa là đã
	// đổi chủ, và vòng lặp reconcile dựa vào đó để biết mình có bị gián đoạn không.
	l2, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-A", time.Minute)
	if err != nil || l2.Token != 1 {
		t.Fatalf("AcquireLease gia hạn = (%+v, %v), muốn token giữ 1", l2, err)
	}
	l3, err := st.RenewLease(ctx, store.LeaseReconciler, "box-A", l2.Token, time.Minute)
	if err != nil || l3.Token != 1 {
		t.Fatalf("RenewLease = (%+v, %v), muốn token giữ 1", l3, err)
	}

	// Sai token = chủ cũ tỉnh dậy sau khi lease đã đổi tay. Phải chặn kể cả khi
	// holder khớp và lease chưa hết hạn.
	if _, err := st.RenewLease(ctx, store.LeaseReconciler, "box-A", 99, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Errorf("RenewLease sai token: muốn ErrConflict, nhận %v", err)
	}
	if _, err := st.RenewLease(ctx, store.LeaseReconciler, "box-B", l3.Token, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Errorf("RenewLease sai holder: muốn ErrConflict, nhận %v", err)
	}
	if err := st.ReleaseLease(ctx, store.LeaseReconciler, "box-B", l3.Token); !errors.Is(err, store.ErrConflict) {
		t.Errorf("ReleaseLease sai holder: muốn ErrConflict, nhận %v", err)
	}

	got, err := st.GetLease(ctx, store.LeaseReconciler)
	if err != nil || got.Holder != "box-A" {
		t.Fatalf("GetLease = (%+v, %v), muốn box-A", got, err)
	}

	if err := st.ReleaseLease(ctx, store.LeaseReconciler, "box-A", l3.Token); err != nil {
		t.Fatalf("ReleaseLease: %v", err)
	}
	if _, err := st.GetLease(ctx, store.LeaseReconciler); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetLease sau release: muốn ErrNotFound, nhận %v", err)
	}
	// Nhả rồi thì box khác vào được ngay, và token phải TĂNG (đổi chủ).
	l4, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-B", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease box-B sau release: %v", err)
	}
	if l4.Token != 1 {
		// Row đã bị DELETE nên đây là lease mới hoàn toàn: token bắt đầu lại từ 1.
		t.Errorf("token sau release+acquire = %d, muốn 1 (row mới)", l4.Token)
	}
}

// LS-02 — chủ chết thì box khác nhận lease SAU TTL, không sớm hơn.
func testLeaseExpiryHandover(t *testing.T, st store.Store) {
	ctx := context.Background()

	// TTL 1 giây: cột expires_at có độ phân giải giây (làm tròn LÊN), nên
	// dưới 1 giây không biểu diễn được.
	l1, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-A", time.Second)
	if err != nil {
		t.Fatalf("AcquireLease box-A: %v", err)
	}

	// Trước hạn: không ai cướp được.
	if _, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-B", time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("AcquireLease box-B trước hạn: muốn ErrConflict, nhận %v", err)
	}

	// Chờ qua hạn (+1s biên cho việc làm tròn lên giây).
	time.Sleep(2100 * time.Millisecond)

	l2, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-B", time.Minute)
	if err != nil {
		t.Fatalf("AcquireLease box-B sau hạn: %v", err)
	}
	if l2.Holder != "box-B" {
		t.Fatalf("holder sau hạn = %q, muốn box-B", l2.Holder)
	}
	// Đổi chủ PHẢI tăng token — đây là toàn bộ giá trị của fencing token.
	if l2.Token <= l1.Token {
		t.Errorf("token sau đổi chủ = %d, muốn > %d", l2.Token, l1.Token)
	}

	// Box-A tỉnh dậy với token cũ: mọi cửa vào đều phải đóng. Không có kiểm
	// token thì nó gia hạn thành công và ta có HAI chủ cùng lúc.
	if _, err := st.RenewLease(ctx, store.LeaseReconciler, "box-A", l1.Token, time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Errorf("box-A gia hạn bằng token cũ: muốn ErrConflict, nhận %v", err)
	}
	if err := st.ReleaseLease(ctx, store.LeaseReconciler, "box-A", l1.Token); !errors.Is(err, store.ErrConflict) {
		t.Errorf("box-A nhả lease của box-B: muốn ErrConflict, nhận %v", err)
	}
	if _, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-A", time.Minute); !errors.Is(err, store.ErrConflict) {
		t.Errorf("box-A giành lại khi box-B đang giữ: muốn ErrConflict, nhận %v", err)
	}
}

// testLeaseConcurrentAcquire — N goroutine cùng giành lease trống, ĐÚNG MỘT
// thắng. Chứng minh không có cửa sổ giữa "đọc" và "ghi" (kiểm bằng SELECT rồi
// UPDATE sẽ cho nhiều hơn một thắng ở đây).
func testLeaseConcurrentAcquire(t *testing.T, st store.Store) {
	ctx := context.Background()
	const n = 8

	var (
		mu      sync.Mutex
		winners []string
		wg      sync.WaitGroup
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			holder := "box-" + string(rune('A'+i))
			<-start
			l, err := st.AcquireLease(ctx, store.LeaseReconciler, holder, time.Minute)
			if err == nil {
				mu.Lock()
				winners = append(winners, l.Holder)
				mu.Unlock()
				return
			}
			if !errors.Is(err, store.ErrConflict) {
				t.Errorf("AcquireLease %s: muốn ErrConflict, nhận %v", holder, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if len(winners) != 1 {
		t.Fatalf("%d goroutine giành lease → %d người thắng (%v), muốn đúng 1", n, len(winners), winners)
	}
}

// LS-03 — visibility timeout: worker chết thì job về queued, không kẹt running.
func testJobVisibilityTimeout(t *testing.T, st store.Store) {
	ctx := context.Background()

	if _, err := st.EnqueueJob(ctx, "backup", nil, nil); err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// Claim với hạn giữ 1 giây rồi "chết" — không CompleteJob, không FailJob.
	job, err := st.ClaimJobAs(ctx, nil, "worker-1", time.Second)
	if err != nil {
		t.Fatalf("ClaimJobAs: %v", err)
	}
	if job.State != "running" || job.LeaseOwner != "worker-1" || job.LeaseUntil == nil {
		t.Fatalf("job sau claim = %+v, muốn running + lease_owner + lease_until", job)
	}

	// Chưa quá hạn: không ai claim được, và ReclaimExpired không đụng vào.
	if _, err := st.ClaimJobAs(ctx, nil, "worker-2", time.Second); !errors.Is(err, store.ErrNoJob) {
		t.Errorf("ClaimJobAs khi job đang có chủ: muốn ErrNoJob, nhận %v", err)
	}
	if n, err := st.ReclaimExpired(ctx); err != nil || n != 0 {
		t.Errorf("ReclaimExpired trước hạn = (%d, %v), muốn 0", n, err)
	}

	time.Sleep(2100 * time.Millisecond)

	n, err := st.ReclaimExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("ReclaimExpired sau hạn = (%d, %v), muốn 1", n, err)
	}
	if n, err := st.ReclaimExpired(ctx); err != nil || n != 0 {
		t.Errorf("ReclaimExpired lần 2 = (%d, %v), muốn 0 (idempotent)", n, err)
	}

	again, err := st.ClaimJobAs(ctx, nil, "worker-2", time.Minute)
	if err != nil {
		t.Fatalf("ClaimJobAs sau thu hồi: %v", err)
	}
	if again.ID != job.ID {
		t.Errorf("job claim lại có id %d, muốn %d", again.ID, job.ID)
	}
	// Thu hồi KHÔNG tính là một lần thất bại: worker bị kill 4 lần sẽ đẩy job
	// sang 'failed' vĩnh viễn dù bản thân job chưa bao giờ chạy sai.
	if again.Attempt != 0 {
		t.Errorf("Attempt sau thu hồi = %d, muốn giữ 0", again.Attempt)
	}
	if again.LeaseOwner != "worker-2" {
		t.Errorf("LeaseOwner sau claim lại = %q, muốn worker-2", again.LeaseOwner)
	}

	// Kết thúc job phải nhả lease, nếu không ReclaimExpired sẽ thấy rác.
	if err := st.CompleteJob(ctx, again.ID, nil); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}
	if n, err := st.ReclaimExpired(ctx); err != nil || n != 0 {
		t.Errorf("ReclaimExpired sau CompleteJob = (%d, %v), muốn 0", n, err)
	}
}
