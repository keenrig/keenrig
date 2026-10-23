// Package storetest — conformance suite cho store.Store (kiểu drivertest của Go CDK).
// Mọi implementation của store.Store phải pass RunConformance.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// RunConformance chạy toàn bộ suite trên store do open cấp (mỗi subtest 1 store tươi).
func RunConformance(t *testing.T, open func(t *testing.T) store.Store) {
	t.Run("AppCRUDDelete", func(t *testing.T) { testAppCRUDDelete(t, open(t)) })
	t.Run("RevMonotonic", func(t *testing.T) { testRevMonotonic(t, open(t)) })
	t.Run("ConcurrentUpdateDesired", func(t *testing.T) { testConcurrentUpdateDesired(t, open(t)) })
	t.Run("ConflictAndNotFound", func(t *testing.T) { testConflictAndNotFound(t, open(t)) })
	t.Run("Settings", func(t *testing.T) { testSettings(t, open(t)) })
	t.Run("SecretsRoundtrip", func(t *testing.T) { testSecretsRoundtrip(t, open(t)) })
	t.Run("JobsLifecycle", func(t *testing.T) { testJobsLifecycle(t, open(t)) })
	t.Run("ConcurrentClaim", func(t *testing.T) { testConcurrentClaim(t, open(t)) })
	t.Run("EventsAppendList", func(t *testing.T) { testEventsAppendList(t, open(t)) })
	t.Run("ListAppsNeedingReconcile", func(t *testing.T) { testListAppsNeedingReconcile(t, open(t)) })
	t.Run("TwoPhaseDelete", func(t *testing.T) { testTwoPhaseDelete(t, open(t)) })
	t.Run("Endpoints", func(t *testing.T) { testEndpoints(t, open(t)) })
	t.Run("Domains", func(t *testing.T) { testDomains(t, open(t)) })
	t.Run("DomainsCascadeOnPurge", func(t *testing.T) { testDomainsCascadeOnPurge(t, open(t)) })
	t.Run("AppAddons", func(t *testing.T) { testAppAddons(t, open(t)) })
	t.Run("LeaseSingleHolder", func(t *testing.T) { testLeaseSingleHolder(t, open(t)) })     // LS-01
	t.Run("LeaseExpiryHandover", func(t *testing.T) { testLeaseExpiryHandover(t, open(t)) }) // LS-02
	t.Run("LeaseConcurrentAcquire", func(t *testing.T) { testLeaseConcurrentAcquire(t, open(t)) })
	t.Run("JobVisibilityTimeout", func(t *testing.T) { testJobVisibilityTimeout(t, open(t)) }) // LS-03
	t.Run("APITokenLifecycle", func(t *testing.T) { testAPITokenLifecycle(t, open(t)) })       // ID-04
	t.Run("APITokenExpiryFilteredInSQL", func(t *testing.T) { testAPITokenExpiryFilteredInSQL(t, open(t)) })
	t.Run("APITokenIsolationBetweenUsers", func(t *testing.T) { testAPITokenIsolationBetweenUsers(t, open(t)) })
	t.Run("APITokenForeignKey", func(t *testing.T) { testAPITokenForeignKey(t, open(t)) })
	t.Run("OIDCClientCRUD", func(t *testing.T) { testOIDCClientCRUD(t, open(t)) }) // ID-01
	t.Run("OIDCCodeSingleUseUnderConcurrency", func(t *testing.T) {
		testOIDCCodeSingleUseUnderConcurrency(t, open(t))
	})
	t.Run("OIDCCodeExpiry", func(t *testing.T) { testOIDCCodeExpiry(t, open(t)) })
	t.Run("OIDCCodeForeignKeys", func(t *testing.T) { testOIDCCodeForeignKeys(t, open(t)) })
	t.Run("SnapshotToSelfContainedFile", func(t *testing.T) { testSnapshotTo(t, open(t)) })       // BK-02
	t.Run("SnapshotRefusesOverwrite", func(t *testing.T) { testSnapshotNoOverwrite(t, open(t)) }) // BK-02
	t.Run("SnapshotDuringWrites", func(t *testing.T) { testSnapshotDuringWrites(t, open(t)) })    // BK-02
}

func mustCreate(t *testing.T, st store.Store, id, slug string) *store.App {
	t.Helper()
	app := &store.App{ID: id, Slug: slug, Desired: json.RawMessage(`{"image":"nginx:1"}`)}
	if err := st.CreateApp(context.Background(), app); err != nil {
		t.Fatalf("CreateApp(%s): %v", id, err)
	}
	return app
}

func testAppCRUDDelete(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")

	got, err := st.GetApp(ctx, "app-1")
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	if got.Slug != "hello" || got.DesiredRev != 1 || got.AppliedRev != 0 {
		t.Errorf("GetApp sai: %+v", got)
	}

	apps, err := st.ListApps(ctx)
	if err != nil || len(apps) != 1 {
		t.Fatalf("ListApps = (%d app, %v), muốn 1 app", len(apps), err)
	}

	rev, err := st.UpdateDesired(ctx, "app-1", json.RawMessage(`{"image":"nginx:2"}`))
	if err != nil || rev != 2 {
		t.Fatalf("UpdateDesired = (%d, %v), muốn (2, nil)", rev, err)
	}

	if err := st.DeleteApp(ctx, "app-1"); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if _, err := st.GetApp(ctx, "app-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetApp sau delete: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.DeleteApp(ctx, "app-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeleteApp lần 2: muốn ErrNotFound, nhận %v", err)
	}
}

// ST-01: applied_rev không bao giờ được vượt desired_rev.
func testRevMonotonic(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")

	if rev, err := st.UpdateDesired(ctx, "app-1", json.RawMessage(`{"image":"v2"}`)); err != nil || rev != 2 {
		t.Fatalf("UpdateDesired #1 = (%d, %v), muốn (2, nil)", rev, err)
	}
	if rev, err := st.UpdateDesired(ctx, "app-1", json.RawMessage(`{"image":"v3"}`)); err != nil || rev != 3 {
		t.Fatalf("UpdateDesired #2 = (%d, %v), muốn (3, nil)", rev, err)
	}

	status := json.RawMessage(`{"app_id":"app-1","state":"running"}`)
	if err := st.SetStatus(ctx, "app-1", status, 3); err != nil {
		t.Fatalf("SetStatus applied=3: %v", err)
	}
	if err := st.SetStatus(ctx, "app-1", status, 4); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("SetStatus applied=4 > desired=3: muốn ErrConflict, nhận %v", err)
	}
	// applied_rev ÂM cũng phải bị chặn: nó qua được guard `desired_rev >= ?`
	// nhưng làm app kẹt vĩnh viễn trong ListAppsNeedingReconcile.
	if err := st.SetStatus(ctx, "app-1", status, -1); !errors.Is(err, store.ErrConflict) {
		t.Errorf("SetStatus applied=-1: muốn ErrConflict, nhận %v", err)
	}
	got, err := st.GetApp(ctx, "app-1")
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	if got.AppliedRev != 3 {
		t.Errorf("AppliedRev sau conflict = %d, muốn giữ 3", got.AppliedRev)
	}
}

func testConcurrentUpdateDesired(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")

	revs := make(chan int64, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rev, err := st.UpdateDesired(ctx, "app-1", json.RawMessage(fmt.Sprintf(`{"image":"v%d"}`, i)))
			if err != nil {
				t.Errorf("UpdateDesired goroutine %d: %v", i, err)
				return
			}
			revs <- rev
		}(i)
	}
	wg.Wait()
	close(revs)

	seen := map[int64]bool{}
	for rev := range revs {
		seen[rev] = true
	}
	if !seen[2] || !seen[3] || len(seen) != 2 {
		t.Errorf("revs từ 2 goroutine = %v, muốn {2, 3}", seen)
	}
}

func testConflictAndNotFound(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")

	err := st.CreateApp(ctx, &store.App{ID: "app-2", Slug: "hello", Desired: json.RawMessage(`{}`)})
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("CreateApp slug trùng: muốn ErrConflict, nhận %v", err)
	}

	if _, err := st.GetApp(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetApp missing: muốn ErrNotFound, nhận %v", err)
	}
	if _, err := st.UpdateDesired(ctx, "missing", json.RawMessage(`{}`)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UpdateDesired missing: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.SetStatus(ctx, "missing", json.RawMessage(`{}`), 0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetStatus missing: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.DeleteApp(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeleteApp missing: muốn ErrNotFound, nhận %v", err)
	}

	if err := st.AppendEvent(ctx, "test.nil-data", "storetest", "app-1", nil); err != nil {
		t.Errorf("AppendEvent data nil: %v", err)
	}
}

func testSettings(t *testing.T, st store.Store) {
	ctx := context.Background()
	if _, err := st.GetSetting(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetSetting missing: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.SetSetting(ctx, "k", "v1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := st.SetSetting(ctx, "k", "v2"); err != nil {
		t.Fatalf("SetSetting upsert: %v", err)
	}
	if v, err := st.GetSetting(ctx, "k"); err != nil || v != "v2" {
		t.Errorf("GetSetting = (%q, %v), muốn (v2, nil)", v, err)
	}
}

func testSecretsRoundtrip(t *testing.T, st store.Store) {
	ctx := context.Background()

	if _, err := st.GetSecret(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetSecret missing: muốn ErrNotFound, nhận %v", err)
	}

	if err := st.PutSecret(ctx, "db/pass", []byte("s3cret-v1")); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	got, err := st.GetSecret(ctx, "db/pass")
	if err != nil || string(got) != "s3cret-v1" {
		t.Fatalf("GetSecret = (%q, %v), muốn s3cret-v1", got, err)
	}

	if err := st.PutSecret(ctx, "db/pass", []byte("s3cret-v2")); err != nil {
		t.Fatalf("PutSecret overwrite: %v", err)
	}
	got, err = st.GetSecret(ctx, "db/pass")
	if err != nil || string(got) != "s3cret-v2" {
		t.Fatalf("GetSecret sau overwrite = (%q, %v), muốn s3cret-v2", got, err)
	}

	if err := st.DeleteSecret(ctx, "db/pass"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := st.GetSecret(ctx, "db/pass"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetSecret sau delete: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.DeleteSecret(ctx, "db/pass"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeleteSecret lần 2: muốn ErrNotFound, nhận %v", err)
	}
}

func testJobsLifecycle(t *testing.T, st store.Store) {
	ctx := context.Background()

	// Happy path + filter kind.
	alphaID, err := st.EnqueueJob(ctx, "alpha", json.RawMessage(`{"n":1}`), nil)
	if err != nil {
		t.Fatalf("EnqueueJob alpha: %v", err)
	}
	betaID, err := st.EnqueueJob(ctx, "beta", nil, nil)
	if err != nil {
		t.Fatalf("EnqueueJob beta: %v", err)
	}

	if _, err := st.ClaimJob(ctx, []string{"gamma"}); !errors.Is(err, store.ErrNoJob) {
		t.Errorf("ClaimJob kind lạ: muốn ErrNoJob, nhận %v", err)
	}
	job, err := st.ClaimJob(ctx, []string{"beta"})
	if err != nil {
		t.Fatalf("ClaimJob beta: %v", err)
	}
	if job.ID != betaID || job.Kind != "beta" || job.State != "running" || job.Attempt != 0 {
		t.Errorf("ClaimJob beta sai: %+v", job)
	}
	job, err = st.ClaimJob(ctx, nil)
	if err != nil {
		t.Fatalf("ClaimJob nil kinds: %v", err)
	}
	if job.ID != alphaID || job.Kind != "alpha" || string(job.Args) != `{"n":1}` {
		t.Errorf("ClaimJob alpha sai: %+v", job)
	}
	if err := st.CompleteJob(ctx, alphaID, json.RawMessage(`{"ok":true}`)); err != nil {
		t.Fatalf("CompleteJob alpha: %v", err)
	}
	if err := st.CompleteJob(ctx, betaID, nil); err != nil {
		t.Fatalf("CompleteJob beta: %v", err)
	}
	if _, err := st.ClaimJob(ctx, nil); !errors.Is(err, store.ErrNoJob) {
		t.Errorf("ClaimJob sau complete hết: muốn ErrNoJob, nhận %v", err)
	}

	// notBefore tương lai → chưa claim được; quá hạn → claim được.
	future := time.Now().Add(1 * time.Hour)
	if _, err := st.EnqueueJob(ctx, "later", nil, &future); err != nil {
		t.Fatalf("EnqueueJob later: %v", err)
	}
	if _, err := st.ClaimJob(ctx, []string{"later"}); !errors.Is(err, store.ErrNoJob) {
		t.Errorf("ClaimJob notBefore tương lai: muốn ErrNoJob, nhận %v", err)
	}
	past := time.Now().Add(-1 * time.Hour)
	pastID, err := st.EnqueueJob(ctx, "past", nil, &past)
	if err != nil {
		t.Fatalf("EnqueueJob past: %v", err)
	}
	job, err = st.ClaimJob(ctx, []string{"past"})
	if err != nil || job.ID != pastID {
		t.Fatalf("ClaimJob notBefore quá hạn = (%+v, %v), muốn claim được", job, err)
	}
	if job.NotBefore == nil {
		t.Error("job.NotBefore nil, muốn giữ giá trị đã enqueue")
	}

	// Retry: fail < MaxJobAttempts → queued lại kèm not_before; fail đủ → failed.
	flakyID, err := st.EnqueueJob(ctx, "flaky", nil, nil)
	if err != nil {
		t.Fatalf("EnqueueJob flaky: %v", err)
	}
	if job, err = st.ClaimJob(ctx, []string{"flaky"}); err != nil || job.ID != flakyID {
		t.Fatalf("ClaimJob flaky: (%+v, %v)", job, err)
	}
	for i := 1; i < store.MaxJobAttempts; i++ {
		if err := st.FailJob(ctx, flakyID, fmt.Sprintf("boom %d", i), 0); err != nil {
			t.Fatalf("FailJob #%d: %v", i, err)
		}
		job, err = st.ClaimJob(ctx, []string{"flaky"})
		if err != nil {
			t.Fatalf("ClaimJob sau fail #%d: %v (job phải về queued)", i, err)
		}
		if job.Attempt != i {
			t.Errorf("attempt sau fail #%d = %d, muốn %d", i, job.Attempt, i)
		}
		if job.LastError != fmt.Sprintf("boom %d", i) {
			t.Errorf("last_error = %q, muốn 'boom %d'", job.LastError, i)
		}
		if job.NotBefore == nil {
			t.Errorf("fail #%d: NotBefore nil, muốn được set khi requeue", i)
		}
	}
	if err := st.FailJob(ctx, flakyID, "boom final", 0); err != nil {
		t.Fatalf("FailJob final: %v", err)
	}
	if _, err := st.ClaimJob(ctx, []string{"flaky"}); !errors.Is(err, store.ErrNoJob) {
		t.Errorf("ClaimJob sau fail đủ %d lần: muốn ErrNoJob (state failed), nhận %v", store.MaxJobAttempts, err)
	}

	// Fail với retryAfter tương lai → chưa claim lại được.
	slowID, err := st.EnqueueJob(ctx, "slow", nil, nil)
	if err != nil {
		t.Fatalf("EnqueueJob slow: %v", err)
	}
	if _, err := st.ClaimJob(ctx, []string{"slow"}); err != nil {
		t.Fatalf("ClaimJob slow: %v", err)
	}
	if err := st.FailJob(ctx, slowID, "retry later", 2*time.Hour); err != nil {
		t.Fatalf("FailJob slow: %v", err)
	}
	if _, err := st.ClaimJob(ctx, []string{"slow"}); !errors.Is(err, store.ErrNoJob) {
		t.Errorf("ClaimJob khi not_before tương lai: muốn ErrNoJob, nhận %v", err)
	}
}

func testConcurrentClaim(t *testing.T, st store.Store) {
	ctx := context.Background()
	const nJobs, nWorkers = 5, 8

	want := map[int64]bool{}
	for i := 0; i < nJobs; i++ {
		id, err := st.EnqueueJob(ctx, "cc", nil, nil)
		if err != nil {
			t.Fatalf("EnqueueJob #%d: %v", i, err)
		}
		want[id] = true
	}

	claimed := make(chan int64, nJobs*2)
	var wg sync.WaitGroup
	for w := 0; w < nWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				job, err := st.ClaimJob(ctx, []string{"cc"})
				if errors.Is(err, store.ErrNoJob) {
					return
				}
				if err != nil {
					t.Errorf("ClaimJob: %v", err)
					return
				}
				claimed <- job.ID
			}
		}()
	}
	wg.Wait()
	close(claimed)

	got := map[int64]int{}
	total := 0
	for id := range claimed {
		got[id]++
		total++
	}
	if total != nJobs {
		t.Errorf("tổng claim = %d, muốn %d (mỗi job đúng 1 lần)", total, nJobs)
	}
	for id := range want {
		if got[id] != 1 {
			t.Errorf("job %d bị claim %d lần, muốn đúng 1", id, got[id])
		}
	}
}

func testEventsAppendList(t *testing.T, st store.Store) {
	ctx := context.Background()

	if err := st.AppendEvent(ctx, "e.first", "tester", "s1", nil); err != nil {
		t.Fatalf("AppendEvent 1: %v", err)
	}
	if err := st.AppendEvent(ctx, "e.second", "tester", "s2", json.RawMessage(`{"k":"v"}`)); err != nil {
		t.Fatalf("AppendEvent 2: %v", err)
	}
	if err := st.AppendEvent(ctx, "e.third", "", "", nil); err != nil {
		t.Fatalf("AppendEvent 3: %v", err)
	}

	events, err := st.ListEvents(ctx, 2)
	if err != nil {
		t.Fatalf("ListEvents(2): %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("ListEvents(2) trả %d event, muốn 2", len(events))
	}
	if events[0].Action != "e.third" || events[1].Action != "e.second" {
		t.Errorf("thứ tự sai (muốn mới nhất trước): %s, %s", events[0].Action, events[1].Action)
	}
	if events[0].ID <= events[1].ID {
		t.Errorf("ID phải giảm dần: %d, %d", events[0].ID, events[1].ID)
	}
	if string(events[1].Data) != `{"k":"v"}` {
		t.Errorf("Data roundtrip sai: %q", events[1].Data)
	}
	if events[0].Data != nil {
		t.Errorf("Data nil roundtrip sai: %q", events[0].Data)
	}
	if events[1].Actor != "tester" || events[1].Subject != "s2" {
		t.Errorf("Actor/Subject sai: %+v", events[1])
	}
	if events[0].CreatedAt.IsZero() {
		t.Error("CreatedAt rỗng")
	}

	all, err := st.ListEvents(ctx, 100)
	if err != nil || len(all) != 3 {
		t.Errorf("ListEvents(100) = (%d, %v), muốn 3", len(all), err)
	}
}

func testListAppsNeedingReconcile(t *testing.T, st store.Store) {
	ctx := context.Background()

	mustCreate(t, st, "app-a", "aaa")
	time.Sleep(5 * time.Millisecond) // tách created_at để ORDER BY ổn định
	mustCreate(t, st, "app-b", "bbb")

	apps, err := st.ListAppsNeedingReconcile(ctx)
	if err != nil {
		t.Fatalf("ListAppsNeedingReconcile: %v", err)
	}
	if len(apps) != 2 || apps[0].ID != "app-a" || apps[1].ID != "app-b" {
		t.Fatalf("muốn [app-a app-b] theo created_at, nhận %v", appIDs(apps))
	}

	// app-b hội tụ (applied = desired) → ra khỏi danh sách.
	if err := st.SetStatus(ctx, "app-b", json.RawMessage(`{"state":"running"}`), 1); err != nil {
		t.Fatalf("SetStatus app-b: %v", err)
	}
	apps, err = st.ListAppsNeedingReconcile(ctx)
	if err != nil || len(apps) != 1 || apps[0].ID != "app-a" {
		t.Fatalf("sau khi app-b hội tụ: muốn [app-a], nhận (%v, %v)", appIDs(apps), err)
	}

	// UpdateDesired app-b → rev 2 > applied 1 → quay lại danh sách.
	if _, err := st.UpdateDesired(ctx, "app-b", json.RawMessage(`{"image":"v2"}`)); err != nil {
		t.Fatalf("UpdateDesired app-b: %v", err)
	}
	apps, err = st.ListAppsNeedingReconcile(ctx)
	if err != nil || len(apps) != 2 {
		t.Fatalf("sau UpdateDesired app-b: muốn 2 app, nhận (%v, %v)", appIDs(apps), err)
	}
}

// testTwoPhaseDelete (regression BUG-2): DeleteApp chỉ ĐÁNH DẤU xoá — app biến
// mất khỏi Get/List/ListAppsNeedingReconcile nhưng còn trong ListAppsPendingDelete
// để reconciler kịp gọi runtime.Remove; PurgeApp mới xoá thật và giải phóng slug.
func testTwoPhaseDelete(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "app-1", "hello")

	if err := st.DeleteApp(ctx, "app-1"); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	assertMarkedDeleted(t, st)
	assertPurgeFrees(t, st)
}

// assertMarkedDeleted — pha 1: app-1 đã đánh dấu xoá nhưng chưa purge.
func assertMarkedDeleted(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()

	// Vô hình với đọc thường...
	if _, err := st.GetApp(ctx, "app-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetApp sau DeleteApp: muốn ErrNotFound, nhận %v", err)
	}
	if apps, err := st.ListApps(ctx); err != nil || len(apps) != 0 {
		t.Errorf("ListApps sau DeleteApp = (%v, %v), muốn rỗng", appIDs(apps), err)
	}
	if apps, err := st.ListAppsNeedingReconcile(ctx); err != nil || len(apps) != 0 {
		t.Errorf("ListAppsNeedingReconcile sau DeleteApp = (%v, %v), muốn rỗng — "+
			"đừng vừa dựng vừa xoá", appIDs(apps), err)
	}
	// ...nhưng reconciler PHẢI thấy để còn dọn container.
	pending, err := st.ListAppsPendingDelete(ctx)
	if err != nil || len(pending) != 1 || pending[0].ID != "app-1" {
		t.Fatalf("ListAppsPendingDelete = (%v, %v), muốn [app-1] — không có nó thì "+
			"container thành mồ côi vĩnh viễn", appIDs(pending), err)
	}
	// Ghi/xoá tiếp trên app đã đánh dấu → NotFound.
	if _, err := st.UpdateDesired(ctx, "app-1", json.RawMessage(`{"image":"v9"}`)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UpdateDesired trên app chờ xoá: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.SetStatus(ctx, "app-1", json.RawMessage(`{"state":"running"}`), 1); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetStatus trên app chờ xoá: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.DeleteApp(ctx, "app-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("DeleteApp lần 2: muốn ErrNotFound, nhận %v", err)
	}
}

// assertPurgeFrees — pha 2: purge xoá hẳn row và giải phóng slug.
func assertPurgeFrees(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()

	// Trước purge, slug vẫn bị giữ → app mới KHÔNG thể chiếm tên container
	// của app cũ khi container đó chưa được dọn (chặn đường tái hiện BUG-1).
	dup := &store.App{ID: "app-2", Slug: "hello", Desired: json.RawMessage(`{"image":"nginx:1"}`)}
	if err := st.CreateApp(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Errorf("CreateApp dùng lại slug khi chưa purge: muốn ErrConflict, nhận %v", err)
	}

	if err := st.PurgeApp(ctx, "app-1"); err != nil {
		t.Fatalf("PurgeApp: %v", err)
	}
	if pending, err := st.ListAppsPendingDelete(ctx); err != nil || len(pending) != 0 {
		t.Errorf("ListAppsPendingDelete sau purge = (%v, %v), muốn rỗng", appIDs(pending), err)
	}
	if err := st.PurgeApp(ctx, "app-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("PurgeApp lần 2: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.CreateApp(ctx, dup); err != nil {
		t.Errorf("CreateApp dùng lại slug sau purge: %v", err)
	}
}

func appIDs(apps []*store.App) []string {
	ids := make([]string, len(apps))
	for i, a := range apps {
		ids[i] = a.ID
	}
	return ids
}
