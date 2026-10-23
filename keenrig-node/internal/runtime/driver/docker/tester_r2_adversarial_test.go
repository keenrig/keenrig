package docker

// Test đối kháng vòng 2 — AGENT TESTER. Đánh vào các đường mà conformance
// suite không chạm: người vận hành can thiệp tay (docker stop), và danh tính
// container khi TÊN trùng nhưng LABEL app.id khác (§0.11 nói "danh tính thật
// = labels").
// Docker không chạy → Skip (không Fail).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

func advR2Spec(t *testing.T, slug string) runtime.AppSpec {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	id := "whoami-" + hex.EncodeToString(b)
	if slug == "" {
		slug = id
	}
	return runtime.AppSpec{
		ID:         id,
		Slug:       slug,
		DesiredRev: 1,
		Desired:    contracts.DesiredApp{Image: testImage},
	}
}

// TestAdvR2ManualStopThenApplyRecovers: người vận hành `docker stop` container
// do driver quản → Status PHẢI báo trạng thái không-running (error/stopped),
// và Apply lại cùng spec PHẢI hồi phục về running mà KHÔNG tạo container thứ 2.
func TestAdvR2ManualStopThenApplyRecovers(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	spec := advR2Spec(t, "")
	cleanupApp(t, d, spec.ID)

	obs, err := d.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}
	if obs.Phase != contracts.AppStateRunning || len(obs.ContainerIDs) != 1 {
		t.Fatalf("Apply = %+v, muốn running + 1 container", obs)
	}
	origID := obs.ContainerIDs[0]

	// Can thiệp TAY: dừng container ngoài driver.
	sec := 5
	if _, err := cli.ContainerStop(ctx, origID, client.ContainerStopOptions{Timeout: &sec}); err != nil {
		t.Fatalf("docker stop thủ công: %v", err)
	}

	// Status PHẢI phản ánh sự thật — không được vẫn báo running.
	var st runtime.Observed
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err = d.Status(ctx, spec.ID)
		if err != nil {
			t.Fatalf("Status sau stop: %v", err)
		}
		if st.Phase != contracts.AppStateRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("30s sau `docker stop`, Status VẪN báo running: %+v", st)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if st.Phase != contracts.AppStateError && st.Phase != contracts.AppStateStopped {
		t.Errorf("Status sau stop = %q, muốn error hoặc stopped", st.Phase)
	}
	t.Logf("OK — sau `docker stop`: phase=%q message=%q", st.Phase, st.Message)

	// Apply lại cùng spec → hồi phục, KHÔNG nhân đôi.
	obs2, err := d.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply lại sau stop tay: %v", err)
	}
	if obs2.Phase != contracts.AppStateRunning || len(obs2.ContainerIDs) != 1 {
		t.Fatalf("Apply lại = %+v, muốn running + 1 container", obs2)
	}
	if obs2.ContainerIDs[0] != origID {
		t.Errorf("ensure idempotent: muốn START LẠI container cũ %s, nhận %s (tạo mới?)",
			origID[:12], obs2.ContainerIDs[0][:12])
	}
	items := listByLabel(t, cli, spec.ID)
	if len(items) != 1 {
		t.Errorf("tổng container theo label = %d, muốn ĐÚNG 1 (không tạo container thứ 2)", len(items))
	}
	if len(items) == 1 && items[0].State != container.StateRunning {
		t.Errorf("container state = %s, muốn running", items[0].State)
	}
}

// TestAdvR2SlugReuseIdentity — CẠM BẪY danh tính (§0.11: "Danh tính thật =
// labels", §2.3 bước 5 ensure THEO TÊN).
//
// Kịch bản thật: app A (slug "s") bị DeleteApp khỏi store nhưng container chưa
// được Remove (không có code path nào gọi runtime.Remove khi xoá app) → app B
// mới được tạo dùng LẠI slug "s" (store cho phép vì A đã bị xoá) → rev cũng
// bắt đầu từ 1 → TÊN container trùng hệt: su-s-0-r1.
//
// Kỳ vọng đúng: Apply(B) phải SỞ HỮU container mang label app.id = B.
// Nếu driver adopt container của A chỉ vì trùng tên thì Apply(B) báo running
// trong khi Status(B) báo stopped — hai API mâu thuẫn nhau.
func TestAdvR2SlugReuseIdentity(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	specA := advR2Spec(t, "")
	sharedSlug := specA.Slug
	specB := advR2Spec(t, sharedSlug) // slug + rev giống hệt, app.id KHÁC
	cleanupApp(t, d, specA.ID)
	cleanupApp(t, d, specB.ID)

	obsA, err := d.Apply(ctx, specA)
	if err != nil {
		t.Fatalf("Apply A: %v", err)
	}
	if len(obsA.ContainerIDs) != 1 {
		t.Fatalf("Apply A = %+v, muốn 1 container", obsA)
	}

	// App A "bị xoá khỏi store" nhưng container còn — giờ B dùng lại slug.
	obsB, err := d.Apply(ctx, specB)
	if err != nil {
		t.Fatalf("Apply B (slug dùng lại): %v", err)
	}
	t.Logf("A.id=%s → %v", specA.ID, obsA.ContainerIDs)
	t.Logf("B.id=%s → %v", specB.ID, obsB.ContainerIDs)

	ownedByB := listByLabel(t, cli, specB.ID)
	ownedByA := listByLabel(t, cli, specA.ID)
	t.Logf("container mang label app.id=A: %d, app.id=B: %d", len(ownedByA), len(ownedByB))

	if len(obsB.ContainerIDs) > 0 && obsB.ContainerIDs[0] == obsA.ContainerIDs[0] {
		t.Errorf("BUG danh tính: Apply(B) TRẢ VỀ container của A (%s) — adopt theo TÊN "+
			"mà không kiểm label %s. Container này vẫn mang label app.id=%s.",
			obsA.ContainerIDs[0][:12], labelAppID, specA.ID)
	}
	if len(ownedByB) == 0 {
		t.Errorf("BUG danh tính: sau Apply(B) KHÔNG có container nào mang label %s=%s. "+
			"Hệ quả: Apply(B) báo phase=%q nhưng Status(B) sẽ báo stopped, và Remove(B) "+
			"không bao giờ dọn được tài nguyên mà B tưởng mình sở hữu.",
			labelAppID, specB.ID, obsB.Phase)
	}

	// Chứng minh mâu thuẫn Apply vs Status.
	stB, err := d.Status(ctx, specB.ID)
	if err != nil {
		t.Fatalf("Status B: %v", err)
	}
	t.Logf("Apply(B).Phase=%q  vs  Status(B).Phase=%q", obsB.Phase, stB.Phase)
	if obsB.Phase == contracts.AppStateRunning && stB.Phase != contracts.AppStateRunning {
		t.Errorf("MÂU THUẪN API: Apply(B) trả %q nhưng Status(B) trả %q (%s) — reconciler "+
			"sẽ ghi applied_rev=1 rồi refresh tick lập tức lật status về %q",
			obsB.Phase, stB.Phase, stB.Message, stB.Phase)
	}
}
