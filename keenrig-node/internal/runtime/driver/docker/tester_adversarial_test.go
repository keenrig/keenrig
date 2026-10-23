package docker

// Test ĐỐI KHÁNG do AGENT TESTER (vòng 2) viết — KHÔNG phải test của Coder.
// Mục tiêu: phá các bất biến của T5 mà conformance happy-path không chạm tới:
//   - §2.3 bước 4: pull image lỗi → KHÔNG được đụng container rev cũ
//   - §2.3 bước 6–7: "new trước old" — chứng minh bằng quan sát 2 rev ĐỒNG TỒN TẠI
//   - RT-02 fast-path: Apply nhiều lần liên tiếp không sinh thêm container
//   - RT-06: Remove → Status → Remove lần 2
// Dùng lại helper sẵn có trong docker_test.go (cùng package): newDriver,
// rawClient, testSpec, cleanupApp, listByLabel.

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
)

// badImage — tag chắc chắn không tồn tại trên registry.
const badImage = "traefik/whoami:v0-khong-ton-tai"

func tadvCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// tadvRunningCount đếm container theo label app.id đang thực sự Running.
func tadvRunningCount(items []container.Summary) int {
	n := 0
	for _, c := range items {
		if c.State == container.StateRunning {
			n++
		}
	}
	return n
}

// TestAdvApplyBadImageKeepsOldContainers — §2.3 bước 4.
// App đang chạy ổn ở rev1. Apply rev2 với image KHÔNG tồn tại phải:
//   - trả error (không nuốt lỗi),
//   - GIỮ NGUYÊN container rev cũ đang chạy (không được stop/remove trước khi
//     rev mới sẵn sàng) — nếu sai thì user mất service chỉ vì gõ nhầm tag.
func TestAdvApplyBadImageKeepsOldContainers(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx := tadvCtx(t)

	spec := testSpec(t)
	spec.Desired.Env = map[string]string{"DEPLOY_MARK": "r1"}
	cleanupApp(t, d, spec.ID)

	obs1, err := d.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply rev1 (image tốt): %v", err)
	}
	if obs1.Phase != contracts.AppStateRunning || len(obs1.ContainerIDs) != 1 {
		t.Fatalf("Apply rev1 = %+v, muốn running + 1 container", obs1)
	}
	oldID := obs1.ContainerIDs[0]

	// rev2 với image rác.
	spec2 := spec
	spec2.DesiredRev = 2
	spec2.Desired.Image = badImage

	obs2, err := d.Apply(ctx, spec2)
	if err == nil {
		t.Fatalf("Apply với image %q trả nil error (obs=%+v) — MUỐN lỗi", badImage, obs2)
	}
	t.Logf("Apply image rác trả lỗi đúng như mong đợi: %v", err)
	if obs2.Phase != contracts.AppStateError {
		t.Errorf("Observed.Phase = %q khi Apply lỗi, muốn %q", obs2.Phase, contracts.AppStateError)
	}

	// BẤT BIẾN QUAN TRỌNG: rev cũ phải còn nguyên và vẫn Running.
	items := listByLabel(t, cli, spec.ID)
	if len(items) != 1 {
		names := make([]string, 0, len(items))
		for _, c := range items {
			names = append(names, displayName(c)+"/"+c.Labels[labelRev]+"/"+string(c.State))
		}
		t.Fatalf("sau Apply lỗi có %d container (muốn đúng 1 — rev cũ): %v", len(items), names)
	}
	if items[0].ID != oldID {
		t.Errorf("container còn lại ID %s ≠ rev cũ %s — rev cũ đã bị thay", items[0].ID, oldID)
	}
	if items[0].State != container.StateRunning {
		t.Errorf("container rev cũ State = %q — MUỐN running (§2.3 bước 4: pull lỗi không đụng container cũ)", items[0].State)
	}
	if got := items[0].Labels[labelRev]; got != "1" {
		t.Errorf("label rev của container còn lại = %q, muốn \"1\"", got)
	}

	// Status vẫn phải báo running (service chưa chết).
	st, err := d.Status(ctx, spec.ID)
	if err != nil {
		t.Fatalf("Status sau Apply lỗi: %v", err)
	}
	if st.Phase != contracts.AppStateRunning || len(st.ContainerIDs) != 1 {
		t.Errorf("Status sau Apply lỗi = %+v, MUỐN vẫn running + 1 container", st)
	}

	// Apply lại rev2 với image TỐT → phải hội tụ bình thường (không kẹt).
	spec3 := spec
	spec3.DesiredRev = 2
	spec3.Desired.Env = map[string]string{"DEPLOY_MARK": "r2"}
	obs3, err := d.Apply(ctx, spec3)
	if err != nil {
		t.Fatalf("Apply rev2 với image tốt sau lần lỗi: %v", err)
	}
	if obs3.Phase != contracts.AppStateRunning || len(obs3.ContainerIDs) != 1 {
		t.Fatalf("Apply rev2 = %+v, muốn running + 1 container", obs3)
	}
	if items := listByLabel(t, cli, spec.ID); len(items) != 1 {
		t.Errorf("sau khi hồi phục có %d container, muốn đúng 1 (rev cũ đã dọn)", len(items))
	}
}

// TestAdvApplyBadImageOnFreshAppLeavesNothing: app CHƯA có container nào,
// Apply với image rác → lỗi và KHÔNG để lại container rác nào.
func TestAdvApplyBadImageOnFreshAppLeavesNothing(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx := tadvCtx(t)

	spec := testSpec(t)
	spec.Desired.Image = badImage
	cleanupApp(t, d, spec.ID)

	if obs, err := d.Apply(ctx, spec); err == nil {
		t.Fatalf("Apply image rác trên app mới trả nil error (obs=%+v) — MUỐN lỗi", obs)
	}
	if items := listByLabel(t, cli, spec.ID); len(items) != 0 {
		t.Errorf("Apply lỗi vẫn để lại %d container rác", len(items))
	}

	// Status trên app không có container → stopped, 0 ID.
	st, err := d.Status(ctx, spec.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Phase != contracts.AppStateStopped || len(st.ContainerIDs) != 0 {
		t.Errorf("Status = %+v, muốn stopped + 0 container", st)
	}
}

// TestAdvRollingNewBeforeOld — §2.3 bước 6–7 (RT-03) BẢN CHỨNG MINH TRỰC TIẾP.
// Conformance chỉ khẳng định "không lúc nào phase=stopped". Test này mạnh hơn:
// poll THẲNG Docker theo label trong lúc Apply rev2 và đòi hỏi
//   - số container Running KHÔNG BAO GIỜ về 0 (không downtime), VÀ
//   - có ÍT NHẤT một thời điểm quan sát được 2 container (rev1 + rev2 đồng tồn
//     tại) — bằng chứng rev mới được dựng TRƯỚC khi rev cũ bị hạ.
//
// Nếu driver stop-trước-start thì maxSeen sẽ là 1 và minRunning sẽ là 0.
func TestAdvRollingNewBeforeOld(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx := tadvCtx(t)

	spec := testSpec(t)
	spec.Desired.Env = map[string]string{"DEPLOY_MARK": "r1"}
	cleanupApp(t, d, spec.ID)

	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}

	var (
		mu         sync.Mutex
		maxSeen    int
		minRunning = 1 << 30
		revsSeen   = map[string]bool{}
		samples    int
	)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				res, err := cli.ContainerList(context.Background(), client.ContainerListOptions{
					All:     true,
					Filters: make(client.Filters).Add("label", labelAppID+"="+spec.ID),
				})
				if err != nil {
					continue
				}
				mu.Lock()
				samples++
				if n := len(res.Items); n > maxSeen {
					maxSeen = n
				}
				if n := tadvRunningCount(res.Items); n < minRunning {
					minRunning = n
				}
				for _, c := range res.Items {
					revsSeen[c.Labels[labelRev]] = true
				}
				mu.Unlock()
			}
		}
	}()

	spec2 := spec
	spec2.DesiredRev = 2
	spec2.Desired.Env = map[string]string{"DEPLOY_MARK": "r2"}
	obs2, err := d.Apply(ctx, spec2)
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatalf("Apply rev2: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	t.Logf("quan sát %d mẫu: maxContainer=%d minRunning=%d revs=%v", samples, maxSeen, minRunning, revsSeen)
	if samples < 3 {
		t.Fatalf("chỉ lấy được %d mẫu — quá ít để kết luận (Apply quá nhanh?)", samples)
	}
	if minRunning < 1 {
		t.Errorf("có thời điểm 0 container Running — DOWNTIME, vi phạm rolling (§2.3 bước 7)")
	}
	if maxSeen < 2 {
		t.Errorf("không bao giờ thấy 2 container cùng lúc (max=%d) — rev cũ có thể đã bị hạ TRƯỚC khi rev mới chạy (§2.3 bước 6–7)", maxSeen)
	}
	if !revsSeen["1"] || !revsSeen["2"] {
		t.Errorf("không quan sát đủ cả 2 rev (thấy %v) — không chứng minh được new-trước-old", revsSeen)
	}

	// Kết thúc: đúng 1 container, đúng rev 2.
	items := listByLabel(t, cli, spec.ID)
	if len(items) != 1 {
		t.Fatalf("sau rolling có %d container, muốn đúng 1 (rev cũ phải được dọn)", len(items))
	}
	if got := items[0].Labels[labelRev]; got != "2" {
		t.Errorf("container còn lại có rev %q, muốn \"2\"", got)
	}
	if items[0].ID != obs2.ContainerIDs[0] {
		t.Errorf("container còn lại %s ≠ ID Apply trả về %s", items[0].ID, obs2.ContainerIDs[0])
	}
}

// TestAdvApplyThriceNoContainerGrowth — RT-02 fast-path, bản đối kháng.
// Apply 3 lần liên tiếp cùng spec (replicas=2): sau MỖI lần, số container theo
// label phải đúng bằng replicas và ContainerIDs phải y hệt nhau.
// Bắt lỗi kiểu "mỗi lần Apply lại tạo thêm 1 container" mà test 2-lần bỏ sót.
func TestAdvApplyThriceNoContainerGrowth(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx := tadvCtx(t)

	const replicas = 2
	spec := testSpec(t)
	spec.Desired.Resources = &contracts.Resources{Replicas: replicas}
	cleanupApp(t, d, spec.ID)

	var first []string
	for i := 1; i <= 3; i++ {
		obs, err := d.Apply(ctx, spec)
		if err != nil {
			t.Fatalf("Apply lần %d: %v", i, err)
		}
		if obs.Phase != contracts.AppStateRunning {
			t.Fatalf("Apply lần %d phase = %q, muốn running", i, obs.Phase)
		}
		if len(obs.ContainerIDs) != replicas {
			t.Fatalf("Apply lần %d trả %d ID, muốn %d", i, len(obs.ContainerIDs), replicas)
		}

		items := listByLabel(t, cli, spec.ID)
		if len(items) != replicas {
			t.Fatalf("sau Apply lần %d có %d container theo label, MUỐN đúng %d — Apply sinh sôi tài nguyên",
				i, len(items), replicas)
		}
		if n := tadvRunningCount(items); n != replicas {
			t.Errorf("sau Apply lần %d chỉ %d/%d container Running", i, n, replicas)
		}
		// Mỗi idx đúng 1 container, label rev đúng.
		byIdx := map[string]int{}
		for _, c := range items {
			byIdx[c.Labels[labelReplica]]++
			if got := c.Labels[labelRev]; got != strconv.FormatInt(spec.DesiredRev, 10) {
				t.Errorf("lần %d: container %s có rev %q, muốn %d", i, displayName(c), got, spec.DesiredRev)
			}
		}
		for idx := 0; idx < replicas; idx++ {
			if n := byIdx[strconv.Itoa(idx)]; n != 1 {
				t.Errorf("lần %d: replica idx %d có %d container, muốn 1", i, idx, n)
			}
		}

		if i == 1 {
			first = append([]string(nil), obs.ContainerIDs...)
			continue
		}
		for k := range first {
			if obs.ContainerIDs[k] != first[k] {
				t.Errorf("Apply lần %d tạo container MỚI ở idx %d: %s ≠ %s (fast-path RT-02 hỏng)",
					i, k, obs.ContainerIDs[k], first[k])
			}
		}
	}
}

// TestAdvRemoveStatusRemove — RT-06 đối kháng: sau Remove, Status phải là
// stopped + 0 ID; Remove lần 2 (và lần 3) phải trả nil; Remove app CHƯA TỪNG
// tồn tại cũng phải nil (idempotent hoàn toàn).
func TestAdvRemoveStatusRemove(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx := tadvCtx(t)

	spec := testSpec(t)
	spec.Desired.Resources = &contracts.Resources{Replicas: 2}
	cleanupApp(t, d, spec.ID)

	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if items := listByLabel(t, cli, spec.ID); len(items) != 2 {
		t.Fatalf("trước Remove có %d container, muốn 2", len(items))
	}

	if err := d.Remove(ctx, spec.ID); err != nil {
		t.Fatalf("Remove #1: %v", err)
	}
	if items := listByLabel(t, cli, spec.ID); len(items) != 0 {
		t.Errorf("sau Remove còn %d container theo label, muốn 0", len(items))
	}

	st, err := d.Status(ctx, spec.ID)
	if err != nil {
		t.Fatalf("Status sau Remove: %v", err)
	}
	if st.Phase != contracts.AppStateStopped {
		t.Errorf("Status.Phase sau Remove = %q, muốn %q", st.Phase, contracts.AppStateStopped)
	}
	if len(st.ContainerIDs) != 0 {
		t.Errorf("Status.ContainerIDs sau Remove = %v, muốn rỗng", st.ContainerIDs)
	}

	for i := 2; i <= 3; i++ {
		if err := d.Remove(ctx, spec.ID); err != nil {
			t.Errorf("Remove #%d (idempotent) = %v, muốn nil", i, err)
		}
	}
	if err := d.Remove(ctx, "whoami-app-chua-bao-gio-ton-tai"); err != nil {
		t.Errorf("Remove app không tồn tại = %v, muốn nil", err)
	}

	// Network dùng chung KHÔNG được xoá theo.
	res, err := cli.NetworkList(ctx, client.NetworkListOptions{
		Filters: make(client.Filters).Add("name", networkName),
	})
	if err != nil {
		t.Fatalf("NetworkList: %v", err)
	}
	found := false
	for _, n := range res.Items {
		if n.Name == networkName {
			found = true
		}
	}
	if !found {
		t.Errorf("network %s biến mất sau Remove — Remove không được xoá network dùng chung", networkName)
	}
}
