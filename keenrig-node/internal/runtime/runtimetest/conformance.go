// Package runtimetest — conformance suite cho runtime.Runtime (kiểu drivertest).
// Driver nào cũng phải pass RunConformance (docker hôm nay, swarm/k8s sau).
package runtimetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

// TestImage — image nhỏ, không HEALTHCHECK (health phải là "unknown").
const TestImage = "traefik/whoami:v1.10"

// Harness cấp driver cho suite. KillReplica (tuỳ chọn) kill 1 replica của app
// bằng đường ngoài driver (client thô) — nil thì skip StatusAfterKill.
type Harness struct {
	Factory     func(t *testing.T) runtime.Runtime
	KillReplica func(t *testing.T, appID string)
}

// RunConformance chạy toàn bộ RT-01..RT-08 (trừ RT-07 resource limits —
// cần inspect driver-specific nên nằm ở test của driver).
func RunConformance(t *testing.T, h Harness) {
	t.Run("ApplyRunsContainer", func(t *testing.T) { testApplyRunsContainer(t, h) })
	t.Run("ApplyIdempotent", func(t *testing.T) { testApplyIdempotent(t, h) })
	t.Run("RollingByRev", func(t *testing.T) { testRollingByRev(t, h) })
	t.Run("Replicas", func(t *testing.T) { testReplicas(t, h) })
	t.Run("StatusAfterKill", func(t *testing.T) { testStatusAfterKill(t, h) })
	t.Run("RemoveIdempotent", func(t *testing.T) { testRemoveIdempotent(t, h) })
	t.Run("ConvergeAfterCancel", func(t *testing.T) { testConvergeAfterCancel(t, h) })
	RunEndpointConformance(t, h) // T6c
}

// randomSpec sinh app id/slug ngẫu nhiên whoami-<hex8> (tránh đụng app cũ sót).
func randomSpec(t *testing.T) runtime.AppSpec {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	id := "whoami-" + hex.EncodeToString(b)
	return runtime.AppSpec{
		ID:         id,
		Slug:       id,
		DesiredRev: 1,
		Desired:    contracts.DesiredApp{Image: TestImage},
	}
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func cleanupApp(t *testing.T, rt runtime.Runtime, appID string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		if err := rt.Remove(ctx, appID); err != nil {
			t.Errorf("cleanup Remove(%s): %v", appID, err)
		}
	})
}

func waitFor(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout %s đợi: %s", timeout, desc)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func disjoint(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return false
		}
	}
	return true
}

// RT-01: Apply chạy container thật, Status thấy running.
func testApplyRunsContainer(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	cleanupApp(t, rt, spec.ID)

	obs, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if obs.Phase != contracts.AppStateRunning || len(obs.ContainerIDs) != 1 {
		t.Fatalf("Apply = %+v, muốn running + 1 container", obs)
	}
	if obs.Health != contracts.HealthUnknown {
		t.Errorf("Health = %q, muốn unknown (image không có HEALTHCHECK)", obs.Health)
	}

	st, err := rt.Status(ctx, spec.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Phase != contracts.AppStateRunning || len(st.ContainerIDs) != 1 {
		t.Errorf("Status = %+v, muốn running + 1 container", st)
	}
}

// RT-02: Apply lần 2 cùng spec là no-op — cùng đúng những ContainerIDs cũ.
func testApplyIdempotent(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	cleanupApp(t, rt, spec.ID)

	obs1, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply #1: %v", err)
	}
	obs2, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply #2: %v", err)
	}
	if !sameIDs(obs1.ContainerIDs, obs2.ContainerIDs) {
		t.Errorf("Apply idempotent: IDs #1 %v ≠ #2 %v", obs1.ContainerIDs, obs2.ContainerIDs)
	}
	if obs2.Phase != contracts.AppStateRunning {
		t.Errorf("Apply #2 phase = %q, muốn running", obs2.Phase)
	}
}

// RT-03: đổi env → rev 2. Rolling new-trước-old: trong suốt quá trình Status
// không bao giờ thấy 0 container hay phase stopped; IDs mới ≠ cũ.
func testRollingByRev(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	spec.Desired.Env = map[string]string{"DEPLOY_MARK": "r1"}
	cleanupApp(t, rt, spec.ID)

	obs1, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}

	var (
		mu         sync.Mutex
		violations []string
	)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				st, err := rt.Status(context.Background(), spec.ID)
				if err != nil {
					continue // lỗi thoáng qua khi container đang bị dọn — không phải downtime
				}
				if st.Phase == contracts.AppStateStopped || len(st.ContainerIDs) == 0 {
					mu.Lock()
					violations = append(violations,
						"phase="+st.Phase+" containers="+strings.Join(st.ContainerIDs, ","))
					mu.Unlock()
				}
			}
		}
	}()

	spec2 := spec
	spec2.DesiredRev = 2
	spec2.Desired.Env = map[string]string{"DEPLOY_MARK": "r2"}
	obs2, err := rt.Apply(ctx, spec2)
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatalf("Apply rev2: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(violations) > 0 {
		t.Errorf("có downtime trong lúc rolling: %v", violations)
	}
	if obs2.Phase != contracts.AppStateRunning || len(obs2.ContainerIDs) != 1 {
		t.Fatalf("Apply rev2 = %+v, muốn running + 1 container", obs2)
	}
	if !disjoint(obs1.ContainerIDs, obs2.ContainerIDs) {
		t.Errorf("rev2 phải là container MỚI: cũ %v, mới %v", obs1.ContainerIDs, obs2.ContainerIDs)
	}

	st, err := rt.Status(ctx, spec.ID)
	if err != nil || len(st.ContainerIDs) != 1 {
		t.Errorf("sau rolling Status = (%+v, %v), muốn đúng 1 container (rev cũ đã dọn)", st, err)
	}
}

// RT-04: replicas 2 → scale xuống 1 (replica idx thừa phải bị dọn).
func testReplicas(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	spec.Desired.Resources = &contracts.Resources{Replicas: 2}
	cleanupApp(t, rt, spec.ID)

	obs, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply replicas=2: %v", err)
	}
	if len(obs.ContainerIDs) != 2 || obs.ContainerIDs[0] == obs.ContainerIDs[1] {
		t.Fatalf("Apply replicas=2 IDs = %v, muốn 2 container khác nhau", obs.ContainerIDs)
	}

	spec1 := spec
	spec1.Desired.Resources = &contracts.Resources{Replicas: 1}
	obs1, err := rt.Apply(ctx, spec1)
	if err != nil {
		t.Fatalf("Apply replicas=1: %v", err)
	}
	if len(obs1.ContainerIDs) != 1 {
		t.Fatalf("Apply replicas=1 IDs = %v, muốn đúng 1", obs1.ContainerIDs)
	}
	if obs1.ContainerIDs[0] != obs.ContainerIDs[0] {
		t.Errorf("scale down phải giữ replica 0: muốn %s, nhận %s", obs.ContainerIDs[0], obs1.ContainerIDs[0])
	}

	st, err := rt.Status(ctx, spec.ID)
	if err != nil || len(st.ContainerIDs) != 1 {
		t.Errorf("Status sau scale down = (%+v, %v), muốn 1 container", st, err)
	}
}

// RT-05: kill 1 replica ngoài driver → Status phải báo error kèm exit.
func testStatusAfterKill(t *testing.T, h Harness) {
	if h.KillReplica == nil {
		t.Skip("Harness không có KillReplica")
	}
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	cleanupApp(t, rt, spec.ID)

	if _, err := rt.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	h.KillReplica(t, spec.ID)

	var last runtime.Observed
	waitFor(t, 15*time.Second, "Status báo phase error sau kill", func() bool {
		st, err := rt.Status(ctx, spec.ID)
		if err != nil {
			return false
		}
		last = st
		return st.Phase == contracts.AppStateError
	})
	if !strings.Contains(strings.ToLower(last.Message), "exit") {
		t.Errorf("message = %q, muốn nhắc tới exit (kèm code)", last.Message)
	}
}

// RT-06: Remove sạch và idempotent.
func testRemoveIdempotent(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	cleanupApp(t, rt, spec.ID)

	if _, err := rt.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := rt.Remove(ctx, spec.ID); err != nil {
		t.Fatalf("Remove #1: %v", err)
	}
	st, err := rt.Status(ctx, spec.ID)
	if err != nil {
		t.Fatalf("Status sau remove: %v", err)
	}
	if st.Phase != contracts.AppStateStopped || len(st.ContainerIDs) != 0 {
		t.Errorf("Status sau remove = %+v, muốn stopped + 0 container", st)
	}
	if err := rt.Remove(ctx, spec.ID); err != nil {
		t.Errorf("Remove #2 (idempotent): %v", err)
	}
}

// RT-08: Apply bị cắt ctx giữa chừng → Apply lại phải hội tụ đúng 2 replica,
// không nhân đôi tài nguyên.
func testConvergeAfterCancel(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	spec.Desired.Resources = &contracts.Resources{Replicas: 2}
	cleanupApp(t, rt, spec.ID)

	shortCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	_, _ = rt.Apply(shortCtx, spec) // có thể lỗi vì ctx — chấp nhận mọi kết quả
	cancel()

	obs, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply lại sau cancel: %v", err)
	}
	if obs.Phase != contracts.AppStateRunning || len(obs.ContainerIDs) != 2 {
		t.Fatalf("Apply lại = %+v, muốn running + đúng 2 container", obs)
	}
	if obs.ContainerIDs[0] == obs.ContainerIDs[1] {
		t.Errorf("2 replica trùng ID: %v", obs.ContainerIDs)
	}

	st, err := rt.Status(ctx, spec.ID)
	if err != nil || len(st.ContainerIDs) != 2 {
		t.Errorf("Status = (%+v, %v), muốn đúng 2 container (không nhân đôi)", st, err)
	}
}
