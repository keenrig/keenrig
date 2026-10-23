package docker

// Test cần Docker daemon thật. dockerd không chạy → Skip (không Fail).
// Nên `docker pull traefik/whoami:v1.10` trước để đỡ chờ pull trong test.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime/runtimetest"
)

const testImage = runtimetest.TestImage

// newDriver — gate: Docker không chạy → t.Skip.
func newDriver(t *testing.T) *Driver {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := New(ctx)
	if err != nil {
		t.Skipf("Docker không khả dụng — skip: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// rawClient — client thô, độc lập driver, để thao tác/kiểm chứng từ ngoài.
func rawClient(t *testing.T) *client.Client {
	t.Helper()
	cli, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("raw client: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

func testSpec(t *testing.T) runtime.AppSpec {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	id := "whoami-" + hex.EncodeToString(b)
	return runtime.AppSpec{
		ID:         id,
		Slug:       id,
		DesiredRev: 1,
		Desired:    contracts.DesiredApp{Image: testImage},
	}
}

func cleanupApp(t *testing.T, d *Driver, appID string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		if err := d.Remove(ctx, appID); err != nil {
			t.Errorf("cleanup Remove(%s): %v", appID, err)
		}
	})
}

func listByLabel(t *testing.T, cli *client.Client, appID string) []container.Summary {
	t.Helper()
	res, err := cli.ContainerList(context.Background(), client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("label", labelAppID+"="+appID),
	})
	if err != nil {
		t.Fatalf("ContainerList theo label: %v", err)
	}
	return res.Items
}

func TestDockerConformance(t *testing.T) {
	newDriver(t) // gate skip sớm

	runtimetest.RunConformance(t, runtimetest.Harness{
		Factory: func(t *testing.T) runtime.Runtime { return newDriver(t) },
		KillReplica: func(t *testing.T, appID string) {
			t.Helper()
			cli := rawClient(t)
			items := listByLabel(t, cli, appID)
			if len(items) == 0 {
				t.Fatalf("KillReplica: không có container cho app %s", appID)
			}
			if _, err := cli.ContainerKill(context.Background(), items[0].ID, client.ContainerKillOptions{}); err != nil {
				t.Fatalf("KillReplica: %v", err)
			}
		},
	})
}

// RT-07: memory/cpu limit + restart policy phải vào HostConfig thật.
func TestResourceLimits(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	spec := testSpec(t)
	spec.Desired.Resources = &contracts.Resources{MemoryMB: 64, CPU: 0.5, Replicas: 1}
	cleanupApp(t, d, spec.ID)

	obs, err := d.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(obs.ContainerIDs) != 1 {
		t.Fatalf("muốn 1 container, nhận %v", obs.ContainerIDs)
	}

	ins, err := d.cli.ContainerInspect(ctx, obs.ContainerIDs[0], client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	hc := ins.Container.HostConfig
	if hc == nil {
		t.Fatal("HostConfig nil")
	}
	if hc.Memory != 64<<20 {
		t.Errorf("Memory = %d, muốn %d (64MB)", hc.Memory, int64(64)<<20)
	}
	if hc.NanoCPUs != 5e8 {
		t.Errorf("NanoCPUs = %d, muốn 5e8 (0.5 CPU)", hc.NanoCPUs)
	}
	if hc.RestartPolicy.Name != container.RestartPolicyUnlessStopped {
		t.Errorf("RestartPolicy = %q, muốn unless-stopped", hc.RestartPolicy.Name)
	}
}

// RT-08 deterministic: replica 0 đã được create (KHÔNG start) từ lần trước,
// replica 1 chưa có → Apply replicas=2 phải adopt + start + tạo bù, đúng 2.
func TestConvergeFromPartialState(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	spec := testSpec(t)
	spec.Desired.Resources = &contracts.Resources{Replicas: 2}
	cleanupApp(t, d, spec.ID)

	if err := d.ensureImage(ctx, testImage); err != nil {
		t.Fatalf("ensureImage: %v", err)
	}

	// Client thô tạo TRƯỚC replica 0 đủ labels nhưng không start — mô phỏng
	// Apply trước đó chết ngay sau ContainerCreate.
	cli := rawClient(t)
	name := containerName(spec.ID, spec.Slug, 0, spec.DesiredRev)
	if _, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image:  testImage,
			Labels: appLabels(spec, 0, contracts.DefaultHTTPPort),
		},
		HostConfig: &container.HostConfig{
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{networkName: {}},
		},
	}); err != nil {
		t.Fatalf("pre-create replica 0: %v", err)
	}

	obs, err := d.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if obs.Phase != contracts.AppStateRunning || len(obs.ContainerIDs) != 2 {
		t.Fatalf("Apply = %+v, muốn running + đúng 2 container", obs)
	}

	items := listByLabel(t, cli, spec.ID)
	if len(items) != 2 {
		t.Fatalf("tổng container theo label = %d, muốn đúng 2 (không nhân đôi)", len(items))
	}
	for _, c := range items {
		if c.State != container.StateRunning {
			t.Errorf("container %s state = %s, muốn running", displayName(c), c.State)
		}
	}
}

// RT-06 mở rộng: Remove dọn hết theo label nhưng network keenrig0 giữ nguyên.
func TestRemoveCleansByLabel(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	spec := testSpec(t)
	spec.Desired.Resources = &contracts.Resources{Replicas: 2}
	cleanupApp(t, d, spec.ID)

	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := d.Remove(ctx, spec.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	cli := rawClient(t)
	if items := listByLabel(t, cli, spec.ID); len(items) != 0 {
		t.Errorf("sau Remove còn %d container theo label, muốn 0", len(items))
	}

	nets, err := cli.NetworkList(ctx, client.NetworkListOptions{
		Filters: make(client.Filters).Add("name", networkName),
	})
	if err != nil {
		t.Fatalf("NetworkList: %v", err)
	}
	found := false
	for _, n := range nets.Items {
		if n.Name == networkName {
			found = true
		}
	}
	if !found {
		t.Errorf("network %s phải còn sau Remove", networkName)
	}
}
