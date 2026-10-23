package docker

// Regression BUG-1 (vòng 2b): danh tính container = LABEL keenrig.com.id, KHÔNG
// phải tên. Trước khi sửa, ensureReplica/createStart Inspect-theo-tên rồi adopt
// luôn → Apply(B) trả về container của app khác.
// Dùng lại helper trong docker_test.go: newDriver, rawClient, testSpec, listByLabel.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// createForeign tạo container thô mang tên name và label app.id = ownerID
// (ownerID rỗng → không gắn label app.id, mô phỏng container lạ của người dùng).
func createForeign(t *testing.T, cli *client.Client, name, ownerID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	labels := map[string]string{labelManaged: "true"}
	if ownerID != "" {
		labels[labelAppID] = ownerID
	}
	res, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:   name,
		Config: &container.Config{Image: testImage, Labels: labels},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{networkName: {}},
		},
	})
	if err != nil {
		t.Fatalf("tạo container ngoại lai %s: %v", name, err)
	}
	if _, err := cli.ContainerStart(ctx, res.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start container ngoại lai %s: %v", name, err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		sec := 5
		cli.ContainerStop(c, res.ID, client.ContainerStopOptions{Timeout: &sec})
		cli.ContainerRemove(c, res.ID, client.ContainerRemoveOptions{Force: true})
	})
	return res.ID
}

// mustStillExist khẳng định container id vẫn còn (driver KHÔNG được xoá tài
// nguyên của app khác).
func mustStillExist(t *testing.T, cli *client.Client, id, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{}); err != nil {
		t.Errorf("%s (%s) đã biến mất — driver KHÔNG được xoá container của app khác: %v",
			what, id[:12], err)
	}
}

// TestContainerNameCarriesAppID (không cần Docker) — 2 app KHÁC app.id trùng
// slug + trùng rev + trùng idx PHẢI ra 2 tên khác nhau, nếu không app thứ hai
// vĩnh viễn không deploy được (tên đã bị app kia chiếm). Tên cũng phải ổn định
// giữa các lần gọi (ensure theo tên là idempotent).
func TestContainerNameCarriesAppID(t *testing.T) {
	a := containerName("app-a", "shop", 0, 1)
	b := containerName("app-b", "shop", 0, 1)
	if a == b {
		t.Errorf("2 app khác nhau cùng slug/rev/idx ra CÙNG tên %q — sẽ tranh nhau container", a)
	}
	if again := containerName("app-a", "shop", 0, 1); again != a {
		t.Errorf("containerName không ổn định: %q rồi %q", a, again)
	}
	if !strings.HasPrefix(a, "su-shop-") || !strings.HasSuffix(a, "-0-r1") {
		t.Errorf("tên %q không theo format su-<slug>-<appIDShort>-<idx>-r<rev>", a)
	}
	// rev/idx vẫn phải nằm trong tên (RT-03: 2 rev đồng tồn tại lúc rolling).
	if containerName("app-a", "shop", 0, 2) == a || containerName("app-a", "shop", 1, 1) == a {
		t.Error("tên không phân biệt được rev hoặc idx")
	}
}

// TestApplyRejectsForeignContainerName — tên container bị app KHÁC chiếm
// (label keenrig.com.id lệch) → Apply phải trả LỖI, không adopt, không xoá.
func TestApplyRejectsForeignContainerName(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	spec := testSpec(t)
	const foreignID = "app-khac"
	name := containerName(spec.ID, spec.Slug, 0, spec.DesiredRev) // su-<slug>-<appIDShort>-0-r1
	foreignCID := createForeign(t, cli, name, foreignID)

	obs, err := d.Apply(ctx, spec)
	if err == nil {
		t.Fatalf("Apply với tên bị app khác chiếm: muốn LỖI, nhận nil (obs=%+v)", obs)
	}
	if !strings.Contains(err.Error(), foreignID) {
		t.Errorf("lỗi %q nên nêu rõ app.id chiếm tên (%s)", err, foreignID)
	}

	// Bất biến: KHÔNG trả về container mang label app.id khác spec.ID.
	for _, id := range obs.ContainerIDs {
		if id == foreignCID {
			t.Errorf("Apply trả về container của %s (%s) — vi phạm bất biến danh tính",
				foreignID, id[:12])
		}
	}
	// Không được đụng vào tài nguyên của app khác.
	mustStillExist(t, cli, foreignCID, "container của app-khac")
	if items := listByLabel(t, cli, foreignID); len(items) != 1 {
		t.Errorf("container mang label app.id=%s = %d, muốn giữ nguyên 1", foreignID, len(items))
	}
	// Và spec.ID không sở hữu gì cả.
	if items := listByLabel(t, cli, spec.ID); len(items) != 0 {
		t.Errorf("Apply lỗi nhưng vẫn tạo %d container cho %s", len(items), spec.ID)
	}
}

// TestApplyRejectsUnlabeledContainerName — container lạ (không có label app.id)
// trùng tên → cũng phải lỗi, không adopt, không xoá.
func TestApplyRejectsUnlabeledContainerName(t *testing.T) {
	d := newDriver(t)
	cli := rawClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	spec := testSpec(t)
	name := containerName(spec.ID, spec.Slug, 0, spec.DesiredRev)
	strayCID := createForeign(t, cli, name, "")

	obs, err := d.Apply(ctx, spec)
	if err == nil {
		t.Fatalf("Apply với tên bị container lạ chiếm: muốn LỖI, nhận nil (obs=%+v)", obs)
	}
	for _, id := range obs.ContainerIDs {
		if id == strayCID {
			t.Errorf("Apply adopt container lạ %s — vi phạm bất biến danh tính", id[:12])
		}
	}
	mustStillExist(t, cli, strayCID, "container lạ")
	t.Logf("OK — Apply từ chối tên bị chiếm: %v", err)
}
