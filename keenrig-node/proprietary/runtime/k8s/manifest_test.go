package k8s

// Test phần KIỂM CHỨNG ĐƯỢC của driver k8s: dịch AppSpec → manifest và đọc
// trạng thái pod. Phần nói chuyện với API server nằm ở k8s_conformance_test.go
// và chỉ chạy khi có cluster thật.

import (
	"encoding/json"
	"strings"
	"testing"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

func spec(id, slug string, rev int64) runtime.AppSpec {
	return runtime.AppSpec{
		ID: id, Slug: slug, DesiredRev: rev,
		Desired: contracts.DesiredApp{Image: "traefik/whoami:v1.10"},
	}
}

func TestDeploymentShape(t *testing.T) {
	s := spec("app-1", "hello", 3)
	s.Desired.Env = map[string]string{"B": "2", "A": "1"}
	s.Desired.Resources = &contracts.Resources{Replicas: 2, MemoryMB: 512, CPU: 0.5}
	s.Desired.HTTPPort = 8080

	dep := buildDeployment(s, "keenrig")

	if dep.APIVersion != "apps/v1" || dep.Kind != "Deployment" {
		t.Errorf("apiVersion/kind = %s/%s", dep.APIVersion, dep.Kind)
	}
	if dep.Spec.Replicas != 2 {
		t.Errorf("replicas = %d", dep.Spec.Replicas)
	}
	if dep.Metadata.Labels[labelAppID] != "app-1" || dep.Metadata.Labels[labelRev] != "3" {
		t.Errorf("labels = %v", dep.Metadata.Labels)
	}

	// SELECTOR không được chứa rev: selector của Deployment là BẤT BIẾN, nhét
	// rev vào nghĩa là lần deploy thứ hai phải xoá và tạo lại → downtime.
	if _, has := dep.Spec.Selector.MatchLabels[labelRev]; has {
		t.Error("selector chứa rev — Deployment sẽ không update được tại chỗ")
	}
	if dep.Spec.Selector.MatchLabels[labelAppID] != "app-1" {
		t.Errorf("selector = %v", dep.Spec.Selector.MatchLabels)
	}

	// Rolling phải là new-trước-old để khớp hợp đồng RT-03 của driver docker.
	if dep.Spec.Strategy == nil || dep.Spec.Strategy.RollingUpdate == nil {
		t.Fatal("thiếu strategy rolling")
	}
	if dep.Spec.Strategy.RollingUpdate.MaxUnavailable != 0 {
		t.Errorf("maxUnavailable = %d, muốn 0 (không downtime)", dep.Spec.Strategy.RollingUpdate.MaxUnavailable)
	}

	// Annotation rev trên POD TEMPLATE: thiếu nó thì đổi env mà giữ nguyên image
	// sẽ không kích hoạt rolling, và app chạy mãi cấu hình cũ.
	if dep.Spec.Template.Metadata.Annotations["keenrig.com/rev"] != "3" {
		t.Errorf("annotation rev = %v", dep.Spec.Template.Metadata.Annotations)
	}

	c := dep.Spec.Template.Spec.Containers[0]
	if c.Image != "traefik/whoami:v1.10" {
		t.Errorf("image = %q", c.Image)
	}
	if len(c.Ports) != 1 || c.Ports[0].ContainerPort != 8080 {
		t.Errorf("ports = %+v", c.Ports)
	}
	// Env phải SẮP XẾP: thứ tự map trong Go ngẫu nhiên, và PUT lại một manifest
	// khác thứ tự sẽ tạo diff giả mỗi lần Apply.
	if len(c.Env) != 2 || c.Env[0].Name != "A" || c.Env[1].Name != "B" {
		t.Errorf("env không sắp xếp: %+v", c.Env)
	}
	if c.Resources == nil || c.Resources.Limits["memory"] != "512Mi" || c.Resources.Limits["cpu"] != "500m" {
		t.Errorf("resources = %+v", c.Resources)
	}

	// Manifest phải serialise được và không rơi trường bắt buộc.
	raw, err := json.Marshal(dep)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"apiVersion":"apps/v1"`, `"selector"`, `"template"`, `"containers"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON thiếu %s: %s", want, raw)
		}
	}
}

// Tên tài nguyên phải hợp lệ DNS-1123 và ≤63 ký tự, kể cả với slug dài nhất mà
// apps.MaxSlugLen cho phép.
func TestResourceNameFitsDNS1123(t *testing.T) {
	long := strings.Repeat("a", 40) // apps.MaxSlugLen
	for _, tc := range []struct{ id, slug string }{
		{"app-1", "hello"},
		{"app-2", long},
		{"app-3", "a"},
	} {
		n := resourceName(tc.id, tc.slug)
		if len(n) > 63 {
			t.Errorf("tên %q dài %d ký tự, tối đa 63", n, len(n))
		}
		for i := 0; i < len(n); i++ {
			c := n[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				t.Errorf("tên %q chứa ký tự không hợp lệ %q", n, string(c))
			}
		}
		if n[0] == '-' || n[len(n)-1] == '-' {
			t.Errorf("tên %q bắt đầu/kết thúc bằng dấu gạch", n)
		}
	}
	// Hai app khác id nhưng TRÙNG slug phải cho hai tên khác nhau — cùng bài
	// học BUG-1 của driver docker.
	if resourceName("app-a", "web") == resourceName("app-b", "web") {
		t.Error("hai app trùng slug cho cùng tên tài nguyên")
	}
}

func TestServiceShape(t *testing.T) {
	s := spec("app-1", "hello", 1)
	s.Desired.HTTPPort = 3000
	svc := buildService(s, "keenrig")

	if svc.Spec.Type != "ClusterIP" {
		t.Errorf("type = %q", svc.Spec.Type)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 3000 || svc.Spec.Ports[0].TargetPort != 3000 {
		t.Errorf("ports = %+v", svc.Spec.Ports)
	}
	if _, has := svc.Spec.Selector[labelRev]; has {
		t.Error("selector của Service chứa rev — trong lúc rolling nó sẽ mất hết endpoint")
	}
	if svc.Metadata.Name != resourceName("app-1", "hello") {
		t.Errorf("Service phải cùng tên Deployment để Remove tìm được: %q", svc.Metadata.Name)
	}
}

func TestPortFallback(t *testing.T) {
	if got := portOf(spec("a", "b", 1)); got != contracts.DefaultHTTPPort {
		t.Errorf("cổng mặc định = %d, muốn %d", got, contracts.DefaultHTTPPort)
	}
	s := spec("a", "b", 1)
	s.Desired.HTTPPort = 9999
	if got := portOf(s); got != 9999 {
		t.Errorf("http_port tường minh bị bỏ qua: %d", got)
	}
}

// podReady: Phase=Running CHƯA đủ — readiness probe mới nói app phục vụ được.
func TestPodReady(t *testing.T) {
	running := func(cond ...podCondition) pod {
		return pod{Status: podStatus{Phase: "Running", Conditions: cond}}
	}
	cases := []struct {
		name string
		p    pod
		want bool
	}{
		{"Ready=True", running(podCondition{Type: "Ready", Status: "True"}), true},
		{"Ready=False", running(podCondition{Type: "Ready", Status: "False"}), false},
		{"chưa có condition", running(), false},
		{"Pending", pod{Status: podStatus{Phase: "Pending"}}, false},
		{"Succeeded", pod{Status: podStatus{Phase: "Succeeded"}}, false},
	}
	for _, c := range cases {
		if got := podReady(c.p); got != c.want {
			t.Errorf("%s: podReady = %v, muốn %v", c.name, got, c.want)
		}
	}
}

// terminalFailure phải phân biệt lỗi TỰ KHỎI với lỗi không tự khỏi — chờ hết
// 3 phút rồi báo "timeout" là giấu mất nguyên nhân thật.
func TestTerminalFailure(t *testing.T) {
	waiting := func(reason string) pod {
		p := pod{Status: podStatus{Phase: "Pending"}}
		var cs containerStatus
		cs.State.Waiting = &struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}{Reason: reason}
		p.Status.ContainerStatuses = []containerStatus{cs}
		return p
	}

	for _, r := range []string{"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CrashLoopBackOff", "CreateContainerConfigError"} {
		if terminalFailure(waiting(r)) == "" {
			t.Errorf("%s phải là lỗi hỏng hẳn", r)
		}
	}
	// Những cái này TỰ KHỎI — báo lỗi ở đây sẽ làm mọi lần deploy đều hỏng.
	for _, r := range []string{"ContainerCreating", "PodInitializing", ""} {
		if got := terminalFailure(waiting(r)); got != "" {
			t.Errorf("%s bị coi là hỏng hẳn: %q", r, got)
		}
	}
	if terminalFailure(pod{Status: podStatus{Phase: "Failed"}}) == "" {
		t.Error("Phase=Failed phải là hỏng")
	}
	if terminalFailure(pod{Status: podStatus{Phase: "Running"}}) != "" {
		t.Error("pod Running bị coi là hỏng")
	}
}

// Hội tụ = đúng số lượng VÀ tất cả ở rev mới (bài học từ conformance swarm thật).
func TestAllAtRev(t *testing.T) {
	mk := func(rev string) pod {
		return pod{Metadata: objectMeta{Labels: map[string]string{labelRev: rev}}}
	}
	if !allAtRev([]pod{mk("2"), mk("2")}, "2") {
		t.Error("cùng rev mà báo chưa hội tụ")
	}
	if allAtRev([]pod{mk("1"), mk("2")}, "2") {
		t.Error("còn pod rev cũ mà đã báo hội tụ")
	}
	if allAtRev([]pod{mk("")}, "2") {
		t.Error("pod không có label rev mà đã báo hội tụ")
	}
}

// readyPods KHÔNG lọc theo rev: pod rev cũ vẫn đang phục vụ, bỏ chúng ra khỏi
// Observed sẽ khiến reconciler gỡ sạch upstream giữa lúc rolling.
func TestReadyPodsKeepsOldRevServing(t *testing.T) {
	mk := func(rev, ip string) pod {
		return pod{
			Metadata: objectMeta{Name: "p" + rev + ip, Labels: map[string]string{labelRev: rev}},
			Status: podStatus{
				Phase: "Running", PodIP: ip,
				Conditions: []podCondition{{Type: "Ready", Status: "True"}},
			},
		}
	}
	ready, err := readyPods([]pod{mk("1", "10.0.0.1"), mk("2", "10.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 2 {
		t.Fatalf("readyPods = %d, muốn 2 (cả rev cũ lẫn mới đều đang phục vụ)", len(ready))
	}
}
