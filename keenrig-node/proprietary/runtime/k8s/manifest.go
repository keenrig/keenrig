package k8s

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

// Kiểu manifest — chỉ khai những trường ta THẬT SỰ ghi hoặc đọc.
//
// Khai thiếu là an toàn cho phía ĐỌC (JSON bỏ qua trường thừa), nhưng nguy hiểm
// cho phía GHI: PUT một Deployment thiếu trường sẽ xoá trường đó khỏi cluster.
// Ta chỉ PUT thứ mình hoàn toàn sở hữu (Deployment do chính ta tạo, nhận diện
// bằng label app.id), nên rủi ro đó nằm trong tầm kiểm soát — nhưng đừng mở
// rộng PUT sang tài nguyên của người khác.

type objectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	DeletionTimestamp string            `json:"deletionTimestamp,omitempty"`
}

type deployment struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   objectMeta     `json:"metadata"`
	Spec       deploymentSpec `json:"spec"`
}

type deploymentList struct {
	Items []deployment `json:"items"`
}

type deploymentSpec struct {
	Replicas int             `json:"replicas"`
	Selector labelSelector   `json:"selector"`
	Template podTemplateSpec `json:"template"`
	Strategy *strategy       `json:"strategy,omitempty"`
}

type labelSelector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

type strategy struct {
	Type          string         `json:"type"`
	RollingUpdate *rollingUpdate `json:"rollingUpdate,omitempty"`
}

type rollingUpdate struct {
	MaxUnavailable int `json:"maxUnavailable"`
	MaxSurge       int `json:"maxSurge"`
}

type podTemplateSpec struct {
	Metadata objectMeta `json:"metadata"`
	Spec     podSpec    `json:"spec"`
}

type podSpec struct {
	Containers []k8sContainer `json:"containers"`
}

type k8sContainer struct {
	Name      string          `json:"name"`
	Image     string          `json:"image"`
	Env       []envVar        `json:"env,omitempty"`
	Ports     []containerPort `json:"ports,omitempty"`
	Resources *resourceReqs   `json:"resources,omitempty"`
}

type envVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type containerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
}

type resourceReqs struct {
	Limits map[string]string `json:"limits,omitempty"`
}

type service struct {
	APIVersion string      `json:"apiVersion"`
	Kind       string      `json:"kind"`
	Metadata   objectMeta  `json:"metadata"`
	Spec       serviceSpec `json:"spec"`
}

type serviceSpec struct {
	Selector map[string]string `json:"selector"`
	Ports    []servicePort     `json:"ports"`
	Type     string            `json:"type,omitempty"`
}

type servicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int    `json:"port"`
	TargetPort int    `json:"targetPort"`
	Protocol   string `json:"protocol,omitempty"`
}

type pod struct {
	Metadata objectMeta `json:"metadata"`
	Status   podStatus  `json:"status"`
}

type podList struct {
	Items []pod `json:"items"`
}

type podStatus struct {
	Phase             string            `json:"phase"`
	PodIP             string            `json:"podIP"`
	Conditions        []podCondition    `json:"conditions"`
	ContainerStatuses []containerStatus `json:"containerStatuses"`
}

type podCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type containerStatus struct {
	Name  string `json:"name"`
	Ready bool   `json:"ready"`
	State struct {
		Waiting *struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"waiting"`
		Terminated *struct {
			Reason   string `json:"reason"`
			ExitCode int    `json:"exitCode"`
		} `json:"terminated"`
	} `json:"state"`
}

// --- dịch AppSpec → manifest ------------------------------------------------------

// appIDShort — 8 hex đầu của SHA-256(app.id). Cùng lý do với hai driver kia.
func appIDShort(appID string) string {
	sum := sha256.Sum256([]byte(appID))
	return hex.EncodeToString(sum[:4])
}

// resourceName — tên Deployment/Service.
//
// Phải là DNS-1123 label: chữ thường, số, dấu gạch, ≤63 ký tự. slug đã được
// apps.NormalizeSlug siết về đúng tập ký tự đó, nhưng ta vẫn CẮT theo độ dài ở
// đây — một slug 40 ký tự cộng hậu tố sẽ vượt 63 và Kubernetes từ chối với một
// thông báo chẳng liên quan gì tới slug.
func resourceName(appID, slug string) string {
	const maxLen = 63
	suffix := "-" + appIDShort(appID)
	if len(slug)+len(suffix) > maxLen {
		slug = slug[:maxLen-len(suffix)]
	}
	return slug + suffix
}

func replicasOf(spec runtime.AppSpec) int {
	if spec.Desired.Resources == nil || spec.Desired.Resources.Replicas < 1 {
		return 1
	}
	return spec.Desired.Resources.Replicas
}

func portOf(spec runtime.AppSpec) int {
	if spec.Desired.HTTPPort > 0 {
		return spec.Desired.HTTPPort
	}
	return contracts.DefaultHTTPPort
}

func portFromLabels(labels map[string]string) int {
	n, err := strconv.Atoi(labels[labelPort])
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}

func labelsFor(spec runtime.AppSpec, port int) map[string]string {
	return map[string]string{
		labelManaged: "true",
		labelAppID:   spec.ID,
		labelAppSlug: spec.Slug,
		labelRev:     strconv.FormatInt(spec.DesiredRev, 10),
		labelPort:    strconv.Itoa(port),
	}
}

// selectorFor — nhãn dùng làm SELECTOR của Deployment.
//
// CHỈ app.id, KHÔNG có rev. Selector của Deployment là BẤT BIẾN sau khi tạo;
// nhét rev vào đây nghĩa là lần deploy thứ hai phải xoá và tạo lại Deployment —
// tức là downtime, đúng thứ rolling update sinh ra để tránh.
func selectorFor(spec runtime.AppSpec) map[string]string {
	return map[string]string{labelAppID: spec.ID}
}

func envVars(env map[string]string) []envVar {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys) // thứ tự ổn định → PUT lặp lại không tạo diff giả
	out := make([]envVar, 0, len(keys))
	for _, k := range keys {
		out = append(out, envVar{Name: k, Value: env[k]})
	}
	return out
}

func buildDeployment(spec runtime.AppSpec, namespace string) deployment {
	port := portOf(spec)
	labels := labelsFor(spec, port)
	name := resourceName(spec.ID, spec.Slug)

	res := resourcesOf(spec)

	return deployment{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Metadata: objectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: deploymentSpec{
			Replicas: replicasOf(spec),
			Selector: labelSelector{MatchLabels: selectorFor(spec)},
			Strategy: &strategy{
				Type: "RollingUpdate",
				// maxUnavailable 0: giữ đủ replica đang phục vụ trong suốt lần
				// cập nhật — cùng ngữ nghĩa "new-trước-old" của driver docker.
				RollingUpdate: &rollingUpdate{MaxUnavailable: 0, MaxSurge: 1},
			},
			Template: podTemplateSpec{
				Metadata: objectMeta{
					Labels: labels,
					// Rev vào ANNOTATION của pod template: đổi annotation làm
					// Kubernetes coi template là mới và khởi động rolling, kể
					// cả khi image không đổi (vd chỉ đổi env).
					Annotations: map[string]string{
						"keenrig.com/rev": strconv.FormatInt(spec.DesiredRev, 10),
					},
				},
				Spec: podSpec{
					Containers: []k8sContainer{{
						Name:      "app",
						Image:     spec.Desired.Image,
						Env:       envVars(spec.Desired.Env),
						Ports:     []containerPort{{Name: "http", ContainerPort: port, Protocol: "TCP"}},
						Resources: res,
					}},
				},
			},
		},
	}
}

// buildService — ClusterIP để app trong cluster gọi nhau bằng DNS ổn định.
//
// Gateway KHÔNG dùng Service này (nó nối thẳng PodIP — xem godoc package); nó
// tồn tại cho lưu lượng đông-tây giữa các app.
func buildService(spec runtime.AppSpec, namespace string) service {
	port := portOf(spec)
	return service{
		APIVersion: "v1",
		Kind:       "Service",
		Metadata: objectMeta{
			Name:      resourceName(spec.ID, spec.Slug),
			Namespace: namespace,
			Labels:    labelsFor(spec, port),
		},
		Spec: serviceSpec{
			Type:     "ClusterIP",
			Selector: selectorFor(spec),
			Ports:    []servicePort{{Name: "http", Port: port, TargetPort: port, Protocol: "TCP"}},
		},
	}
}

// --- đọc trạng thái pod ------------------------------------------------------------

// podReady — điều kiện Ready=True, không phải Phase=Running.
//
// Phase Running chỉ nói container đã start; readiness probe mới nói app đã
// phục vụ được. Đưa một pod Running-nhưng-chưa-Ready vào tập endpoint là gửi
// request tới một app còn đang khởi tạo.
func podReady(p pod) bool {
	if p.Status.Phase != "Running" {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == "Ready" {
			return c.Status == "True"
		}
	}
	// Không có condition Ready (pod vừa tạo) → chưa sẵn sàng.
	return false
}

// terminalFailure trả lý do pod hỏng theo kiểu KHÔNG tự khỏi ("" nếu không).
//
// Phân biệt với lỗi thoáng qua là điểm mấu chốt: ContainerCreating hay
// PodInitializing sẽ tự hết, còn ImagePullBackOff thì không — chờ hết 3 phút
// rồi báo "timeout" là giấu mất nguyên nhân thật.
func terminalFailure(p pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil {
			switch w.Reason {
			case "ImagePullBackOff", "ErrImagePull", "InvalidImageName",
				"CreateContainerConfigError", "CreateContainerError", "CrashLoopBackOff":
				msg := w.Reason
				if w.Message != "" {
					msg += ": " + w.Message
				}
				return msg
			}
		}
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 && t.Reason != "Completed" {
			return fmt.Sprintf("%s (exit %d)", t.Reason, t.ExitCode)
		}
	}
	if p.Status.Phase == "Failed" {
		return "pod Failed"
	}
	return ""
}
