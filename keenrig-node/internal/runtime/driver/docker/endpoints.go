package docker

import (
	"context"
	"strconv"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

// Sinh runtime.Endpoint cho T6c.
//
// # Vì sao IP nội bộ chứ không phải cổng publish ra host
//
// Container của app KHÔNG publish cổng ra host: gateway đứng cùng máy và nối
// thẳng vào IP trên network keenrig0. Publish ra host sẽ mở app ra ngoài vòng
// kiểm soát của gateway (bỏ qua TLS, WAF, rate limit) và làm hai app không thể
// cùng dùng cổng 8080. Vì vậy endpoint luôn là <ip-keenrig0>:<cổng-trong-container>.
//
// # Vì sao cổng nằm trên LABEL của container
//
// Status(ctx, appID) không nhận AppSpec — nó chỉ có app.id. Nếu cổng chỉ suy
// được từ desired thì Apply và Status sẽ cho hai kết quả khác nhau cho cùng một
// container, và cái sai sẽ là cái nào chạy sau. Đóng cổng đã giải vào label lúc
// tạo container thì mọi đường đọc về sau đều đọc CÙNG một sự thật — đúng
// nguyên tắc "danh tính là label" đã trả giá ở BUG-1 vòng 2.
//
// Thứ tự giải cổng, một lần duy nhất lúc Apply:
//
//  1. desired.http_port — nguồn tường minh (người dùng, hoặc httpPort của manifest).
//  2. EXPOSE của IMAGE — image đã nói rồi thì đừng bắt người dùng khai lại.
//     Chọn cổng TCP NHỎ NHẤT cho tất định: map trong Go duyệt ngẫu nhiên, lấy
//     "cổng đầu tiên" sẽ cho endpoint đổi giữa hai lần Apply mà chẳng có gì đổi.
//  3. contracts.DefaultHTTPPort.

// resolvePort giải cổng cho một app. Gọi MỘT lần mỗi Apply, trước khi tạo
// container, để giá trị được đóng vào label.
//
// ImageInspect lỗi không phải lỗi Apply: cùng lắm ta mất bước suy từ EXPOSE và
// rơi về mặc định. Chặn cả lần deploy chỉ vì không đọc được metadata image là
// đổi một bất tiện nhỏ lấy một sự cố lớn.
func (d *Driver) resolvePort(ctx context.Context, spec runtime.AppSpec) int {
	if spec.Desired.HTTPPort > 0 {
		return spec.Desired.HTTPPort
	}
	ins, err := d.cli.ImageInspect(ctx, spec.Desired.Image)
	if err == nil && ins.Config != nil {
		if p := lowestTCPPortFromKeys(ins.Config.ExposedPorts); p > 0 {
			return p
		}
	} else if err != nil && !cerrdefs.IsNotFound(err) {
		// Chỉ log-worthy khi không phải "image chưa có" — nhưng driver không giữ
		// logger; im lặng rơi về mặc định là hành vi recorded trong godoc.
		_ = err
	}
	return contracts.DefaultHTTPPort
}

// lowestTCPPortFromKeys nhận tập khoá kiểu "8080/tcp" (định dạng ExposedPorts
// của image config) và trả cổng TCP nhỏ nhất; 0 nếu không có cổng TCP nào.
func lowestTCPPortFromKeys[V any](exposed map[string]V) int {
	best := 0
	for key := range exposed {
		port, proto, ok := strings.Cut(key, "/")
		if ok && !strings.EqualFold(proto, "tcp") {
			continue // UDP/SCTP: gateway HTTP không nối tới được
		}
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			continue
		}
		if best == 0 || n < best {
			best = n
		}
	}
	return best
}

// portFromLabels đọc cổng đã đóng vào label; 0 nếu thiếu hoặc hỏng.
func portFromLabels(labels map[string]string) int {
	n, err := strconv.Atoi(labels[labelPort])
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}

// portOrFallback — label là nguồn chính; container do bản box CŨ tạo chưa có
// label này nên vẫn phải có đường lui, nếu không mọi app đang chạy sẽ mất sạch
// endpoint ngay lần OTA đầu tiên.
func portOrFallback(labels map[string]string, fallback int) int {
	if p := portFromLabels(labels); p > 0 {
		return p
	}
	if fallback > 0 {
		return fallback
	}
	return contracts.DefaultHTTPPort
}

// ipOnKeenrigNet lấy IP của container trên network keenrig0 ("" nếu chưa có).
//
// CHỈ đọc network của mình: container có thể được attach thêm mạng khác, và IP
// trên mạng đó gateway không tới được. Lấy "mạng đầu tiên" sẽ sinh upstream
// không route được mà nhìn thì rất giống đúng.
func ipOnKeenrigNet(nets map[string]*network.EndpointSettings) string {
	es := nets[networkName]
	if es == nil || !es.IPAddress.IsValid() || es.IPAddress.IsUnspecified() {
		return ""
	}
	return es.IPAddress.String()
}

// endpointFromSummary dựng endpoint từ kết quả ContainerList.
// Container không Running, hoặc chưa có IP trên keenrig0 → (zero, false).
func endpointFromSummary(c container.Summary, fallbackPort int) (runtime.Endpoint, bool) {
	if c.State != container.StateRunning || c.NetworkSettings == nil {
		return runtime.Endpoint{}, false
	}
	ip := ipOnKeenrigNet(c.NetworkSettings.Networks)
	if ip == "" {
		return runtime.Endpoint{}, false
	}
	return runtime.Endpoint{Host: ip, Port: portOrFallback(c.Labels, fallbackPort)}, true
}

// endpointFromInspect dựng endpoint từ ContainerInspect (đường đi ngay sau
// create/start, lúc chưa có Summary).
func endpointFromInspect(ins container.InspectResponse, fallbackPort int) (runtime.Endpoint, bool) {
	if ins.State == nil || ins.State.Status != container.StateRunning || ins.NetworkSettings == nil {
		return runtime.Endpoint{}, false
	}
	ip := ipOnKeenrigNet(ins.NetworkSettings.Networks)
	if ip == "" {
		return runtime.Endpoint{}, false
	}
	var labels map[string]string
	if ins.Config != nil {
		labels = ins.Config.Labels
	}
	return runtime.Endpoint{Host: ip, Port: portOrFallback(labels, fallbackPort)}, true
}
