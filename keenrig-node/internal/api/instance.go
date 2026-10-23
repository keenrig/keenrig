package api

import (
	"net/http"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/instance"
)

// SettingParentDomain — khoá trong bảng `settings` giữ tên miền gốc của instance.
//
// App nằm ở `<app>.<parent>` và Admin ở `admin.<parent>`, nên đây là dữ kiện
// Admin UI cần để đề xuất tên miền thay vì bắt người dùng gõ cả FQDN. Định
// nghĩa chính nằm ở internal/instance cùng với luật "cloud thắng"; đây là bí
// danh cho chỗ đọc cũ.
const SettingParentDomain = instance.SettingParentDomain

// instanceInfo — những gì Admin UI cần biết về instance TRƯỚC khi đăng nhập.
//
// # Vì sao không cần xác thực
//
// Nó trả về đúng một thứ: tên miền gốc — mà bất kỳ ai mở được trang này đã đọc
// được từ thanh địa chỉ của họ. Bắt đăng nhập để lấy một giá trị người ta đang
// nhìn là bảo mật hình thức, và nó làm hỏng ca dùng thật: màn thiết lập lần đầu
// chạy khi CHƯA có tài khoản nào.
//
// # Vì sao CHỈ có GET
//
// Tên miền gốc của một môi trường là quyết định của keenrig-cloud, đi xuống
// box qua agent → node API (luật chủ dự án 2026-09-07: "keenrig-admin là nơi
// nhận thông tin thôi"). Không có PUT/POST/PATCH nào ở đường này, và có test
// canh điều đó — một route ghi thêm vào đây là mở đường cho Admin và Console
// cãi nhau về tên của cùng một máy.
func (s *Server) instanceInfo(w http.ResponseWriter, r *http.Request) {
	info, err := instance.New(s.st).Info(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"parent_domain":        info.ParentDomain,
		"parent_domain_source": info.Source,
		"domain_mode":          info.Mode,
	})
}
