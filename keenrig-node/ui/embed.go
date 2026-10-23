// Package ui — asset của Keenrig Admin, nhúng thẳng vào binary keenrig-box.
//
// # Vì sao NHÚNG chứ không serve từ đĩa
//
// Bố cục runtime nói rằng <base>/bin bị THAY NGUYÊN KHỐI mỗi lần update, còn ba
// mặt phẳng còn lại phải sống sót (paths). Asset UI là CODE, không phải state.
// Để nó ngoài binary sẽ tạo ra một thứ vừa phải update cùng bin vừa nằm ngoài
// bin — tức là một đường để UI và API lệch phiên bản nhau, và lệch phiên bản
// giữa hai thứ nói chuyện qua JSON là kiểu lỗi rất khó nhìn ra.
//
// # Khi chưa build
//
// `go:embed` bắt buộc thư mục phải tồn tại lúc biên dịch. Ta commit
// dist/.gitkeep để `go build` chạy được trên một checkout sạch chưa chạy npm;
// khi đó Available() trả false và box vẫn phục vụ API bình thường, chỉ không
// có Admin. Đó là hành vi đúng cho một máy CI chỉ kiểm Go.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// FS trả cây asset đã build (gốc là dist/).
func FS() (fs.FS, error) { return fs.Sub(distFS, "dist") }

// Available cho biết UI đã được build vào binary chưa.
func Available() bool {
	sub, err := FS()
	if err != nil {
		return false
	}
	_, err = fs.Stat(sub, "index.html")
	return err == nil
}

// Handler phục vụ SPA: file tĩnh nếu có, còn lại trả index.html.
//
// Fallback về index.html là bắt buộc với SPA, nhưng KHÔNG được áp cho
// /assets/*: một file bundle gõ sai tên mà trả về index.html sẽ khiến trình
// duyệt báo "Unexpected token '<'" — thông báo không liên quan gì tới nguyên
// nhân thật. Trả 404 cho asset thiếu thì lỗi tự nói ra nó là gì.
func Handler() http.Handler {
	sub, err := FS()
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "ui: not built", http.StatusNotImplemented)
		})
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err == nil {
			// Asset có hash trong tên (vite) nên cache được vĩnh viễn; index.html
			// thì KHÔNG, nếu không người dùng sẽ giữ mãi bản UI cũ sau update.
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			files.ServeHTTP(w, r)
			return
		}
		// Cùng lý do cho mọi file có đuôi (favicon.ico, robots.txt…): route SPA
		// không bao giờ có đuôi. Trả HTML cho /favicon.ico khiến trình duyệt giữ
		// favicon cũ đã cache cho host này — trên một VPS tái sử dụng, tab Keenrig
		// Admin hiện logo của phần mềm cài trước đó.
		if strings.HasPrefix(p, "assets/") || path.Ext(p) != "" {
			http.NotFound(w, r)
			return
		}
		index, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "ui: not built", http.StatusNotImplemented)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}
