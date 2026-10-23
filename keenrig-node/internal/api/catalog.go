package api

// Route danh mục app (UI-01).
//
// # Cài là MỘT lời gọi, không phải bốn
//
// Không có endpoint này thì "cài app từ catalog" là: đọc manifest → tự dịch
// sang desired → POST /apps → POST /apps/{id}/domains. Bốn bước, và bước thứ
// hai là chỗ mỗi client tự viết lại phép dịch — nghĩa là mỗi client tự quyết
// định có ghim digest hay không.
//
// Gộp vào một lời gọi đưa phép dịch về đúng MỘT chỗ (catalog.ToDesired), và
// biến "cài app" thành thao tác đo được cho gate <60s của UI-01.

import (
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/catalog"
)

func (s *Server) catalogRoutes() {
	if s.cat == nil {
		return // chưa cắm danh mục — route không tồn tại thay vì trả rỗng
	}
	s.mux.Handle("GET /api/v1/catalog", s.guard.Require(authz.ScopeAppsRead, http.HandlerFunc(s.listCatalog)))
	s.mux.Handle("GET /api/v1/catalog/{id}", s.guard.Require(authz.ScopeAppsRead, http.HandlerFunc(s.getCatalogItem)))
	s.mux.Handle("POST /api/v1/catalog/{id}/install", s.guard.Require(authz.ScopeAppsWrite, http.HandlerFunc(s.installFromCatalog)))
	// Icon nằm SAU /catalog/{id} trong file nhưng không tranh chấp với nó:
	// {id} khớp đúng MỘT đoạn đường dẫn, còn icons/{file} là hai đoạn.
	s.mux.Handle("GET /api/v1/catalog/icons/{file}", s.guard.Require(authz.ScopeAppsRead, http.HandlerFunc(s.serveCatalogIcon)))
}

// serveCatalogIcon trả file icon nhúng trong binary.
//
// # Vì sao cần route này
//
// Manifest khai `"icon": "nginx.svg"` — TÊN FILE, không phải nội dung. Không có
// chỗ nào phục vụ file đó thì UI chỉ còn cầm một chuỗi, và nó đã in thẳng chuỗi
// ấy ra thẻ icon: người dùng thấy chữ "nginx.svg" đè lên tên app.
//
// # Vì sao vẫn sau guard
//
// Icon là trang trí, nhưng danh sách app đã cài là thông tin về hệ thống. Để
// icon công khai thì ai cũng dò được binary này mang sẵn app nào. Admin xác
// thực bằng cookie HttpOnly same-origin, nên <img> tự gửi cookie — guard không
// tốn gì của UI.
func (s *Server) serveCatalogIcon(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")

	// fs.ValidPath chặn "..", đường dẫn tuyệt đối và tên rỗng. ServeMux đã cắt
	// theo đoạn nên "/" không lọt tới đây được, nhưng không dựa vào điều đó:
	// một lần đổi pattern thành {file...} là chỗ này thành lỗ duyệt thư mục.
	if !fs.ValidPath(name) || strings.ContainsAny(name, `/\`) {
		writeJSON(w, http.StatusBadRequest, errBody{"bad icon name"})
		return
	}

	data, err := fs.ReadFile(s.cat.Icons(), name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody{"no such icon"})
		return
	}

	ct := mime.TypeByExtension(path.Ext(name))
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	// SVG là tài liệu chạy được script trong trình duyệt. Icon đến từ manifest
	// nhúng, nhưng CSP + nosniff làm cho việc thả nhầm một SVG độc vào danh mục
	// ngoài không biến thành XSS trên chính origin của Admin.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Icon đi kèm binary: đổi icon nghĩa là đổi binary. Cache dài vô hại.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// catalogItem — hình dạng gửi cho UI.
//
// KHÔNG trả thẳng catalog.Manifest: digest là chi tiết vận hành, còn thứ người
// dùng cần thấy là "nginx:1.27.4-alpine". Trả cả hai, đặt tên rõ cái nào là
// cái nào — UI hiện display_ref, và image_ref có đó cho ai muốn kiểm chứng.
type catalogItem struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// TitleVI / DescriptionVI — UI chọn theo ngôn ngữ, thiếu thì dùng bản chuẩn.
	TitleVI       string   `json:"title_vi,omitempty"`
	DescriptionVI string   `json:"description_vi,omitempty"`
	Version       string   `json:"version"`
	DisplayRef    string   `json:"display_ref"`
	ImageRef      string   `json:"image_ref"`
	HTTPPort      int      `json:"http_port"`
	MinMemoryMB   int      `json:"min_memory_mb,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Icon          string   `json:"icon,omitempty"`
	Website       string   `json:"website,omitempty"`
	Source        string   `json:"source,omitempty"`
	// Installed — app trên box này đang chạy image của mục này. LUÔN là mảng
	// (rỗng khi chưa cài): UI đọc `.length`, và null ở đó là lỗi runtime.
	Installed []installedRef `json:"installed"`
}

// installedRef — đủ để UI dẫn người dùng tới app đã cài.
type installedRef struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

func toItem(m *catalog.Manifest) catalogItem {
	return catalogItem{
		ID: m.ID, Title: m.Title, TitleVI: m.TitleVI, Description: m.Description, DescriptionVI: m.DescriptionVI, Version: m.Version,
		DisplayRef: m.DisplayRef(), ImageRef: m.ImageRef(), HTTPPort: m.HTTPPort,
		MinMemoryMB: m.MinMemoryMB, Tags: m.Tags, Icon: m.Icon,
		Website: m.Website, Source: m.Source,
		Installed: []installedRef{},
	}
}

// imageRepo — "docker.io/traefik/whoami@sha256:…" → "docker.io/traefik/whoami".
//
// So theo REPOSITORY chứ không theo cả ref: bản catalog mới đổi digest thì app
// cài từ bản cũ vẫn là "đã cài". Dấu ":" chỉ là tag khi nó nằm SAU "/" cuối —
// "registry:5000/app" có cổng, không có tag.
func imageRepo(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		ref = ref[:i]
	}
	return ref
}

// listCatalog — danh mục kèm "app nào đã cài".
//
// # Vì sao đối chiếu theo image
//
// Box không lưu app được cài từ mục nào: cài từ catalog chỉ để lại desired
// (image đã ghim digest). Không đối chiếu thì thẻ Whoami vẫn mời "Install" trên
// một box đã chạy whoami, người dùng bấm, và gói 1-app trả lỗi hạn mức — trông
// như hỏng. Image là dấu vết duy nhất có sẵn, và nó có trên MỌI app đã cài,
// kể cả app cài trước bản vá này hay do cloud ra lệnh cài.
func (s *Server) listCatalog(w http.ResponseWriter, r *http.Request) {
	list := s.cat.List()
	installed, err := s.installedByRepo(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	items := make([]catalogItem, 0, len(list))
	for _, m := range list {
		it := toItem(m)
		if refs := installed[m.Repository]; refs != nil {
			it.Installed = refs
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": items})
}

func (s *Server) installedByRepo(r *http.Request) (map[string][]installedRef, error) {
	apps, err := s.apps.List(r.Context())
	if err != nil {
		return nil, err
	}
	out := map[string][]installedRef{}
	for _, a := range apps {
		var d struct {
			Image string `json:"image"`
		}
		if json.Unmarshal(a.Desired, &d) != nil || d.Image == "" {
			continue
		}
		repo := imageRepo(d.Image)
		out[repo] = append(out[repo], installedRef{ID: a.ID, Slug: a.Slug})
	}
	return out, nil
}

func (s *Server) getCatalogItem(w http.ResponseWriter, r *http.Request) {
	m, err := s.cat.Get(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toItem(m))
}

// installFromCatalog — manifest + lựa chọn người dùng → app đang hội tụ.
//
// Trả 201 NGAY khi app đã vào store, KHÔNG đợi container chạy. Đợi ở đây sẽ
// giữ một kết nối HTTP mở suốt thời gian pull image (có thể vài phút với image
// lớn), và mọi proxy trên đường đi đều có quyền cắt nó. Tiến độ đọc qua
// GET /apps/{id} — cùng đường mà mọi thay đổi khác dùng.
func (s *Server) installFromCatalog(w http.ResponseWriter, r *http.Request) {
	m, err := s.cat.Get(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}

	var body struct {
		// Slug rỗng → dùng id trong danh mục. Cài hai bản của cùng một app thì
		// mới cần đặt tên khác.
		Slug    string            `json:"slug"`
		Domains []string          `json:"domains"`
		Env     map[string]string `json:"env"`
		// MemoryMB 0 → min_memory_mb của manifest.
		MemoryMB int `json:"memory_mb"`
	}
	// Body rỗng là hợp lệ: "cài với mặc định" phải là lời gọi ngắn nhất có thể.
	if r.ContentLength > 0 && !decode(w, r, &body) {
		return
	}

	desired, err := m.ToDesired(catalog.InstallOptions{
		Domains: body.Domains, Env: body.Env, MemoryMB: body.MemoryMB,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	slug := body.Slug
	if slug == "" {
		slug = m.ID
	}
	app, err := s.apps.CreateFromDesired(r.Context(), slug, desired)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, app)
}

// writeCatalogErr — phần bổ sung của bảng dịch lỗi cho UI-01.
func writeCatalogErr(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, catalog.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody{"no such app in the catalog"})
	case errors.Is(err, catalog.ErrInvalidManifest):
		// 400 chứ không 500: manifest hỏng là dữ liệu sai, và người vận hành
		// sửa được nó. 500 sẽ gợi ý sai rằng lỗi nằm ở phía ta.
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
	default:
		return false
	}
	return true
}
