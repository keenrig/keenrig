package importer

import (
	"fmt"
	"sort"
	"strings"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// IM-02 — service chạy một database CHÍNH THỨC được HẤP THỤ thành addon managed,
// không thành một app riêng.
//
// # Vì sao hấp thụ chứ không dịch thành app
//
// Dịch `postgres:16` thành một app bình thường thì người dùng được một container
// postgres do CHÍNH HỌ quản: không ai sao lưu nó (`Backup` của addon là thứ biết
// chạy `pg_dump`), không ai cách ly nó ở tầng SQL, không ai vá nó khi có CVE. Nó
// trông giống thành công cho tới lúc cần restore.
//
// Hấp thụ nghĩa là: bỏ service đó khỏi danh sách app, và bật
// `addons.postgres.enabled` trên app THẬT SỰ dùng nó.
//
// # Chỉ nhận image CHÍNH THỨC, có chủ đích
//
// `postgres`, `library/postgres`, `docker.io/library/postgres` — và không hơn.
// Một image `mycompany/postgres-with-extensions` có thể đã sửa cấu hình, thêm
// extension, đổi cả cách khởi tạo; hấp thụ nó thành addon là hứa với người dùng
// rằng nền tảng chạy thứ tương đương, mà ta không biết điều đó. Không nhận thì
// nó thành một app bình thường và người dùng thấy ngay — đoán sai thì họ mất dữ
// liệu vài tuần sau.

// managedAddonKinds — image chính thức → addon kind.
var managedAddonKinds = map[string]string{
	"postgres": "postgres",
	"postgis":  "", // KHÔNG hấp thụ: postgis là postgres + extension, addon chưa có
	"redis":    "redis",
	"valkey":   "", // fork của redis; addon chưa khai là tương đương
	"mysql":    "", // chưa có addon kind — xem Note bên dưới
	"mariadb":  "",
	"mongo":    "",
}

// addonKindFor trả kind addon cho một image, và biết cả những image NÊN là addon
// nhưng nền tảng chưa hỗ trợ.
//
// Trả về (kind, known): `known` đúng cho cả hai nhóm — nhận được và biết-nhưng-
// chưa-hỗ-trợ. Nhờ vậy caller nói được câu thứ hai thay vì im lặng để nó thành
// một app postgres tự quản.
func addonKindFor(image string) (kind string, known bool) {
	repo := strings.ToLower(strings.TrimSpace(image))
	if i := strings.IndexByte(repo, '@'); i >= 0 { // bỏ digest
		repo = repo[:i]
	}
	if i := strings.LastIndexByte(repo, ':'); i >= 0 && !strings.Contains(repo[i:], "/") {
		repo = repo[:i] // bỏ tag
	}
	// Chỉ chấp nhận đường dẫn CHÍNH THỨC của Docker Hub.
	for _, prefix := range []string{"docker.io/library/", "library/", "index.docker.io/library/"} {
		repo = strings.TrimPrefix(repo, prefix)
	}
	if strings.Contains(repo, "/") {
		return "", false // image của bên thứ ba
	}
	k, ok := managedAddonKinds[repo]
	return k, ok
}

// absorbAddons hấp thụ service-database thành addon trên app dùng nó.
//
// Trả về danh sách app CÒN LẠI (đã bật addon) và ghi chú cấp file.
func absorbAddons(apps []App, services map[string]composeService, dependsOn map[string][]string) ([]App, []Note) {
	// Bước 1: phân loại service nào là database chính thức.
	absorbed := map[string]string{} // tên service → addon kind
	var notes []Note
	for name, s := range services {
		kind, known := addonKindFor(s.Image)
		if !known {
			continue
		}
		if kind == "" {
			notes = append(notes, Note{
				Severity: SeverityRejected, Service: name, Field: "image",
				Message: fmt.Sprintf("%q looks like a managed data service, but the platform has no addon for it yet "+
					"(only postgres and redis). Running it as a plain app would give you a database nobody backs up, "+
					"isolates or patches — so it is refused rather than imported into a shape that fails later", s.Image),
			})
			continue
		}
		absorbed[name] = kind
	}
	if len(absorbed) == 0 {
		return apps, notes
	}

	// Bước 2: xác định app nào DÙNG addon đó.
	//
	// `depends_on` là tín hiệu đáng tin nhất và nó có sẵn trong compose. Khi
	// không ai khai depends_on mà chỉ còn ĐÚNG MỘT app không phải database thì
	// gán cho nó — đó là hình dạng của gần như mọi compose hai service. Nhiều
	// app mà không có depends_on thì KHÔNG đoán: đoán sai nghĩa là một app chạy
	// mà không có DB, và triệu chứng nằm trong log của app.
	remaining := make([]App, 0, len(apps))
	bySlug := map[string]int{}
	for _, a := range apps {
		if _, isAddon := absorbed[a.composeName]; isAddon {
			continue
		}
		bySlug[a.composeName] = len(remaining)
		remaining = append(remaining, a)
	}

	names := make([]string, 0, len(absorbed))
	for n := range absorbed {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, svc := range names {
		kind := absorbed[svc]
		targets := dependentsOf(svc, dependsOn, bySlug)
		if len(targets) == 0 && len(remaining) == 1 {
			targets = []int{0}
		}
		if len(targets) == 0 {
			notes = append(notes, Note{
				Severity: SeverityDropped, Service: svc, Field: "addons",
				Message: fmt.Sprintf("%s was recognised as a managed %s addon but nothing declares `depends_on: [%s]`, "+
					"and there is more than one other service — enable the addon by hand on the app that needs it",
					svc, kind, svc),
			})
			continue
		}
		for _, i := range targets {
			enableAddon(&remaining[i], kind)
			remaining[i].Notes = append(remaining[i].Notes, Note{
				Severity: SeverityInfo, Service: remaining[i].composeName, Field: "addons",
				Message: fmt.Sprintf("service %q became a managed %s addon: the platform creates the database and "+
					"injects KEENRIG_%s_URL. Any hand-written connection string in this app's `environment` still "+
					"points at the old service name and MUST be changed to read that variable",
					svc, kind, strings.ToUpper(kind)),
			})
		}
	}
	return remaining, notes
}

// dependentsOf trả chỉ số các app khai `depends_on` service svc.
func dependentsOf(svc string, dependsOn map[string][]string, bySlug map[string]int) []int {
	var out []int
	for name, deps := range dependsOn {
		i, ok := bySlug[name]
		if !ok {
			continue
		}
		for _, d := range deps {
			if d == svc {
				out = append(out, i)
				break
			}
		}
	}
	sort.Ints(out)
	return out
}

func enableAddon(a *App, kind string) {
	if a.Desired.Addons == nil {
		a.Desired.Addons = &contracts.Addons{}
	}
	switch kind {
	case "postgres":
		a.Desired.Addons.Postgres = &contracts.AddonSpec{Enabled: true}
	case "redis":
		a.Desired.Addons.Redis = &contracts.AddonSpec{Enabled: true}
	}
}
