package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"testing"
	"testing/fstest"
)

// ST-04 — migration up từ MỌI bản đã phát hành, checksum schema khớp bản mới nhất.
//
// # Vì sao ma trận phải đọc từ GIT TAG, không phải từ một danh sách viết tay
//
// Một danh sách version trong code là thứ người ta quên cập nhật, và lúc quên
// thì test vẫn xanh — nó chỉ ngừng kiểm bản mới nhất. Git tag là nguồn sự thật
// duy nhất về "bản nào đã phát hành", và nó được cập nhật bởi chính hành động
// phát hành.
//
// # Nói thẳng điều test này CHƯA khẳng định được hôm nay
//
// Tag đầu tiên `v0.1.0` trỏ vào commit đóng M1, và cả bảy migration (0001–0007)
// đã có sẵn ở đó. Nên ma trận v0.1.0 → HEAD hiện tự khớp với chính nó. Giá trị
// nằm ở chỗ khác: kể từ migration 0008, đây là chỗ bắt được một schema trôi.
//
// Cách hỏng mà nó canh, cụ thể: thêm 0008 rồi lỡ tay sửa luôn 0005 (đổi một cột,
// thêm một index). Instance mới dựng đúng vì nó chạy 0005 đã sửa; instance CŨ
// nâng cấp thì không, vì 0005 với nó đã chạy xong từ lâu và `user_version` đã
// vượt qua. Hai schema trôi xa nhau, không có gì đỏ, và nó chỉ lộ ra khi một
// truy vấn mới gặp một cột không tồn tại trên máy khách hàng.
func TestMigrationFromEveryReleasedTag(t *testing.T) {
	tags := releasedTags(t)
	if len(tags) == 0 {
		t.Skip("chưa có git tag nào — không có bản phát hành để nâng cấp TỪ")
	}
	dir := migrationsDirInRepo(t)

	// Schema đích: DB dựng bằng migration HIỆN TẠI, không qua bản nào cũ.
	target := openRawDB(t)
	if err := migrateFS(target, migrationsFS, "migrations"); err != nil {
		t.Fatal(err)
	}
	want := schemaChecksum(t, target)

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			old, err := migrationsAt(tag, dir)
			if err != nil {
				t.Fatalf("đọc migration ở %s: %v", tag, err)
			}
			if len(old) == 0 {
				t.Fatalf("%s không có migration nào — tag trỏ sai chỗ?", tag)
			}

			// Dựng DB đúng như bản đã phát hành, RỒI nâng lên HEAD.
			db := openRawDB(t)
			if err := migrateFS(db, old, "migrations"); err != nil {
				t.Fatalf("dựng schema của %s: %v", tag, err)
			}
			if err := migrateFS(db, migrationsFS, "migrations"); err != nil {
				t.Fatalf("nâng %s lên HEAD: %v", tag, err)
			}

			if got := schemaChecksum(t, db); got != want {
				t.Errorf("schema sau khi nâng từ %s KHÁC schema dựng mới:\n  nâng cấp: %s\n  dựng mới: %s\n"+
					"Một instance nâng cấp và một instance mới cài đang chạy trên hai schema khác nhau.",
					tag, got, want)
			}
		})
	}
}

// Số migration chỉ được TĂNG giữa các bản phát hành.
//
// Xoá hay đổi tên một file đã phát hành làm `user_version` của instance cũ trỏ
// vào một thứ không còn tồn tại, và mọi suy luận "đã chạy tới đâu" sai từ đó.
func TestReleasedMigrationsAreNeverRemoved(t *testing.T) {
	tags := releasedTags(t)
	if len(tags) == 0 {
		t.Skip("chưa có git tag nào")
	}
	dir := migrationsDirInRepo(t)
	cur, err := migrationsAt("HEAD", dir)
	if err != nil {
		t.Skipf("không đọc được migration ở HEAD: %v", err)
	}
	for _, tag := range tags {
		old, err := migrationsAt(tag, dir)
		if err != nil {
			t.Fatalf("%s: %v", tag, err)
		}
		for name := range old {
			if _, still := cur[name]; !still {
				t.Errorf("%s có %s nhưng HEAD không còn — migration đã phát hành không được xoá", tag, name)
			}
		}
	}
}

// schemaChecksum phải THẬT SỰ phân biệt được hai schema khác nhau.
//
// Không có test này thì hai test trên vô dụng theo cách tệ nhất: một
// schemaChecksum trả hằng số sẽ làm chúng luôn xanh, và ta sẽ tin rằng ma trận
// migration đang được canh trong khi nó không canh gì.
func TestSchemaChecksumHasTeeth(t *testing.T) {
	partial := openRawDB(t)
	if err := migrateFS(partial, fstest.MapFS{
		"migrations/0001_init.sql": &fstest.MapFile{Data: []byte(`CREATE TABLE chi_mot_bang (id INTEGER PRIMARY KEY);`)},
	}, "migrations"); err != nil {
		t.Fatal(err)
	}
	full := openRawDB(t)
	if err := migrateFS(full, migrationsFS, "migrations"); err != nil {
		t.Fatal(err)
	}
	if schemaChecksum(t, partial) == schemaChecksum(t, full) {
		t.Fatal("hai schema khác hẳn nhau cho ra cùng một băm — phép so trong ST-04 không kiểm gì")
	}

	// Và cùng một schema phải cho cùng một băm, kể cả khi dựng lại từ đầu:
	// một băm phụ thuộc thứ tự dòng trả về sẽ đỏ ngẫu nhiên.
	again := openRawDB(t)
	if err := migrateFS(again, migrationsFS, "migrations"); err != nil {
		t.Fatal(err)
	}
	if schemaChecksum(t, again) != schemaChecksum(t, full) {
		t.Error("cùng một schema cho hai băm khác nhau — phép so không ổn định")
	}
}

// --- helper -----------------------------------------------------------------------

// releasedTags trả tag dạng vN.N.N, đã sắp xếp. Skip có LÝ DO khi không có git.
func releasedTags(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("không có git trong PATH — ma trận theo tag chỉ chạy được trong checkout đầy đủ")
	}
	out, err := exec.Command("git", "tag", "-l", "v*", "--sort=v:refname").Output()
	if err != nil {
		t.Skipf("không đọc được danh sách tag (không phải git checkout?): %v", err)
	}
	var tags []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			tags = append(tags, s)
		}
	}
	return tags
}

// migrationsDirInRepo trả đường dẫn thư mục migrations TÍNH TỪ GỐC REPO.
//
// Không đặt cứng chuỗi "keenrig-node/internal/store/migrations": chuỗi đặt cứng
// sẽ im lặng sai vào ngày package này đổi chỗ, và test sẽ báo "tag không có
// migration nào" — một thông báo nói sai nguyên nhân.
func migrationsDirInRepo(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-prefix").Output()
	if err != nil {
		t.Skipf("không xác định được vị trí trong repo: %v", err)
	}
	return path.Join(strings.TrimSpace(string(out)), "migrations")
}

// migrationsAt đọc mọi file .sql của thư mục migrations tại một ref, KHÔNG
// checkout — `git show` đọc thẳng từ object store nên cây làm việc không bị đụng.
func migrationsAt(ref, dir string) (fstest.MapFS, error) {
	// `--full-tree` là BẮT BUỘC, không phải tuỳ chọn cho gọn: không có nó,
	// `git ls-tree` hiểu đường dẫn theo THƯ MỤC HIỆN TẠI, và `go test` luôn chạy
	// từ thư mục package. Bỏ quên nó thì lệnh trả về RỖNG với exit code 0 — test
	// sẽ báo "tag không có migration nào", một thông báo nói sai nguyên nhân.
	// (Đã trả giá đúng một lần khi viết test này.)
	// KHONG khoa theo duong dan hien tai cua package.
	//
	// Duong dan do chua ten thu muc module, va ten module DOI DUOC — du an
	// nay da doi mot lan (speedup-node -> keenrig-node). Dung duong dan hom
	// nay de doc mot tag cua hom qua thi git ls-tree tra RONG voi exit code 0,
	// va test bao "tag khong co migration nao": mot thong bao do loi cho cai
	// tag trong khi thu pham la cai ten.
	//
	// Nen quet ca cay cua ref roi khop theo DUOI duong dan. Dung voi moi lan
	// doi ten module ve sau, ke ca lan chua xay ra.
	suffix := dir
	if i := strings.Index(suffix, "internal/"); i >= 0 {
		suffix = suffix[i:] // "internal/store/migrations"
	}
	out, err := exec.Command("git", "ls-tree", "--full-tree", "--name-only", "-r", ref).Output()
	if err != nil {
		return nil, err
	}
	// Gom theo MODULE (phần đứng trước đuôi): từ v0.2.0 repo là monorepo, và
	// Keenrig Cloud (`store/migrations`) cũng mang đúng đuôi này — migration
	// Postgres của cloud lọt vào SQLite của box và nổ "near (". Chọn module hiện
	// tại nếu tag có nó; không thì module có chữ "node" (v0.1.0: speedup-node).
	byModule := map[string][]string{}
	for _, p := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		p = strings.TrimSpace(p)
		if !strings.HasSuffix(p, ".sql") {
			continue
		}
		i := strings.Index(p, suffix+"/")
		if i < 0 {
			continue
		}
		byModule[p[:i]] = append(byModule[p[:i]], p)
	}
	module := strings.TrimSuffix(dir, suffix)
	if _, ok := byModule[module]; !ok {
		module = ""
		for m := range byModule {
			if len(byModule) == 1 || strings.Contains(m, "node") {
				module = m
				break
			}
		}
	}
	fsys := fstest.MapFS{}
	for _, p := range byModule[module] {
		body, err := exec.Command("git", "show", ref+":"+p).Output()
		if err != nil {
			return nil, fmt.Errorf("git show %s:%s: %w", ref, p, err)
		}
		// Giữ NGUYÊN tiền tố "migrations/" như cây thật: migrateFS ghép
		// dir + "/" + tên, nên một MapFS phẳng sẽ báo "file does not exist".
		fsys["migrations/"+path.Base(p)] = &fstest.MapFile{Data: body}
	}
	return fsys, nil
}

// schemaChecksum băm TOÀN BỘ định nghĩa schema.
//
// Đọc từ `sqlite_master` chứ không so từng câu SQL trong file: thứ ta quan tâm
// là TRẠNG THÁI CUỐI, và hai chuỗi migration khác nhau vẫn phải cho ra cùng một
// trạng thái. Bỏ qua index tự sinh của SQLite (`sqlite_autoindex_*`) vì tên
// chúng phụ thuộc thứ tự tạo bảng chứ không phải ý định của schema.
func schemaChecksum(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT type, name, COALESCE(sql, '') FROM sqlite_master
	                       WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	h := sha256.New()
	for rows.Next() {
		var typ, name, ddl string
		if err := rows.Scan(&typ, &name, &ddl); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00", typ, name, normalizeDDL(ddl))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeDDL bỏ khác biệt về khoảng trắng: SQLite lưu nguyên văn câu CREATE,
// nên thụt lề khác nhau giữa hai file sẽ cho hai băm khác nhau dù schema y hệt.
func normalizeDDL(s string) string { return strings.Join(strings.Fields(s), " ") }
