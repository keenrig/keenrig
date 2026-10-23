package importer_test

import (
	"strings"
	"testing"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/importer"
)

// IM-06 — fuzz parser: KHÔNG panic, KHÔNG OOM, với input bất kỳ.
//
// # Vì sao ở đây `testing.F` là đúng, còn ở chaos thì không
//
// Bộ fuzz bit-flip của SEC-02 duyệt CÓ HỆ THỐNG vì không gian hữu hạn và đã
// biết. Ở đây thì ngược lại: input là "một chuỗi byte bất kỳ", không gian vô
// hạn, và thứ ta muốn là bộ sinh tiến hoá theo coverage để bò vào những nhánh
// phân tích mà ta không nghĩ ra. Đó đúng là việc của `testing.F`.
//
// # Khẳng định là gì, và KHÔNG là gì
//
// Không khẳng định "input hợp lệ thì nhận, sai thì từ chối" — với byte ngẫu
// nhiên thì hai nhóm đó không phân biệt được. Khẳng định là:
//
//	không panic          panic trong importer = chết `keenrig-box` = mất control
//	                     plane, vì một người dán một file vào ô nhập
//	trả về TRONG GIỚI HẠN  không treo, không nuốt RAM — bảo đảm bằng IM-07
//	kết quả TỰ NHẤT QUÁN   nhận thì mọi app phải có Image; từ chối thì phải có
//	                     ít nhất một Note giải thích
//
// Khẳng định thứ ba là thứ bắt được lỗi thật: một parser trả về `Result` nửa
// vời — app không có image, hoặc từ chối mà không nói lý do — sẽ đẩy rác xuống
// tầng dưới thay vì dừng ở đây.
func FuzzImportCompose(f *testing.F) {
	seeds := []string{
		"",
		"services:\n  x:\n    image: nginx\n",
		"services:\n  x:\n    image: nginx\n    ports: [\"8080:80\"]\n",
		"services:\n  x:\n    image: nginx\n    volumes:\n      - data:/data\n",
		"services:\n  x:\n    image: nginx\n    volumes:\n      - /:/host\n",
		"services:\n  x:\n    privileged: true\n",
		"services:\n  x:\n    build: .\n",
		"services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: x\n",
		"not yaml at all",
		"services: []",
		"services:\n  x:\n    image: nginx\n    deploy:\n      replicas: -1\n",
		"a: &a [*a]\n", // alias tự trỏ
		strings.Repeat("[", 200) + strings.Repeat("]", 200),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := importer.Import(data)
		if err != nil {
			// Từ chối là kết quả hợp lệ với gần như mọi input. Chỉ cần nó KHÔNG
			// panic — điều đó đã được bảo đảm bởi việc tới được dòng này.
			return
		}

		// Nhận thì kết quả phải TỰ NHẤT QUÁN.
		for i, a := range res.Apps {
			if a.Slug == "" && len(rejectedOf(a)) == 0 {
				t.Fatalf("app %d không có slug mà cũng không bị từ chối — "+
					"slug đi thẳng vào tên container su-<slug>-…", i)
			}
			if a.Desired.Image == "" && len(rejectedOf(a)) == 0 {
				t.Fatalf("app %q không có image mà cũng không có ghi chú từ chối — "+
					"Result nửa vời sẽ đẩy rác xuống tầng dưới", a.Slug)
			}
			// Volume đã vào desired thì phải qua được chính bộ kiểm của hợp đồng.
			// Đây là chỗ fuzz đáng giá nhất: importer sinh ra `volumes`, và một
			// tên volume lọt qua đây sẽ thành một đoạn ĐƯỜNG DẪN trên máy chủ.
			if verr := contracts.ValidateVolumes(a.Desired.Volumes); verr != nil {
				t.Fatalf("app %q có volume KHÔNG hợp lệ lọt vào desired: %v", a.Slug, verr)
			}
		}
		// Bị từ chối thì phải NÓI LÝ DO.
		if len(res.Rejected()) > 0 {
			said := false
			for _, a := range res.Apps {
				if len(rejectedOf(a)) > 0 {
					said = true
				}
			}
			if !said {
				t.Fatal("Result.Rejected() khác rỗng nhưng không app nào mang ghi chú từ chối")
			}
		}
	})
}

func rejectedOf(a importer.App) []importer.Note {
	var out []importer.Note
	for _, n := range a.Notes {
		if n.Severity == importer.SeverityRejected {
			out = append(out, n)
		}
	}
	return out
}

// IM-06 cho đường vào thứ hai: `docker run` cũng phải không panic với input bất kỳ.
//
// Đường này phân tích CHUỖI DÒNG LỆNH bằng tay — nháy, thoát ký tự, nối dòng —
// nên nó có nhiều chỗ vỡ hơn YAML, nơi đã có một thư viện chịu trận.
func FuzzImportDockerRun(f *testing.F) {
	for _, s := range []string{
		"docker run nginx",
		`docker run -d --name x -p 80:80 -e A=1 -v d:/d nginx:1`,
		`docker run -e "A=b c" nginx`,
		"docker run --privileged nginx",
		`docker run -v /var/run/docker.sock:/var/run/docker.sock nginx`,
		"docker run \\n  --name x \\n  nginx",
		`docker run -e 'A=1' "nginx"`,
		"-", "--", "---", `"`, `'`, "\\",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		res, err := importer.ImportDockerRun(cmd)
		if err != nil {
			return
		}
		for _, a := range res.Apps {
			if a.Slug == "" && len(rejectedOf(a)) == 0 {
				t.Fatalf("app không có slug mà cũng không bị từ chối (cmd=%q)", cmd)
			}
			if a.Desired.Image == "" && len(rejectedOf(a)) == 0 {
				t.Fatalf("app không có image mà cũng không bị từ chối (cmd=%q)", cmd)
			}
			if verr := contracts.ValidateVolumes(a.Desired.Volumes); verr != nil {
				t.Fatalf("volume không hợp lệ lọt vào desired: %v (cmd=%q)", verr, cmd)
			}
		}
	})
}
