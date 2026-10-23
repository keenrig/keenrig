# Nhập devopsbookmarks.com vào catalog

Chuyển [devopsbookmarks.com](https://github.com/devopsbookmarks/devopsbookmarks.com)
(234 tool DevOps) sang định dạng manifest của `keenrig-catalog`.

## Điều phải biết trước

**Hai bên không cùng loại dữ liệu.** Một entry devopsbookmarks là

```json
{ "slug": "gitea", "name": "gitea", "description": "…", "url": "https://gitea.io/", "tags": ["linux", "open-source", "scm", "vcs"] }
```

— một **bookmark tới trang chủ dự án**. Manifest catalog thì bắt buộc
`repository` + `tag` + `digest` (`sha256:` đủ 64 hex) + `http_port`, và
`internal/catalog.Parse` dùng `DisallowUnknownFields` nên không có cửa nào cho
một manifest thiếu trường. Bốn trường đó **không suy ra được từ một URL**.

Đã thử dò tự động Docker Hub theo tên slug cho cả 234 entry: chỉ 18 slug trùng
tên một repo có thật, và quá nửa số đó là CLI hoặc engine (`docker`, `ansible`,
`chef`, `consul`) chứ không phải web app cài một cú bấm. Đoán image theo tên là
cách nhanh nhất để ship một manifest trỏ vào image của người khác trùng tên.

Nên phần ánh xạ image nằm ở [`mapping.json`](mapping.json) và **viết tay**.

## Chạy

```sh
git clone --depth 1 https://github.com/devopsbookmarks/devopsbookmarks.com.git /tmp/dob
node import.mjs --src /tmp/dob            # sinh out/
node import.mjs --src /tmp/dob --refresh  # resolve lại digest từ registry
node import.mjs --src /tmp/dob --promote  # chép entry `ready` vào ../../manifests/
```

Đầu ra (`out/` là thư mục **sinh ra**, xoá và dựng lại được bất cứ lúc nào):

| Tệp | Là gì |
| --- | --- |
| `out/directory.generated.json` | Cả 234 entry, id + tag chủ đề đã chuẩn hoá, kèm `status` |
| `out/manifests/*.json` | Manifest thật, digest đã resolve — cho entry có trong `mapping.json` |
| `out/REPORT.md` | Cái gì vào đâu, và cái gì đang chặn |

`mapping.lock.json` thì **không** sinh lại được: nó giữ digest đã resolve. Không
có `--refresh` thì script không gọi mạng lấy một byte nào, đúng tinh thần UI-11
— một lần chạy lại không được phụ thuộc vào việc Docker Hub có sống hay không.

## Vì sao chỉ một app được promote

`status` trong `mapping.json` quyết định. Chỉ `ready` mới vào `manifests/`:

| status | Nghĩa |
| --- | --- |
| `ready` | Cấu hình **mặc định** của image không ghi gì xuống đĩa → chạy không volume cũng không mất gì |
| `needs-volumes` | Chạy được, nhưng deploy lại là mất sạch. `Manifest` chưa có trường `volumes` (`contracts.DesiredApp` thì có) |
| `needs-addons` | Cần database/queue ngoài. `Manifest` chưa có trường `addons` |
| `needs-host` | Cần mount `/proc`, `/sys` hoặc docker socket của host — nằm ngoài mô hình app |

Hôm nay đúng **một** entry là `ready`: `zipkin`, vì storage mặc định của nó là
in-memory theo tài liệu chính thức — "mất khi khởi động lại" là hành vi được kỳ
vọng chứ không phải một mất mát bất ngờ.

21 entry `needs-volumes` đã có manifest hoàn chỉnh, digest đã ghim, nằm sẵn
trong `out/manifests/`. Chúng chờ đúng **một** thay đổi: `Manifest` mở trường
`volumes`. Lúc đó đổi `status` và chạy lại `--promote` là xong — không phải tra
lại image nào.

Thêm `volumes` vào `Manifest` là một quyết định thiết kế, không phải một bước
của việc nhập dữ liệu — xem godoc của `internal/catalog` về việc mỗi trường mới
là một quyết định có ý thức. Đó là lý do nó không nằm trong thay đổi này.

## Tag

`topics.json` ánh xạ tag thô của devopsbookmarks sang tag chủ đề. Slug giữ
**tiếng Anh** (`scm`, `ci`, `monitoring`) vì nó đi vào trường `tags` của
manifest, cùng không gian tên với id app; chỉ label hiển thị mới dịch.

Ba nhóm tag bị **bỏ có chủ đích**: nền tảng (`linux`/`windows`/`osx`), giấy
phép (`open-source`/`commercial`) và ngôn ngữ (`python`/`ruby`/`go`). Chúng mô
tả *dự án*, không mô tả *app đang chạy trong container* — lọc catalog theo
`ruby` không trả lời được câu hỏi nào người dùng thực sự hỏi.

## Còn nợ

- **Tag của ba manifest có sẵn chưa theo quy ước này.** `nginx`/`caddy-static`
  dùng `web`, `whoami` dùng `chẩn-đoán` — tiếng Việt, và không có trong
  `topics.json`. Catalog đang trộn hai quy ước. Đổi chúng là sửa dữ liệu đã
  phát hành nên để lại thành một quyết định riêng.
- **Label hiển thị chưa được nối vào UI.** `topics.json` có sẵn nhãn `vi`/`en`,
  nhưng `keenrig-web` và Admin UI vẫn render tag thô. Nối vào là một thay đổi ở
  tầng i18n, không phải ở tầng dữ liệu.
- **Mô tả của app nhập vào là tiếng Anh** (lấy nguyên từ nguồn), trong khi ba
  manifest có sẵn viết tiếng Việt. `mapping.json` cho phép ghi đè `description`
  từng app — `zipkin` đã viết lại tiếng Việt, phần còn lại thì chưa.
- **App nhập vào chưa có icon.** devopsbookmarks không mang logo, và bịa một
  logo cho phần mềm của người khác là chuyện nhãn hiệu chứ không phải chuyện dữ
  liệu. `keenrig-web` bỏ qua icon rỗng không lỗi (`{icon && …}` trong
  `apps/page.tsx`) nên chỉ lệch về mặt nhìn: ba thẻ có icon, thẻ mới thì không.
  Admin UI không hiển thị icon nên không ảnh hưởng.
- **40 entry `unmapped`.** Chưa ai tra image, cổng, đường health cho chúng.
  `out/REPORT.md` liệt kê đủ tên để làm tiếp.
