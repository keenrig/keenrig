// Package updater — phần PHÍA BOX của luồng tự cập nhật. Việc thay binary đã chuyển sang
// tiến trình riêng `cmd/keenrig-ota` (V2-DELTA §2.1), package này không làm việc đó.
//
// Lý do tách: một tiến trình không thể thay thế đáng tin cậy chính binary nó đang chạy.
// Phần còn lại ở box: xử lý `POST /node/v1/drain` và `/resume` (ngừng nhận việc mới, chờ
// việc đang chạy xong — hết timeout mà còn việc thì trả 503 để ota HUỶ update, OT-02),
// báo cáo version/`INFRA_VERSION`, cohort check, và snapshot DB trước khi chạy migration.
// Ràng buộc: migration phải expand–contract (điều kiện §7.5) — box cũ và box mới đọc chung
// một `platform.db` trong cửa sổ chuyển giao; migration phá tương thích ngược làm rollback
// bất khả thi (OT-05), và đó cũng là lý do `Release` có `min_upgradable_from`.
//
// TODO(M5): chưa implement.
package updater
