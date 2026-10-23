// Package backup — sao lưu/khôi phục instance và từng app.
//
// Hai seam, tách nhau CÓ CHỦ ĐÍCH, một lớp bọc ở giữa, và một caller gom cả ba:
//
//	snapshot        GOM instance thành nhiều phần rồi đẩy đi.          BK-02 ✔
//	format.Format   ĐÓNG GÓI thế nào (tgz → restic).                   BK-02 ✔ (seam)
//	crypt           MÃ HOÁ bằng passphrase riêng.                      BK-02 ✔
//	target.Target   NƠI đặt bytes (dir → s3 → sftp → cloud-managed).   BT-01 ✔
//
// `snapshot` KHÔNG phải seam thứ ba — nó là người dùng ba lớp kia, và nó là chỗ
// duy nhất biết một instance gồm những gì.
//
// "Lưu ở đâu" và "đóng gói thế nào" đổi độc lập. Gộp lại thì thêm một target phải
// viết lại toàn bộ phần nén/dedup, và đổi từ tgz sang restic phải sửa mọi driver.
//
// `crypt` KHÔNG phải seam thứ ba — nó là một lớp bọc stream, và nó nằm giữa hai
// seam vì đó là chỗ duy nhất đúng: nhét vào tgz thì driver format thứ hai phải
// viết lại, nhét vào s3 thì driver `dir` sẽ không có mã hoá.
//
// Phạm vi restore theo FILESYSTEM.md: `instance/` + `node/` (chọn lọc) + `apps/`.
// KHÔNG khôi phục `bin/` — installer tải lại đúng version ghi trong `VERSION`.
// `node/backup/` chỉ chứa METADATA snapshot; archive thật nằm ở Target.
// restic và litestream chạy bằng exec process con (Luật 2), không nhúng thư viện.
//
// # Trạng thái
//
//	BT-01  ✔  target.Target + targettest + driver dir + driver s3.
//	          dir chạy trên filesystem thật, s3 chạy trên MinIO THẬT.
//	          Nhánh NAS(smb) dùng chính driver dir — xem cảnh báo về tính nguyên
//	          tử của rename trên CIFS ở godoc driver/dir.
//	          Nhánh cloud-managed CHƯA có: keenrig-cloud chưa có endpoint nhận
//	          bản sao lưu (M5).
//	BK-01  ✔  ở tầng addon (addontest → BackupRestoreRoundTrip).
//	BK-05  ✔  ở tầng addon (addontest → CredsPerAppAreDistinct).
//	BK-02  ~  seam format.Format + formattest + driver tgz XONG. 18 subtest dùng
//	          chung + 12 test riêng của tgz, chạy trên Linux THẬT (cả uid≠0 lẫn
//	          root): mode, symlink, uid/gid, và zip-slip qua BA cửa — tên entry,
//	          symlink làm thành phần cha, và entry thư mục trùng tên symlink.
//	          Lớp `crypt` xong: AES-256-GCM theo chunk, khoá dẫn xuất từ
//	          KEENRIG_BACKUP_PASSPHRASE bằng argon2id. `master.key` NẰM TRONG
//	          snapshot — chốt 2026-08-12, lý lẽ ở WORKING-STATE.md §3.
//	          `snapshot` xong: Create/List/Load/Restore + ba lệnh
//	          `keenrig-box backup | backups | restore`. Vòng rebuild T0 đã chạy
//	          THẬT: sao lưu → restore lên thư mục trắng → box khởi động → tài
//	          khoản owner đăng nhập được bằng mật khẩu cũ.
//	          CÒN NỢ: dump addon chưa gắn vào lệnh (cần provisioner + Docker,
//	          thuộc jobs.Worker), và **"RTO đo được <30′ trên VM sạch"** — phần
//	          đó cần khung VM nightly, chưa có. Gate BK-02 do đó CHƯA đóng.
//	BK-03  —  WAL archive cho postgres, RPO ≤5 phút.
//	BK-04  —  litestream + kill -9 lặp 100 lần: cần khung chaos, chưa có.
//
// # Metadata snapshot ghi ba thứ, không phải một
//
// Rút ra từ chính ba lớp trên, và mỗi thứ đóng một cửa hỏng:
//
//	tên format     restore mở đúng driver, KHÔNG đọc từ biến môi trường —
//	               đổi biến mà làm snapshot cũ mở không được là mất dữ liệu.
//	đã mã hoá hay  archive cũ chưa mã hoá vẫn phải restore được, và thông báo
//	chưa           phải nói đúng "bản này không mã hoá" thay vì "sai passphrase".
//	băm PLAINTEXT  `tgz` cố ý tất định để so hai bản bằng một phép băm; salt ngẫu
//	               nhiên của `crypt` xoá tính chất đó ở tầng ciphertext. Ghi băm
//	               của archive TRƯỚC khi mã hoá thì giữ lại được — và nó là thứ
//	               duy nhất bắt được "Target trả đúng số byte của object KHÁC".
package backup
