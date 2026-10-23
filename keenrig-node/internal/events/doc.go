// Package events — audit log append-only của instance: ai làm gì, lúc nào, trên tài
// nguyên nào.
//
// Tách khỏi `notifications` vì hai mục đích khác nhau: audit là bằng chứng bất biến, không
// có trạng thái đã-đọc, không gộp, không xoá; notification thì ngược lại — nên hai bảng.
// Ghi xuyên tiến trình (`POST /node/v1/events` từ agent/ota) BẮT BUỘC `Idempotency-Key`:
// key trùng trả 409 và không sinh event trùng (ND-03, điều kiện §7.6) — agent sẽ retry mỗi
// lần mạng chớp.
// Store hiện đã có `AppendEvent`; package này là tầng truy vấn/phân loại/giữ hạn trên đó.
//
// TRẠNG THÁI (2026-08-12): package này VẪN CHỈ CÓ doc.go — nhãn `TODO(M1)` cũ nói sai.
// Việc ghi event đã chạy thật từ M1 nhưng đi THẲNG qua `store.AppendEvent` từ
// apps/certs/identity/jobs, và `GET /api/v1/events` đọc thẳng từ store. Thứ chưa có là
// tầng truy vấn/phân loại/giữ hạn mô tả ở trên.
//
// TODO(M3): cần cho `ND-03` (ghi event xuyên tiến trình, `Idempotency-Key` → 409).
// Và cần vì một lý do đã đo được: không chỗ nào GỘP event lặp, nên một vòng lặp lỗi
// ghi thẳng vào bảng events mà không gì hãm — driver `nginx` từng ghi
// `proxy.apply_failed` mỗi 15 giây, ~518.000 dòng sau 90 ngày retention.
package events
