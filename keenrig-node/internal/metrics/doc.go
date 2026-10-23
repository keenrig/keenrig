// Package metrics — thu thập và phơi metric Prometheus của box tại `/metrics`.
//
// Luật 7 buộc `/healthz` + `/readyz` + `/metrics` có trên MỌI tiến trình, nên phần chung
// (registry, tên metric, nhãn) nằm ở đây để `cmd/keenrig-agent` và `cmd/keenrig-ota` dùng
// lại — ba tiến trình phải cùng quy ước tên, nếu không fleet aggregation phía cloud sẽ vá.
// Ràng buộc: agent lấy số liệu app QUA node API, không scrape trực tiếp Docker và không
// đọc `node/logs/` (Luật 5, ND-05). Package này là nguồn cho `metrics_summary`
// trong `sync.schema.json`.
// Metric bắt buộc có từ M1: tuổi lease của reconciler, độ trễ hàng đợi jobs, kết quả Apply
// theo driver proxy — ba thứ mà không có thì sự cố chỉ nhìn thấy sau khi khách báo.
//
// TRẠNG THÁI (2026-08-12): cả ba đã có — `keenrig_reconciler_lease_age_seconds`,
// `keenrig_jobs_queue_lag_seconds`, `keenrig_proxy_apply_total{driver,result}`.
// Xem godoc từng hàm Set* trong metrics.go và test khoá TÊN ở required_test.go.
//
// Chúng được thêm muộn, và cái giá của việc thiếu đã đo được: driver `nginx` chọn
// được nhưng không định tuyến gì, mỗi 15 giây ghi một event lỗi vào platform.db,
// không ai thấy trong nhiều tháng. `keenrig_proxy_apply_total{result="error"}`
// tăng đều sẽ tự nói ra ngay từ phút đầu.
//
// CÒN NỢ (OB-01, P0-M3): danh mục đầy đủ theo V1 §9 + test snapshot tên metric.
// Ba cái trên là nền, không phải toàn bộ.
package metrics
