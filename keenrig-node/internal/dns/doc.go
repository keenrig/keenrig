// Package dns — seam #4 (`dns.Provider`): tạo/xoá bản ghi DNS cho domain của app.
//
// Phạm vi hẹp có chủ đích: seam này dành cho instance KHÔNG link cloud (self-managed
// domain). Instance đã pair thì cloud lo DNS + wildcard cert qua Keenrig Cloud (`dns`),
// và provider ở đây chạy chế độ `noop`/`manual` — chỉ báo cho người vận hành biết cần trỏ
// bản ghi nào.
// Impl dự kiến: noop, manual, rồi cloudflare. Cần conformance `dnstest/` trước khi có
// provider thứ hai (V2-DELTA §5).
// Không có DNS resolver nhúng trong kiến trúc (V2-DELTA §2.1): bind `:53` cần thêm quyền và
// OTA restart sẽ giết DNS của mọi container. Package này chỉ nói chuyện với DNS bên ngoài.
//
// TODO(M3): chưa implement. Nhãn cũ ghi M2 — SAI: không gate M2 nào phủ package
// này. Gate thật là `DC-01` (wildcard cert DNS-01 → push xuống instance, đo <60s)
// và `DC-02` (flip A record khi rebuild/failover), cả hai P0-M3.
package dns
