// Package notifications — thông báo cho người dùng của instance: sắp hết hạn license,
// cert renew hỏng, app unhealthy, backup thất bại.
//
// Tách khỏi `events` là quyết định có lý do, không phải chia nhỏ cho đẹp: notification có
// trạng thái đã-đọc, có gộp trùng (một app flap 50 lần vẫn là một thông báo), có kênh gửi
// (UI, email qua cloud) và có thể xoá. Audit event thì bất biến và không được gộp.
// Ràng buộc: package này ĐỌC từ events/health monitor để sinh thông báo, chiều ngược lại
// không tồn tại — gửi thông báo hỏng không được phép làm mất bản ghi audit.
// Gửi email đi qua cloud (Keenrig Cloud (`email`)); instance không tự nói SMTP.
//
// TODO(P1): chưa implement. Nhãn cũ ghi M2 — SAI: không gate M2 nào phủ package
// này. Gate thật là `DC-04` (template mời/nhắc license/cảnh báo gửi đúng, có
// unsubscribe hợp lệ), mức P1 — tức bắt buộc trước GA, không phải trước M2.
package notifications
