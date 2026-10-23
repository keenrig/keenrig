-- Migration 0006 — khoá thao tác + tiến độ job. Vẫn EXPAND-ONLY.
--
-- Mỗi khoá là một HÀNG, khoá chính là tên thao tác — giành khoá là một câu
-- INSERT nguyên tử, SQLite tự phân xử khi hai bên cùng giành.

-- locks — khoá theo TÊN THAO TÁC, có chủ và có hạn.
--
-- Vì sao cần dù đã có bảng `leases`: hai thứ trả lời hai câu khác nhau.
--   leases: "ai được LÀM VIỆC LIÊN TỤC" (một reconciler duy nhất, gia hạn mãi)
--   locks:  "thao tác A và B có được CHẠY CÙNG LÚC không" (hữu hạn, có ma trận
--           tương thích)
-- Gộp chung sẽ buộc backup phải giành lease của reconciler, tức là dừng hẳn
-- vòng hội tụ trong suốt lần backup.
--
-- expires_at là HÀNG RÀO CUỐI, không phải cơ chế chính: chủ sở hữu phải tự nhả.
-- Nó tồn tại cho đúng một trường hợp — tiến trình giữ khoá chết giữa chừng —
-- và nếu không có nó thì một lần crash sẽ khoá vĩnh viễn tính năng backup.
CREATE TABLE locks (
    name       TEXT PRIMARY KEY,
    holder     TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_locks_holder ON locks (holder);
CREATE INDEX idx_locks_expiry ON locks (expires_at);

-- jobs.percent/message — tiến độ để UI hiển thị được.
--
-- Một job chạy 20 phút mà API chỉ trả
-- "running" thì người dùng không phân biệt được "đang chạy" với "đã treo", và
-- họ sẽ bấm lại. Hai cột này là toàn bộ khác biệt giữa hai trạng thái đó.
ALTER TABLE jobs ADD COLUMN percent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN message TEXT NOT NULL DEFAULT '';

-- jobs.finished_at — mốc kết thúc, để janitor dọn job cũ theo tuổi.
-- Không có nó thì bảng jobs phình vô hạn.
ALTER TABLE jobs ADD COLUMN finished_at TEXT;
