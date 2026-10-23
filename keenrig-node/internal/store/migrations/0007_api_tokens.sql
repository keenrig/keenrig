-- Migration 0007 — API token (ID-04). Vẫn EXPAND–CONTRACT: chỉ THÊM bảng mới.
--
-- # Vì sao KHÔNG dùng lại bảng sessions
--
-- Phiên và token trông giống nhau (đều là bí mật mang theo request) nhưng vòng
-- đời đối lập: phiên ngắn, tự gia hạn, chết khi đổi mật khẩu; token dài, do
-- người dùng đặt hạn, và PHẢI SỐNG SÓT qua lần đổi mật khẩu — nếu không thì
-- mọi script CI của người vận hành hỏng mỗi lần họ đổi mật khẩu.
--
-- Nhét cả hai vào một bảng nghĩa là mỗi câu truy vấn phải nhớ lọc thêm một cột
-- "loại", và chỗ nào quên lọc là một lỗ. Hai bảng thì quên là lỗi biên dịch.

CREATE TABLE api_tokens (
    -- token_hash: SHA-256 của token trần. Cùng lý do với sessions — bảng này đi
    -- vào mọi bản backup, và lưu token trần nghĩa là ai đọc được một backup cũ
    -- là gọi được API bằng quyền của chủ token.
    token_hash TEXT PRIMARY KEY,
    -- id: khoá công khai để REVOKE. Không dùng token_hash làm id vì UI phải
    -- hiện được danh sách token và cho bấm xoá, mà đưa hash ra UI là đưa ra thứ
    -- chỉ cần một lần tra bảng cầu vồng... không, hash SHA-256 của 256 bit
    -- ngẫu nhiên thì không dò được. Lý do thật đơn giản hơn: id ổn định và ngắn,
    -- hash thì dài và trông như một bí mật — người vận hành sẽ ngại dán nó vào
    -- ticket, và ta muốn họ dán được.
    id         TEXT NOT NULL UNIQUE,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- name: người đặt, để biết token nào của việc gì lúc cần thu hồi.
    name       TEXT NOT NULL DEFAULT '',
    -- scopes: quyền của RIÊNG token, luôn là TẬP CON quyền của user tại thời
    -- điểm tạo. Ràng buộc tập con được ép ở tầng service, không ở đây — SQLite
    -- không biểu diễn được nó, và một CHECK sai còn tệ hơn không có CHECK.
    scopes     TEXT NOT NULL DEFAULT '',

    -- expires_at NOT NULL — token vô hạn là thứ lộ ra rồi vẫn còn giá trị sau
    -- ba năm. Muốn "không hết hạn" thì đặt hạn xa, và lúc đó nó nằm trong danh
    -- sách để người vận hành nhìn thấy chứ không ẩn dưới một ô NULL.
    expires_at TEXT NOT NULL,

    -- allowed_ip_cidrs: CSV các dải CIDR được phép gọi. RỖNG = mọi IP.
    --
    -- Rỗng-là-mọi-IP chứ không phải rỗng-là-cấm-hết: mặc định phải là thứ chạy
    -- được, nếu không thì mọi token vừa tạo đều chết và người dùng học cách
    -- điền 0.0.0.0/0 vào — tức là biến tính năng thành nghi thức vô nghĩa.
    allowed_ip_cidrs TEXT NOT NULL DEFAULT '',

    created_at   TEXT NOT NULL,
    -- last_used_*: để trả lời "token này còn ai dùng không" TRƯỚC khi thu hồi.
    -- Không có nó thì mọi lần dọn dẹp đều là đánh cược.
    last_used_at TEXT,
    last_used_ip TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);
CREATE INDEX idx_api_tokens_expiry ON api_tokens (expires_at);
