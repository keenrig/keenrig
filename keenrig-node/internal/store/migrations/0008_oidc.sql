-- Migration 0008 — OpenID Connect provider (ID-01). Vẫn EXPAND–CONTRACT: chỉ THÊM bảng mới.
--
-- # Keenrig là NHÀ CUNG CẤP danh tính, không phải bên tiêu thụ
--
-- Chiều của luồng quyết định toàn bộ thiết kế bên dưới: app cài trên nền tảng
-- (Grafana, Nextcloud, một dashboard nội bộ) đăng nhập BẰNG tài khoản Keenrig.
-- Nên ở đây ta giữ khoá ký, cấp mã uỷ quyền, và chịu trách nhiệm cho mọi thứ
-- một IdP chịu trách nhiệm — chứ không phải lưu token của Google.
--
-- Hệ quả trực tiếp: một lỗi ở hai bảng này không làm hỏng một app, nó làm hỏng
-- ĐĂNG NHẬP CỦA MỌI APP. Đó là lý do mọi cột dưới đây được giải thích.

-- oidc_clients — mỗi app được phép SSO là một client.
--
-- Client được cấp bởi nền tảng lúc cài app, KHÔNG phải bằng dynamic client
-- registration (RFC 7591). Đăng ký động nghĩa là bất kỳ ai gọi được endpoint
-- đều tự tạo được một client hợp lệ, và trên một box tự lưu trữ thì "bất kỳ ai"
-- gồm cả mọi app đang chạy trên chính máy đó.
CREATE TABLE oidc_clients (
    client_id  TEXT PRIMARY KEY,

    -- app_id: client thuộc app nào. ON DELETE CASCADE — gỡ app là gỡ luôn quyền
    -- đăng nhập của nó. Không cascade thì một client mồ côi vẫn cấp được token
    -- mang danh tính người dùng, cho một app không còn tồn tại.
    --
    -- NULL được phép: client cấp bằng tay cho một dịch vụ ngoài box (một app
    -- chạy trên máy khác) không gắn với app nào ở đây.
    app_id     TEXT REFERENCES apps (id) ON DELETE CASCADE,

    -- name: hiện cho người dùng biết họ đang đăng nhập vào ĐÂU.
    name       TEXT NOT NULL DEFAULT '',

    -- secret_ref: khoá tra cứu vào bảng secrets, KHÔNG phải secret.
    --
    -- Cùng luật với AppAddon.ConfigRef và User.TOTPRef. Client secret đủ để đổi
    -- một mã uỷ quyền lấy token, nên nó phải nằm sau master.key như mọi bí mật
    -- khác — không phải trong một cột mà `SELECT *` nào cũng đọc được.
    secret_ref TEXT NOT NULL,

    -- redirect_uris: CSV, so khớp CHÍNH XÁC từng ký tự.
    --
    -- Không wildcard, không so khớp tiền tố. Đây là chỗ mà mọi hướng dẫn OAuth
    -- đều cảnh báo và vẫn có người làm sai: cho phép `https://app.example.com/*`
    -- nghĩa là một open redirect bất kỳ trên chính domain đó biến thành đường
    -- lấy mã uỷ quyền của người dùng.
    redirect_uris TEXT NOT NULL DEFAULT '',

    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_oidc_clients_app ON oidc_clients (app_id);

-- oidc_codes — mã uỷ quyền, sống vài chục giây và dùng ĐÚNG MỘT LẦN.
--
-- # Vì sao lưu HASH chứ không lưu mã
--
-- Cùng lý do với sessions và api_tokens: bảng này đi vào mọi bản sao lưu. Khác
-- một điểm — mã chỉ sống 60 giây, nên rủi ro nhỏ hơn nhiều. Vẫn băm, vì cái giá
-- là một dòng code và không có lý do nào để một bí mật nằm trần.
CREATE TABLE oidc_codes (
    code_hash    TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL REFERENCES oidc_clients (client_id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- redirect_uri: URI mà mã này ĐÃ được cấp cho.
    --
    -- Lưu lại để bước đổi token kiểm nó khớp với URI client gửi lên. Không kiểm
    -- lại ở bước hai thì một client bị lộ secret đổi được mã của người dùng về
    -- một URI khác — chính lỗ mà RFC 6749 §4.1.3 bắt buộc chặn.
    redirect_uri TEXT NOT NULL,

    scope        TEXT NOT NULL DEFAULT '',

    -- nonce: do RP sinh, đi thẳng vào ID token.
    --
    -- Nó là thứ cho RP biết ID token này trả lời ĐÚNG yêu cầu đăng nhập nó vừa
    -- gửi, chứ không phải một ID token cũ bị phát lại.
    nonce        TEXT NOT NULL DEFAULT '',

    -- code_challenge: PKCE S256, BẮT BUỘC (xem godoc package oidc).
    code_challenge TEXT NOT NULL,

    -- auth_time: lúc người dùng THẬT SỰ đăng nhập, không phải lúc cấp mã.
    --
    -- RP dùng nó với `max_age` để tự quyết định có bắt đăng nhập lại không. Lấy
    -- nhầm thành thời điểm cấp mã sẽ làm mọi phiên trông như vừa mới đăng nhập.
    auth_time    TEXT NOT NULL,

    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_oidc_codes_expiry ON oidc_codes (expires_at);
