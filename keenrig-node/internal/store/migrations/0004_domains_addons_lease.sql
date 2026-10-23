-- Migration 0004 — gộp bốn thứ T7/T8/lease cần, viết theo EXPAND–CONTRACT
-- (V2-DELTA §7 điều kiện 5): TOÀN BỘ thay đổi ở đây là THÊM (bảng mới + cột
-- mới nullable). Không đổi kiểu, không đổi tên, không thêm NOT NULL vào bảng
-- đang có. Nhờ vậy box bản CŨ đọc cùng platform.db trong cửa sổ OTA vẫn chạy
-- được — nếu không, rollback thành bất khả thi và `min_upgradable_from` vô nghĩa.

-- 1. app_domains — UNIQUE fqdn Ở TẦNG DB, không phải chỉ ở tầng service.
--
-- Vì sao ràng buộc phải nằm dưới DB: hai request POST /apps cùng lúc xin cùng
-- FQDN sẽ cùng đọc thấy "chưa ai dùng" nếu chỉ kiểm bằng SELECT rồi INSERT.
-- Hai app cùng trỏ một tên miền thì gateway nhận hai site trùng FQDN — hỏng
-- im lặng, và cái nào thắng là tuỳ thứ tự Apply.
--
-- fqdn lưu đã CHUẨN HOÁ (lowercase, không dấu chấm cuối) — tầng domains lo
-- việc đó; UNIQUE ở đây phân biệt hoa thường nên chuẩn hoá là bắt buộc.
--
-- ON DELETE CASCADE ăn theo PurgeApp (pha 2 của xoá 2 pha). Trong pha 1 app
-- chỉ có deleted_at nên domain VẪN CÒN giữ chỗ — đúng ý: tên miền chưa được
-- giải phóng khi container cũ chưa dọn xong, hệt như slug.
CREATE TABLE app_domains (
    app_id     TEXT NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    fqdn       TEXT NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    cert_ref   TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (app_id, fqdn)
);

CREATE UNIQUE INDEX idx_app_domains_fqdn ON app_domains (fqdn);

-- Một app chỉ được có ĐÚNG MỘT domain chính. Partial unique index làm được
-- việc đó mà không cấm nhiều domain phụ.
CREATE UNIQUE INDEX idx_app_domains_primary ON app_domains (app_id) WHERE is_primary = 1;

-- 2. app_addons — addon nào đã cấp cho app nào, và credential nằm ở đâu.
--
-- config_ref là KHOÁ TRA CỨU vào bảng secrets, không phải credential. Mật khẩu
-- postgres của app không được nằm ở bảng này: bảng này bị đọc bởi mọi đường
-- liệt kê app, còn secrets đi qua keystore AES-256-GCM.
CREATE TABLE app_addons (
    app_id     TEXT NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    addon      TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'pending'
               CHECK (state IN ('pending', 'ready', 'error')),
    config_ref TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (app_id, addon)
);

-- 3. jobs.lease_until — visibility timeout (LS-03).
--
-- Trước migration này ClaimJob đặt state='running' và không có gì đưa job trở
-- lại: worker chết giữa chừng thì job kẹt 'running' VĨNH VIỄN. Nay ClaimJob ghi
-- kèm hạn giữ; ReclaimExpired đưa job quá hạn về 'queued'.
--
-- Cột nullable, mặc định NULL = "không có hạn" — job đang running do box bản cũ
-- claim trước lúc migrate sẽ không bị cướp mất giữa chừng.
ALTER TABLE jobs ADD COLUMN lease_until TEXT;
ALTER TABLE jobs ADD COLUMN lease_owner TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_jobs_lease ON jobs (state, lease_until);

-- 4. leases — lease có FENCING TOKEN cho reconciler (LS-01/02).
--
-- Vì sao cần ngay chứ không phải "phòng xa cho nấc 1": cửa sổ OTA (drain box cũ
-- → khởi động box mới) làm hai tiến trình box chồng nhau vài giây. Hai
-- reconciler cùng lái MỘT dockerd là hỏng thật — cả hai cùng thấy app lệch rev,
-- cùng gọi Apply, cùng dựng container thay thế.
--
-- token tăng đơn điệu mỗi lần lease ĐỔI CHỦ (không tăng khi gia hạn). Đây là
-- fencing token của Fowler/Kleppmann: chủ cũ bị treo GC 30 giây rồi tỉnh dậy
-- vẫn tin mình giữ lease, nhưng token của nó đã cũ. Chỉ đối chiếu expires_at là
-- KHÔNG đủ, vì đồng hồ và stop-the-world không cho ta biên an toàn nào cả.
CREATE TABLE leases (
    name       TEXT PRIMARY KEY,
    holder     TEXT NOT NULL,
    token      INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 5. apps.endpoints — địa chỉ IP:port các replica đang chạy, do reconciler ghi
-- sau mỗi lần Apply (T6c).
--
-- Cột JSON trên apps chứ không phải bảng riêng, vì tập endpoint là DẪN XUẤT và
-- luôn được thay NGUYÊN KHỐI theo từng app (level-triggered, giống proxy.Apply).
-- Bảng riêng sẽ mời gọi cập nhật từng dòng, và cập nhật từng dòng chính là chỗ
-- sinh ra endpoint mồ côi khi số replica giảm.
--
-- Đây cũng là ranh giới §2.1: reconciler GHI, httpd chỉ ĐỌC — httpd không được
-- import runtime.
ALTER TABLE apps ADD COLUMN endpoints TEXT;
