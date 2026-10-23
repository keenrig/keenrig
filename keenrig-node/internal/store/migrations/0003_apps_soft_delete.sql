-- Xoá app 2 pha: DeleteApp chỉ đánh dấu deleted_at, reconciler dọn container
-- (runtime.Remove) rồi mới PurgeApp xoá hẳn row. Crash giữa chừng → row còn
-- deleted_at nên tick sau vẫn dọn tiếp (không có container mồ côi).
ALTER TABLE apps ADD COLUMN deleted_at TEXT;

CREATE INDEX idx_apps_deleted ON apps (deleted_at);
