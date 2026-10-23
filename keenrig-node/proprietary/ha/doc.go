// Package ha — chế độ standby và chuyển đổi vai trò cho nấc HA T1 phía instance.
//
// Gồm: điều phối PG streaming replica + litestream restore chu kỳ + rsync volume app,
// promote/demote có fencing, sinh cấu hình WireGuard cho đường giữa hai node.
// Ràng buộc: fencing dựa trên lease của reconciler (Luật 8) — hai box cùng lái một Docker
// daemon là hỏng thật, không phải giả thuyết (LS-01/LS-02). Không có lease thì promote chỉ
// là đổi nhãn.
// `/readyz` phải phản ánh vai trò: standby là "sống nhưng chưa sẵn sàng nhận traffic",
// khác hẳn "treo" — đó là lý do Luật 7 tách readyz khỏi healthz.
// Gate bằng `license.features.ha_t1`.
//
// TODO(M6): chưa implement.
package ha
