// Package cluster — bootstrap/join cụm k3s và quản lý vòng đời của nó (server/agent,
// embedded etcd từ 3 node trở lên).
//
// Đây là điều kiện hạ tầng cho `proprietary/runtime/k8s` (seam #2, M7) — package này lo việc
// DỰNG cụm, không lo việc chạy app trên cụm; đừng trộn hai thứ.
// Gate bằng license: `license.schema.json` có `features.runtime` enum [docker, swarm, k8s]
// và `max_nodes` — join quá hạn mức phải bị từ chối ở đây, không đợi k3s báo lỗi.
// Điều kiện tiên quyết: lease của reconciler (Luật 8) phải chạy đúng trước khi có nhiều
// node, nếu không sẽ có hai reconciler cùng lái một cụm.
//
// TODO(M7): chưa implement.
package cluster
