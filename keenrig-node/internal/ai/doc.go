// Package ai — trợ lý AI phía instance: chat SSE, tool-calling vào API nội bộ,
// approval queue, MCP server, job chẩn đoán sự cố.
//
// Provider là plugin (claude-cloud qua Keenrig Cloud (`llmproxy`), ollama, openai-compat);
// instance không có provider vẫn dùng được AI của Console vì phần đó chạy hoàn toàn phía
// cloud — hai đường khác nhau, đừng gộp.
// Ràng buộc: mọi hành động sinh ra từ tool-calling phải đi qua approval queue rồi mới
// chạm `apps`/`api` — LLM không được ghi thẳng desired state.
// Luật 2 (fault-isolation, thu hẹp ở V2-DELTA §3): xử lý context lớn chạy process con,
// không để OOM kéo sập box.
// Nguồn tín hiệu chẩn đoán là health monitor của `reconciler`, không phải đọc log file.
//
// TODO(M4): chưa implement.
package ai
