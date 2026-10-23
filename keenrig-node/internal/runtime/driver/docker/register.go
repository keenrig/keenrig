package docker

import (
	"context"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

// Name — tên driver trong registry.
const Name = runtime.DriverDocker

// Đăng ký driver mặc định. Factory bỏ qua Config.DSN nếu rỗng và dùng
// client.FromEnv (DOCKER_HOST) — đó vẫn là cách chuẩn để trỏ tới daemon khác,
// nên không cần thêm cú pháp DSN riêng cho driver này.
func init() {
	runtime.Register(Name, func(ctx context.Context, cfg runtime.Config) (runtime.Runtime, error) {
		// Layout đi xuống driver: từ khi có `volumes`, driver phải map tên
		// volume → thư mục THẬT trên máy chủ, và nó chỉ được lấy đường dẫn từ
		// paths.Layout — không từ DSN, không từ env. Cùng luật với proxy.Config.
		return NewWithLayout(ctx, cfg.Layout)
	})
}
