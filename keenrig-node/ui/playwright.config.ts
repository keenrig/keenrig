import { defineConfig } from '@playwright/test'

// Bộ đo UI của Keenrig Admin — chạy trên keenrig-box THẬT, artifact THẬT.
//
// # Khác bộ Console một điểm bản chất: KHÔNG có dev server
//
// Console test qua vite dev + proxy vì cloud là tiến trình riêng. Admin thì
// chính keenrig-box serve SPA đã build (go:embed dist/) — nên bộ này build UI,
// build binary Go, chạy binary, và đo ĐÚNG thứ sẽ đến tay người dùng. Một lỗi
// chỉ có ở bản build (chunk hỏng, asset lệch đường dẫn, embed thiếu file) sẽ
// lộ ra ở đây chứ không phải ở khách.
//
// Không cần Docker: box chạy --reconcile=false — mọi gate UI đo ở đây là về
// hình dạng + API, không về container. UI-01 đo "app xuất hiện và desired
// được ghi", nửa "container sống <60s" thuộc bộ e2e của keenrig-tests.
export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:18085',
    locale: 'vi-VN',
    trace: 'retain-on-failure',
  },
})
