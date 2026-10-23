import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Build ra `dist/`, và keenrig-box nhúng thư mục đó vào binary (ui/embed.go).
//
// Vì sao nhúng chứ không serve từ đĩa: bố cục thư mục runtime nói rằng
// <base>/bin bị THAY NGUYÊN KHỐI mỗi lần update, còn ba mặt phẳng còn lại phải
// sống sót. Asset UI là CODE, không phải state — để nó ngoài binary sẽ tạo ra
// một thứ vừa phải update cùng bin vừa nằm ngoài bin, tức là một đường lệch
// phiên bản giữa UI và API.
export default defineConfig({
  plugins: [vue()],
  // base tương đối: Admin có thể được phục vụ sau một reverse proxy ở đường dẫn
  // con, và đường dẫn tuyệt đối sẽ hỏng ngay khi đó.
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Không sinh sourcemap cho bản phát hành: nó nhân đôi kích thước thứ được
    // nhúng vào binary mà chỉ có ích khi debug bản dev.
    sourcemap: false,
  },
  server: {
    proxy: {
      // `npm run dev` gọi thẳng box đang chạy — không cần build lại Go để sửa UI.
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: false },
    },
  },
})
