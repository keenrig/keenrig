// Địa chỉ Keenrig Console mà Admin trỏ link tới.
//
// Admin KHÔNG gọi API nào của cloud — đây chỉ là chỗ dựng URL cho thẻ <a>.
// Máy đã pair: agent báo `cloud_url` (= KEENRIG_CLOUD_URL, mặc định
// https://console.keenrig.com — keenrig-node-installer/get.sh) qua GET
// /api/v1/cloud, nên dùng đúng control plane máy này đang nói chuyện. Máy
// standalone: Console mặc định — người dùng đăng nhập ở đó là xong.
export const CONSOLE_URL = 'https://console.keenrig.com'

export function consoleBase(link) {
  const u = (link?.cloud_url || '').trim()
  if (!/^https?:\/\/[^/]+/i.test(u)) return CONSOLE_URL
  return u.replace(/\/+$/, '')
}

// Trang "Xin thêm app" của Console (form + bảng bình chọn). `from=admin` để
// Console biết người ta đến từ đâu; `name` điền sẵn ô tên app.
export function requestAppUrl(base, name) {
  const p = new URLSearchParams({ from: 'admin' })
  const n = (name || '').trim()
  if (n) p.set('name', n)
  return `${base || CONSOLE_URL}/request-app?${p}`
}
