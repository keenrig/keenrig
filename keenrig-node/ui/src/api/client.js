// Client mỏng cho /api/v1.
//
// Kiểu dữ liệu SINH TỪ instance.yaml (`npm run gen:api` → src/api/schema.d.ts),
// nên khi hợp đồng đổi mà UI chưa theo thì tsc báo — không phải đợi tới lúc
// người dùng bấm nút. Bản thân client thì viết tay: sinh cả tầng gọi từ OpenAPI
// kéo theo một runtime lớn hơn toàn bộ Admin, để đổi lấy vài dòng fetch.
//
// Xác thực đi bằng COOKIE phiên (HttpOnly). Vì vậy không có chỗ nào trong UI
// chạm được token — đúng ý đồ: một lỗ XSS không lấy được thứ nó không đọc được.

const BASE = '/api/v1'

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error || `HTTP ${status}`)
    this.status = status
    this.code = body?.code || ''
    this.body = body
  }
}

async function request(method, path, body) {
  const res = await fetch(BASE + path, {
    method,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    // same-origin: Admin luôn được chính box serve. 'include' sẽ gửi cookie
    // sang cả origin khác nếu ai đó cấu hình nhầm — không cần thì đừng mở.
    credentials: 'same-origin',
  })
  if (res.status === 204) return null
  const text = await res.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = { error: text }
    }
  }
  if (!res.ok) throw new ApiError(res.status, data)
  return data
}

export const api = {
  // auth
  setupStatus: () => request('GET', '/auth/setup'),
  instance: () => request('GET', '/instance'),
  // cloud — trạng thái pair như AGENT báo về (AD-12). Khác /instance, đường
  // này đòi phiên: nó lộ URL cloud + env id. 501 trên box cũ chưa nối.
  cloud: () => request('GET', '/cloud'),
  // pairCloud — dán join token từ Console; box nhờ pair.sh (root) đổi lấy khoá
  // agent. 202 = Console đã nhận máy; trạng thái `synced` đến sau, qua /cloud.
  pairCloud: (token) => request('POST', '/cloud/pair', { token }),
  createOwner: (username, password) => request('POST', '/auth/setup', { username, password }),
  login: (username, password, totp) => request('POST', '/auth/login', { username, password, totp }),
  logout: () => request('POST', '/auth/logout'),
  me: () => request('GET', '/auth/me'),
  // Tài khoản của chính mình (Settings › Đăng nhập). enroll trả otpauth_uri;
  // TOTP chỉ BẬT sau confirm với một mã đúng — enroll một mình không khoá ai.
  totpEnroll: () => request('POST', '/auth/totp/enroll', {}),
  totpConfirm: (code) => request('POST', '/auth/totp/confirm', { code }),
  totpDisable: (password) => request('POST', '/auth/totp/disable', { password }),
  // Đổi mật khẩu thu hồi MỌI phiên, kể cả phiên này: UI phải đưa về đăng nhập.
  changePassword: (oldPassword, newPassword) =>
    request('POST', '/auth/password', { old_password: oldPassword, new_password: newPassword }),

  // apps
  listApps: () => request('GET', '/apps'),
  getApp: (id) => request('GET', `/apps/${encodeURIComponent(id)}`),
  createApp: (slug, desired) => request('POST', '/apps', { slug, desired }),
  updateDesired: (id, desired) => request('PATCH', `/apps/${encodeURIComponent(id)}/desired`, desired),
  // Trả 202 chứ không 204: app biến mất khỏi API ngay nhưng container còn
  // đang được dọn. UI phải nói "đang xoá", không phải "đã xoá".
  deleteApp: (id) => request('DELETE', `/apps/${encodeURIComponent(id)}`),

  // domains
  listDomains: (id) => request('GET', `/apps/${encodeURIComponent(id)}/domains`),
  addDomain: (id, fqdn, isPrimary) =>
    request('POST', `/apps/${encodeURIComponent(id)}/domains`, { fqdn, is_primary: !!isPrimary }),
  removeDomain: (fqdn) => request('DELETE', `/domains/${encodeURIComponent(fqdn)}`),

  // catalog (UI-01)
  //
  // install nhận `opts` có thể RỖNG: "cài với mặc định" phải là lời gọi ngắn
  // nhất, vì đó là đường mà nút một-cú-bấm đi qua.
  listCatalog: () => request('GET', '/catalog'),
  installFromCatalog: (id, opts = {}) =>
    request('POST', `/catalog/${encodeURIComponent(id)}/install`, opts),

  events: (limit = 100) => request('GET', `/events?limit=${limit}`),

  // version — KHÔNG nằm dưới /api/v1: đây là endpoint gốc của box và nó trả
  // lời cả khi chưa đăng nhập. Vẫn đặt ở đây vì luật là MỌI lời gọi mạng của
  // UI đi qua đúng một file — chỗ duy nhất xử lý 401 và credentials.
  version: async () => {
    const res = await fetch('/version', { credentials: 'same-origin' })
    // Box chưa phơi /version trên cổng HTTP thì SPA trả index.html với 200:
    // không phải JSON = không biết phiên bản, KHÔNG phải lỗi cú pháp.
    if (!res.ok || !(res.headers.get('content-type') || '').includes('json')) throw new ApiError(res.status, null)
    return res.json()
  },
}
