/**
 * theme — sáng / tối / theo hệ thống (design/v2: sáng trước, tối đầy đủ).
 *
 * "auto" = không đặt data-theme, để `prefers-color-scheme` quyết. Lựa chọn tay
 * ghi `data-theme` lên <html>, đúng cơ chế mà token trong style.css đọc.
 *
 * localStorage có thể ném lỗi (cửa sổ riêng tư, chặn cookie) — khi đó theme vẫn
 * đổi trong phiên, chỉ không nhớ qua lần tải sau. Không bao giờ làm vỡ trang.
 */
import { ref } from 'vue'

const KEY = 'keenrig.theme'

function read() {
  try {
    const v = localStorage.getItem(KEY)
    return v === 'light' || v === 'dark' ? v : 'auto'
  } catch {
    return 'auto'
  }
}

export const theme = ref(read())

function apply(v) {
  const root = document.documentElement
  if (v === 'light' || v === 'dark') root.setAttribute('data-theme', v)
  else root.removeAttribute('data-theme')
}

export function initTheme() {
  apply(theme.value)
}

export function setTheme(v) {
  theme.value = v === 'light' || v === 'dark' ? v : 'auto'
  apply(theme.value)
  try {
    localStorage.setItem(KEY, theme.value)
  } catch {
    /* chỉ không nhớ được — vẫn đổi trong phiên */
  }
}
