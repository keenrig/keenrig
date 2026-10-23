import { createI18n } from 'vue-i18n'
import vi from './vi.json'
import en from './en.json'

// Tiếng Anh là MẶC ĐỊNH và là fallback; tiếng Việt là ngoại lệ có yêu cầu.
//
// Đổi ngày 2026-09-02, cùng lượt với việc bỏ gate `UI-08` ("tiếng Việt là locale
// gốc"). Luật cũ là `startsWith('en') ? 'en' : 'vi'`, tức MỌI trình duyệt không
// phải tiếng Anh — Nhật, Đức, Pháp — rơi vào tiếng Việt: một ngôn ngữ họ không
// đọc được, ở màn ĐẦU TIÊN họ thấy, trước khi nút đổi ngôn ngữ có nghĩa gì với
// họ. Đảo lại: chỉ trình duyệt NÓI tiếng Việt mới nhận tiếng Việt.
//
// `fallbackLocale` cũng theo: mọi thông báo của box và mọi lỗi API đã là tiếng
// Anh (xem WORKING-STATE §3), nên rơi về tiếng Việt là trộn hai thứ tiếng ở
// đúng chỗ người đọc đang cần một câu trả lời.
//
// CẢ HAI ngôn ngữ vẫn phải phủ 100% khoá — `ui/embed_test.go` canh điều đó.
// Mặc định đổi không có nghĩa tiếng Việt bị hạ cấp thành bản dịch nửa vời.
//
// Cùng luật với Console (`keenrig-cloud/ui/src/i18n/index.js`) và với `/` → `/en`
// của keenrig-web, nên ba mặt của sản phẩm không mâu thuẫn nhau.
const STORAGE_KEY = 'keenrig.locale'

function initialLocale() {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved === 'vi' || saved === 'en') return saved
  return (navigator.language || '').toLowerCase().startsWith('vi') ? 'vi' : 'en'
}

export const i18n = createI18n({
  legacy: false,
  locale: initialLocale(),
  fallbackLocale: 'en',
  messages: { vi, en },
})

export function setLocale(l) {
  i18n.global.locale.value = l
  localStorage.setItem(STORAGE_KEY, l)
  document.documentElement.lang = l
}
