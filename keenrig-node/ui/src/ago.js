/**
 * ago — "bao lâu trước", dịch theo ngôn ngữ đang chọn.
 *
 * Nhận `t` của vue-i18n thay vì import i18n toàn cục, để hàm này thuần và test
 * được không cần dựng app; các khoá `common.justNow/minsAgo/hoursAgo/daysAgo`
 * đã có ở CẢ en.json và vi.json. `null`/'' → "chưa bao giờ": một mốc vắng là
 * một sự thật ("agent chưa báo lần nào"), không phải một lỗi định dạng.
 *
 * AppDetailView có một bản `rel()` cùng luật viết trước — để nguyên, vì gỡ nó
 * là đụng vào một màn đã đo; màn mới dùng bản này.
 */
export function ago(t, ts, now = Date.now()) {
  if (!ts) return t('common.never')
  const ms = Date.parse(ts)
  if (Number.isNaN(ms)) return t('common.never')
  const s = Math.max(0, Math.floor((now - ms) / 1000))
  if (s < 60) return t('common.justNow')
  if (s < 3600) return t('common.minsAgo', Math.floor(s / 60))
  if (s < 86400) return t('common.hoursAgo', Math.floor(s / 3600))
  return t('common.daysAgo', Math.floor(s / 86400))
}
