/**
 * appMeta — luật hiển thị một app, dùng chung cho lưới Apps, trang chi tiết và
 * ô tìm kiếm ⌘K. Ba chỗ cùng nói một câu về cùng một app; hai bản sao của luật
 * "đang áp" là hai câu sẽ có ngày trái nhau trên cùng màn.
 */

/**
 * statusOf — trạng thái hiển thị, suy từ dữ liệu THẬT của reconciler.
 *
 * Đang áp (desired chạy trước applied) đứng trước mọi nhãn cũ: đó là điều đang
 * xảy ra ngay lúc này. Không có `state` nào được báo thì là `unknown` — UI nói
 * "chưa báo cáo", không bịa "running" cho đẹp (P6).
 */
export function statusOf(a) {
  if (!a) return 'unknown'
  const st = a.status && typeof a.status === 'object' ? a.status : {}
  if ((a.desired_rev ?? 0) > (a.applied_rev ?? 0)) return 'deploying'
  if (st.health === 'unhealthy') return 'degraded'
  return st.state || 'unknown'
}

/** ledOf — màu đèn cho một trạng thái. Đèn luôn đi kèm chữ, không bao giờ một mình. */
export function ledOf(s) {
  return { running: 'ok', deploying: 'busy', degraded: 'warn', error: 'danger' }[s] ?? ''
}

/** needsAttention — trạng thái mà người dùng phải làm gì đó. */
export function needsAttention(s) {
  return s === 'degraded' || s === 'error'
}

export function primaryDomain(a) {
  const ds = a?.domains ?? []
  return ds.find((d) => d.is_primary)?.fqdn || ds[0]?.fqdn || ''
}

/** initials — hai ký tự trên ô icon: "n8n" → "n8", "whoami" → "wh". */
export function initials(s) {
  const clean = String(s || '?').replace(/[^a-zA-Z0-9]/g, '')
  return (clean.slice(0, 2) || '?').replace(/^./, (c) => c.toUpperCase())
}

/**
 * hue — sắc màu ỔN ĐỊNH cho mỗi app (cùng slug → cùng màu ở mọi màn, mọi lần
 * mở). Băm chuỗi chứ không chọn ngẫu nhiên: màu đổi mỗi lần tải trang là thứ
 * làm người dùng mất dấu app của mình.
 */
export function hue(s) {
  let h = 0
  for (const ch of String(s || '')) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return h % 360
}

export function imageShort(a) {
  const img = a?.desired?.image || ''
  return img.split('@')[0].split(':')[0].split('/').pop() || ''
}
