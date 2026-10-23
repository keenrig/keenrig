// Nhãn đọc được cho tag của manifest.
//
// Manifest ghi tag dạng slug ("chẩn-đoán", "luu-tru-file", "automation") — in
// thẳng ra chip là thứ người dùng thấy "chẩn-đoá…". Tag ĐÃ BIẾT dịch qua i18n
// (khoá `tags.*` ở cả en lẫn vi); tag lạ thì gạch ngang → khoảng trắng, viết
// hoa chữ đầu — không bao giờ rỗng, không bao giờ là slug trần.
const KNOWN = {
  automation: 'automation',
  web: 'web',
  monitoring: 'monitoring',
  'chẩn-đoán': 'diagnostics',
  'chan-doan': 'diagnostics',
  diagnostics: 'diagnostics',
  'website-gioi-thieu': 'companyWebsite',
  'luu-tru-file': 'fileStorage',
}

export function tagKey(slug) {
  const s = String(slug || '').normalize('NFC').trim().toLowerCase()
  return KNOWN[s] || ''
}

export function prettySlug(slug) {
  const s = String(slug || '').normalize('NFC').trim().replace(/[-_]+/g, ' ').replace(/\s+/g, ' ')
  return s ? s.charAt(0).toLocaleUpperCase() + s.slice(1) : ''
}

export function tagLabel(t, slug) {
  const k = tagKey(slug)
  return k ? t(`tags.${k}`) : prettySlug(slug)
}
