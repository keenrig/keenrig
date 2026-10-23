/**
 * parentDomain — tên miền gốc của instance này.
 *
 * App phải nằm ở `<app>.<parent>`, nhưng chỗ nào cần biết `<parent>` cũng phải
 * tự tìm lấy: `KEENRIG_DOMAIN` được get.sh ghi vào unit mà không binary nào
 * đọc. Có hai nguồn, theo thứ tự tin cậy:
 *
 *  1. `GET /instance` → `parent_domain`: giá trị CHÍNH THỨC, đến từ `--domain`
 *     của trình cài. Truyền vào đây qua `known`.
 *  2. `location.hostname`: trang này đang được phục vụ ở `admin.<parent>` (hoặc
 *     chính `<parent>`), nên trình duyệt LUÔN biết câu trả lời — kể cả khi box
 *     chưa được khai tên miền nào, và kể cả khi đi qua tunnel.
 *
 * Trả '' khi vào bằng IP hoặc localhost: khi đó không có gì để suy, và ô nhập
 * phải quay về trống thay vì đoán bừa.
 *
 * Ở MỘT chỗ vì hai màn hình cùng cần nó (cài từ danh mục, và thêm domain cho
 * app đã cài). Hai bản sao của luật "bỏ tiền tố admin." là hai bản sẽ trôi.
 */
export function parentDomain(known = '') {
  if (known) return known.toLowerCase()
  const h = (window.location.hostname || '').toLowerCase()
  if (!h || h === 'localhost' || /^[0-9.]+$/.test(h) || h.includes(':')) return ''
  // Ít nhất hai nhãn: `a.b` mới là một tên miền dùng được.
  if (h.split('.').length < 2) return ''
  return h.startsWith('admin.') ? h.slice('admin.'.length) : h
}

/** suggestFqdn — `<label>.<parent>`, hoặc '' khi không suy được parent. */
export function suggestFqdn(label, known = '') {
  const parent = parentDomain(known)
  const l = (label || '').trim()
  return parent && l ? `${l}.${parent}` : ''
}
