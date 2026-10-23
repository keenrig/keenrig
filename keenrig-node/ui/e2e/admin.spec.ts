// Bộ đo Keenrig Admin — trên binary thật, artifact thật, data trắng.
//
// Mỗi test mang tên gate nó đo. Tuần tự (workers:1) và CÓ THỨ TỰ: A1 tạo
// owner, các test sau dùng phiên đó qua storageState — đúng vòng đời một
// instance thật: setup một lần, dùng mãi.
//
// 2026-10-15: giao diện chuyển sang design/v2 (admin.html). Selector đổi theo
// cấu trúc mới (đèn + chữ thay pill, sidebar 6 mục, App Store thay "Cài app"),
// HÀNH VI được đo giữ nguyên: setup một màn không gọi ra ngoài, cài một chạm,
// diff trước khi áp, gợi ý domain, tên cloud chỉ đọc, trạng thái pair thật,
// 360px không cuộn ngang, đổi ngôn ngữ thật.
import { test, expect } from '@playwright/test'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { BOX_LOG, TMP } from './global-setup'

const AUTH = join(TMP, 'auth-state.json')
const OWNER = 'vincent'
const OWNER_PASS = 'mat-khau-du-dai-12'

// RFC 6238 (TOTP) trên RFC 4226 (HOTP): HMAC-SHA1, 6 chữ số, bước 30 giây — đúng
// tham số box ghi trong otpauth:// (internal/identity/totp.go). Viết lại ở đây
// thay vì hỏi box: bộ đo phải là một "app xác thực" ĐỘC LẬP, không thì một lỗi
// chung ở cả hai phía sẽ tự khớp với chính nó.
function base32Decode(s: string): Buffer {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let val = 0
  const out: number[] = []
  for (const ch of s.replace(/[\s=]/g, '').toUpperCase()) {
    const i = A.indexOf(ch)
    if (i < 0) throw new Error(`ký tự base32 lạ: ${ch}`)
    val = ((val << 5) | i) & 0xffff
    bits += 5
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}
function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)))
  const h = createHmac('sha1', base32Decode(secret)).update(counter).digest()
  const off = h[h.length - 1] & 0x0f
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]
  return String(bin % 1_000_000).padStart(6, '0')
}

test.describe.configure({ mode: 'serial' })

// ---------------------------------------------------------------------------------
// A1 + UI-11 — wizard owner: MỘT màn, và KHÔNG một network call nào ra ngoài máy.
// ---------------------------------------------------------------------------------
test('A1/UI-11: tạo owner đi tới cùng — không shell, không gọi ra ngoài', async ({ page, baseURL }) => {
  // UI-11: toàn flow không có network call bắt buộc nào tới cloud. Đo ở tầng
  // MẠNG: mọi request phải ở lại 127.0.0.1 — một cú gọi font CDN cũng là vi phạm.
  const outbound: string[] = []
  page.on('request', (r) => {
    const u = r.url()
    if (/^https?:/.test(u) && !u.startsWith(baseURL!)) outbound.push(u)
  })

  await page.goto('/')
  // Chưa có owner → màn setup, KHÔNG có sidebar (chưa đăng nhập thì không có
  // gì để điều hướng).
  await expect(page.locator('aside.side')).toHaveCount(0)
  await expect(page.getByText('Tạo tài khoản quản trị')).toBeVisible()
  // Lời hứa của A1 nói RA TRÊN MÀN, không phải trong tài liệu.
  await expect(page.getByText('Không hỏi tên miền · Không cần tài khoản cloud', { exact: false })).toBeVisible()

  await page.locator('#lg-user').fill(OWNER)
  await page.locator('#lg-pass').fill(OWNER_PASS)
  // Thước mật khẩu phải nói "mạnh" khi đủ 12 ký tự — đèn xanh + chữ.
  const meter = page.getByTestId('pw-strength')
  await expect(meter).toHaveText(/Mạnh/)
  await expect(meter.locator('.led.ok')).toHaveCount(1)
  await page.getByRole('button', { name: /Bắt đầu/ }).click()

  // Vào thẳng dashboard — và giờ shell phải CÓ.
  await expect(page).toHaveURL(/#\/apps/)
  await expect(page.locator('aside.side')).toBeVisible()

  expect(outbound, `UI-11 vỡ — có request rời máy: ${outbound.join(', ')}`).toHaveLength(0)
  await page.context().storageState({ path: AUTH })
})

test.describe('đã đăng nhập', () => {
  test.use({ storageState: AUTH })

  // -------------------------------------------------------------------------------
  // A6 + A2 — trạng thái rỗng của Apps, sidebar 6 mục v2, và ô ⌘K chạy được
  // KHÔNG cần AI (AI-08 nửa Admin: vắng mặt duyên dáng, không nút chết).
  // -------------------------------------------------------------------------------
  test('A6: empty state một primary, sidebar đúng 6 mục, ô tìm kiếm chạy không cần AI', async ({ page }) => {
    await page.goto('/#/apps')
    const empty = page.getByTestId('apps-empty')
    await expect(empty.locator('h3')).toHaveText('Máy chủ đã sẵn sàng. Cài app đầu tiên.')
    // P2: đúng MỘT hành động chính trên màn — dẫn sang Kho ứng dụng.
    await expect(page.locator('.content .btn.primary')).toHaveCount(1)
    await expect(empty.locator('.btn.primary')).toHaveText(/Mở Kho ứng dụng/)
    // Gợi ý pair là LỜI MỜI ở hint cuối, không phải điều kiện.
    await expect(empty.locator('.hint').last()).toContainText('không bắt buộc')

    const labels = await page.locator('aside a.nav:not(.sub) .lbl').allTextContents()
    expect(labels).toEqual(['Ứng dụng', 'Kho ứng dụng', 'Tên miền', 'Sao lưu', 'Cloud Link', 'Cài đặt'])
    // Không nhãn "CLI" hay huy hiệu kỹ thuật nào trên nav (v0.2.1).
    await expect(page.locator('aside a.nav .badge')).toHaveCount(0)

    // AI-08: không còn bong bóng AI mờ. Ô tìm kiếm mở bằng Ctrl+K, điều hướng
    // được, và nhóm Trợ lý nói thẳng là chưa có (một dòng chữ, không phải nút).
    await expect(page.locator('.fab')).toHaveCount(0)
    await page.keyboard.press('Control+k')
    const pal = page.locator('.palette')
    await expect(pal).toBeVisible()
    await expect(pal.locator('.pal-na').last()).toContainText('Admin chưa có trợ lý')
    await expect(pal.locator('.pal-r.na')).toHaveCount(1)
    await pal.locator('input').fill('domains')
    await page.keyboard.press('Enter')
    await expect(page).toHaveURL(/#\/domains/)
    await expect(pal).toHaveCount(0)
  })

  // -------------------------------------------------------------------------------
  // UI-01 — cài từ App Store: nút cài KHÔNG hỏi gì, app xuất hiện trên lưới với
  // trạng thái thật (desired > applied vì không có reconciler → "đang áp").
  // Đi vào bằng đường CŨ /#/catalog: redirect phải đưa tới /#/store.
  // -------------------------------------------------------------------------------
  test('UI-01: cài app từ App Store một cú bấm — app lên lưới, trạng thái từ rev thật', async ({ page }) => {
    await page.goto('/#/catalog')
    await expect(page).toHaveURL(/#\/store/)
    const cards = page.getByTestId('store-card')
    await expect(cards.first()).toBeVisible() // catalog NHÚNG trong binary — trống là lỗi build
    const title = await cards.first().locator('h3').textContent()

    // Nút cài ghi "Cài", không phải "Cài đặt" — "Cài đặt" là tên trang Settings.
    await cards.first().getByRole('button', { name: 'Cài', exact: true }).click()
    await expect(page).toHaveURL(/#\/apps/)

    const tile = page.getByTestId('app-tile').first()
    await expect(tile).toBeVisible()
    // Không reconciler → desired_rev(1) > applied_rev(0) → "đang thiết lập" với
    // đèn tím nhấp nháy, KHÔNG phải một chữ "running" bịa cho đẹp — và một dòng
    // nói nó có thể mất bao lâu (v0.2.1: chữ "đang áp" trần không giải thích gì).
    await expect(tile.getByTestId('app-status')).toHaveText(/đang thiết lập/i)
    await expect(tile.locator('.led.busy')).toHaveCount(1)
    await expect(tile.getByTestId('app-hint')).toContainText('vài phút')
    expect(title).toBeTruthy()

    // Quay lại store: thẻ vừa cài phải nói "Đã cài" và nút chính là "Mở" —
    // không thì nó vẫn mời "Cài đặt", và gói 1-app trả lỗi hạn mức trông như hỏng.
    await page.goto('/#/store')
    const card = page.getByTestId('store-card').filter({ has: page.locator('h3', { hasText: title! }) })
    await expect(card.getByTestId('catalog-installed')).toHaveText('Đã cài')
    await expect(card.getByRole('button', { name: 'Cài', exact: true })).toHaveCount(0)
    await card.getByRole('link', { name: 'Mở', exact: true }).click()
    await expect(page).toHaveURL(/#\/apps\/.+/)
    // Thẻ chưa cài vẫn giữ nút cài — nhãn không được lan sang mọi thẻ.
    await page.goto('/#/store')
    await expect(page.getByTestId('catalog-installed')).toHaveCount(1)
  })

  // -------------------------------------------------------------------------------
  // App Store: lối "xin thêm app" sang Console + chip tag là NHÃN, không phải slug.
  // Máy standalone (chưa agent nào báo cloud_url) → Console mặc định.
  // -------------------------------------------------------------------------------
  test('Store: ô xin thêm app trỏ Console, lọc rỗng mời xin đúng tên, chip tag đọc được', async ({ page }) => {
    await page.goto('/#/store')
    const req = page.getByTestId('store-request')
    await expect(req).toHaveAttribute('href', 'https://console.keenrig.com/request-app?from=admin')
    await expect(req).toHaveAttribute('target', '_blank')
    await expect(req).toHaveAttribute('rel', /noopener/)

    // Chip: không còn slug có gạch ngang; tag đã biết ra nhãn tiếng Việt.
    const chips = await page.locator('.chips .chip').allTextContents()
    for (const c of chips) expect(c.trim(), `chip "${c}" là slug trần`).not.toMatch(/-/)
    expect(chips.map((c) => c.trim())).toContain('Tự động hoá')

    await page.locator('.store-filter input').fill('mattermost xyz')
    const none = page.getByTestId('store-nomatch')
    await expect(none.locator('h3')).toContainText('mattermost xyz')
    await expect(none.getByTestId('store-request-q')).toHaveAttribute(
      'href',
      'https://console.keenrig.com/request-app?from=admin&name=mattermost+xyz',
    )
  })

  // -------------------------------------------------------------------------------
  // A3 — 5 tab; Logs/Backups chưa có API → in LỆNH THẬT đã điền ID app (không
  // nút giả). Configuration là form → diff → MỘT PATCH, rev tăng và đầu trang
  // sống nói "đang áp rev 2". Rời tab khi còn thay đổi → guard, không âm thầm bỏ.
  // -------------------------------------------------------------------------------
  test('A3: diff trước khi áp, guard đổi tab, PATCH tăng rev, Logs/Backups là lệnh thật', async ({ page }) => {
    await page.goto('/#/apps')
    await page.getByTestId('app-settings').first().click()
    await expect(page).toHaveURL(/#\/apps\/.+/)
    const appId = decodeURIComponent(page.url().split('#/apps/')[1].split('?')[0])

    const tabs = page.locator('.tabs button')
    await expect(tabs).toHaveCount(5)

    // Backups: chưa có API → lệnh restore thật, --app là ID của CHÍNH app này.
    await page.locator('[data-tab=backups]').click()
    await expect(page.locator('.cmdbox code', { hasText: `--app ${appId}` })).toBeVisible()
    await expect(page.locator('.content .btn.primary')).toHaveCount(0)

    // Configuration: đổi RAM → diff hiện ĐÚNG khoá + hai chiều cũ/mới.
    await page.locator('[data-tab=config]').click()
    await page.getByTestId('cfg-memory').fill('1024')
    // Diff ghi nhãn người đọc được, không phải đường dẫn JSON.
    await expect(page.locator('.diff .k', { hasText: 'Bộ nhớ (MB)' })).toBeVisible()
    await expect(page.locator('.diff .add', { hasText: '+ 1024' })).toBeVisible()
    await expect(page.locator('.diff .del')).toBeVisible()
    await expect(page.locator('[data-tab=config] .badge')).toHaveText('1 chưa lưu')

    // Guard: bấm sang Truy cập khi còn thay đổi → cảnh báo tại chỗ, ở lại.
    await page.locator('[data-tab=access]').click()
    await expect(page.locator('.note.warn', { hasText: 'thay đổi chưa lưu' })).toBeVisible()
    await page.getByRole('button', { name: 'Xem lại thay đổi' }).click()
    await expect(page.locator('[data-tab=config]')).toHaveClass(/on/)

    // Áp dụng = MỘT PATCH; đầu trang vẫn "đang thiết lập" vì desired vừa vượt
    // applied — không cần reload. Số phiên bản nằm ở Tổng quan, không ở tiêu đề.
    await page.getByRole('button', { name: /Áp dụng 1 thay đổi/ }).click()
    await expect(page.getByTestId('app-state')).toHaveText(/đang thiết lập/i)
    // Diff phải RỖNG sau khi áp — form đồng bộ với desired mới.
    await expect(page.getByText('Chưa có thay đổi nào', { exact: false })).toBeVisible()
    // Cột phải đổi theo trạng thái: đang áp → các bước rollout thế chỗ tài nguyên.
    await page.locator('[data-tab=overview]').click()
    await expect(page.getByTestId('rollout')).toContainText('Đang khởi chạy lần đầu')
    await expect(page.getByTestId('rev')).toHaveText('0 / 2')
  })

  // -------------------------------------------------------------------------------
  // Truy cập — app cài KHÔNG kèm domain (ô Domain trống vì vào bằng IP) vẫn phải
  // mở ra với `<slug>.<parent>` điền sẵn, lấy từ parent_domain của box.
  //
  // Đo bằng cách CHẶN /instance và trả parent_domain: baseURL của bộ này là
  // 127.0.0.1 nên phép suy từ URL trả '' — nếu UI chỉ suy từ URL mà không đọc
  // giá trị chính thức của box thì test này đỏ.
  // -------------------------------------------------------------------------------
  test('Truy cập: app chưa có domain → ô nhập điền sẵn <slug>.<parent> từ /instance', async ({ page }) => {
    await page.route('**/api/v1/instance', async (route) => {
      const res = await route.fetch()
      const body = await res.json()
      await route.fulfill({ json: { ...body, parent_domain: 'demo.acme.keenrig.com' } })
    })

    await page.goto('/#/apps')
    await page.getByTestId('app-settings').first().click()
    const slug = (await page.locator('.crumbs .cur').textContent())!.trim()
    await page.locator('[data-tab=access]').click()

    // Danh sách domain vẫn RỖNG: gợi ý là gợi ý, không phải một hàng domain bịa
    // — gateway chưa có route lẫn cert cho tên đó.
    await expect(page.locator('.dmn')).toHaveCount(0)
    await expect(page.locator('input[placeholder="shop.cuahang.vn"]')).toHaveValue(
      `${slug}.demo.acme.keenrig.com`,
    )
    // Domain đầu tiên của app → primary tick sẵn.
    await expect(page.locator('input[type=checkbox]')).toBeChecked()
    await page.unroute('**/api/v1/instance')
  })

  // -------------------------------------------------------------------------------
  // Truy cập + A4 — thêm domain ở app, thấy nó ở cả hai màn.
  // -------------------------------------------------------------------------------
  test('A4: thêm domain trong tab Truy cập → hiện ở app và ở trang Domains', async ({ page }) => {
    await page.goto('/#/apps')
    await page.getByTestId('app-settings').first().click()
    await page.locator('[data-tab=access]').click()

    await page.locator('input[placeholder="shop.cuahang.vn"]').fill('shop.test.local')
    await page.getByRole('button', { name: 'Thêm', exact: true }).click()
    await expect(page.locator('.dmn .m', { hasText: 'shop.test.local' })).toBeVisible()

    await page.goto('/#/domains')
    const row = page.locator('.dmn', { hasText: 'shop.test.local' })
    await expect(row).toBeVisible()
    // Mỗi domain trỏ về app của nó — link mang slug, mở tab Truy cập.
    await expect(row.locator('a.applink')).toHaveAttribute('href', /tab=access/)
  })

  // -------------------------------------------------------------------------------
  // Tên miền gốc do cloud cấp: đi vào box qua node API (đường của agent), hiện ở
  // Domains CHỈ ĐỌC với nhãn Cloud — và control API KHÔNG có đường ghi.
  //
  // Node API trên Windows rơi về TCP loopback với cổng ngẫu nhiên và box in địa
  // chỉ đó ra log — bộ đo đọc log để tìm nó, y như agent đọc KEENRIG_BOX_ADDR.
  // Trên Linux nó là unix socket mà fetch của Node không gõ được: khi đó test
  // này bỏ qua NÓI RÕ lý do, thay vì giả vờ đã đo.
  // -------------------------------------------------------------------------------
  test('Domains: tên do cloud cấp đi vào qua node API, hiện read-only, Admin API không ghi được', async ({ page }) => {
    const m = readFileSync(BOX_LOG, 'utf-8').match(/node API is listening on TCP (\d+\.\d+\.\d+\.\d+:\d+)/)
    test.skip(!m, 'node API nghe unix socket — fetch của Node không gõ được; ca này đo trên đường TCP dev-only')

    const res = await fetch(`http://${m![1]}/node/v1/parent-domain`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ parent_domain: 'demo.acme.keenrig.com', mode: 'keenrig' }),
    })
    expect(res.status, await res.text()).toBe(200)

    await page.goto('/#/domains')
    const card = page.getByTestId('instance-domain')
    await expect(card).toBeVisible()
    await expect(card.getByTestId('parent-domain')).toHaveText('demo.acme.keenrig.com')
    await expect(card).toContainText('Do Keenrig Cloud cấp')
    await expect(card.locator('.badge.cloud')).toHaveText('Cloud')
    await expect(card.locator('.mono', { hasText: 'admin.demo.acme.keenrig.com' })).toBeVisible()
    await expect(card.locator('.hint')).toContainText('không sửa được ở đây')
    // Không có ô nhập hay nút nào trong thẻ: hiển thị, không phải sửa.
    await expect(card.locator('input, button')).toHaveCount(0)

    // Và control API (phiên admin thật, qua cookie) không có đường ghi.
    for (const method of ['put', 'post', 'patch', 'delete'] as const) {
      const r = await page.request[method]('/api/v1/instance', { data: { parent_domain: 'evil.example.com' } })
      expect(r.ok(), `${method.toUpperCase()} /api/v1/instance = ${r.status()} — Admin API không được đặt tên miền`).toBeFalsy()
    }
    const after = await (await page.request.get('/api/v1/instance')).json()
    expect(after.parent_domain).toBe('demo.acme.keenrig.com')
    expect(after.parent_domain_source).toBe('cloud')
  })

  // -------------------------------------------------------------------------------
  // AD-12 — Cloud Link hiện trạng thái pair THẬT, từ agent qua node API.
  //
  // Trước 2026-09-19 màn này viết cứng "chưa pair" — trên box thử nghiệm đang sync
  // mỗi 30 giây. Bộ đo đóng vai agent: PUT /node/v1/cloud-link với mốc vừa rồi
  // qua đường TCP dev-only (đọc địa chỉ từ box.log như test Domains), rồi mở
  // #/cloud và đòi đèn xanh "Đã đồng bộ" + env id. Trên socket unix thì skip có lý do.
  // -------------------------------------------------------------------------------
  test('AD-12: agent báo pair qua node API → Cloud Link hiện "đã đồng bộ" + env id, không viết cứng', async ({ page, baseURL }) => {
    const m = readFileSync(BOX_LOG, 'utf-8').match(/node API is listening on TCP (\d+\.\d+\.\d+\.\d+:\d+)/)
    test.skip(!m, 'node API nghe unix socket — fetch của Node không gõ được; ca này đo trên đường TCP dev-only')

    // Trước khi agent báo: standalone THẬT (không phải "không lấy được").
    await page.goto('/#/cloud')
    await expect(page.getByTestId('cloud-state')).toHaveText(/Độc lập/)
    await expect(page.getByText('Trạng thái kết nối chưa được báo')).toHaveCount(0)
    // Đường thật là `sh` (get.sh là POSIX sh), không phải `bash`.
    await expect(page.locator('[data-testid=join-cmd] code')).toContainText('| sudo sh -s -- --join')

    const res = await fetch(`http://${m![1]}/node/v1/cloud-link`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cloud_url: 'https://keenrig.com', env_id: 'env_01J8ZK', last_sync_at: new Date().toISOString() }),
    })
    expect(res.status, await res.text()).toBe(200)

    // reload, không goto: đang ở đúng #/cloud nên goto cùng hash không dựng lại view.
    await page.reload()
    const st = page.getByTestId('cloud-state')
    await expect(st).toHaveText(/Đã đồng bộ/)
    await expect(st.locator('.led.ok')).toHaveCount(1)
    const card = page.locator('.cloud-link')
    await expect(card.locator('.env-id')).toHaveText('env_01J8ZK')
    await expect(card.locator('a[href="https://keenrig.com"]').first()).toBeVisible()
    await expect(page.getByTestId('cloud-sub')).toContainText('keenrig.com')
    await expect(page.getByTestId('cloud-sub')).toContainText('vừa xong')
    // Và không có thẻ mời pair nữa — hai trạng thái không chồng lên nhau.
    await expect(page.getByText('Kết nối với Keenrig Console có thêm:')).toHaveCount(0)

    // Đường này đòi phiên: không cookie → 401.
    const anon = (await fetch(`${baseURL}/api/v1/cloud`)).status
    expect(anon, 'GET /api/v1/cloud không phiên phải là 401 — nó lộ URL cloud + env id').toBe(401)

    // Agent im quá 5 phút → stale: đèn vàng + MỐC GIỜ + lệnh chẩn đoán, app vẫn chạy.
    const old = new Date(Date.now() - 6 * 60_000).toISOString()
    const res2 = await fetch(`http://${m![1]}/node/v1/cloud-link`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cloud_url: 'https://keenrig.com', env_id: 'env_01J8ZK', last_sync_at: old }),
    })
    expect(res2.status).toBe(200)
    await page.reload()
    await expect(st).toHaveText(/Không tới được Keenrig Cloud/)
    await expect(st.locator('.led.warn')).toHaveCount(1)
    await expect(page.locator('[data-testid=diag-cmd] code')).toContainText('journalctl -u keenrig-agent')
    await expect(page.getByText('App vẫn chạy.', { exact: false })).toBeVisible()
  })

  // -------------------------------------------------------------------------------
  // R1 — 360px: không cuộn ngang toàn trang (luật 1), drawer mở bằng ☰ (mốc ≤576).
  // /#/backup là đường CŨ — redirect sang /#/backups cũng được đo ở đây.
  // -------------------------------------------------------------------------------
  test('Chân sidebar: một dòng tài khoản, menu có phiên bản + Cài đặt + Đăng xuất, Esc đóng', async ({ page }) => {
    await page.goto('/')
    const me = page.locator('aside.side .foot .me')
    await expect(me).toHaveAttribute('aria-expanded', 'false')
    // Không còn nút đăng xuất trần ở sidebar — nó nằm trong menu.
    await expect(page.locator('aside.side .logout')).toHaveCount(0)
    await me.click()
    const menu = page.locator('.acct-menu[role=menu]')
    await expect(menu).toBeVisible()
    // Dòng phiên bản chỉ hiện khi box báo phiên bản THẬT — không bao giờ
    // "Keenrig — chưa báo cáo" ở đầu menu.
    for (const v of await menu.locator('.am-ver').allTextContents()) expect(v).toMatch(/^Keenrig \d/)
    await expect(menu.getByRole('menuitem', { name: /Cài đặt|Settings/ })).toBeVisible()
    await expect(menu.locator('button.logout')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(menu).toHaveCount(0)
    await expect(me).toHaveAttribute('aria-expanded', 'false')
  })

  test('R1: ở 360px không cuộn ngang, drawer mở bằng ☰ và điều hướng được', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 740 })

    for (const path of ['/#/apps', '/#/store', '/#/domains', '/#/backup', '/#/cloud', '/#/settings', '/#/events']) {
      await page.goto(path)
      await page.waitForLoadState('networkidle')
      const over = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      )
      expect(over, `trang ${path} cuộn ngang ${over}px — vi phạm luật R1 #1`).toBeLessThanOrEqual(0)
    }
    await expect(page).toHaveURL(/#\/events/)

    // Drawer: sidebar ẩn cho tới khi bấm ☰, mở ra là điều hướng được.
    await page.goto('/#/apps')
    const ham = page.locator('.topbar .ham')
    await expect(ham).toBeVisible()
    await ham.click()
    await expect(page.locator('aside.side.open')).toBeVisible()
    await page.locator('aside a.nav[data-nav=domains]').click()
    await expect(page).toHaveURL(/#\/domains/)
    // Drawer phải TỰ ĐÓNG sau khi điều hướng — còn che màn là một cú chạm bị nuốt.
    await expect(page.locator('aside.side.open')).toHaveCount(0)
  })

  // -------------------------------------------------------------------------------
  // i18n — đổi ngôn ngữ đổi nhãn THẬT, cả hai chiều.
  //
  // `playwright.config.ts` ép `locale: 'vi-VN'`, nên context này là một trình
  // duyệt NÓI tiếng Việt: nó nhận tiếng Việt kể cả sau khi mặc định toàn cục đổi
  // sang tiếng Anh (2026-09-02, bỏ gate UI-08). Ca trình duyệt KHÔNG nói tiếng
  // Việt nằm ở describe cuối file — đó là ca mà luật cũ làm sai.
  // -------------------------------------------------------------------------------
  test('i18n: chuyển English đổi nhãn nav, chuyển lại giữ nguyên tiếng Việt', async ({ page }) => {
    await page.goto('/#/apps')
    const storeLbl = page.locator('aside a.nav[data-nav=store] .lbl')
    await page.locator('.topbar .lang button[data-locale=en]').click()
    await expect(storeLbl).toHaveText('App Store')
    await page.locator('.topbar .lang button[data-locale=vi]').click()
    await expect(storeLbl).toHaveText('Kho ứng dụng')
  })

  // -------------------------------------------------------------------------------
  // Theme — sáng trước, tối đầy đủ: Settings đổi data-theme trên <html>, "Tự
  // động" gỡ nó để prefers-color-scheme quyết.
  // -------------------------------------------------------------------------------
  test('Theme: Settings đổi sáng/tối thật, Tự động trả về theo hệ thống', async ({ page }) => {
    await page.goto('/#/settings')
    const html = page.locator('html')
    await page.locator('[data-theme-set=dark]').click()
    await expect(html).toHaveAttribute('data-theme', 'dark')
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor)
    await page.locator('[data-theme-set=light]').click()
    await expect(html).toHaveAttribute('data-theme', 'light')
    expect(await page.evaluate(() => getComputedStyle(document.body).backgroundColor)).not.toBe(bg)
    await page.locator('[data-theme-set=auto]').click()
    await expect(html).not.toHaveAttribute('data-theme', /.+/)
  })

  // -------------------------------------------------------------------------------
  // Settings › Đăng nhập — mã hai bước: bật bằng mã THẬT tính từ khoá đang hiện,
  // đăng nhập sau đó PHẢI hỏi mã, tắt bằng mật khẩu thì hết hỏi.
  //
  // Đăng nhập thử chạy ở một context RIÊNG (không cookie): phiên của trang
  // Settings không bị đụng, và đó đúng là "lần đăng nhập sau" của người dùng.
  // Ca này trả tài khoản về trạng thái cũ (2FA tắt) — các ca sau không phải biết.
  // -------------------------------------------------------------------------------
  test('Settings: bật 2FA bằng mã TOTP thật → đăng nhập đòi mã → tắt bằng mật khẩu', async ({ page, browser, baseURL }) => {
    async function signIn() {
      const ctx = await browser.newContext({ baseURL, locale: 'vi-VN' })
      const p = await ctx.newPage()
      await p.goto('/#/login')
      await p.locator('#lg-user').fill(OWNER)
      await p.locator('#lg-pass').fill(OWNER_PASS)
      await p.getByRole('button', { name: 'Đăng nhập', exact: true }).click()
      return { ctx, p }
    }

    await page.goto('/#/settings')
    const st = page.getByTestId('tfa-state')
    await expect(st).toHaveText('Tắt')
    await page.getByTestId('tfa-on').click()

    // Khoá hiện theo nhóm 4 ký tự để gõ tay — bỏ khoảng trắng là đúng secret base32.
    const shown = (await page.getByTestId('tfa-secret').textContent())!.replace(/\s/g, '')
    expect(shown, 'khoá TOTP phải là base32 trần, không phải URI').toMatch(/^[A-Z2-7]{16,}$/)
    // Link otpauth:// mang ĐÚNG khoá đó — mở trên điện thoại ra cùng tài khoản.
    const href = await page.getByTestId('tfa-enroll').locator('a[href^="otpauth://"]').getAttribute('href')
    expect(new URL(href!).searchParams.get('secret')).toBe(shown)

    // Mã sai thì KHÔNG bật — enroll một mình không khoá ai ra ngoài.
    const confirm = page.getByTestId('tfa-enroll').getByRole('button', { name: 'Bật', exact: true })
    const wrong = String((Number(totp(shown)) + 500_000) % 1_000_000).padStart(6, '0')
    await page.locator('#tfa-code').fill(wrong)
    await confirm.click()
    await expect(page.getByTestId('tfa-enroll').locator('.err')).toHaveText('Mã xác thực không đúng.')
    await expect(st).toHaveText('Tắt')

    await page.locator('#tfa-code').fill(totp(shown))
    await confirm.click()
    await expect(st).toHaveText('Bật')
    await expect(st.locator('.led.ok')).toHaveCount(1)
    await expect(page.getByTestId('tfa-enroll')).toHaveCount(0)

    // Lần đăng nhập sau: mật khẩu đúng chưa đủ — màn hỏi mã; đủ 6 số là tự gửi.
    {
      const { ctx, p } = await signIn()
      await expect(p.locator('#lg-totp')).toBeVisible()
      await expect(p).toHaveURL(/#\/login/)
      await p.locator('#lg-totp').fill(totp(shown))
      await expect(p).toHaveURL(/#\/apps/)
      await ctx.close()
    }

    // Tắt: hỏi lại mật khẩu; sai mật khẩu thì vẫn bật.
    await page.getByRole('button', { name: 'Tắt mã xác thực hai bước…' }).click()
    const off = page.getByTestId('tfa-disable')
    await off.locator('#tfa-pass').fill('sai-mat-khau-roi')
    await off.getByRole('button', { name: 'Tắt', exact: true }).click()
    await expect(off.locator('.err')).toHaveText('Sai mật khẩu.')
    await expect(st).toHaveText('Bật')
    await off.locator('#tfa-pass').fill(OWNER_PASS)
    await off.getByRole('button', { name: 'Tắt', exact: true }).click()
    await expect(st).toHaveText('Tắt')
    await expect(off).toHaveCount(0)

    // Và đăng nhập lại chỉ cần mật khẩu.
    {
      const { ctx, p } = await signIn()
      await expect(p).toHaveURL(/#\/apps/)
      await expect(p.locator('#lg-totp')).toHaveCount(0)
      await ctx.close()
    }
  })

  // -------------------------------------------------------------------------------
  // Settings › Đổi mật khẩu — server thu hồi MỌI phiên: UI về màn đăng nhập và
  // nói vì sao; mật khẩu cũ hết dùng được, mật khẩu mới vào được.
  //
  // Phiên trong AUTH chết theo, nên cuối ca trả mật khẩu về như cũ qua API, đăng
  // nhập lại và GHI LẠI AUTH — các ca phía sau không phải biết ca này từng chạy.
  // -------------------------------------------------------------------------------
  test('Settings: đổi mật khẩu → về đăng nhập, mật khẩu cũ bị từ chối, mật khẩu mới vào được', async ({ page }) => {
    const NEW = 'mat-khau-moi-du-dai-34'
    await page.goto('/#/settings')
    await page.getByRole('button', { name: 'Đổi mật khẩu…' }).click()
    const go = page.getByRole('button', { name: 'Đổi mật khẩu', exact: true })
    await page.locator('#pw-old').fill(OWNER_PASS)
    await page.locator('#pw-new').fill('ngan-qua')
    // Dưới 12 ký tự: nút không bấm được — server cũng từ chối, nhưng UI nói trước.
    await expect(go).toBeDisabled()
    await page.locator('#pw-new').fill(NEW)
    await go.click()

    await expect(page).toHaveURL(/#\/login/)
    await expect(page.getByTestId('pw-changed')).toContainText('mật khẩu mới')
    // Phiên cũ bị thu hồi THẬT — không chỉ là UI chuyển trang.
    expect((await page.request.get('/api/v1/auth/me')).status()).toBe(401)

    await page.locator('#lg-user').fill(OWNER)
    await page.locator('#lg-pass').fill(OWNER_PASS)
    await page.getByRole('button', { name: 'Đăng nhập', exact: true }).click()
    await expect(page.locator('.err')).toHaveText('Sai tên đăng nhập hoặc mật khẩu.')

    await page.locator('#lg-pass').fill(NEW)
    await page.getByRole('button', { name: 'Đăng nhập', exact: true }).click()
    await expect(page).toHaveURL(/#\/apps/)
    await expect(page.locator('aside.side')).toBeVisible()

    const back = await page.request.post('/api/v1/auth/password', { data: { old_password: NEW, new_password: OWNER_PASS } })
    expect(back.ok(), await back.text()).toBeTruthy()
    const re = await page.request.post('/api/v1/auth/login', { data: { username: OWNER, password: OWNER_PASS } })
    expect(re.ok(), await re.text()).toBeTruthy()
    await page.context().storageState({ path: AUTH })
  })
})

// -------------------------------------------------------------------------------
// Mặc định của một trình duyệt KHÔNG nói tiếng Việt là tiếng Anh.
//
// Đây là lỗi mà luật cũ (`startsWith('en') ? 'en' : 'vi'`) gây ra: một người dùng
// Nhật, Đức hay Pháp mở Admin lần đầu và nhận một giao diện tiếng Việt — ở màn
// ĐẦU TIÊN, trước khi cái nút đổi ngôn ngữ có nghĩa gì với họ. Test đứng riêng ở
// một describe vì nó cần `test.use({ locale })` khác với phần còn lại của file.
//
// Nó CÓ RĂNG: đảo `initialLocale` về luật cũ thì nhãn là "Kho ứng dụng" và test đỏ.
test.describe('i18n: mặc định theo ngôn ngữ trình duyệt', () => {
  // storageState đi kèm locale: không có phiên thì `/#/apps` đẩy về màn đăng
  // nhập và cái nav này không tồn tại — test sẽ đỏ vì lý do sai.
  test.use({ storageState: AUTH, locale: 'ja-JP' })

  test('trình duyệt tiếng Nhật nhận tiếng Anh, không phải tiếng Việt', async ({ page }) => {
    await page.goto('/#/apps')
    await expect(page.locator('aside a.nav[data-nav=store] .lbl')).toHaveText('App Store')
  })
})

// R1 cho màn đăng nhập: không phiên, 360px. Thẻ auth từng rộng 420px cố định
// trong một lưới tự co theo nội dung → cuộn ngang 73px trên điện thoại.
test.describe('R1: màn đăng nhập ở 360px', () => {
  test('không cuộn ngang', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 740 })
    await page.goto('/#/login')
    await expect(page.locator('#lg-user')).toBeVisible()
    const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(over, `màn đăng nhập cuộn ngang ${over}px`).toBeLessThanOrEqual(0)
  })
})
