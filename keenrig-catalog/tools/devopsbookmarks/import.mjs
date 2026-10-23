// Nhập danh mục devopsbookmarks.com → định dạng manifest của keenrig-catalog.
//
// # Hai đầu ra, vì hai thứ được nhập KHÔNG cùng loại dữ liệu
//
// Một entry devopsbookmarks là {slug, name, description, url, tags} — một
// BOOKMARK. Một manifest catalog bắt buộc repository + tag + digest +
// http_port. Bốn trường đó không suy ra được từ một URL trang chủ, nên script
// này KHÔNG giả vờ chuyển đổi được tất cả:
//
//	out/directory.generated.json  Cả 234 entry, đã chuẩn hoá id + tag chủ đề,
//	                              kèm `status` nói rõ vì sao entry đó chưa (hoặc
//	                              không bao giờ) thành manifest được.
//	out/manifests/<id>.json       Manifest THẬT, digest đã resolve từ registry,
//	                              cho những entry có trong mapping.json.
//	out/REPORT.md                 Ai vào đâu, và cái gì đang chặn.
//
// Chỉ entry `status: "ready"` mới được `--promote` chép vào ../../manifests/.
// Cái còn lại nằm trong out/ cho tới khi thứ đang chặn nó được mở.
//
// # Vì sao có mapping.lock.json
//
// UI-11: không lời gọi mạng BẮT BUỘC nào. Chạy lại script mà không có
// `--refresh` thì digest lấy từ lock file, và bản build không phụ thuộc vào
// việc Docker Hub có sống hay không. `--refresh` là lúc DUY NHẤT digest đổi, và
// nó là một hành động có chủ đích của người chạy.
//
// # Vì sao validate lại ở đây khi Go đã validate
//
// Không phải để thay Go — internal/catalog.Parse mới là trọng tài, và
// TestBuiltinCatalogIsValid là cái gác cổng thật. Kiểm ở đây chỉ để lỗi lộ ra
// ngay lúc sinh file, kèm tên app, thay vì lộ ra ở một dòng `go test` nói
// "manifest nhúng hỏng" sau khi đã chép 30 file vào manifests/.
//
// Dùng:
//	node import.mjs --src /đường/dẫn/devopsbookmarks.com [--refresh] [--promote]

import { readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync, existsSync, copyFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const catalogRoot = resolve(here, '..', '..')
const outDir = join(here, 'out')
const outManifestDir = join(outDir, 'manifests')
const lockFile = join(here, 'mapping.lock.json')

// --- tham số ---------------------------------------------------------------------

const argv = process.argv.slice(2)
function flag(name) {
  return argv.includes(`--${name}`)
}
function opt(name) {
  const i = argv.indexOf(`--${name}`)
  return i >= 0 ? argv[i + 1] : undefined
}

const srcDir = opt('src') ?? process.env.DOB_SRC
const doRefresh = flag('refresh')
const doPromote = flag('promote')

if (!srcDir) {
  die(
    'thiếu --src.\n' +
      'Cần một bản clone của https://github.com/devopsbookmarks/devopsbookmarks.com:\n' +
      '  git clone --depth 1 https://github.com/devopsbookmarks/devopsbookmarks.com.git\n' +
      '  node import.mjs --src ./devopsbookmarks.com',
  )
}

const toolsDir = join(resolve(srcDir), 'data', 'tools')
if (!existsSync(toolsDir)) die(`không thấy ${toolsDir} — --src phải trỏ vào GỐC repo devopsbookmarks`)

function die(msg) {
  console.error(`[dob-import] ${msg}`)
  process.exit(1)
}

// --- luật của manifest, chép từ internal/catalog/catalog.go ----------------------
//
// Giữ nguyên hình dạng regex bên Go. Lệch một ký tự ở đây nghĩa là script báo
// xanh còn `go test` báo đỏ, và người đọc sẽ tin nhầm cái sai.
const ID_RE = /^[a-z][a-z0-9-]{1,38}[a-z0-9]$/
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/
const REPO_RE = /^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(\/[a-z0-9]+([._-][a-z0-9]+)*)*$/
const MAX_TITLE = 100
const MAX_DESC = 2000
const MAX_ENV_VARS = 50
const MAX_ENV_VALUE_LEN = 4096

function validateManifest(m) {
  const bad = []
  if (!ID_RE.test(m.id)) bad.push(`id ${JSON.stringify(m.id)} không khớp ${ID_RE}`)
  const title = String(m.title ?? '').trim()
  if (!title || title.length > MAX_TITLE) bad.push(`title rỗng hoặc dài quá ${MAX_TITLE}`)
  if ((m.description ?? '').length > MAX_DESC) bad.push(`description dài quá ${MAX_DESC}`)
  if (!String(m.version ?? '').trim()) bad.push('thiếu version')
  if (!REPO_RE.test(m.repository ?? '')) bad.push(`repository ${JSON.stringify(m.repository)} có ký tự không cho phép`)
  if (!DIGEST_RE.test(m.digest ?? '')) bad.push(`digest ${JSON.stringify(m.digest)} phải là sha256:<64 hex>`)
  if (!(m.http_port >= 1 && m.http_port <= 65535)) bad.push(`http_port ${m.http_port} ngoài 1–65535`)
  if (m.icon && (/[/\\]/.test(m.icon) || m.icon.includes('..'))) bad.push(`icon ${JSON.stringify(m.icon)} phải là TÊN FILE`)
  const env = m.env ?? {}
  if (Object.keys(env).length > MAX_ENV_VARS) bad.push(`quá ${MAX_ENV_VARS} biến môi trường`)
  for (const [k, v] of Object.entries(env)) {
    if (!k || /[= \t\n\r\0]/.test(k)) bad.push(`tên biến môi trường không hợp lệ: ${JSON.stringify(k)}`)
    if (String(v).length > MAX_ENV_VALUE_LEN) bad.push(`giá trị của ${k} dài quá ${MAX_ENV_VALUE_LEN}`)
    if (String(v).includes('\0')) bad.push(`giá trị của ${k} chứa NUL`)
  }
  for (const u of [m.website, m.source]) {
    if (u && !/^https?:\/\//.test(u)) bad.push(`url ${JSON.stringify(u)} phải bắt đầu bằng http:// hoặc https://`)
  }
  return bad
}

// --- đọc nguồn -------------------------------------------------------------------

const { topics } = readJSON(join(here, 'topics.json'))
const mapping = readJSON(join(here, 'mapping.json')).apps
const classification = readJSON(join(here, 'classification.json'))
const lock = existsSync(lockFile) ? readJSON(lockFile) : {}

function readJSON(p) {
  try {
    return JSON.parse(readFileSync(p, 'utf8'))
  } catch (e) {
    die(`không đọc được ${p}: ${e.message}`)
  }
}

/** slug → bucket, dựng ngược từ classification.json. */
const bucketOf = new Map()
for (const [bucket, slugs] of Object.entries(classification)) {
  if (bucket.startsWith('_')) continue
  for (const s of slugs) bucketOf.set(s, bucket)
}

const tools = []
const readErrors = []
for (const f of readdirSync(toolsDir).sort()) {
  if (!f.endsWith('.json')) continue
  let parsed
  try {
    parsed = JSON.parse(readFileSync(join(toolsDir, f), 'utf8'))
  } catch (e) {
    // Nguồn ngoài, và nó CÓ file hỏng thật. Một file hỏng không được làm chết
    // cả lần nhập — cùng lý lẽ với catalog.LoadFS.
    readErrors.push(`${f}: ${e.message}`)
    continue
  }
  for (const t of Array.isArray(parsed) ? parsed : [parsed]) tools.push({ ...t, _file: f })
}

// --- chuẩn hoá -------------------------------------------------------------------

/**
 * slug của devopsbookmarks → id hợp lệ theo ID_RE.
 * Trả null khi không cứu được (có một entry mà slug là cả một URL).
 */
function toID(slug) {
  const s = String(slug ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
  return ID_RE.test(s) ? s : null
}

/** tag thô của devopsbookmarks → tag chủ đề, đã dedupe và sắp xếp. */
function toTopics(tags) {
  const out = new Set()
  for (const raw of tags ?? []) {
    const tag = String(raw).toLowerCase().trim()
    for (const t of topics) if (t.include_tags.includes(tag)) out.add(t.slug)
  }
  return [...out].sort()
}

// --- resolve digest --------------------------------------------------------------

const ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(',')

function splitRepo(repository) {
  const parts = repository.split('/')
  const host = parts[0]
  const path = parts.slice(1).join('/')
  // docker.io là tên logic; endpoint thật là registry-1.docker.io.
  return { registry: host === 'docker.io' ? 'registry-1.docker.io' : host, path }
}

async function tokenFor(challenge, path) {
  // www-authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
  const get = (k) => challenge.match(new RegExp(`${k}="([^"]+)"`))?.[1]
  const realm = get('realm')
  if (!realm) return null
  const u = new URL(realm)
  const service = get('service')
  if (service) u.searchParams.set('service', service)
  u.searchParams.set('scope', `repository:${path}:pull`)
  const r = await fetch(u, { signal: AbortSignal.timeout(30_000) })
  if (!r.ok) return null
  const j = await r.json()
  return j.token ?? j.access_token ?? null
}

/** @returns {Promise<string>} digest của manifest list (thứ `docker pull repo@digest` dùng) */
async function resolveDigest(repository, tag) {
  const { registry, path } = splitRepo(repository)
  const url = `https://${registry}/v2/${path}/manifests/${encodeURIComponent(tag)}`
  const opts = { headers: { Accept: ACCEPT }, signal: AbortSignal.timeout(30_000) }

  let r = await fetch(url, opts)
  if (r.status === 401) {
    const token = await tokenFor(r.headers.get('www-authenticate') ?? '', path)
    if (!token) throw new Error(`registry ${registry} đòi xác thực nhưng không cấp token ẩn danh`)
    r = await fetch(url, { ...opts, headers: { ...opts.headers, Authorization: `Bearer ${token}` } })
  }
  if (!r.ok) throw new Error(`GET ${url} → HTTP ${r.status}`)

  const digest = r.headers.get('docker-content-digest')
  if (!digest) throw new Error(`${repository}:${tag} không trả Docker-Content-Digest`)
  if (!DIGEST_RE.test(digest)) throw new Error(`digest lạ từ registry: ${digest}`)
  return digest
}

async function digestFor(repository, tag) {
  const key = `${repository}:${tag}`
  if (!doRefresh && lock[key]?.digest) return { digest: lock[key].digest, fromLock: true }
  const digest = await resolveDigest(repository, tag)
  lock[key] = { digest, resolved_at: new Date().toISOString() }
  return { digest, fromLock: false }
}

// --- dựng ------------------------------------------------------------------------

const directory = []
const manifests = []
const problems = []
const seenIDs = new Map()

for (const t of tools) {
  const spec = mapping[t.slug] ?? {}
  const id = spec.id ?? toID(t.slug)
  const entry = {
    id,
    source_slug: t.slug,
    title: spec.title ?? String(t.name ?? '').trim(),
    description: spec.description ?? String(t.description ?? '').trim(),
    tags: toTopics(t.tags),
    source_tags: t.tags ?? [],
    website: spec.website ?? t.url ?? null,
    status: spec.status ?? bucketOf.get(t.slug) ?? 'unmapped',
    note: spec.note ?? null,
    repository: spec.repository ?? null,
    tag: spec.tag ?? null,
    digest: null,
    http_port: spec.http_port ?? null,
    min_memory_mb: spec.min_memory_mb ?? null,
    healthcheck_path: spec.healthcheck_path ?? null,
  }

  if (!id) {
    // Có một entry thật mà `slug` là cả một URL MSDN. Không cứu được thành id,
    // và bịa một id nghĩa là entry đó không grep ra được từ dữ liệu nguồn.
    entry.status = 'bad-slug'
    problems.push(`${t._file}: slug ${JSON.stringify(t.slug)} không chuẩn hoá thành id hợp lệ được`)
    directory.push(entry)
    continue
  }
  if (seenIDs.has(id)) {
    // devopsbookmarks CÓ id trùng thật (slug "simp" xuất hiện hai lần, hai dự
    // án khác nhau). Giữ cái đầu, báo cái sau — im lặng ghi đè nghĩa là một
    // entry biến mất và không ai biết.
    entry.status = 'duplicate-id'
    problems.push(`${t._file}: id ${JSON.stringify(id)} đã dùng bởi ${seenIDs.get(id)} — bỏ qua entry sau`)
    directory.push(entry)
    continue
  }
  seenIDs.set(id, t._file)
  directory.push(entry)

  if (!spec.repository) continue

  try {
    const { digest, fromLock } = await digestFor(spec.repository, spec.tag)
    entry.digest = digest

    // Thứ tự trường bám theo manifest có sẵn (nginx.json) — diff giữa một entry
    // nhập và một entry viết tay phải là nội dung, không phải thứ tự khoá.
    const m = {
      id,
      title: entry.title,
      description: entry.description,
      version: spec.version ?? String(spec.tag).replace(/^v/, ''),
      repository: spec.repository,
      tag: spec.tag,
      digest,
      http_port: spec.http_port,
      // env chỉ mang giá trị KHÔNG phụ thuộc từng lần cài. Thứ phụ thuộc tên
      // miền hay bí mật của người dùng (ALLOWED_HOSTS, OAuth secret) thuộc về
      // InstallOptions.Env lúc bấm cài, không thuộc về manifest.
      env: spec.env && Object.keys(spec.env).length ? spec.env : null,
      min_memory_mb: spec.min_memory_mb,
      healthcheck_path: spec.healthcheck_path ?? '/',
      tags: entry.tags,
      website: entry.website,
      // devopsbookmarks chỉ có MỘT url. Chép nó vào cả website lẫn source thì
      // trang chi tiết app hiện hai nút giống hệt nhau trỏ cùng một chỗ (xem
      // apps/[slug]/page.tsx). `source` chỉ có nghĩa khi nó KHÁC website.
      source: spec.source && spec.source !== entry.website ? spec.source : null,
    }
    for (const k of Object.keys(m)) if (m[k] === null || m[k] === undefined) delete m[k]

    const bad = validateManifest(m)
    if (bad.length) {
      entry.status = 'invalid'
      problems.push(`${id}: ${bad.join('; ')}`)
      continue
    }
    manifests.push({ manifest: m, status: entry.status, note: entry.note })
    console.log(`[dob-import] ${id.padEnd(16)} ${spec.repository}:${spec.tag} ${fromLock ? '(lock)' : '→ ' + digest.slice(0, 19)}`)
  } catch (e) {
    entry.status = 'resolve-failed'
    problems.push(`${id}: không resolve được ${spec.repository}:${spec.tag} — ${e.message}`)
  }
}

// --- ghi ra ----------------------------------------------------------------------

rmSync(outDir, { recursive: true, force: true })
mkdirSync(outManifestDir, { recursive: true })

directory.sort((a, b) => String(a.id ?? a.source_slug).localeCompare(String(b.id ?? b.source_slug)))
writeFileSync(
  join(outDir, 'directory.generated.json'),
  JSON.stringify({ source: 'devopsbookmarks.com', count: directory.length, entries: directory }, null, 2) + '\n',
)

manifests.sort((a, b) => a.manifest.id.localeCompare(b.manifest.id))
for (const { manifest } of manifests) {
  // Tên file PHẢI bằng id: catalog.LoadFS từ chối file lệch tên.
  writeFileSync(join(outManifestDir, `${manifest.id}.json`), JSON.stringify(manifest, null, 2) + '\n')
}

writeFileSync(lockFile, JSON.stringify(sortKeys(lock), null, 2) + '\n')

function sortKeys(o) {
  return Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)))
}

// --- báo cáo ---------------------------------------------------------------------

const byStatus = new Map()
for (const e of directory) byStatus.set(e.status, [...(byStatus.get(e.status) ?? []), e])

const STATUS_DOC = {
  ready: 'Cài được ngay, không mất dữ liệu. Được `--promote` vào ../../manifests/.',
  'needs-volumes': 'Manifest chưa có trường `volumes` (contracts.DesiredApp thì có). Chạy được nhưng deploy lại là mất dữ liệu.',
  'needs-addons': 'Manifest chưa có trường `addons`. Cần database/queue ngoài mới khởi động được.',
  'needs-host': 'Cần mount đường dẫn host hoặc docker socket — ngoài mô hình app, không phải chuyện thêm một trường.',
  saas: 'Dịch vụ thương mại, không có bản self-host chạy container.',
  cli: 'Công cụ dòng lệnh hoặc thư viện — không phục vụ HTTP, không có http_port để khai.',
  'host-platform': 'Bản thân nó là runtime/orchestrator, chạy ở tầng host.',
  'k8s-only': 'Chỉ chạy như workload trong Kubernetes.',
  'multi-container': 'Cần nhiều container phối hợp; một manifest một image không diễn đạt được.',
  dead: 'Dự án ngừng phát triển, không còn image phát hành.',
  unmapped: 'CHƯA AI KHẢO SÁT. Không phải "không dùng được" — chỉ là chưa ai tra image, cổng và đường health.',
  'bad-slug': 'slug nguồn không chuẩn hoá thành id hợp lệ được.',
  'duplicate-id': 'Trùng id với một entry trước đó.',
  invalid: 'Đã dựng được manifest nhưng nó KHÔNG qua validate. Đây là lỗi của mapping.json.',
  'resolve-failed': 'Không lấy được digest từ registry — tag sai, repo đổi tên, hoặc mất mạng.',
}

const ORDER = ['ready', 'needs-volumes', 'needs-addons', 'needs-host', 'invalid', 'resolve-failed', 'multi-container', 'k8s-only', 'host-platform', 'cli', 'saas', 'dead', 'bad-slug', 'duplicate-id', 'unmapped']

let md = `# Nhập devopsbookmarks.com → catalog\n\n`
md += `Sinh bởi \`tools/devopsbookmarks/import.mjs\`. KHÔNG sửa tay — sửa \`mapping.json\` rồi chạy lại.\n\n`
md += `- Entry nguồn: **${directory.length}**\n`
md += `- Dựng được manifest hợp lệ: **${manifests.length}** (trong \`out/manifests/\`)\n`
md += `- Trong đó \`ready\`, được promote: **${manifests.filter((m) => m.status === 'ready').length}**\n\n`
md += `Chỉ \`ready\` mới vào \`keenrig-catalog/manifests/\`. Lý do ở mỗi mục dưới đây.\n\n`

if (readErrors.length) {
  md += `## File nguồn đọc không được\n\n${readErrors.map((e) => `- ${e}`).join('\n')}\n\n`
}
if (problems.length) {
  md += `## Vấn đề\n\n${problems.map((e) => `- ${e}`).join('\n')}\n\n`
}

for (const status of ORDER) {
  const list = byStatus.get(status)
  if (!list?.length) continue
  md += `## \`${status}\` — ${list.length}\n\n${STATUS_DOC[status] ?? ''}\n\n`
  for (const e of list) {
    md += `- **${e.id ?? e.source_slug}** — ${e.title}`
    if (e.repository) md += ` \`${e.repository}:${e.tag}\``
    if (e.note) md += `\n  - ${e.note}`
    md += `\n`
  }
  md += `\n`
}
writeFileSync(join(outDir, 'REPORT.md'), md)

// --- promote ---------------------------------------------------------------------

let promoted = 0
if (doPromote) {
  const dest = join(catalogRoot, 'manifests')
  for (const { manifest, status } of manifests) {
    if (status !== 'ready') continue
    copyFileSync(join(outManifestDir, `${manifest.id}.json`), join(dest, `${manifest.id}.json`))
    promoted++
  }
}

console.log(
  `[dob-import] ${directory.length} entry → ${manifests.length} manifest hợp lệ, ` +
    `${byStatus.get('ready')?.length ?? 0} ready` +
    (doPromote ? `, ${promoted} đã promote vào manifests/` : ', chưa promote (thêm --promote)'),
)
if (problems.length) console.log(`[dob-import] ${problems.length} vấn đề — xem out/REPORT.md`)
console.log(`[dob-import] out/ ← directory.generated.json, manifests/, REPORT.md`)

// Vấn đề ở mapping.json là LỖI CỦA TA, không phải của nguồn: nếu một entry ta
// tự khai mà không dựng được manifest thì lần chạy này phải đỏ.
const ourFault = directory.filter((e) => e.status === 'invalid' || e.status === 'resolve-failed')
if (ourFault.length) process.exit(1)
