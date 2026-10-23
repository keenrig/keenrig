<script setup>
// A3s — App Store + sheet cài app (design/v2/admin.html#a3s). Thay mục "Cài app".
//
// # Nút Install KHÔNG hỏi gì trước (gate UI-01)
//
// Gate: wizard owner → cài app → app sống, đo <60s. Bấm "Install" trên thẻ là
// cài ngay với mặc định của manifest. Ai cần đặt tên/domain/RAM thì mở
// "Customize…" — sheet phủ lên store (đóng là về đúng chỗ đang xem), domain
// suy ra và đổi theo ô Name cho tới khi người dùng tự sửa (P3).
//
// # Thứ thiết kế vẽ mà box chưa có — KHÔNG vẽ (P8)
//
//  - Nhãn "Signed": catalog chưa trả chữ ký nào cho UI đọc.
//  - Thanh bộ nhớ "in use / left after install": box chưa đo RAM của máy.
//    Thay bằng con số thật duy nhất có: min_memory_mb của manifest.
//  - Tab "Docker Compose" / thẻ "Your own app": chưa có POST /apps/import.
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter, useRoute } from 'vue-router'
import { api, ApiError } from '../api/client'
import { parentDomain as sharedParentDomain } from '../parentDomain'
import { initials, hue } from '../appMeta'
import { CONSOLE_URL, consoleBase, requestAppUrl } from '../console'
import { tagLabel } from '../tagLabel'
import Icon from '../components/Icon.vue'

const { t, locale } = useI18n()
const router = useRouter()
const route = useRoute()

// Mô tả theo ngôn ngữ đang dùng; manifest thiếu bản vi thì rơi về bản chuẩn (en).
function titleOf(item) {
  return (locale.value === 'vi' && item.title_vi) || item.title
}
function descOf(item) {
  return (locale.value === 'vi' && item.description_vi) || item.description
}

// --- mô tả dài: kẹp 3 dòng, "Xem thêm" khi THẬT SỰ bị cắt ----------------------------
//
// Mô tả n8n/Activepieces dài gấp ba Nginx: không kẹp thì một hàng thẻ cao lệch
// nhau và nút Cài trôi xuống mỗi thẻ một độ cao. "Xem thêm" chỉ hiện ở thẻ mà
// chữ bị cắt thật (đo DOM, không đoán theo số ký tự — cùng câu, màn hẹp thì cắt,
// màn rộng thì không). Bản đầy đủ cũng nằm trong sheet Tuỳ chỉnh.
const expanded = ref({})
const clamped = ref({})
const descEls = new Map()
// Đo lúc ref gắn vào là QUÁ SỚM: phần tử có thể chưa được dàn trang (font chưa
// về, lưới chưa chia cột) nên scrollHeight == clientHeight và "Xem thêm" không
// bao giờ hiện dù chữ bị cắt (rà v0.2.1). ResizeObserver báo lại mỗi khi khối
// chữ đổi cỡ — kể cả lần dàn trang đầu tiên — nên phép đo luôn là phép đo thật.
const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(() => remeasure())
function check(id, el) {
  if (expanded.value[id]) return
  const cut = el.scrollHeight > el.clientHeight + 1
  if (!!clamped.value[id] !== cut) clamped.value = { ...clamped.value, [id]: cut }
}
function measure(id, el) {
  const prev = descEls.get(id)
  if (!el) {
    if (prev) ro?.unobserve(prev)
    descEls.delete(id)
    return
  }
  if (prev !== el) {
    if (prev) ro?.unobserve(prev)
    descEls.set(id, el)
    ro?.observe(el)
  }
  check(id, el)
}
function remeasure() {
  for (const [id, el] of descEls) check(id, el)
}
onMounted(() => window.addEventListener('resize', remeasure))
onUnmounted(() => {
  window.removeEventListener('resize', remeasure)
  ro?.disconnect()
})
function toggleDesc(id) {
  expanded.value = { ...expanded.value, [id]: !expanded.value[id] }
}

const items = ref([])
const loading = ref(true)
const error = ref('') // lỗi của lần cài một chạm từ thẻ (sheet có ô lỗi riêng)
const installing = ref('')
const q = ref(typeof route.query.q === 'string' ? route.query.q : '')
const tag = ref('')
const knownParent = ref('')

// Luật suy `<parent>` nằm ở ../parentDomain.js — cùng một luật với tab Access
// của trang chi tiết app, nên hai chỗ không thể trôi khỏi nhau.
function parentDomain() {
  return sharedParentDomain(knownParent.value)
}

// --- lọc: ô tìm + chip theo tag THẬT của manifest ---------------------------------
// Chip in NHÃN (tagLabel), lọc theo slug. Hai slug cùng nghĩa ("chẩn-đoán" và
// "chan-doan") ra cùng một nhãn → gộp thành MỘT chip lọc cả hai.
const tags = computed(() => {
  const by = new Map() // label → [slug…]
  for (const i of items.value) {
    for (const tg of i.tags || []) {
      const l = tagLabel(t, tg)
      if (!by.has(l)) by.set(l, [])
      if (!by.get(l).includes(tg)) by.get(l).push(tg)
    }
  }
  return [...by.entries()]
    .map(([label, slugs]) => ({ label, slugs, key: slugs[0] }))
    .sort((a, b) => a.label.localeCompare(b.label, locale.value))
})
const activeTag = computed(() => tags.value.find((x) => x.key === tag.value))
const shown = computed(() => {
  const needle = q.value.trim().toLowerCase()
  return items.value.filter((i) => {
    if (tag.value) {
      const slugs = activeTag.value?.slugs || [tag.value]
      if (!(i.tags || []).some((tg) => slugs.includes(tg))) return false
    }
    if (!needle) return true
    return [i.id, i.title, i.title_vi, i.description, i.description_vi].some((s) => (s || '').toLowerCase().includes(needle))
  })
})

// --- "Xin thêm app" → Console ------------------------------------------------------
// Chỉ là LINK: Admin không gọi API cloud. Máy đã pair dùng Console nó đang nói
// chuyện (cloud_url do agent báo); standalone dùng Console mặc định — người
// dùng đăng nhập ở đó.
const consoleUrl = ref(CONSOLE_URL)
const requestHref = computed(() => requestAppUrl(consoleUrl.value))
const requestQHref = computed(() => requestAppUrl(consoleUrl.value, q.value))

// item.icon là TÊN FILE ("nginx.svg"), không phải nội dung — nó phải đi qua
// route phục vụ icon. In thẳng ra template là cách chữ "nginx.svg" từng tràn
// đè lên tên app.
const iconFailed = ref({})
function iconUrl(item) {
  if (!item.icon || iconFailed.value[item.id]) return ''
  return `/api/v1/catalog/icons/${encodeURIComponent(item.icon)}`
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    items.value = (await api.listCatalog())?.apps || []
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

/**
 * conflictMessage — 409 KHÔNG chỉ có một nghĩa (P9).
 *
 * Server trả ba `code` khác nhau cho ba nguyên nhân, và trước đây giao diện gộp
 * cả ba thành "slug hoặc domain đã được app khác dùng". Người chạm trần "1 app"
 * của bậc starter đọc câu đó rồi đi đổi tên app — mãi mãi không qua được, vì
 * tên chưa bao giờ là vấn đề.
 */
function conflictKind(e) {
  if (!(e instanceof ApiError) || e.status !== 409) return ''
  return e.code || 'unknown'
}
function conflictMessage(e) {
  switch (conflictKind(e)) {
    case 'license_limit':
      return t('store.errLicenseLimit')
    case 'quota':
      return t('store.errQuota')
    case 'conflict':
      return t('store.conflict')
    case 'unknown':
      // Bản box cũ chưa gửi `code`: dùng thông báo THẬT của server thay vì
      // đoán. Nó kỹ thuật hơn, nhưng đúng.
      return e.message || t('store.conflict')
    default:
      return e.message
  }
}

// --- cài một chạm từ thẻ ---------------------------------------------------------------
async function quickInstall(item) {
  installing.value = item.id
  error.value = ''
  const body = {}
  const p = parentDomain()
  if (p) body.domains = [`${item.id}.${p}`]
  try {
    await api.installFromCatalog(item.id, body)
    router.push('/apps')
  } catch (e) {
    error.value = conflictMessage(e)
  } finally {
    installing.value = ''
  }
}

// --- sheet "Customize…" -------------------------------------------------------------------
const sheet = ref(null) // { item, slug, domain, domainEdited, memory, err, kind, busy }
// Focus vào sheet khi mở, trả về nút đã mở nó khi đóng; Esc đóng ở bất kỳ đâu
// trên trang (R9) — @keydown trên lớp phủ chỉ chạy khi focus đã nằm trong nó.
const sheetEl = ref(null)
let sheetOpener = null
function onSheetKey(e) {
  if (e.key === 'Escape' && sheet.value) closeSheet()
}
onMounted(() => document.addEventListener('keydown', onSheetKey))
onUnmounted(() => document.removeEventListener('keydown', onSheetKey))
async function openSheet(item) {
  sheetOpener = document.activeElement
  const p = parentDomain()
  sheet.value = {
    item,
    slug: '',
    // Đề xuất, không ép: ô vẫn sửa được, và xoá trắng thì app không có domain.
    domain: p ? `${item.id}.${p}` : '',
    domainEdited: false,
    editingDomain: false,
    memory: '',
    err: '',
    kind: '',
    busy: false,
  }
  await nextTick()
  sheetEl.value?.querySelector('input,button')?.focus()
}
function closeSheet() {
  sheet.value = null
  sheetOpener?.focus?.()
  sheetOpener = null
}
/**
 * onSlugInput — đổi tên thì domain đi theo, TRỪ KHI người dùng đã tự sửa nó.
 *
 * Không có luật "trừ khi" này thì mỗi ký tự gõ vào ô tên sẽ xoá mất domain
 * người ta vừa nhập tay — thứ chỉ lộ ra khi ai đó thật sự dùng cả hai ô.
 */
function onSlugInput(v) {
  const s = sheet.value
  s.slug = v
  if (s.domainEdited) return
  const p = parentDomain()
  const label = (v || '').trim() || s.item.id
  s.domain = p ? `${label}.${p}` : ''
}
function onDomainInput(v) {
  sheet.value.domain = v
  // Từ giây phút người dùng chạm vào ô này, nó là của họ.
  sheet.value.domainEdited = true
}
// Gợi ý tên khác khi trùng (P9: lỗi nói bước tiếp theo).
const altNames = computed(() => {
  const s = sheet.value
  if (!s || s.kind !== 'conflict') return []
  const base = (s.slug || s.item.id).trim()
  return [`${base}-2`, `${base}-test`]
})
async function installFromSheet() {
  const s = sheet.value
  if (!s || s.busy) return
  s.busy = true
  s.err = ''
  s.kind = ''
  const body = {}
  if (s.slug.trim()) body.slug = s.slug.trim()
  if (s.domain.trim()) body.domains = [s.domain.trim()]
  if (s.memory) body.memory_mb = Number(s.memory)
  try {
    await api.installFromCatalog(s.item.id, body)
    sheet.value = null
    router.push('/apps')
  } catch (e) {
    s.kind = conflictKind(e)
    s.err = conflictMessage(e)
  } finally {
    if (sheet.value) s.busy = false
  }
}

onMounted(async () => {
  api.cloud().then((l) => (consoleUrl.value = consoleBase(l))).catch(() => { /* mặc định */ })
  // Hỏi box tên miền gốc của nó TRƯỚC khi vẽ danh mục, để domain gợi ý đúng
  // ngay từ đầu. Hỏng thì bỏ qua: suy từ URL vẫn đúng gần như mọi ca, và một
  // gợi ý thiếu không đáng để chặn cả trang.
  try {
    const info = await api.instance()
    knownParent.value = (info?.parent_domain || '').toLowerCase()
  } catch {
    /* suy từ URL */
  }
  await load()
})
</script>

<template>
  <div class="stack-lg">
    <div class="page-h">
      <div class="ttl">
        <h1>{{ t('store.title') }}</h1>
        <p class="faint">{{ t('store.subtitle') }}</p>
      </div>
    </div>

    <div v-if="items.length" class="row store-filter">
      <label class="search inline">
        <Icon name="search" />
        <input v-model="q" type="search" :placeholder="t('store.search')" :aria-label="t('store.search')" />
      </label>
      <div v-if="tags.length" class="chips" role="group" :aria-label="t('store.filter')">
        <button type="button" class="chip" :class="{ on: !tag }" :aria-pressed="!tag" @click="tag = ''">{{ t('store.all') }}</button>
        <button
          v-for="tg in tags"
          :key="tg.key"
          type="button"
          class="chip"
          :class="{ on: tag === tg.key }"
          :aria-pressed="tag === tg.key"
          :data-tag="tg.key"
          @click="tag = tg.key"
        >{{ tg.label }}</button>
      </div>
    </div>

    <p v-if="error" class="err" role="alert">{{ error }}</p>

    <p v-if="loading" class="faint">{{ t('common.loading') }}</p>
    <div v-else-if="!items.length" class="empty">
      <span class="emp-ic"><Icon name="store" /></span>
      <h3>{{ t('store.emptyTitle') }}</h3>
      <p>{{ t('store.empty') }}</p>
      <a class="btn" :href="requestHref" target="_blank" rel="noopener">{{ t('store.requestApp') }}</a>
    </div>
    <!-- Lọc ra rỗng: nói rõ cái gì không khớp + đường xin thêm ĐÚNG app đó. -->
    <div v-else-if="!shown.length" class="empty" data-testid="store-nomatch">
      <span class="emp-ic"><Icon name="search" /></span>
      <h3 class="wrap">{{ q.trim() ? t('store.noMatchQ', { q: q.trim() }) : t('store.noMatch') }}</h3>
      <p>{{ t('store.noMatchBody') }}</p>
      <div class="row center-row">
        <a class="btn primary" :href="q.trim() ? requestQHref : requestHref" target="_blank" rel="noopener" data-testid="store-request-q">
          <span class="wrap">{{ q.trim() ? t('store.requestQ', { q: q.trim() }) : t('store.requestApp') }}</span>
        </a>
        <button type="button" class="btn ghost" @click="(q = ''), (tag = '')">{{ t('store.clearFilter') }}</button>
      </div>
    </div>
    <div v-else class="cards">
      <div v-for="item in shown" :key="item.id" class="panel card" data-testid="store-card">
        <div class="row">
          <span class="appicon" :style="{ '--h': hue(item.id) }">
            <!-- alt rỗng có chủ đích: tên app đã nằm ngay dưới ở <h3>, đọc
                 lại lần nữa chỉ làm screen reader ồn hơn. Icon 404 thì rơi về
                 chữ cái đầu, đúng thứ các app không khai icon vẫn dùng. -->
            <img v-if="iconUrl(item)" :src="iconUrl(item)" alt="" @error="iconFailed[item.id] = true" />
            <template v-else>{{ initials(item.title || item.id) }}</template>
          </span>
          <span class="spacer" />
          <!-- Server đối chiếu theo image (api/catalog.go): app cài dưới slug
               khác hay do cloud ra lệnh cài vẫn hiện ở đây. -->
          <span v-if="item.installed?.length" class="badge ok" data-testid="catalog-installed">
            <Icon name="check" />{{ t('store.installedBadge') }}
          </span>
        </div>
        <h3>{{ titleOf(item) }}</h3>
        <p :id="`desc-${item.id}`" :ref="(el) => measure(item.id, el)" class="muted desc" :class="{ full: expanded[item.id] }">{{ descOf(item) }}</p>
        <button
          v-if="clamped[item.id] || expanded[item.id]"
          type="button"
          class="more-btn"
          :aria-expanded="!!expanded[item.id]"
          :aria-controls="`desc-${item.id}`"
          @click="toggleDesc(item.id)"
        >{{ expanded[item.id] ? t('store.less') : t('store.more') }}</button>
        <span class="grow-gap" />
        <p v-if="item.installed?.length" class="dom">
          {{ t('store.installedAs', { slugs: item.installed.map((a) => a.slug).join(', ') }) }}
        </p>
        <!-- Domain app sẽ nhận, hiện NGAY chứ không giấu sau "Customize": giấu
             địa chỉ của thứ vừa cài nghĩa là người dùng không biết mở nó ở đâu. -->
        <p v-else-if="parentDomain()" class="dom">{{ item.id }}.{{ parentDomain() }}</p>
        <p class="meta">
          <Icon name="chip" />
          <template v-if="item.min_memory_mb">{{ t('store.needsMemory', { mb: item.min_memory_mb }) }}</template>
          <template v-else>{{ t('store.memoryNotReported') }}</template>
          <span v-if="item.version" class="mono ver">· {{ item.version }}</span>
        </p>
        <div class="card-acts">
          <router-link v-if="item.installed?.length" class="btn sm" :to="`/apps/${item.installed[0].id}`">
            {{ t('store.open') }}
          </router-link>
          <button v-else type="button" class="btn sm" :disabled="installing === item.id" @click="quickInstall(item)">
            {{ installing === item.id ? t('store.installing') : t('store.install') }}
          </button>
          <button type="button" class="btn ghost sm" @click="openSheet(item)">
            {{ item.installed?.length ? t('store.installAnother') : t('store.customize') }}
          </button>
        </div>
      </div>
      <!-- Ô cuối lưới, luôn có, cố ý nhạt: lối ra khi kho thiếu app — dẫn sang
           form + bảng bình chọn của Console (tab mới, Admin không gọi cloud). -->
      <a class="card req-card" :href="requestHref" target="_blank" rel="noopener" data-testid="store-request">
        <span class="ic-circle"><Icon name="plus" /></span>
        <span class="vcol">
          <b>{{ t('store.requestTitle') }}</b>
          <span class="hint">{{ t('store.requestBody') }}</span>
          <span class="req-link">{{ t('store.requestLink') }}</span>
        </span>
      </a>
    </div>

    <!-- Sheet cài: phủ lên store, một primary nói đúng việc (P2) -->
    <div v-if="sheet" class="over right" @click.self="closeSheet">
      <aside ref="sheetEl" class="sheet" role="dialog" aria-modal="true" :aria-label="t('store.installApp', { app: titleOf(sheet.item) })">
        <div class="sh-h">
          <span class="appicon sm" :style="{ '--h': hue(sheet.item.id) }">{{ initials(sheet.item.title || sheet.item.id) }}</span>
          <div class="grow">
            <h3>{{ t('store.installApp', { app: titleOf(sheet.item) }) }}</h3>
            <span v-if="sheet.item.version" class="hint">{{ t('store.version', { v: sheet.item.version }) }}</span>
          </div>
          <button type="button" class="btn ghost icon" :aria-label="t('common.close')" @click="closeSheet"><Icon name="x" /></button>
        </div>
        <form class="sh-b stack" @submit.prevent="installFromSheet">
          <p class="muted sh-desc">{{ descOf(sheet.item) }}</p>
          <div class="field">
            <label for="sh-slug">{{ t('store.name') }}</label>
            <input
              id="sh-slug"
              class="input mono"
              :class="{ invalid: sheet.kind === 'conflict' }"
              :value="sheet.slug"
              :placeholder="sheet.item.id"
              spellcheck="false"
              autocapitalize="none"
              @input="onSlugInput($event.target.value)"
            />
            <span class="hint">{{ t('store.nameHint') }}</span>
          </div>
          <div class="field">
            <label for="sh-domain">{{ t('store.domain') }}</label>
            <div v-if="!sheet.editingDomain && sheet.domain" class="domlive">
              <span class="mono">https://{{ sheet.domain }}</span>
              <button type="button" class="btn sm ghost" @click="sheet.editingDomain = true">{{ t('common.edit') }}</button>
            </div>
            <input
              v-else
              id="sh-domain"
              class="input mono"
              :value="sheet.domain"
              :placeholder="t('store.domainPh')"
              spellcheck="false"
              autocapitalize="none"
              @input="onDomainInput($event.target.value)"
            />
            <span class="hint">{{ t('store.domainHint') }}</span>
          </div>
          <div class="field">
            <label for="sh-mem">{{ t('store.memory') }}</label>
            <input id="sh-mem" v-model="sheet.memory" class="input" type="number" min="0" :placeholder="t('store.memoryPh')" />
            <span class="hint">
              <template v-if="sheet.item.min_memory_mb">{{ t('store.needsMemory', { mb: sheet.item.min_memory_mb }) }} · </template>{{ t('store.memoryFreeNotReported') }}
            </span>
          </div>

          <div v-if="sheet.err" class="note danger" role="alert">
            <Icon name="alert" />
            <div class="vcol">
              <p>{{ sheet.err }}</p>
              <div v-if="altNames.length" class="row">
                <span class="hint">{{ t('store.try') }}</span>
                <button v-for="n in altNames" :key="n" type="button" class="btn sm" @click="onSlugInput(n)">{{ n }}</button>
              </div>
            </div>
          </div>
        </form>
        <div class="sh-f">
          <span class="spacer" />
          <button type="button" class="btn ghost" @click="closeSheet">{{ t('common.cancel') }}</button>
          <button type="button" class="btn primary" :disabled="sheet.busy" @click="installFromSheet">
            {{ sheet.busy ? t('store.installing') : t('store.installApp', { app: titleOf(sheet.item) }) }}
          </button>
        </div>
      </aside>
    </div>
  </div>
</template>
