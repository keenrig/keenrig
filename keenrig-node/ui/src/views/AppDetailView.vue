<script setup>
// A3 — Chi tiết app (design/v2/admin.html#a3): xem app đang ra sao và đổi một
// thiết lập một cách an toàn.
//
// # Đầu trang: sự thật trước, hành động sau
//
// Đèn + chữ trạng thái (P6), dòng đồng bộ desired ↔ applied ("Applied
// revision 7 · up to date" / "Applying revision 8…"), số revision, image, App ID
// nằm trong Details (P5). Hành động: Open (khi app có domain) và ⋯ → Uninstall.
// Thiết kế vẽ thêm Restart/Stop: box chưa có API cho hai việc đó, nên KHÔNG vẽ
// (P8) — thay vì nút xám có tooltip như v1.
//
// # Năm tab
//
//   Overview · Access · Configuration · Logs · Backups
//
// Logs và Backups chưa có API: hai tab đó in LỆNH THẬT (đã điền sẵn ID app)
// kèm nút Copy — phiên bản "hôm nay" trung thực của thiết kế (P8).
//
// # Configuration là form → diff → MỘT PATCH
//
// Mọi chỉnh sửa gom thành MỘT PATCH /apps/:id/desired; người dùng thấy chính
// xác diff trước khi áp. Rời tab khi còn thay đổi chưa áp thì hiện guard inline
// — không âm thầm bỏ (thiết kế A3, ghi chú 5).
import { ref, computed, inject, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from '../api/client'
import { suggestFqdn } from '../parentDomain'
import { statusOf, ledOf, needsAttention, initials, hue } from '../appMeta'
import { ago } from '../ago'
import Icon from '../components/Icon.vue'
import CmdBox from '../components/CmdBox.vue'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const id = route.params.id
const instance = inject('instance', ref(null))

const app = ref(null)
const domains = ref([])
const err = ref('')
const notice = ref('')
const TABS = ['overview', 'access', 'config', 'logs', 'backups']
const tab = ref(TABS.includes(route.query.tab) ? route.query.tab : 'overview')
let poll

// --- nạp + poll: đang áp thì 2s, rảnh thì 10s -------------------------------------
const busy = computed(() => !!app.value && app.value.desired_rev > app.value.applied_rev)

async function load() {
  try {
    app.value = await api.getApp(id)
    domains.value = (await api.listDomains(id)) ?? []
    err.value = ''
    suggest()
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      router.replace('/apps')
      return
    }
    err.value = e.message
  }
  schedule()
}
function schedule() {
  window.clearTimeout(poll)
  poll = window.setTimeout(load, busy.value ? 2000 : 10000)
}
onMounted(async () => {
  // Hỏi box tên miền gốc TRƯỚC khi nạp app: hỏng thì suy từ URL vẫn đúng gần
  // như mọi ca, và một gợi ý thiếu không đáng để chặn cả trang.
  try {
    knownParent.value = ((await api.instance())?.parent_domain || '').toLowerCase()
  } catch {
    /* suy từ URL */
  }
  await load()
  if (tab.value === 'config') openConfig()
})
onUnmounted(() => window.clearTimeout(poll))

const status = computed(() => (app.value?.status && typeof app.value.status === 'object' ? app.value.status : {}))
const stateName = computed(() => statusOf(app.value))
const primary = computed(() => domains.value.find((d) => d.is_primary)?.fqdn || domains.value[0]?.fqdn || '')
const image = computed(() => app.value?.desired?.image || '')

// Thông điệp của reconciler không có dấu chấm cuối; ghép cạnh câu khác thì cần.
function sentence(m) {
  const s = String(m || '').trim()
  return /[.!?…]$/.test(s) ? s : `${s}.`
}
function rel(ts) {
  return ago(t, ts)
}
function copy(v) {
  navigator.clipboard?.writeText(v).then(
    () => flash(t('common.copied')),
    () => flash(t('common.pressCtrlC')),
  )
}
function flash(msg, ms = 1500) {
  notice.value = msg
  window.setTimeout(() => (notice.value = ''), ms)
}

// --- tab + guard thay đổi chưa áp -------------------------------------------------------
const pendingTab = ref('')
function selectTab(name) {
  if (name === tab.value) return
  if (tab.value === 'config' && dirty.value) {
    pendingTab.value = name
    return
  }
  goTab(name)
}
function goTab(name) {
  pendingTab.value = ''
  if (name === 'config') openConfig()
  tab.value = name
  router.replace({ query: name === 'overview' ? {} : { tab: name } })
}
function discardAndGo() {
  const next = pendingTab.value
  openConfig() // form về đúng desired hiện tại → diff rỗng
  goTab(next)
}

// --- tab Configuration: form → diff → PATCH --------------------------------------------
const FIELDS = [
  { key: 'image', label: 'detail.fImage' },
  { key: 'memory_mb', label: 'detail.fMemoryMb' },
  { key: 'cpu', label: 'detail.fCpu' },
  { key: 'replicas', label: 'detail.fReplicas' },
]
function current() {
  const d = app.value?.desired ?? {}
  return {
    image: d.image ?? '',
    memory_mb: d.resources?.memory_mb ?? '',
    cpu: d.resources?.cpu ?? '',
    replicas: d.resources?.replicas ?? '',
  }
}
const form = ref(null) // {image, memory_mb, cpu, replicas}
function openConfig() {
  form.value = current()
}
function changed(k) {
  return !!form.value && !!app.value && String(current()[k]) !== String(form.value[k])
}
const changes = computed(() => {
  if (!form.value || !app.value) return []
  // Diff ghi NHÃN người đọc được ("Bộ nhớ (MB)"), không phải đường dẫn JSON
  // ("resources.memory_mb"): người xem lại là chủ cửa hàng, không phải API.
  return FIELDS.filter((f) => changed(f.key)).map((f) => ({
    path: f.key === 'image' ? 'image' : `resources.${f.key}`,
    label: t(f.label),
    from: current()[f.key],
    to: form.value[f.key],
  }))
})
const dirty = computed(() => changes.value.length > 0)
function show(v) {
  return v === '' || v === null || v === undefined ? t('detail.empty') : String(v)
}
const applyBusy = ref(false)
async function applyConfig() {
  if (!dirty.value || applyBusy.value) return
  applyBusy.value = true
  err.value = ''
  try {
    // PATCH mang desired ĐẦY ĐỦ đã sửa — server validate qua schema, và một
    // trường bịa sẽ chết ở admission chứ không im lặng đi tiếp.
    const next = JSON.parse(JSON.stringify(app.value.desired ?? {}))
    next.image = form.value.image
    next.resources = next.resources ?? {}
    for (const k of ['memory_mb', 'cpu', 'replicas']) {
      const v = form.value[k]
      if (v === '' || v === null) delete next.resources[k]
      else next.resources[k] = Number(v)
    }
    if (Object.keys(next.resources).length === 0) delete next.resources
    await api.updateDesired(id, next)
    await load()
    openConfig() // đồng bộ form với desired mới → diff rỗng
    flash(t('detail.applied'), 2500)
  } catch (e) {
    err.value = e.message
  } finally {
    applyBusy.value = false
  }
}

// --- tab Access: domains ----------------------------------------------------------------
//
// # Ô nhập mở ra đã có `<slug>.<parent>`, không phải trống trơn
//
// App cài từ danh mục lúc ô "Domain" còn trống ra đời KHÔNG có domain nào — và
// trang này chỉ nói "chưa có domain nào", để người dùng tự gõ lại cả FQDN mà
// box đã biết thừa. Nên điền sẵn.
//
// Điền sẵn là ĐỀ XUẤT, không phải sự thật: chừng nào chưa bấm Add thì gateway
// vẫn chưa có route lẫn cert cho tên đó. Vì vậy nó nằm trong Ô NHẬP chứ không
// phải trong danh sách domain — hiện nó ở danh sách sẽ là một lời hứa mà
// https:// không giữ, đúng kiểu bẫy "200 OK vô nghĩa".
const newFqdn = ref('')
const newPrimary = ref(false)
const domBusy = ref(false)
const fqdnEdited = ref(false) // người dùng chạm vào ô → poll 10s không được giẫm lên
const knownParent = ref('')

function suggest() {
  if (fqdnEdited.value || domains.value.length || !app.value) return
  const s = suggestFqdn(app.value.slug, knownParent.value)
  if (!s) return
  newFqdn.value = s
  newPrimary.value = true // domain đầu tiên của app thì primary là mặc định đúng
}
async function addDomain() {
  const fqdn = newFqdn.value.trim().toLowerCase()
  if (!fqdn || domBusy.value) return
  domBusy.value = true
  err.value = ''
  try {
    await api.addDomain(id, fqdn, newPrimary.value)
    newFqdn.value = ''
    newPrimary.value = false
    fqdnEdited.value = false
    await load()
  } catch (e) {
    err.value = e instanceof ApiError && e.status === 409 ? t('detail.domainTaken') : e.message
  } finally {
    domBusy.value = false
  }
}
// Nguồn của domain là NHÃN (thiết kế A4 ghi chú 5): tên nằm dưới tên miền do
// Keenrig Cloud cấp thì mang nhãn Cloud — đó là thứ sẽ dừng khi rút cloud.
function isCloudName(fqdn) {
  const p = instance.value?.parent_domain
  return instance.value?.parent_domain_source === 'cloud' && !!p && (fqdn === p || fqdn.endsWith('.' + p))
}
// Gỡ domain là gỡ route + cert ngay — gõ lại đúng FQDN mới cho bấm, kiểu
// GitHub "type the repo name". Một cú click nhầm không được làm sập https://.
const removing = ref('') // fqdn đang mở hộp xác nhận
const removeTyped = ref('')
function askRemove(fqdn) {
  removing.value = fqdn
  removeTyped.value = ''
}
function cancelRemove() {
  removing.value = ''
  removeTyped.value = ''
}
async function removeDomain() {
  const fqdn = removing.value
  if (!fqdn || removeTyped.value.trim().toLowerCase() !== fqdn || domBusy.value) return
  domBusy.value = true
  err.value = ''
  try {
    await api.removeDomain(fqdn)
    cancelRemove()
    fqdnEdited.value = false // xoá hết thì ô nhập lại mở ra với gợi ý
    await load()
  } catch (e) {
    err.value = e.message
  } finally {
    domBusy.value = false
  }
}

// --- ⋯ → Uninstall (xác nhận hai bước, nói rõ 202-đang-xoá) ---------------------------
const menu = ref(false)
const confirmDelete = ref(false)
// Gỡ app xoá cả DỮ LIỆU — nặng hơn gỡ domain, nên ít nhất cũng phải gõ lại
// tên như gỡ domain (trước đây chỉ hai cú bấm).
const deleteTyped = ref('')
const deleteBusy = ref(false)
function askDelete() {
  confirmDelete.value = true
  deleteTyped.value = ''
}
function deleteToBackups() {
  confirmDelete.value = false
  selectTab('backups')
}
// Menu đóng khi bấm ra ngoài hoặc Esc (R9), và Esc trả focus về nút ⋯.
const menuWrap = ref(null)
const menuBtn = ref(null)
function onDocDown(e) {
  if (menu.value && !menuWrap.value?.contains(e.target)) menu.value = false
}
function onDocKey(e) {
  if (e.key === 'Escape' && menu.value) {
    menu.value = false
    menuBtn.value?.focus()
  }
}
onMounted(() => {
  document.addEventListener('mousedown', onDocDown)
  document.addEventListener('keydown', onDocKey)
})
onUnmounted(() => {
  document.removeEventListener('mousedown', onDocDown)
  document.removeEventListener('keydown', onDocKey)
})
async function doDelete() {
  if (deleteTyped.value.trim() !== app.value?.slug || deleteBusy.value) return
  deleteBusy.value = true
  try {
    await api.deleteApp(id)
    // 202: app rời API ngay, container còn đang dọn — Apps nói "đang gỡ".
    router.replace({ path: '/apps', query: { removed: app.value.slug } })
  } catch (e) {
    err.value = e.message
  } finally {
    deleteBusy.value = false
  }
}

// --- lệnh thật cho Logs / Backups ----------------------------------------------------------
// Container mang nhãn keenrig.com.id=<app id> (runtime/driver/docker): lọc theo
// nhãn đúng cả khi rev đổi và tên container đổi theo.
const logsCmd = computed(() => `sudo docker logs --tail 200 $(sudo docker ps -q --filter label=keenrig.com.id=${id} | head -n 1)`)
const BOX = '/var/lib/keenrig/bin/keenrig-box'
const listCmd = `${BOX} backups`
const restoreCmd = computed(() => `${BOX} restore --data /var/lib/keenrig --from <id> --app ${id}`)
</script>

<template>
  <div v-if="app" class="stack-lg" :class="{ 'has-savebar': tab === 'config' && dirty }">
    <nav class="crumbs" :aria-label="t('detail.crumbs')">
      <router-link to="/apps">{{ t('nav.apps') }}</router-link><span>/</span><b class="cur">{{ app.slug }}</b>
    </nav>

    <div class="apph">
      <span class="appicon lg" :style="{ '--h': hue(app.slug) }">{{ initials(app.slug) }}</span>
      <div class="ttl">
        <h1>{{ app.slug }}</h1>
        <a v-if="primary" class="dom-link" :href="`https://${primary}`" target="_blank" rel="noopener noreferrer">{{ primary }}<Icon name="ext" /></a>
        <span v-else class="faint">{{ t('apps.noDomain') }}</span>
        <div class="row">
          <span class="status" data-testid="app-state">
            <span class="led" :class="ledOf(stateName)" />{{ t(`state.${stateName}`) }}
          </span>
        </div>
      </div>
      <div class="acts">
        <a v-if="primary" class="btn" :class="{ primary: !confirmDelete && (!dirty || tab !== 'config') }" :href="`https://${primary}`" target="_blank" rel="noopener noreferrer">
          <Icon name="ext" />{{ t('detail.open') }}
        </a>
        <div ref="menuWrap" class="menu-wrap">
          <button ref="menuBtn" type="button" class="btn icon" aria-haspopup="menu" :aria-label="t('detail.more')" :aria-expanded="menu" @click="menu = !menu"><Icon name="more" /></button>
          <div v-if="menu" class="menu panel" role="menu" @click="menu = false">
            <button type="button" class="menu-i danger" role="menuitem" @click="askDelete"><Icon name="trash" />{{ t('detail.uninstall') }}</button>
          </div>
        </div>
      </div>
    </div>

    <!-- App cần chú ý: nói bước tiếp theo NGAY đầu trang, kèm lối tới đúng tab -->
    <div v-if="needsAttention(stateName)" class="note warn" role="status" data-testid="attention">
      <Icon name="alert" />
      <div class="vcol">
        <p><b>{{ t('apps.attentionTitle', { app: app.slug }) }}</b> <span v-if="status.message" class="wrap">{{ sentence(status.message) }}</span></p>
        <p>{{ t('detail.attnNext') }}</p>
        <div class="row">
          <button type="button" class="btn sm" @click="selectTab('logs')">{{ t('detail.attnLogs') }}</button>
          <button type="button" class="btn ghost sm" @click="selectTab('config')">{{ t('detail.attnConfig') }}</button>
        </div>
      </div>
    </div>

    <!-- xác nhận gỡ: nói rõ mất gì, gõ lại tên app mới cho bấm -->
    <div v-if="confirmDelete" class="note danger" role="alert" data-testid="uninstall-confirm">
      <Icon name="alert" />
      <div class="vcol">
        <p>
          <b>{{ t('detail.deleteWarn', { slug: app.slug }) }}</b> {{ t('detail.deleteBackup') }}
          <a href="#" @click.prevent="deleteToBackups">{{ t('detail.deleteBackupLink') }}</a>
        </p>
        <label class="hint" for="rm-app">{{ t('detail.deleteType') }} <code>{{ app.slug }}</code></label>
        <div class="row">
          <input
            id="rm-app"
            v-model="deleteTyped"
            class="input mono grow"
            type="text"
            :placeholder="app.slug"
            spellcheck="false"
            autocapitalize="none"
            autocomplete="off"
            @keyup.enter="doDelete"
            @keyup.esc="confirmDelete = false"
          />
          <button type="button" class="btn ghost sm" @click="confirmDelete = false">{{ t('common.cancel') }}</button>
          <button type="button" class="btn danger solid sm" :disabled="deleteBusy || deleteTyped.trim() !== app.slug" @click="doDelete">{{ t('detail.deleteGo') }}</button>
        </div>
      </div>
    </div>

    <!-- Dòng đồng bộ desired ↔ applied -->
    <div class="sync">
      <!-- Đang áp + đang ở Tổng quan: thẻ tiến trình bên dưới đã nói đúng câu
           này — không lặp ba lần trên một màn. -->
      <span v-if="!(busy && tab === 'overview')" class="status" data-testid="sync-line">
        <span class="led" :class="busy ? 'busy' : stateName === 'running' ? 'ok' : ''" />
        {{ busy ? (app.applied_rev ? t('detail.syncApplying') : t('detail.syncFirst')) : t('detail.syncUpToDate') }}
      </span>
      <details class="disc">
        <summary>{{ t('detail.details') }}</summary>
        <dl class="kv">
          <dt>{{ t('detail.desiredRev') }}</dt><dd class="mono">{{ app.desired_rev }}</dd>
          <dt>{{ t('detail.appliedRev') }}</dt><dd class="mono">{{ app.applied_rev }}</dd>
          <dt>{{ t('detail.fImage') }}</dt><dd class="mono wrap">{{ image || '—' }}</dd>
          <dt>{{ t('detail.appId') }}</dt><dd class="mono">{{ app.id }}</dd>
        </dl>
      </details>
    </div>

    <div class="tabs" role="tablist">
      <button v-for="name in TABS" :key="name" type="button" role="tab" :aria-selected="tab === name" :class="{ on: tab === name }" :data-tab="name" @click="selectTab(name)">
        {{ t(`detail.tab_${name}`) }}
        <span v-if="name === 'config' && dirty" class="badge accent">{{ t('detail.nUnsaved', changes.length) }}</span>
      </button>
    </div>

    <!-- Guard: rời Configuration khi còn thay đổi chưa áp -->
    <div v-if="pendingTab" class="note warn" role="alert">
      <Icon name="alert" />
      <div class="vcol">
        <p><b>{{ t('detail.guardTitle', changes.length) }}</b> {{ t('detail.guardBody') }}</p>
        <div class="row">
          <button type="button" class="btn sm" @click="pendingTab = ''">{{ t('detail.reviewChanges') }}</button>
          <button type="button" class="btn ghost danger sm" @click="discardAndGo">{{ t('detail.discardAndOpen', { tab: t(`detail.tab_${pendingTab}`) }) }}</button>
        </div>
      </div>
    </div>

    <p v-if="err" class="err" role="alert">{{ err }}</p>
    <p v-if="notice" class="ok-msg" role="status">{{ notice }}</p>

    <!-- ==== OVERVIEW ==== -->
    <div v-if="tab === 'overview'" class="grid-2" :class="{ busy }">
      <div class="panel">
        <dl class="kv panel-b info">
          <!-- Thứ người ta cần trước (tên, địa chỉ, khi nào) lên đầu; mã kỹ thuật
               (phiên bản thiết lập, image, App ID) xuống cuối. -->
          <dt>{{ t('detail.slug') }}</dt><dd class="mono">{{ app.slug }}</dd>
          <dt>{{ t('detail.domain') }}</dt><dd class="mono">{{ primary || '—' }}</dd>
          <dt>{{ t('detail.createdAt') }}</dt><dd>{{ rel(app.created_at) }}</dd>
          <dt>{{ t('detail.updatedAt') }}</dt><dd>{{ rel(app.updated_at) }}</dd>
          <dt>{{ t('detail.revision') }}</dt><dd class="mono" data-testid="rev">{{ app.applied_rev }} / {{ app.desired_rev }}</dd>
          <dt>{{ t('detail.endpoint') }}</dt>
          <dd class="mono">{{ app.endpoints?.length ? `${app.endpoints[0].host}:${app.endpoints[0].port}` : t('common.notReported') }}</dd>
          <dt>{{ t('detail.fImage') }}</dt>
          <dd class="mono">{{ image || '—' }}<button v-if="image" type="button" class="cp" :aria-label="t('common.copy')" @click="copy(image)"><Icon name="copy" /></button></dd>
          <dt>{{ t('detail.appId') }}</dt>
          <dd class="mono">{{ app.id }}<button type="button" class="cp" :aria-label="t('common.copy')" @click="copy(app.id)"><Icon name="copy" /></button></dd>
          <!-- App cần chú ý thì thông điệp đã nằm trong thẻ cảnh báo đầu trang -->
          <template v-if="status.message && !busy && !needsAttention(stateName)">
            <dt>{{ t('detail.message') }}</dt><dd>{{ status.message }}</dd>
          </template>
        </dl>
      </div>
      <div class="stack">
        <!-- Cột phải đổi theo trạng thái: đang áp → tiến trình; rảnh → tài nguyên -->
        <div v-if="busy" class="panel" data-testid="rollout">
          <div class="panel-h"><h3>{{ app.applied_rev ? t('detail.rolloutTitle') : t('detail.rolloutTitleFirst') }}</h3></div>
          <div class="panel-b">
            <ol class="vsteps">
              <li class="done"><span class="m"><Icon name="check" /></span><span>{{ t('detail.stepAccepted') }}</span></li>
              <li class="on"><span class="m"><span class="led busy" /></span><span>{{ status.message || t('detail.stepApplying') }}</span></li>
              <li><span class="m">3</span><span>{{ t('detail.stepDone') }}</span></li>
            </ol>
            <p class="hint">{{ app.applied_rev ? t('detail.rolloutHint') : t('detail.rolloutFirst') }}</p>
          </div>
        </div>
        <div v-else class="panel">
          <div class="panel-h"><h3>{{ t('detail.resources') }}</h3></div>
          <dl class="kv panel-b">
            <dt>{{ t('detail.fMemory') }}</dt><dd class="num">{{ app.desired?.resources?.memory_mb ? `${app.desired.resources.memory_mb} MB` : t('detail.noLimit') }}</dd>
            <dt>{{ t('detail.fCpu') }}</dt><dd class="num">{{ app.desired?.resources?.cpu ?? t('detail.noLimit') }}</dd>
            <dt>{{ t('detail.fReplicas') }}</dt><dd class="num">{{ app.desired?.resources?.replicas ?? 1 }}</dd>
          </dl>
        </div>
        <div v-if="app.desired?.addons && Object.keys(app.desired.addons).length" class="panel">
          <div class="panel-h"><h3>{{ t('detail.addons') }}</h3></div>
          <dl class="kv panel-b">
            <template v-for="(v, k) in app.desired.addons" :key="k">
              <dt>{{ k }}</dt><dd>{{ v?.enabled === false ? t('detail.addonOff') : t('detail.addonOn') }}</dd>
            </template>
          </dl>
        </div>
      </div>
    </div>

    <!-- ==== CONFIGURATION ==== -->
    <template v-else-if="tab === 'config' && form">
      <div class="grid-2">
        <div class="panel">
          <div class="panel-b">
            <div class="fsec">
              <h4>{{ t('detail.cfgImage') }}</h4>
              <div class="field" :class="{ chg: changed('image') }">
                <label for="cf-image">{{ t('detail.fImage') }} <span v-if="changed('image')" class="chgmark">· {{ t('detail.changedWas', { v: show(current().image) }) }}</span></label>
                <input id="cf-image" v-model="form.image" class="input mono" type="text" spellcheck="false" aria-describedby="cf-image-h" />
                <span id="cf-image-h" class="hint">{{ t('detail.imageHint') }}</span>
              </div>
            </div>
            <div class="fsec">
              <h4>{{ t('detail.resources') }}</h4>
              <div class="grid-nums">
                <div class="field" :class="{ chg: changed('memory_mb') }">
                  <label for="cf-mem">{{ t('detail.fMemoryMb') }}</label>
                  <input id="cf-mem" v-model="form.memory_mb" class="input" type="number" min="0" data-testid="cfg-memory" />
                  <span v-if="changed('memory_mb')" class="chgmark">{{ t('detail.changedWas', { v: show(current().memory_mb) }) }}</span>
                </div>
                <div class="field" :class="{ chg: changed('cpu') }">
                  <label for="cf-cpu">{{ t('detail.fCpu') }}</label>
                  <input id="cf-cpu" v-model="form.cpu" class="input" type="number" min="0" step="0.1" />
                  <span v-if="changed('cpu')" class="chgmark">{{ t('detail.changedWas', { v: show(current().cpu) }) }}</span>
                </div>
                <div class="field" :class="{ chg: changed('replicas') }">
                  <label for="cf-rep">{{ t('detail.fReplicas') }}</label>
                  <input id="cf-rep" v-model="form.replicas" class="input" type="number" min="1" />
                  <span v-if="changed('replicas')" class="chgmark">{{ t('detail.changedWas', { v: show(current().replicas) }) }}</span>
                </div>
              </div>
            </div>
            <p v-if="!dirty" class="hint" style="margin-top: var(--s4)">{{ t('detail.noChanges') }}</p>
          </div>
        </div>
        <div class="panel">
          <div class="panel-h"><h3>{{ t('detail.nowRunning') }}</h3></div>
          <dl class="kv panel-b">
            <dt>{{ t('detail.fMemory') }}</dt><dd class="num">{{ app.desired?.resources?.memory_mb ? `${app.desired.resources.memory_mb} MB` : t('detail.noLimit') }}</dd>
            <dt>{{ t('detail.fCpu') }}</dt><dd class="num">{{ app.desired?.resources?.cpu ?? t('detail.noLimit') }}</dd>
            <dt>{{ t('detail.fReplicas') }}</dt><dd class="num">{{ app.desired?.resources?.replicas ?? 1 }}</dd>
          </dl>
        </div>
      </div>

      <div v-if="dirty" class="savebar">
        <div class="sb-h">
          <h3>{{ t('detail.reviewN', changes.length) }}</h3>
        </div>
        <div class="sb-b">
          <pre class="diff"><template v-for="c in changes" :key="c.path"><span class="k">{{ c.label }}</span><span class="del">- {{ show(c.from) }}</span><span class="add">+ {{ show(c.to) }}</span></template></pre>
          <p class="hint">{{ t('detail.savesAs', { app: app.slug }) }}</p>
        </div>
        <div class="sb-f">
          <b>{{ t('detail.nUnsavedLong', changes.length) }}</b>
          <span class="spacer" />
          <button type="button" class="btn ghost" @click="openConfig">{{ t('detail.discard') }}</button>
          <button type="button" class="btn primary" :disabled="applyBusy" @click="applyConfig">
            {{ t('detail.applyN', changes.length) }}
          </button>
        </div>
      </div>
    </template>

    <!-- ==== ACCESS (domains) ==== -->
    <div v-else-if="tab === 'access'" class="stack">
      <div class="panel">
        <div class="panel-h"><h3>{{ t('detail.domains') }}</h3></div>
        <ul class="list dlist">
          <li v-for="d in domains" :key="d.fqdn" class="dmn">
            <span class="star" :class="{ on: d.is_primary }" :title="d.is_primary ? t('detail.primary') : ''"><Icon name="star" /></span>
            <div class="grow">
              <a class="t mono wrap m" :href="`https://${d.fqdn}`" target="_blank" rel="noopener noreferrer">{{ d.fqdn }} ↗</a>
              <div class="row">
                <span v-if="d.is_primary" class="badge accent">{{ t('detail.primary') }}</span>
                <span v-if="isCloudName(d.fqdn)" class="badge cloud">{{ t('domains.srcCloud') }}</span>
                <span v-else class="badge">{{ t('domains.srcOwn') }}</span>
              </div>
              <span class="s status">
                <span class="led" :class="d.cert_ref ? 'ok' : ''" />{{ t('detail.certState', { s: d.cert_ref ? t('domains.certIssued') : t('domains.certNotReported') }) }}
              </span>
            </div>
            <button v-if="removing !== d.fqdn" type="button" class="btn sm" @click="askRemove(d.fqdn)">{{ t('common.remove') }}</button>
            <div v-if="removing === d.fqdn" class="note danger dmn-confirm">
              <Icon name="alert" />
              <div class="vcol">
                <p><b>{{ t('detail.removeDomainWarn', { fqdn: d.fqdn }) }}</b></p>
                <label class="hint" :for="`rm-${d.fqdn}`">{{ t('detail.removeDomainType') }} <code>{{ d.fqdn }}</code></label>
                <div class="row">
                  <input
                    :id="`rm-${d.fqdn}`"
                    v-model="removeTyped"
                    class="input mono grow"
                    type="text"
                    :placeholder="d.fqdn"
                    spellcheck="false"
                    autocapitalize="none"
                    autocomplete="off"
                    @keyup.enter="removeDomain"
                    @keyup.esc="cancelRemove"
                  />
                  <button type="button" class="btn ghost sm" @click="cancelRemove">{{ t('common.cancel') }}</button>
                  <button
                    type="button"
                    class="btn danger solid sm"
                    :disabled="domBusy || removeTyped.trim().toLowerCase() !== d.fqdn"
                    @click="removeDomain"
                  >
                    {{ t('detail.removeDomainGo') }}
                  </button>
                </div>
              </div>
            </div>
          </li>
          <li v-if="!domains.length" class="empty-row">
            <p class="hint">
              {{ t('detail.noDomains') }}
              <template v-if="newFqdn && !fqdnEdited"> {{ t('detail.domainSuggested', { fqdn: newFqdn }) }}</template>
            </p>
          </li>
        </ul>
      </div>

      <form class="panel" @submit.prevent="addDomain">
        <div class="panel-h"><h3>{{ t('detail.addDomain') }}</h3></div>
        <div class="panel-b stack">
          <div class="row">
            <input
              v-model="newFqdn"
              class="input mono grow"
              type="text"
              placeholder="shop.cuahang.vn"
              :aria-label="t('detail.addDomain')"
              spellcheck="false"
              autocapitalize="none"
              @input="fqdnEdited = true"
            />
            <label class="check">
              <input v-model="newPrimary" type="checkbox" />{{ t('detail.makePrimary') }}
            </label>
            <button type="submit" class="btn" :disabled="domBusy || !newFqdn.trim()">
              {{ t('common.add') }}
            </button>
          </div>
          <p class="hint">{{ t('detail.domainHint') }}</p>
        </div>
      </form>
    </div>

    <!-- ==== LOGS — chưa có API: lệnh thật, đã điền ID app ==== -->
    <div v-else-if="tab === 'logs'" class="panel">
      <div class="panel-b stack">
        <div class="note">
          <Icon name="info" />
          <p><b>{{ t('detail.logsTitle') }}</b> {{ t('detail.logsBody') }}</p>
        </div>
        <span class="label">{{ t('detail.logsCmd') }}</span>
        <CmdBox :cmd="logsCmd" />
      </div>
    </div>

    <!-- ==== BACKUPS — chưa có API: lệnh thật, đã điền ID app ==== -->
    <div v-else-if="tab === 'backups'" class="panel">
      <div class="panel-b stack">
        <div class="note">
          <Icon name="info" />
          <p><b>{{ t('detail.bkTitle') }}</b> {{ t('detail.bkBody') }}</p>
        </div>
        <span class="label">{{ t('backup.cmdList') }} <small>{{ t('backup.cmdListNote') }}</small></span>
        <CmdBox :cmd="listCmd" prompt="#" />
        <span class="label">{{ t('detail.bkRestore', { app: app.slug }) }}</span>
        <CmdBox :cmd="restoreCmd" prompt="#" />
        <p class="hint">{{ t('detail.bkHint') }} <router-link to="/backups">{{ t('detail.bkMore') }}</router-link></p>
      </div>
    </div>
  </div>
  <p v-else-if="err" class="err" role="alert">{{ err }}</p>
  <p v-else class="faint">{{ t('common.loading') }}</p>
</template>
