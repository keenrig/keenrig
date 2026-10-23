<script setup>
// A2 — Apps: trang chủ là các app của bạn (design/v2/admin.html#a2, P1).
//
// Cả tile là một link MỞ APP ở tab mới (tới domain chính); bánh răng là đích
// thứ hai, vào cài đặt app. App chưa có domain thì không có gì để mở — tile
// dẫn vào cài đặt luôn, thay vì một link https:// trỏ vào hư không.
//
// Trạng thái là ĐÈN + CHỮ (P6), nguồn là `status` do reconciler ghi và
// desired_rev ↔ applied_rev — không có chuỗi trạng thái nào do UI tự bịa.
// Thiết kế vẽ thêm pill "Reachable": box chưa đo khả năng truy cập từ Internet,
// nên pill đó KHÔNG được vẽ (thiết kế nói rõ: chưa đo thì không hiện pill).
//
// Dải sức khoẻ máy: Disk/Memory chưa có API → "— not reported", không bao giờ
// là 0 hay một thanh rỗng giả; Backups nói thật "chưa có lịch"; Cloud đọc
// trạng thái pair thật từ /cloud.
import { ref, computed, inject, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from '../api/client'
import { statusOf, ledOf, needsAttention, primaryDomain, initials, hue } from '../appMeta'
import { parentDomain } from '../parentDomain'
import { ago } from '../ago'
import Icon from '../components/Icon.vue'

const { t, locale } = useI18n()
const router = useRouter()
const route = useRoute()
// Gỡ app trả 202: app rời API ngay nhưng container còn đang được dọn. Trang chi
// tiết đưa về đây kèm ?removed=<slug> để nói "đang gỡ", không im lặng.
const removed = ref(typeof route.query.removed === 'string' ? route.query.removed : '')
function dismissRemoved() {
  removed.value = ''
  router.replace({ query: {} })
}
// Số app trên chip máy ở sidebar (App.vue). App.vue chỉ đếm một lần lúc
// đăng nhập; trang này poll danh sách nên nó là chỗ giữ con số đó cho đúng —
// trước bản vá, cài app xong sidebar vẫn ghi "0 apps" (thấy khi quay demo 2026-10-07).
const appCount = inject('appCount', null)
const cloudLink = inject('cloudLink', ref(null))
const instance = inject('instance', ref(null))
const apps = ref(null)
const err = ref('')
const q = ref('')
let poll

const counts = computed(() => {
  // `deploying` có nhãn riêng: đếm nó vào "running" làm tiêu đề ghi "1 running"
  // trong khi chính tile ghi "applying" — hai câu trái nhau trên cùng màn.
  const c = { running: 0, applying: 0, attention: 0, stopped: 0 }
  for (const a of apps.value ?? []) {
    const s = statusOf(a)
    if (s === 'running') c.running++
    else if (s === 'deploying') c.applying++
    else if (s === 'stopped') c.stopped++
    else if (needsAttention(s)) c.attention++
  }
  return c
})
const summary = computed(() => {
  const list = apps.value ?? []
  const parts = [t('app.appCount', list.length)]
  if (counts.value.running) parts.push(t('apps.nRunning', counts.value.running))
  if (counts.value.applying) parts.push(t('apps.nApplying', counts.value.applying))
  if (counts.value.attention) parts.push(t('apps.nAttention', counts.value.attention))
  if (counts.value.stopped) parts.push(t('apps.nStopped', counts.value.stopped))
  return parts.join(' · ')
})
const visible = computed(() => {
  const list = apps.value ?? []
  const needle = q.value.trim().toLowerCase()
  if (!needle) return list
  return list.filter((a) => a.slug.toLowerCase().includes(needle) || primaryDomain(a).includes(needle))
})
// R1 luật 6: lỗi khẩn lên đầu — app cần chú ý được gọi tên trên cùng.
const attention = computed(() => (apps.value ?? []).filter((a) => needsAttention(statusOf(a))))

async function load() {
  try {
    const list = (await api.listApps()) ?? []
    // Domain chính hiện trên tile — lấy kèm, nhưng lỗi của MỘT app không được
    // làm trắng cả grid.
    await Promise.all(
      list.map(async (a) => {
        try {
          a.domains = await api.listDomains(a.id)
        } catch {
          a.domains = []
        }
      }),
    )
    apps.value = list
    if (appCount) appCount.value = list.length
    err.value = ''
  } catch (e) {
    err.value = e.message
    if (apps.value === null) apps.value = []
  }
}

// --- cloud trong dải sức khoẻ --------------------------------------------------------
function hhmm(ts) {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ''
  return new Intl.DateTimeFormat(locale.value === 'vi' ? 'vi-VN' : 'en-GB', { hour: '2-digit', minute: '2-digit' }).format(d)
}
const cloud = computed(() => {
  const c = cloudLink.value
  if (!c) return { led: '', text: t('common.loading') }
  if (c.unavailable) return { led: '', text: t('common.notReported') }
  if (c.state === 'synced') return { led: 'ok', text: t('apps.cloudSynced', { ago: ago(t, c.last_sync_at) }) }
  if (c.state === 'stale') return { led: 'warn', text: t('apps.cloudStale', { at: hhmm(c.last_sync_at) }) }
  return { led: '', text: t('apps.cloudStandalone') }
})
const cloudHost = computed(() => {
  try {
    return new URL(cloudLink.value?.cloud_url || '').host
  } catch {
    return ''
  }
})

// --- A6: ba app gợi ý, cài một chạm ------------------------------------------------
//
// Nguồn là catalog THẬT của box (ba mục đầu), domain in sẵn theo đúng luật
// `<id>.<parent>` mà App Store dùng (P3). Cài ở đây = cùng lời gọi một chạm của
// App Store, mặc định của manifest.
const sugg = ref([])
const installing = ref('')
const installErr = ref('')
async function loadSuggestions() {
  try {
    const items = (await api.listCatalog())?.apps || []
    sugg.value = items.filter((i) => !i.installed?.length).slice(0, 3)
  } catch {
    sugg.value = []
  }
}
function suggDomain(item) {
  const p = parentDomain(instance.value?.parent_domain || '')
  return p ? `${item.id}.${p}` : ''
}
function titleOf(item) {
  return (locale.value === 'vi' && item.title_vi) || item.title
}
function descOf(item) {
  return (locale.value === 'vi' && item.description_vi) || item.description
}
async function quickInstall(item) {
  installing.value = item.id
  installErr.value = ''
  const body = {}
  const d = suggDomain(item)
  if (d) body.domains = [d]
  try {
    await api.installFromCatalog(item.id, body)
    await load()
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      installErr.value =
        e.code === 'license_limit' ? t('store.errLicenseLimit') : e.code === 'quota' ? t('store.errQuota') : e.message || t('store.conflict')
    } else {
      installErr.value = e.message
    }
  } finally {
    installing.value = ''
  }
}

onMounted(async () => {
  await load()
  if (apps.value && apps.value.length === 0) loadSuggestions()
  poll = window.setInterval(load, 5000)
})
onUnmounted(() => window.clearInterval(poll))

// Thông điệp của reconciler không có dấu chấm cuối; ghép cạnh câu khác thì cần.
function sentence(m) {
  const s = String(m || '').trim()
  return /[.!?…]$/.test(s) ? s : `${s}.`
}

function openDetail(a) {
  router.push(`/apps/${a.id}`)
}
</script>

<template>
  <div class="stack-lg">
    <div class="page-h">
      <div class="ttl">
        <h1>{{ t('apps.title') }}</h1>
        <p class="faint" data-testid="apps-summary">{{ apps === null ? t('common.loading') : apps.length ? summary : t('apps.none') }}</p>
      </div>
      <div class="acts">
        <input
          v-if="apps && apps.length"
          v-model="q"
          class="input filter"
          type="search"
          :placeholder="t('apps.search')"
          :aria-label="t('apps.search')"
        />
        <router-link v-if="apps && apps.length" class="btn primary sticky-cta" to="/store">
          <Icon name="plus" />{{ t('apps.install') }}
        </router-link>
      </div>
    </div>

    <p v-if="err" class="err" role="alert">{{ err }}</p>

    <div v-if="removed" class="note" role="status" data-testid="apps-removed">
      <Icon name="info" />
      <p class="grow">{{ t('apps.removing', { app: removed }) }}</p>
      <button type="button" class="btn ghost icon sm" :aria-label="t('common.close')" @click="dismissRemoved"><Icon name="x" /></button>
    </div>

    <!-- R1 luật 6: app cần chú ý lên đầu, gọi đích danh -->
    <div v-for="a in attention" :key="'w' + a.id" class="note warn">
      <Icon name="alert" />
      <p>
        <b>{{ t('apps.attentionTitle', { app: a.slug }) }}</b>
        {{ sentence(a.status?.message || t(`state.${statusOf(a)}`)) }}
        {{ t('apps.attentionNext') }}
        <router-link :to="`/apps/${a.id}`">{{ t('apps.seeIssue') }}</router-link>
      </p>
    </div>

    <!-- Dải sức khoẻ máy: bốn ô, số thật hoặc "chưa báo cáo" -->
    <div v-if="apps && apps.length" class="health">
      <div>
        <span class="l">{{ t('apps.hDisk') }}</span>
        <span class="v faint">{{ t('common.notReported') }}</span>
      </div>
      <div>
        <span class="l">{{ t('apps.hMemory') }}</span>
        <span class="v faint">{{ t('common.notReported') }}</span>
      </div>
      <div>
        <span class="l">{{ t('apps.hBackup') }}</span>
        <span class="status"><span class="led" />{{ t('apps.backupNoSchedule') }}</span>
        <router-link to="/backups">{{ t('apps.backupHow') }}</router-link>
      </div>
      <div>
        <span class="l">{{ t('apps.hCloud') }}</span>
        <span class="status"><span class="led" :class="cloud.led" />{{ cloud.text }}</span>
        <span v-if="cloudHost && cloudLink?.state !== 'standalone'" class="hint wrap">{{ cloudHost }}</span>
        <router-link v-else to="/cloud">{{ t('apps.cloudLink') }}</router-link>
      </div>
    </div>

    <p v-if="apps === null" class="faint">{{ t('common.loading') }}</p>

    <!-- A6 — chưa có app: trạng thái rỗng của chính trang Apps -->
    <div v-else-if="apps.length === 0" class="empty" data-testid="apps-empty">
      <span class="emp-ic"><Icon name="server" /></span>
      <h3>{{ t('apps.emptyTitle') }}</h3>
      <p>{{ t('apps.emptyBody') }}</p>
      <div v-if="sugg.length" class="sugg-grid">
        <div v-for="item in sugg" :key="item.id" class="panel sugg">
          <div class="row"><span class="appicon sm" :style="{ '--h': hue(item.id) }">{{ initials(item.title || item.id) }}</span><b>{{ titleOf(item) }}</b></div>
          <p class="muted">{{ descOf(item) }}</p>
          <span v-if="suggDomain(item)" class="dom">{{ suggDomain(item) }}</span>
          <button type="button" class="btn sm" :disabled="!!installing" @click="quickInstall(item)">
            {{ installing === item.id ? t('store.installing') : t('store.install') }}
          </button>
        </div>
      </div>
      <p v-if="installErr" class="err" role="alert">{{ installErr }}</p>
      <router-link class="btn primary lg" to="/store"><Icon name="store" />{{ t('apps.emptyBrowse') }}</router-link>
      <p class="hint">
        {{ t('apps.pairHint') }} <router-link to="/cloud">{{ t('apps.pairLink') }}</router-link> — {{ t('apps.pairUndo') }}
      </p>
    </div>

    <p v-else-if="!visible.length" class="faint">{{ t('apps.noMatch') }}</p>

    <div v-else class="apps">
      <div
        v-for="a in visible"
        :key="a.id"
        class="tile"
        :class="{ off: statusOf(a) === 'stopped', attn: needsAttention(statusOf(a)) }"
        data-testid="app-tile"
      >
        <span class="appicon" :style="{ '--h': hue(a.slug) }">{{ initials(a.slug) }}</span>
        <a
          v-if="primaryDomain(a)"
          class="open"
          :href="`https://${primaryDomain(a)}`"
          target="_blank"
          rel="noopener noreferrer"
          :title="t('apps.openTitle', { app: a.slug })"
        >{{ a.slug }}<Icon name="ext" /></a>
        <a v-else class="open" :href="`#/apps/${a.id}`" @click.prevent="openDetail(a)">{{ a.slug }}</a>
        <span class="dom">{{ primaryDomain(a) || t('apps.noDomain') }}</span>
        <router-link class="btn ghost icon gear" :to="`/apps/${a.id}`" :aria-label="t('apps.settingsOf', { app: a.slug })" data-testid="app-settings">
          <Icon name="settings" />
        </router-link>
        <div class="foot">
          <span class="status" data-testid="app-status"><span class="led" :class="ledOf(statusOf(a))" />{{ t(`state.${statusOf(a)}`) }}</span>
          <router-link v-if="needsAttention(statusOf(a))" class="btn sm attn-btn" :to="`/apps/${a.id}`">{{ t('apps.seeIssue') }}</router-link>
          <!-- "Đang thiết lập…" một mình là câu hỏi "bao lâu? có kẹt không?" —
               trả lời ngay trên tile, không bắt mở trang chi tiết. -->
          <span v-if="statusOf(a) === 'deploying'" class="tile-hint" data-testid="app-hint">{{ t('apps.applyingHint') }}</span>
        </div>
      </div>
    </div>
  </div>
</template>
