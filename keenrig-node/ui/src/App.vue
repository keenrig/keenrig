<script setup>
// Shell của Keenrig Admin — design/v2/admin.html (A2).
//
// # Sidebar 6 mục, app là trang chủ (P1)
//
// Apps · App Store · Domains · Backups · Cloud Link · Settings. Các mục v1 chưa
// có API (Users, Services, System) không còn chiếm chỗ trên nav; Settings kể
// tên chúng thật thà. Eventlog có API thật nên sống tiếp dưới Settings › Activity.
//
// # Ô "Search ⌘K" thay bong bóng AI mờ
//
// Ô ở topbar mở bảng lệnh: tìm app, mở app, nhảy tới trang — chạy được KHÔNG
// cần AI. Admin chưa có trợ lý, nên ô chỉ ghi "Search". Topbar từng có link
// "AI assistant" — chỗ đắt nhất trên màn, dẫn tới một câu "chưa có" (rà UX
// v0.2.1: ngõ cụt). Lời nói thật đó giờ chỉ nằm trong bảng ⌘K và Settings.
//
// # Responsive theo R1
//
// ≥992 sidebar 232px · 577–991 thu còn icon (CSS lo) · ≤576 thành drawer
// mở bằng ☰ — state `drawer` ở đây, và nó ĐÓNG khi đổi route: bấm một mục
// điều hướng mà drawer còn che màn là một cú chạm bị nuốt.
import { ref, computed, nextTick, onMounted, onUnmounted, provide, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from './api/client'
import { setLocale } from './i18n'
import Icon from './components/Icon.vue'
import CommandPalette from './components/CommandPalette.vue'

const router = useRouter()
const route = useRoute()
const { locale, t } = useI18n()

const me = ref(null)
const ready = ref(false)
const drawer = ref(false)
const palette = ref(false)
const appCount = ref(null)
const version = ref('')
const instance = ref(null)
// null = chưa hỏi; { unavailable: true } = hỏi mà box không trả lời được
// (501 trên box cũ) — "không biết" khác "chưa pair".
const cloudLink = ref(null)
provide('me', me)
provide('appCount', appCount)
provide('cloudLink', cloudLink)
provide('instance', instance)
provide('version', version)
provide('logout', () => logout())

const isAuth = computed(() => route.meta.public === true)
let cloudPoll

async function refreshMe() {
  try {
    me.value = await api.me()
  } catch (e) {
    me.value = null
    if (e instanceof ApiError && e.status === 401 && !route.meta.public) {
      router.replace('/login')
    }
  } finally {
    ready.value = true
  }
}

async function refreshCloud() {
  try {
    cloudLink.value = await api.cloud()
  } catch {
    cloudLink.value = { unavailable: true }
  }
}

// Chip máy + đếm app: số THẬT từ API, không hằng số trang trí nào.
async function refreshInst() {
  try {
    version.value = (await api.version()).version ?? ''
  } catch { /* thiếu version không chặn shell — menu ẩn dòng phiên bản */ }
  try {
    instance.value = await api.instance()
  } catch { /* chip rơi về hostname của URL */ }
  try {
    appCount.value = (await api.listApps())?.length ?? 0
  } catch { /* 401 trước đăng nhập là bình thường */ }
  refreshCloud()
}

async function logout() {
  try {
    await api.logout()
  } finally {
    me.value = null
    router.replace('/login')
  }
}

watch(() => route.fullPath, () => {
  drawer.value = false
  palette.value = false
})
watch(me, (v) => {
  window.clearInterval(cloudPoll)
  if (v) {
    refreshInst()
    cloudPoll = window.setInterval(refreshCloud, 60_000)
  }
})

function onKey(e) {
  if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
    if (!me.value || isAuth.value) return
    e.preventDefault()
    palette.value = !palette.value
  }
}
onMounted(() => {
  refreshMe()
  window.addEventListener('keydown', onKey)
})
onUnmounted(() => {
  window.removeEventListener('keydown', onKey)
  window.clearInterval(cloudPoll)
})

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || '')

const NAV = [
  { to: '/apps', ic: 'apps', key: 'nav.apps', id: 'apps' },
  { to: '/store', ic: 'store', key: 'nav.store', id: 'store' },
  { to: '/domains', ic: 'globe', key: 'nav.domains', id: 'domains' },
  { to: '/backups', ic: 'backup', key: 'nav.backups', id: 'backups' },
  { to: '/cloud', ic: 'cloud', key: 'nav.cloud', id: 'cloud', cloud: true },
  { to: '/settings', ic: 'settings', key: 'nav.settings', id: 'settings' },
]
const SETTINGS_SUB = [
  { to: '/settings', key: 'nav.general', id: 'general' },
  { to: '/events', key: 'nav.activity', id: 'events' },
]

const machineName = computed(
  () => instance.value?.parent_domain || (typeof window !== 'undefined' ? window.location.hostname : '') || '—',
)
const cloudLed = computed(() => {
  const s = cloudLink.value?.state
  return s === 'synced' ? 'ok' : s === 'stale' ? 'warn' : ''
})
const avatar = computed(() => (me.value?.username || '?').slice(0, 2).toUpperCase())

// Menu tài khoản ở chân sidebar: phiên bản, Cài đặt, Đăng xuất gom sau MỘT nút.
// `position: fixed` tính từ nút — sidebar cuộn được nên menu absolute sẽ bị cắt.
const menuOpen = ref(false)
const meBtn = ref(null)
const menuEl = ref(null)
const menuPos = ref({})
async function toggleMenu() {
  menuOpen.value = !menuOpen.value
  if (!menuOpen.value || !meBtn.value) return
  const r = meBtn.value.getBoundingClientRect()
  const w = Math.max(r.width, 220)
  menuPos.value = {
    left: `${Math.min(r.left, window.innerWidth - w - 8)}px`,
    bottom: `${window.innerHeight - r.top + 6}px`,
    width: `${w}px`,
  }
  await nextTick()
  menuEl.value?.querySelector('a,button')?.focus()
}
function onMenuDown(e) {
  if (!menuOpen.value) return
  if (menuEl.value?.contains(e.target) || meBtn.value?.contains(e.target)) return
  menuOpen.value = false
}
function onMenuKey(e) {
  if (e.key !== 'Escape') return
  if (menuOpen.value) { menuOpen.value = false; meBtn.value?.focus() }
  else if (drawer.value) drawer.value = false
}
onMounted(() => { document.addEventListener('mousedown', onMenuDown); document.addEventListener('keydown', onMenuKey) })
onUnmounted(() => { document.removeEventListener('mousedown', onMenuDown); document.removeEventListener('keydown', onMenuKey) })
watch(() => route.fullPath, () => { menuOpen.value = false })
function menuLogout() { menuOpen.value = false; logout() }
const pageTitle = computed(() => {
  const n = NAV.find((x) => x.id === route.meta.nav)
  return n ? t(n.key) : 'Keenrig'
})
</script>

<template>
  <!-- A1: màn auth không có shell — chưa đăng nhập thì không có gì để điều hướng -->
  <div v-if="isAuth || !ready">
    <p v-if="!ready" class="faint" style="padding: 24px">{{ t('common.loading') }}</p>
    <router-view v-else @authed="refreshMe" />
  </div>

  <div v-else class="app-shell">
    <div v-if="drawer" class="scrim" @click="drawer = false" />
    <aside class="side" :class="{ open: drawer }" :aria-label="t('nav.aria')">
      <div class="brand">
        <svg class="mark" viewBox="0 0 64 64" aria-hidden="true"><rect class="bg" width="64" height="64" rx="17" /><path class="bolt" d="M37 12 L19 38 H29 L26 53 L46 31 H35 Z" /></svg>
        <span class="lbl">Keenrig</span>
      </div>
      <!-- Luôn biết đang ở máy nào: quan trọng khi mở nhiều Admin cùng lúc.
           Đèn xanh = chính trang này đang nói chuyện được với box. -->
      <div class="ctx" :title="machineName">
        <span class="led ok" />
        <div class="t">
          <b>{{ machineName }}</b>
          <span><template v-if="appCount !== null">{{ t('app.appCount', appCount) }}</template></span>
        </div>
      </div>
      <nav class="navlist" :aria-label="t('nav.aria')">
        <template v-for="n in NAV" :key="n.to">
          <router-link
            class="nav"
            :class="{ on: route.meta.nav === n.id }"
            :to="n.to"
            :aria-current="route.meta.nav === n.id ? 'page' : undefined"
            :data-nav="n.id"
          >
            <Icon :name="n.ic" /><span class="lbl">{{ t(n.key) }}</span>
            <span v-if="n.cloud && cloudLink && !cloudLink.unavailable" class="led nav-led" :class="cloudLed" />
          </router-link>
          <template v-if="n.id === 'settings' && route.meta.nav === 'settings'">
            <router-link
              v-for="s in SETTINGS_SUB"
              :key="s.to"
              class="nav sub"
              :class="{ cur: route.meta.sub === s.id }"
              :to="s.to"
              :aria-current="route.meta.sub === s.id ? 'page' : undefined"
            >
              <span class="lbl">{{ t(s.key) }}</span>
            </router-link>
          </template>
        </template>
      </nav>
      <!-- Chân sidebar: MỘT dòng tài khoản, bấm mở menu (phiên bản · Cài đặt · Đăng xuất). -->
      <div class="foot">
        <button
          ref="meBtn"
          type="button"
          class="me"
          aria-haspopup="menu"
          :aria-expanded="menuOpen"
          :aria-label="t('app.account')"
          :title="me?.username || ''"
          @click="toggleMenu"
        >
          <span class="avatar">{{ avatar }}</span>
          <span class="lbl"><b>{{ me?.username || '—' }}</b><small>{{ t('app.role') }}</small></span>
          <span class="more lbl" aria-hidden="true">⋯</span>
        </button>
      </div>
      <Teleport to="body">
        <div v-if="menuOpen" ref="menuEl" class="acct-menu" role="menu" :style="menuPos">
          <!-- Chỉ hiện khi box báo phiên bản thật: "Keenrig — chưa báo cáo" ở
               dòng đầu menu là nhiễu, Settings › Máy chủ này đã nói điều đó. -->
          <span v-if="version" class="am-ver">Keenrig {{ version }}</span>
          <router-link class="am-item" role="menuitem" to="/settings">{{ t('nav.settings') }}</router-link>
          <hr />
          <button type="button" class="am-item danger logout" role="menuitem" @click="menuLogout">{{ t('app.logout') }}</button>
        </div>
      </Teleport>
    </aside>

    <div class="main">
      <header class="topbar">
        <button type="button" class="btn ghost icon ham" :aria-label="t('nav.openMenu')" @click="drawer = true">
          <Icon name="menu" />
        </button>
        <b class="m-title">{{ pageTitle }}</b>
        <button type="button" class="search" :aria-label="t('palette.open')" @click="palette = true">
          <Icon name="search" /><span class="s-txt">{{ t('palette.search') }}</span>
          <kbd>{{ isMac ? '⌘K' : 'Ctrl K' }}</kbd>
        </button>
        <span class="spacer" />
        <div class="seg lang" role="group" :aria-label="t('app.language')">
          <button type="button" data-locale="en" lang="en" :class="{ on: locale === 'en' }" :aria-pressed="locale === 'en'" @click="setLocale('en')">EN</button>
          <button type="button" data-locale="vi" lang="vi" :class="{ on: locale === 'vi' }" :aria-pressed="locale === 'vi'" @click="setLocale('vi')">VI</button>
        </div>
        <router-link class="avatar" to="/settings" :title="me?.username || ''">{{ avatar }}</router-link>
      </header>
      <main class="content">
        <router-view @authed="refreshMe" @apps-changed="refreshInst" />
      </main>
    </div>

    <CommandPalette v-if="palette" @close="palette = false" />
  </div>
</template>
