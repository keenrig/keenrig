<script setup>
// CommandPalette — ô "Search ⌘K" của design/v2 (A2), bản KHÔNG cần AI.
//
// Làm được ba việc thật: mở một app (tab mới, tới domain chính của nó), vào
// cài đặt của app, nhảy tới một trang. Mọi dòng là một hành động có thật; nhóm
// "Assistant" của thiết kế hiện như một dòng chữ mờ nói rằng Admin chưa có
// trợ lý — không phải một nút bấm vào không làm gì (P8).
//
// Danh sách app nạp lúc MỞ ô, không giữ từ trước: ô này mở thưa, và một danh
// sách cũ là thứ đưa người dùng tới một app vừa xoá.
import { ref, computed, onMounted, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api } from '../api/client'
import { primaryDomain, initials, hue } from '../appMeta'
import Icon from './Icon.vue'

const emit = defineEmits(['close'])
const router = useRouter()
const { t } = useI18n()

const q = ref('')
const apps = ref(null)
const cur = ref(0)
const input = ref(null)

onMounted(async () => {
  await nextTick()
  input.value?.focus()
  try {
    const list = (await api.listApps()) ?? []
    await Promise.all(
      list.map(async (a) => {
        try {
          a.domains = (await api.listDomains(a.id)) ?? []
        } catch {
          a.domains = []
        }
      }),
    )
    apps.value = list
  } catch {
    apps.value = []
  }
})

const PAGES = [
  { to: '/apps', key: 'nav.apps', ic: 'apps' },
  { to: '/store', key: 'nav.store', ic: 'store' },
  { to: '/domains', key: 'nav.domains', ic: 'globe' },
  { to: '/backups', key: 'nav.backups', ic: 'backup' },
  { to: '/cloud', key: 'nav.cloud', ic: 'cloud' },
  { to: '/settings', key: 'nav.settings', ic: 'settings' },
  { to: '/events', key: 'nav.activity', ic: 'list' },
]

// Một danh sách phẳng có nhóm — phím ↑↓ đi qua mọi dòng bấm được theo đúng
// thứ tự người dùng nhìn thấy.
const rows = computed(() => {
  const needle = q.value.trim().toLowerCase()
  const out = []
  for (const a of apps.value ?? []) {
    const dom = primaryDomain(a)
    if (needle && !a.slug.toLowerCase().includes(needle) && !dom.toLowerCase().includes(needle)) continue
    if (dom) out.push({ group: 'apps', kind: 'open', app: a, href: `https://${dom}`, label: t('palette.openApp', { app: a.slug }), k: t('palette.newTab') })
    out.push({ group: 'apps', kind: 'go', app: a, to: `/apps/${a.id}`, label: t('palette.appSettings', { app: a.slug }), k: t('palette.settingsHint') })
  }
  for (const p of PAGES) {
    const label = t(p.key)
    // Khớp tên trang ở CẢ HAI ngôn ngữ: người dùng tiếng Việt vẫn hay gõ
    // "domains", "backup" — từ họ thấy trong tài liệu và lệnh — sau khi nhãn
    // nav đã thành "Tên miền", "Sao lưu".
    const names = [label, t(p.key, {}, { locale: 'en' }), t(p.key, {}, { locale: 'vi' })]
    if (needle && !names.some((n) => n.toLowerCase().includes(needle))) continue
    out.push({ group: 'pages', kind: 'go', to: p.to, ic: p.ic, label })
  }
  if (needle) {
    out.push({ group: 'pages', kind: 'go', to: { path: '/store', query: { q: q.value.trim() } }, ic: 'store', label: t('palette.searchStore', { q: q.value.trim() }) })
  }
  return out
})

watch(q, () => (cur.value = 0))

function run(r) {
  if (!r) return
  if (r.kind === 'open') {
    window.open(r.href, '_blank', 'noopener,noreferrer')
    emit('close')
    return
  }
  emit('close')
  router.push(r.to)
}

function onKey(e) {
  if (e.key === 'Escape') {
    e.preventDefault()
    emit('close')
  } else if (e.key === 'ArrowDown') {
    e.preventDefault()
    cur.value = Math.min(cur.value + 1, rows.value.length - 1)
  } else if (e.key === 'ArrowUp') {
    e.preventDefault()
    cur.value = Math.max(cur.value - 1, 0)
  } else if (e.key === 'Enter') {
    e.preventDefault()
    run(rows.value[cur.value])
  }
}

function idx(r) {
  return rows.value.indexOf(r)
}
const appRows = computed(() => rows.value.filter((r) => r.group === 'apps'))
const pageRows = computed(() => rows.value.filter((r) => r.group === 'pages'))
</script>

<template>
  <div class="pal-over" @click.self="emit('close')">
    <div class="panel palette" role="dialog" :aria-label="t('palette.open')" @keydown="onKey">
      <div class="pal-in">
        <Icon name="search" />
        <input
          ref="input"
          v-model="q"
          type="text"
          :placeholder="t('palette.placeholder')"
          :aria-label="t('palette.placeholder')"
          spellcheck="false"
          autocomplete="off"
        />
        <kbd>Esc</kbd>
      </div>
      <div class="pal-body">
        <p v-if="apps === null" class="pal-na">{{ t('common.loading') }}</p>
        <template v-if="appRows.length">
          <div class="pal-g">{{ t('palette.groupApps') }}</div>
          <a
            v-for="r in appRows"
            :key="r.kind + r.app.id"
            href="#"
            class="pal-r"
            :class="{ on: idx(r) === cur }"
            @mouseenter="cur = idx(r)"
            @click.prevent="run(r)"
          >
            <span v-if="r.kind === 'open'" class="appicon sm" :style="{ '--h': hue(r.app.slug) }">{{ initials(r.app.slug) }}</span>
            <Icon v-else name="settings" />
            <span class="grow">{{ r.label }}</span><span class="k">{{ r.k }}</span>
          </a>
        </template>
        <template v-if="pageRows.length">
          <div class="pal-g">{{ t('palette.groupPages') }}</div>
          <a
            v-for="r in pageRows"
            :key="JSON.stringify(r.to)"
            href="#"
            class="pal-r"
            :class="{ on: idx(r) === cur }"
            @mouseenter="cur = idx(r)"
            @click.prevent="run(r)"
          >
            <Icon :name="r.ic" /><span class="grow">{{ r.label }}</span>
          </a>
        </template>
        <p v-if="apps !== null && !rows.length" class="pal-na">{{ t('palette.noResults') }}</p>
        <div class="pal-g">{{ t('palette.groupAssistant') }}</div>
        <div class="pal-r na"><Icon name="sparkle" />{{ q.trim() ? t('palette.askAbout', { q: q.trim() }) : t('palette.ask') }}</div>
        <p class="pal-na">
          {{ t('palette.noAi') }}
          <router-link to="/settings?s=ai" @click="emit('close')">{{ t('palette.aiLink') }}</router-link>
        </p>
      </div>
      <div class="pal-foot">
        <span><kbd>↑</kbd> <kbd>↓</kbd> {{ t('palette.move') }}</span><span><kbd>↵</kbd> {{ t('palette.choose') }}</span>
      </div>
    </div>
  </div>
</template>
