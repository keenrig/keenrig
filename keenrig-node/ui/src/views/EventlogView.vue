<script setup>
// Settings › Activity — bảng sự kiện thật từ GET /events.
//
// design/v2 bỏ mục Eventlog khỏi sidebar ("chưa có API") — nhưng API này CÓ
// thật, nên màn sống tiếp dưới Settings, giữ đường dẫn /events. Bảng ở desktop,
// thẻ ở ≤576px (R1 luật 2), giá trị kỹ thuật xuống dòng (R1 luật 3).
//
// Trường theo hợp đồng (schema Event): action, actor, subject, data,
// created_at. Các tên cũ (kind/type/message/detail) vẫn được đọc làm dự phòng
// cho box cũ.
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api } from '../api/client'

const { t, te, locale } = useI18n()
const events = ref(null)
const err = ref('')

function when(e) {
  const ts = e.created_at || e.ts || e.time
  if (!ts) return '—'
  try {
    return new Intl.DateTimeFormat(locale.value === 'vi' ? 'vi-VN' : 'en-GB', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(ts))
  } catch {
    return String(ts)
  }
}
function code(e) {
  return e.action || e.kind || e.type || ''
}
// Mã sự kiện ("app.created") là cho máy; người đọc thấy câu ("Cài app"). Mã
// lạ (box mới hơn UI) thì hiện nguyên mã — đúng còn hơn bịa một nhãn.
function kind(e) {
  const c = code(e)
  if (!c) return '—'
  const k = `events.a.${c.replace(/\./g, '_')}`
  return te(k) ? t(k) : c
}
// Chi tiết: tên app / tên người / IP khi sự kiện có — không in JSON và UUID
// thô ra trước mắt người đọc.
function detail(e) {
  const d = e.data && typeof e.data === 'object' ? e.data : {}
  const nice = [d.slug, d.username, d.fqdn, d.ip, d.message, d.error].filter((v) => typeof v === 'string' && v)
  if (nice.length) return nice.join(' · ')
  const parts = []
  if (e.subject) parts.push(e.subject)
  if (e.message || e.detail) parts.push(e.message || e.detail)
  return parts.join(' · ') || '—'
}

// "api", "identity", "worker" là tên thành phần bên trong box — với người đọc,
// tất cả đều là "hệ thống" trừ khi có tên người.
function actor(e) {
  const a = e.actor || ''
  if (!a) return '—'
  const k = `events.by.${a}`
  return te(k) ? t(k) : a
}

onMounted(async () => {
  try {
    const res = await api.events(200)
    events.value = Array.isArray(res) ? res : res?.events || []
  } catch (e) {
    err.value = e.message
    events.value = []
  }
})
</script>

<template>
  <div class="stack-lg">
    <nav class="crumbs" :aria-label="t('detail.crumbs')">
      <router-link to="/settings">{{ t('nav.settings') }}</router-link><span>/</span><b class="cur">{{ t('nav.activity') }}</b>
    </nav>
    <div class="page-h">
      <div class="ttl">
        <h1>{{ t('events.title') }}</h1>
        <p class="faint">{{ t('events.sub') }}</p>
      </div>
    </div>
    <p v-if="err" class="err" role="alert">{{ err }}</p>
    <p v-if="events === null" class="faint">{{ t('common.loading') }}</p>
    <div v-else-if="!events.length" class="empty">
      <h3>{{ t('events.empty') }}</h3>
      <p>{{ t('events.emptyBody') }}</p>
    </div>

    <div v-else class="tw">
      <table class="table stackable">
        <thead>
          <tr><th>{{ t('events.when') }}</th><th>{{ t('events.kind') }}</th><th>{{ t('events.actor') }}</th><th>{{ t('events.detail') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in events" :key="e.id ?? i">
            <td class="mono nowrap" :data-label="t('events.when')">{{ when(e) }}</td>
            <td class="strong" :data-label="t('events.kind')" :title="code(e)">{{ kind(e) }}</td>
            <td :data-label="t('events.actor')">{{ actor(e) }}</td>
            <td class="wrap dimtxt" :data-label="t('events.detail')" :title="e.data ? JSON.stringify(e.data) : ''">{{ detail(e) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
