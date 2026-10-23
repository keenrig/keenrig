<script setup>
// A4 — Domains (design/v2/admin.html#a4): mọi FQDN của instance trên một màn,
// gom từ per-app API.
//
// # Vì sao gom ở client
//
// Instance chưa có endpoint domains toàn cục — nguồn sự thật là
// GET /apps/{id}/domains theo từng app. Màn này gom lại để trả lời câu hỏi
// thật của người vận hành ("tên nào đang sống trên máy này?") mà không bịa
// thêm một endpoint chỉ để tiết kiệm N request trên một trang mở thưa.
// "Add domain" cũng đi qua đúng API per-app đó: chọn app, gõ tên, thêm.
//
// # Thứ thiết kế vẽ mà box chưa có — KHÔNG vẽ (P8)
//
// Bảng bản ghi DNS chính xác, "Last checked", "Check again", "Explain with AI"
// cần /domains/check và IP công khai của máy — box chưa có cả hai. Thay vào đó
// là lệnh `nslookup` thật kèm Copy: người dùng tự kiểm được ngay hôm nay. Là
// nslookup chứ không phải dig: dig không có sẵn trên Windows — máy mà phần lớn
// chủ cửa hàng đang ngồi trước — còn nslookup có trên Windows, macOS và Linux.
//
// # Tên miền gốc của máy: CHỈ HIỂN THỊ
//
// Thẻ đầu trang lấy `parent_domain` + nguồn từ GET /instance. Khi nguồn là
// `cloud` thì tên đó do keenrig-cloud cấp cho môi trường và đi xuống qua agent
// (luật chủ dự án 2026-09-07: Admin là nơi nhận thông tin thôi) — không có ô
// sửa, không có nút, và control API cũng không có đường ghi để một ô như thế
// gọi tới. Nguồn `local` là đường standalone (`--domain` của trình cài).
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from '../api/client'
import Icon from '../components/Icon.vue'
import CmdBox from '../components/CmdBox.vue'

const { t } = useI18n()
const rows = ref(null)
const apps = ref([])
const inst = ref(null)
const err = ref('')

async function load() {
  // /instance không đòi đăng nhập và không phụ thuộc danh sách app: hỏng một
  // bên không được làm trắng bên kia.
  api
    .instance()
    .then((i) => {
      inst.value = i
    })
    .catch(() => {
      inst.value = null
    })
  try {
    const list = (await api.listApps()) ?? []
    apps.value = list
    const out = []
    await Promise.all(
      list.map(async (a) => {
        try {
          for (const d of (await api.listDomains(a.id)) ?? []) {
            out.push({ ...d, slug: a.slug, appId: a.id })
          }
        } catch { /* một app lỗi không làm trắng cả bảng */ }
      }),
    )
    out.sort((x, y) => x.fqdn.localeCompare(y.fqdn))
    rows.value = out
    err.value = ''
  } catch (e) {
    err.value = e.message
    rows.value = rows.value ?? []
  }
}
onMounted(load)

const isCloud = computed(() => inst.value?.parent_domain_source === 'cloud')
function isCloudName(fqdn) {
  const p = inst.value?.parent_domain
  return isCloud.value && !!p && (fqdn === p || fqdn.endsWith('.' + p))
}
// Tên riêng đầu tiên (không phải tên do cloud cấp) — để lệnh dig in sẵn tên thật.
const ownExample = computed(() => rows.value?.find((r) => !isCloudName(r.fqdn))?.fqdn || '')

// --- Add domain: chọn app → tên → thêm (POST /apps/{id}/domains) --------------------
const adding = ref(false)
const addApp = ref('')
const addFqdn = ref('')
const addPrimary = ref(false)
const addBusy = ref(false)
const addErr = ref('')
function openAdd() {
  adding.value = true
  addErr.value = ''
  if (!addApp.value && apps.value.length) addApp.value = apps.value[0].id
}
async function submitAdd() {
  const fqdn = addFqdn.value.trim().toLowerCase()
  if (!fqdn || !addApp.value || addBusy.value) return
  addBusy.value = true
  addErr.value = ''
  try {
    await api.addDomain(addApp.value, fqdn, addPrimary.value)
    addFqdn.value = ''
    addPrimary.value = false
    adding.value = false
    await load()
  } catch (e) {
    addErr.value = e instanceof ApiError && e.status === 409 ? t('detail.domainTaken') : e.message
  } finally {
    addBusy.value = false
  }
}
</script>

<template>
  <div class="stack-lg">
    <div class="page-h">
      <div class="ttl">
        <h1>{{ t('domains.title') }}</h1>
        <p class="faint">{{ t('domains.sub') }}</p>
      </div>
      <div class="acts">
        <button v-if="apps.length" type="button" class="btn primary sticky-cta" :aria-expanded="adding" @click="adding ? (adding = false) : openAdd()">
          <Icon name="plus" />{{ t('domains.add') }}
        </button>
      </div>
    </div>
    <p v-if="err" class="err" role="alert">{{ err }}</p>

    <!-- Thêm domain: một form nhỏ, cùng API với tab Access của app -->
    <form v-if="adding" class="panel" @submit.prevent="submitAdd">
      <div class="panel-h"><h3>{{ t('domains.addTitle') }}</h3></div>
      <div class="panel-b stack">
        <div class="grid-add">
          <div class="field">
            <label for="ad-app">{{ t('domains.forApp') }}</label>
            <select id="ad-app" v-model="addApp" class="input">
              <option v-for="a in apps" :key="a.id" :value="a.id">{{ a.slug }}</option>
            </select>
          </div>
          <div class="field">
            <label for="ad-fqdn">{{ t('domains.name') }}</label>
            <input id="ad-fqdn" v-model="addFqdn" class="input mono" type="text" placeholder="shop.cuahang.vn" spellcheck="false" autocapitalize="none" />
          </div>
        </div>
        <label class="check"><input v-model="addPrimary" type="checkbox" />{{ t('detail.makePrimary') }}</label>
        <p class="hint">{{ t('detail.domainHint') }}</p>
        <p v-if="addErr" class="err" role="alert">{{ addErr }}</p>
      </div>
      <div class="panel-f">
        <button type="button" class="btn ghost" @click="adding = false">{{ t('common.cancel') }}</button>
        <button type="submit" class="btn" :disabled="addBusy || !addFqdn.trim()">{{ t('common.add') }}</button>
      </div>
    </form>

    <!-- Tên miền gốc của máy: chỉ đọc -->
    <div v-if="inst?.parent_domain" class="panel issued" :class="{ cloud: isCloud }" data-testid="instance-domain">
      <div class="panel-b">
        <span class="ic-circle" :class="{ cloud: isCloud }"><Icon :name="isCloud ? 'cloud' : 'server'" /></span>
        <div class="grow">
          <div class="row">
            <b>{{ isCloud ? t('domains.cloudIssued') : t('domains.localSet') }}</b>
            <span v-if="isCloud" class="badge cloud">Cloud</span>
            <span class="badge"><Icon name="lock" />{{ t('domains.readOnly') }}</span>
          </div>
          <!-- <wbr> trước mỗi dấu chấm: tên dài xuống dòng ở ranh giới nhãn, không
               bao giờ giữa chừng một nhãn ("keenrig.c / om"). -->
          <p class="nm" data-testid="parent-domain"><template v-for="(lbl, i) in inst.parent_domain.split('.')" :key="i"><template v-if="i"><wbr />.</template>{{ lbl }}</template></p>
          <ul class="names">
            <li><span class="mono">admin.{{ inst.parent_domain }}</span><span class="faint">{{ t('domains.purposeAdmin') }}</span></li>
            <li><span class="mono">&lt;app&gt;.{{ inst.parent_domain }}</span><span class="faint">{{ t('domains.purposeApps') }}</span></li>
          </ul>
          <p class="hint">{{ isCloud ? t('domains.cloudReadOnly') : t('domains.localHint') }}</p>
        </div>
      </div>
    </div>

    <p v-if="rows === null" class="faint">{{ t('common.loading') }}</p>

    <div v-else-if="rows.length" class="tw">
      <table class="table stackable">
        <thead>
          <tr>
            <th>{{ t('domains.colDomain') }}</th>
            <th>{{ t('domains.colUsedBy') }}</th>
            <th>{{ t('domains.colSource') }}</th>
            <th>{{ t('domains.colCert') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in rows" :key="d.fqdn" class="dmn">
            <td class="mono m" :data-label="t('domains.colDomain')">{{ d.fqdn }}</td>
            <td :data-label="t('domains.colUsedBy')">
              <router-link :to="`/apps/${d.appId}?tab=access`" class="applink">{{ d.slug }}</router-link>
              <span v-if="d.is_primary" class="badge accent">{{ t('detail.primary') }}</span>
            </td>
            <td :data-label="t('domains.colSource')">
              <span v-if="isCloudName(d.fqdn)" class="badge cloud">{{ t('domains.srcCloud') }}</span>
              <span v-else class="badge">{{ t('domains.srcOwn') }}</span>
            </td>
            <td :data-label="t('domains.colCert')">
              <span class="status"><span class="led" :class="d.cert_ref ? 'ok' : ''" />{{ d.cert_ref ? t('domains.certIssued') : t('domains.certNotReported') }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="empty">
      <span class="emp-ic"><Icon name="globe" /></span>
      <h3>{{ t('domains.emptyTitle') }}</h3>
      <p>{{ t('domains.emptyBody') }}</p>
      <router-link v-if="!apps.length" class="btn" to="/store">{{ t('apps.emptyBrowse') }}</router-link>
    </div>

    <!-- Domain riêng: điều cần làm, và cách tự kiểm hôm nay -->
    <div class="panel">
      <div class="panel-h"><h3>{{ t('domains.ownTitle') }}</h3></div>
      <div class="panel-b stack">
        <p class="muted">{{ t('domains.ownBody') }}</p>
        <span class="label">{{ t('domains.digLabel') }}</span>
        <CmdBox :cmd="`nslookup ${ownExample || 'shop.cuahang.vn'}`" />
        <p class="hint">{{ t('domains.digHint') }}</p>
      </div>
    </div>
  </div>
</template>
