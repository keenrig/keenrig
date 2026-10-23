<script setup>
// Settings — nơi các mục v1 chưa có API được kể tên THẬT THÀ (design/v2/admin.html:
// "Users và nhóm chuyển vào Settings › Sign-in; Services, System chưa có API").
//
// Chỉ thứ có thật mới là điều khiển: ngôn ngữ, giao diện sáng/tối (lưu trên
// trình duyệt này), và tài khoản của chính mình — bật/tắt mã hai bước, đổi mật
// khẩu — vì box CÓ route cho cả ba (POST /auth/totp/{enroll,confirm,disable},
// POST /auth/password). Trước v0.2.1 màn này ghi "Mã hai bước: Tắt" cạnh câu
// "chưa có trong Admin" — đọc như một công tắc hỏng, trong khi API đã có sẵn.
// Phần còn lại là thông tin đọc từ API hoặc một câu nói thẳng "chưa có" (P8).
import { ref, computed, inject, onMounted, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError } from '../api/client'
import { useI18n } from 'vue-i18n'
import { setLocale } from '../i18n'
import { theme, setTheme } from '../theme'
import Icon from '../components/Icon.vue'
import CmdBox from '../components/CmdBox.vue'

const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const me = inject('me', ref(null))
const version = inject('version', ref(''))
const instance = inject('instance', ref(null))
const logout = inject('logout', () => {})

// --- Mã hai bước: enroll → nhập mã đúng → mới bật --------------------------------------
//
// Box trả otpauth:// URI, không trả ảnh QR (secret không nằm lại trong cache
// ảnh). Admin chưa có bộ vẽ QR — không nạp thư viện từ CDN — nên đưa KHOÁ để gõ
// tay (app xác thực nào cũng có "Nhập khoá") và một link otpauth:// mở thẳng app
// xác thực khi đang ở trên điện thoại.
const totpOn = computed(() => !!me.value?.totp_enabled)
const enroll = ref(null) // { uri, secret, code, busy, err }
const disabling = ref(null) // { password, busy, err }
const pw = ref(null) // { old, next, busy, err }
const flashMsg = ref('')

async function refreshMe() {
  try {
    me.value = await api.me()
  } catch { /* phiên chết: App.vue lo đưa về đăng nhập */ }
}
function errText(e) {
  if (e instanceof ApiError && (e.code === 'totp_invalid')) return t('login.totpInvalid')
  if (e instanceof ApiError && e.status === 401) return t('settings.wrongPassword')
  if (e instanceof ApiError && e.code === 'locked') return t('login.locked')
  return e?.message || t('common.error')
}
async function startEnroll() {
  disabling.value = null
  pw.value = null
  enroll.value = { uri: '', secret: '', code: '', busy: true, err: '' }
  try {
    const res = await api.totpEnroll()
    const uri = res?.otpauth_uri || ''
    let secret = ''
    try {
      secret = new URL(uri).searchParams.get('secret') || ''
    } catch { /* URI lạ: vẫn còn link */ }
    enroll.value = { ...enroll.value, uri, secret, busy: false }
  } catch (e) {
    enroll.value = { ...enroll.value, busy: false, err: errText(e) }
  }
}
// Khoá chia nhóm 4 ký tự: gõ tay từ màn hình sang điện thoại ít sai hơn.
const secretGroups = computed(() => (enroll.value?.secret || '').replace(/(.{4})/g, '$1 ').trim())
async function confirmEnroll() {
  const e = enroll.value
  if (!e || e.busy || !/^\d{6}$/.test(e.code)) return
  e.busy = true
  e.err = ''
  try {
    await api.totpConfirm(e.code)
    enroll.value = null
    await refreshMe()
    flash(t('settings.tfaOnDone'))
  } catch (err) {
    e.err = errText(err)
    e.busy = false
  }
}
async function confirmDisable() {
  const d = disabling.value
  if (!d || d.busy || !d.password) return
  d.busy = true
  d.err = ''
  try {
    await api.totpDisable(d.password)
    disabling.value = null
    await refreshMe()
    flash(t('settings.tfaOffDone'))
  } catch (err) {
    d.err = errText(err)
    d.busy = false
  }
}
function startPassword() {
  enroll.value = null
  disabling.value = null
  pw.value = { old: '', next: '', busy: false, err: '' }
}
async function submitPassword() {
  const p = pw.value
  if (!p || p.busy || !p.old || p.next.length < 12) return
  p.busy = true
  p.err = ''
  try {
    await api.changePassword(p.old, p.next)
    // Server đã thu hồi MỌI phiên, kể cả phiên này: về đăng nhập, nói vì sao.
    me.value = null
    router.replace({ path: '/login', query: { pw: 'changed' } })
  } catch (err) {
    p.err = errText(err)
    p.busy = false
  }
}
function copySecret() {
  navigator.clipboard?.writeText(enroll.value?.secret || '').then(
    () => flash(t('common.copied')),
    () => flash(t('common.pressCtrlC')),
  )
}
function flash(msg) {
  flashMsg.value = msg
  window.setTimeout(() => (flashMsg.value = ''), 2500)
}

const address = computed(() => instance.value?.parent_domain || window.location.hostname || '—')
const focus = ref(typeof route.query.s === 'string' ? route.query.s : '')

onMounted(async () => {
  if (!focus.value) return
  await nextTick()
  document.getElementById(`set-${focus.value}`)?.scrollIntoView({ block: 'start' })
})
</script>

<template>
  <div class="stack-lg">
    <div class="page-h">
      <div class="ttl">
        <h1>{{ t('nav.settings') }}</h1>
        <p class="faint">{{ t('settings.sub') }}</p>
      </div>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-h"><h3>{{ t('settings.appearance') }}</h3></div>
        <div class="panel-b stack">
          <div class="field">
            <span class="label">{{ t('app.language') }}</span>
            <div class="seg lang" role="group" :aria-label="t('app.language')">
              <button type="button" data-locale="en" lang="en" :class="{ on: locale === 'en' }" :aria-pressed="locale === 'en'" @click="setLocale('en')">English</button>
              <button type="button" data-locale="vi" lang="vi" :class="{ on: locale === 'vi' }" :aria-pressed="locale === 'vi'" @click="setLocale('vi')">Tiếng Việt</button>
            </div>
          </div>
          <div class="field">
            <span class="label">{{ t('settings.theme') }}</span>
            <div class="seg" role="group" :aria-label="t('settings.theme')" data-testid="theme-seg">
              <button v-for="v in ['auto', 'light', 'dark']" :key="v" type="button" :class="{ on: theme === v }" :aria-pressed="theme === v" :data-theme-set="v" @click="setTheme(v)">
                {{ t(`settings.theme_${v}`) }}
              </button>
            </div>
            <span class="hint">{{ t('settings.themeHint') }}</span>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-h"><h3>{{ t('settings.server') }}</h3></div>
        <dl class="kv panel-b">
          <dt>{{ t('settings.version') }}</dt><dd class="mono">{{ version || t('common.notReported') }}</dd>
          <dt>{{ t('settings.address') }}</dt><dd class="mono">{{ address }}</dd>
          <dt>{{ t('settings.domainSource') }}</dt>
          <dd>
            <span v-if="instance?.parent_domain_source === 'cloud'" class="badge cloud">{{ t('domains.srcCloud') }}</span>
            <span v-else-if="instance?.parent_domain_source === 'local'" class="badge">{{ t('domains.localSet') }}</span>
            <span v-else class="faint">{{ t('settings.noDomain') }}</span>
          </dd>
        </dl>
      </div>
    </div>

    <div id="set-signin" class="panel">
      <div class="panel-h"><h3>{{ t('settings.signin') }}</h3></div>
      <div class="panel-b stack">
        <dl class="kv">
          <dt>{{ t('settings.signedInAs') }}</dt><dd class="mono">{{ me?.username || '—' }}</dd>
          <dt>{{ t('settings.twoFactor') }}</dt>
          <dd>
            <span class="status" data-testid="tfa-state"><span class="led" :class="totpOn ? 'ok' : ''" />{{ totpOn ? t('settings.on') : t('settings.off') }}</span>
          </dd>
        </dl>
        <p class="hint">{{ totpOn ? t('settings.tfaOnHint') : t('settings.tfaOffHint') }}</p>
        <p v-if="flashMsg" class="ok-msg" role="status">{{ flashMsg }}</p>

        <!-- Bật mã hai bước: hai bước, chỉ BẬT khi mã đầu tiên đúng -->
        <form v-if="enroll" class="subpanel stack" data-testid="tfa-enroll" @submit.prevent="confirmEnroll">
          <p v-if="enroll.busy && !enroll.uri" class="faint">{{ t('common.loading') }}</p>
          <template v-if="enroll.uri">
            <ol class="ol-steps">
              <li>
                <div class="stack">
                  <span>{{ t('settings.tfaStep1') }}</span>
                  <div class="keybox">
                    <code class="mono wrap" data-testid="tfa-secret">{{ secretGroups || enroll.uri }}</code>
                    <button type="button" class="btn sm" @click="copySecret">{{ t('common.copy') }}</button>
                  </div>
                  <a class="hint" :href="enroll.uri">{{ t('settings.tfaOpenApp') }}</a>
                </div>
              </li>
              <li>
                <div class="stack">
                  <label for="tfa-code">{{ t('settings.tfaStep2') }}</label>
                  <input
                    id="tfa-code"
                    v-model="enroll.code"
                    class="input otp-in"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    maxlength="6"
                    @input="enroll.code = enroll.code.replace(/\D/g, '')"
                  />
                </div>
              </li>
            </ol>
          </template>
          <p v-if="enroll.err" class="err" role="alert">{{ enroll.err }}</p>
          <div class="row">
            <button type="button" class="btn ghost" @click="enroll = null">{{ t('common.cancel') }}</button>
            <button v-if="enroll.uri" type="submit" class="btn primary" :disabled="enroll.busy || enroll.code.length !== 6">{{ t('settings.tfaConfirm') }}</button>
          </div>
        </form>

        <!-- Tắt mã hai bước: hỏi lại mật khẩu (server đòi) -->
        <form v-if="disabling" class="subpanel stack" data-testid="tfa-disable" @submit.prevent="confirmDisable">
          <p>{{ t('settings.tfaOffWarn') }}</p>
          <div class="field">
            <label for="tfa-pass">{{ t('login.password') }}</label>
            <input id="tfa-pass" v-model="disabling.password" class="input" type="password" autocomplete="current-password" />
          </div>
          <p v-if="disabling.err" class="err" role="alert">{{ disabling.err }}</p>
          <div class="row">
            <button type="button" class="btn ghost" @click="disabling = null">{{ t('common.cancel') }}</button>
            <button type="submit" class="btn danger solid" :disabled="disabling.busy || !disabling.password">{{ t('settings.tfaTurnOff') }}</button>
          </div>
        </form>

        <!-- Đổi mật khẩu: mọi phiên bị thu hồi — nói TRƯỚC khi bấm -->
        <form v-if="pw" class="subpanel stack" @submit.prevent="submitPassword">
          <div class="field">
            <label for="pw-old">{{ t('settings.pwOld') }}</label>
            <input id="pw-old" v-model="pw.old" class="input" type="password" autocomplete="current-password" />
          </div>
          <div class="field">
            <label for="pw-new">{{ t('settings.pwNew') }}</label>
            <input id="pw-new" v-model="pw.next" class="input" type="password" autocomplete="new-password" minlength="12" />
          </div>
          <p class="hint">{{ t('settings.pwHint') }}</p>
          <p v-if="pw.err" class="err" role="alert">{{ pw.err }}</p>
          <div class="row">
            <button type="button" class="btn ghost" @click="pw = null">{{ t('common.cancel') }}</button>
            <button type="submit" class="btn primary" :disabled="pw.busy || !pw.old || pw.next.length < 12">{{ t('settings.pwGo') }}</button>
          </div>
        </form>

        <div v-if="!enroll && !disabling && !pw" class="row">
          <button v-if="!totpOn" type="button" class="btn" data-testid="tfa-on" @click="startEnroll">{{ t('settings.tfaTurnOn') }}</button>
          <button v-else type="button" class="btn" @click="disabling = { password: '', busy: false, err: '' }">{{ t('settings.tfaTurnOffAsk') }}</button>
          <button type="button" class="btn" @click="startPassword">{{ t('settings.pwChange') }}</button>
          <button type="button" class="btn ghost" @click="logout">{{ t('app.logout') }}</button>
        </div>
        <p class="hint">{{ t('settings.peopleNotYet') }}</p>
      </div>
    </div>

    <div id="set-updates" class="panel">
      <div class="panel-h"><h3>{{ t('settings.updates') }}</h3></div>
      <div class="panel-b stack">
        <p class="muted">{{ t('settings.updatesBody') }}</p>
        <details class="disc">
          <summary>{{ t('settings.updatesTech') }}</summary>
          <div class="in stack">
            <p class="hint">{{ t('settings.updatesTechBody') }}</p>
            <span class="label">{{ t('settings.updatesLog') }}</span>
            <CmdBox cmd="sudo journalctl -u keenrig-upgrade -n 50" />
          </div>
        </details>
      </div>
    </div>

    <div class="panel">
      <div class="panel-h"><h3>{{ t('settings.more') }}</h3></div>
      <ul class="list">
        <li>
          <Icon name="list" />
          <div class="grow"><span class="t">{{ t('nav.activity') }}</span><span class="s">{{ t('settings.activityBody') }}</span></div>
          <router-link class="btn sm" to="/events">{{ t('settings.openActivity') }}</router-link>
        </li>
        <!-- Trợ lý AI: một DÒNG nói thật "chưa có", đích của link trong bảng ⌘K
             — không còn chiếm một thẻ riêng hay một chỗ trên topbar. -->
        <!-- Chưa có = trạng thái "sắp có" chung của cả ba UI: chữ nhạt + đồng hồ,
             không nút. Cùng hình với "(sắp có)" ở Billing của Console và Web. -->
        <li id="set-ai" class="soon" :class="{ focus: focus === 'ai' }">
          <Icon name="sparkle" />
          <div class="grow"><span class="t">{{ t('settings.ai') }}</span><span class="s">{{ t('settings.aiBody') }}</span></div>
          <span class="badge"><Icon name="clock" />{{ t('common.soon') }}</span>
        </li>
        <li class="soon">
          <Icon name="layers" />
          <div class="grow"><span class="t">{{ t('settings.notYetTitle') }}</span><span class="s">{{ t('settings.notYetBody') }}</span></div>
          <span class="badge"><Icon name="clock" />{{ t('common.soon') }}</span>
        </li>
      </ul>
    </div>
  </div>
</template>
