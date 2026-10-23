<script setup>
// A1 — Lần đầu mở máy, và đăng nhập (design/v2/admin.html#a1).
//
// MỘT thẻ, hai ô nhập: không hỏi domain, không cần tài khoản cloud, và câu đó
// được NÓI RA ngay dưới nút (UI-11: toàn flow không có network call bắt buộc
// nào tới cloud). Cùng thẻ này phục vụ cả đăng nhập thường — hình dạng giống
// hệt, chỉ khác tiêu đề.
//
// Thiết kế v2 vẽ ô Email và ô "Server name"; API tạo owner nhận
// tên đăng nhập + mật khẩu, không có tên máy — nên giữ "Username" và bỏ ô tên
// máy thay vì vẽ một ô không đi đâu cả (P8).
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from '../api/client'
import { setLocale } from '../i18n'

const { t, locale } = useI18n()
const router = useRouter()
const route = useRoute()
// Vừa đổi mật khẩu ở Settings: server đã thu hồi mọi phiên, nên người dùng bị
// đưa về đây — nói vì sao, không thì trông như bị văng ra vô cớ.
const pwChanged = computed(() => route.query.pw === 'changed')
const emit = defineEmits(['authed'])

const needsSetup = ref(false)
const username = ref('')
const password = ref('')
const totp = ref('')
// needTotp bật khi server trả code=totp_required. Hai bước thay vì hỏi mã ngay
// từ đầu: phần lớn tài khoản chưa bật 2FA, và một ô trống bắt buộc bỏ qua là
// thứ người dùng học cách phớt lờ.
const needTotp = ref(false)
const error = ref('')
const busy = ref(false)

// Thước mật khẩu chỉ hiện ở chế độ setup — nó trả lời "đủ chưa?" TRƯỚC khi
// server từ chối, không thay server quyết.
const passStrong = computed(() => password.value.length >= 12)
const passPct = computed(() => Math.min(100, Math.round((password.value.length / 12) * 100)))

// Mở bằng IP qua https: cert tự ký là trạng thái BÌNH THƯỜNG, nên nói vì sao
// trình duyệt cảnh báo và khi nào hết (P5, P6) — ghi chú màu info, không đỏ.
const viaIp = computed(() => {
  const h = window.location.hostname || ''
  return window.location.protocol === 'https:' && (/^[0-9.]+$/.test(h) || h.includes(':'))
})

onMounted(async () => {
  try {
    const s = await api.setupStatus()
    needsSetup.value = !!s.needs_setup
  } catch {
    needsSetup.value = false
  }
})

// Thông báo lấy từ MÃ LỖI máy đọc được, không phải từ chuỗi server trả về:
// chuỗi đó là tiếng Việt cố định, còn UI phải nói đúng ngôn ngữ người dùng chọn.
function messageFor(e) {
  if (!(e instanceof ApiError)) return t('common.error')
  if (e.code === 'locked') return t('login.locked')
  if (e.code === 'totp_invalid') return t('login.totpInvalid')
  if (e.status === 401) return t('login.invalid')
  return e.message || t('common.error')
}

async function submit() {
  if (busy.value) return
  error.value = ''
  busy.value = true
  try {
    if (needsSetup.value) {
      await api.createOwner(username.value, password.value)
      needsSetup.value = false
    }
    await api.login(username.value, password.value, totp.value)
    emit('authed')
    router.replace('/apps')
  } catch (e) {
    if (e instanceof ApiError && e.code === 'totp_required') {
      needTotp.value = true
      error.value = ''
    } else {
      error.value = messageFor(e)
    }
  } finally {
    busy.value = false
  }
}

// Đủ 6 số là tự gửi (thiết kế A1b): dán cả mã là xong, không phải tìm nút.
watch(totp, (v) => {
  const d = (v || '').replace(/\D/g, '')
  if (d !== v) totp.value = d
  else if (needTotp.value && d.length === 6) submit()
})
</script>

<template>
  <div class="auth">
    <div class="authcol">
      <div class="authbrand">
        <svg class="mark" viewBox="0 0 64 64" aria-hidden="true"><rect class="bg" width="64" height="64" rx="17" /><path class="bolt" d="M37 12 L19 38 H29 L26 53 L46 31 H35 Z" /></svg>
        <span class="wordmark">Keen<i>rig</i></span>
      </div>
      <form class="panel authcard" @submit.prevent="submit">
        <div class="panel-b stack">
          <div class="vcol">
            <h2>{{ needTotp ? t('login.totpTitle') : needsSetup ? t('setup.title') : t('login.title') }}</h2>
            <p class="muted">{{ needTotp ? t('login.totpHint') : needsSetup ? t('setup.intro') : t('login.intro') }}</p>
          </div>

          <div v-if="pwChanged && !needsSetup && !needTotp" class="note ok" role="status" data-testid="pw-changed">
            <svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5" /></svg>
            <p>{{ t('login.pwChanged') }}</p>
          </div>

          <template v-if="!needTotp">
            <div class="field">
              <label for="lg-user">{{ t('login.username') }}</label>
              <input id="lg-user" v-model="username" class="input" autocomplete="username" required autofocus spellcheck="false" autocapitalize="none" />
            </div>

            <div class="field">
              <label for="lg-pass">{{ needsSetup ? t('setup.password') : t('login.password') }}</label>
              <input
                id="lg-pass"
                v-model="password"
                class="input"
                type="password"
                :autocomplete="needsSetup ? 'new-password' : 'current-password'"
                :minlength="needsSetup ? 12 : undefined"
                required
              />
              <div v-if="needsSetup && password" class="pwm">
                <span class="bar" :class="passStrong ? 'ok' : 'warn'"><i :style="{ width: passPct + '%' }" /></span>
                <span class="status" data-testid="pw-strength">
                  <span class="led" :class="passStrong ? 'ok' : 'warn'" />{{ passStrong ? t('setup.strong') : t('setup.weak') }}
                </span>
              </div>
            </div>

            <div v-if="needsSetup && viaIp" class="note">
              <svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10.5" width="14" height="10" rx="2" /><path d="M8 10.5v-3a4 4 0 0 1 8 0v3" /></svg>
              <p><b>{{ t('setup.certTitle') }}</b> {{ t('setup.certBody') }}</p>
            </div>
          </template>

          <div v-else class="field">
            <label for="lg-totp">{{ t('login.totp') }}</label>
            <input
              id="lg-totp"
              v-model="totp"
              class="input otp-in"
              inputmode="numeric"
              autocomplete="one-time-code"
              maxlength="6"
              autofocus
            />
            <span class="hint">{{ t('login.totpAuto') }}</span>
          </div>

          <p v-if="error" class="err" role="alert">{{ error }}</p>
          <button class="btn primary lg" type="submit" :disabled="busy || (needTotp && totp.length !== 6)">
            {{ needTotp ? t('login.verify') : needsSetup ? t('setup.submit') : t('login.submit') }}
          </button>
          <button v-if="needTotp" type="button" class="btn ghost sm" @click="needTotp = false; totp = ''">
            {{ t('login.otherAccount') }}
          </button>

          <p v-if="needsSetup" class="hint center">{{ t('setup.promise') }}</p>
        </div>
      </form>
      <div class="seg lang" role="group" :aria-label="t('app.language')">
        <button type="button" data-locale="en" lang="en" :class="{ on: locale === 'en' }" :aria-pressed="locale === 'en'" @click="setLocale('en')">English</button>
        <button type="button" data-locale="vi" lang="vi" :class="{ on: locale === 'vi' }" :aria-pressed="locale === 'vi'" @click="setLocale('vi')">Tiếng Việt</button>
      </div>
    </div>
  </div>
</template>
