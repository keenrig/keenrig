<script setup>
// A5 — Cloud Link (design/v2/admin.html#a5): trạng thái pair THẬT, như agent
// báo về (AD-12).
//
// # Vì sao màn này từng nói dối
//
// Tới 2026-09-19 nó là một wireframe tĩnh: "chưa pair" viết cứng, không một
// lời gọi API — trên box thử nghiệm đang sync mỗi 30 giây và Console đang hiện
// `connected`. Giờ: agent → PUT /node/v1/cloud-link sau mỗi sync thành công →
// box ghi → GET /api/v1/cloud (đòi phiên) → đây.
//
// # Ba trạng thái, không viết cứng cái nào — đèn + chữ + GIỜ (P6)
//
//	standalone  "Standalone": pairing thêm gì (nhãn Cloud), cái gì luôn chạy,
//	            và hai đường pair thật (dán token / lệnh --join).
//	synced      "Synced": Console URL, env id, lần sync cuối.
//	stale       "Can't reach Keenrig Cloud since 14:32": mất cloud phải NÓI RA
//	            (AG-08), kèm cái gì vẫn chạy và lệnh chẩn đoán có Copy.
//
// API lỗi (501 trên box cũ chưa nối) → vẽ như standalone nhưng kèm một dòng
// "không lấy được trạng thái pair": không biết ≠ chưa pair.
//
// # Preflight rút cloud — CHỈ phần thông tin
//
// Thiết kế A5d có hộp thoại "Stops / Keeps running" + gõ tên máy + nút Unplug.
// Box chưa có API (cũng chưa có lệnh) để rút pairing, nên KHÔNG vẽ nút Unplug
// (P8). Phần đáng giá nhất của preflight thì có thật và đưa ra được hôm nay:
// danh sách cái gì dừng / cái gì chạy tiếp, và app NÀO đang chỉ có tên Keenrig
// (tính từ domain thật của từng app) — để không ai bị bất ngờ.
//
// # Dán token = kết nối (POST /cloud/pair)
//
// 202 nghĩa là Console đã nhận máy, CHƯA phải đã sync: màn chuyển sang "đang
// chờ sync" và poll /cloud tới khi agent báo `synced` — không vẽ "đã pair"
// trước khi agent thật sự nói vậy. Lệnh `--join` là đường thứ hai (box cũ chưa
// có pair.sh trả 501). Lệnh đó là `sh`, không phải `bash`: get.sh là POSIX sh.
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api } from '../api/client'
import { ago } from '../ago'
import { initials, hue } from '../appMeta'
import Icon from '../components/Icon.vue'
import CmdBox from '../components/CmdBox.vue'
import { CONSOLE_URL } from '../console'

// Console mặc định. Máy standalone chưa biết control plane nào (cloud_url
// rỗng), nên nút "Open Console" trỏ về đây, thẳng vào wizard với lựa chọn
// "Máy đã cài Keenrig" chọn sẵn.
const consoleNewEnv = `${CONSOLE_URL}/envs/new?server=existing`
const JOIN_CMD = 'curl -fsSL https://get.keenrig.com | sudo sh -s -- --join <token>'
const DIAG_CMD = 'sudo journalctl -u keenrig-agent -n 50'

const { t, locale } = useI18n()
const link = ref(null)
const unavailable = ref(false)
const inst = ref(null)

const token = ref('')
const pairBusy = ref(false)
const pairErr = ref('')
const pairedEnv = ref('') // env id Console trả về; khác '' = đang chờ sync đầu
const syncSlow = ref(false)
let pollTimer = null
let pollStarted = 0

const tokenShapeOK = computed(() => /^[0-9a-f]{64}$/.test(token.value.trim()))

async function refresh() {
  try {
    link.value = await api.cloud()
    unavailable.value = false
  } catch {
    link.value = null
    unavailable.value = true
  }
}

function stopPoll() {
  if (pollTimer) clearInterval(pollTimer)
  pollTimer = null
}

// Poll 2 giây/lần: agent restart rồi sync lần đầu thường mất vài giây. Sau 60
// giây vẫn chưa thấy thì NÓI RA kèm lệnh chẩn đoán, nhưng vẫn poll tiếp.
function startPoll() {
  stopPoll()
  pollStarted = Date.now()
  pollTimer = setInterval(async () => {
    await refresh()
    if (state.value === 'synced' || state.value === 'stale') {
      stopPoll()
      pairedEnv.value = ''
      return
    }
    syncSlow.value = Date.now() - pollStarted > 60_000
  }, 2000)
}

async function pair() {
  pairErr.value = ''
  if (!tokenShapeOK.value) {
    pairErr.value = t('cloud.tokenBad')
    return
  }
  pairBusy.value = true
  try {
    const res = await api.pairCloud(token.value.trim())
    pairedEnv.value = res?.env_id || '?'
    token.value = ''
    startPoll()
  } catch (e) {
    pairErr.value = e?.message || String(e)
  } finally {
    pairBusy.value = false
  }
}

onUnmounted(stopPoll)

const state = computed(() => link.value?.state ?? 'standalone')
const paired = computed(() => state.value === 'synced' || state.value === 'stale')
const lastAgo = computed(() => ago(t, link.value?.last_sync_at))
const lastAt = computed(() => {
  const d = new Date(link.value?.last_sync_at || '')
  if (Number.isNaN(d.getTime())) return ''
  return new Intl.DateTimeFormat(locale.value === 'vi' ? 'vi-VN' : 'en-GB', { dateStyle: 'short', timeStyle: 'short' }).format(d)
})
const cloudHost = computed(() => {
  try {
    return new URL(link.value?.cloud_url || '').host
  } catch {
    return link.value?.cloud_url || ''
  }
})
const keenrigName = computed(() =>
  inst.value?.parent_domain_source === 'cloud' && inst.value?.parent_domain ? `*.${inst.value.parent_domain}` : '',
)

// --- preflight: app nào chỉ có tên Keenrig ---------------------------------------------
const preflight = ref(false)
const pfApps = ref(null)
async function openPreflight() {
  preflight.value = !preflight.value
  if (!preflight.value || pfApps.value) return
  try {
    const list = (await api.listApps()) ?? []
    const p = inst.value?.parent_domain || ''
    const isCloud = inst.value?.parent_domain_source === 'cloud'
    const out = []
    await Promise.all(
      list.map(async (a) => {
        let ds = []
        try {
          ds = (await api.listDomains(a.id)) ?? []
        } catch { /* coi như chưa có domain */ }
        const cloudNames = ds.filter((d) => isCloud && p && (d.fqdn === p || d.fqdn.endsWith('.' + p)))
        const own = ds.filter((d) => !cloudNames.includes(d))
        if (cloudNames.length) out.push({ id: a.id, slug: a.slug, cloudName: cloudNames[0].fqdn, own: own[0]?.fqdn || '' })
      }),
    )
    out.sort((x, y) => x.slug.localeCompare(y.slug))
    pfApps.value = out
  } catch {
    pfApps.value = []
  }
}
const pfAtRisk = computed(() => (pfApps.value ?? []).filter((a) => !a.own))

onMounted(async () => {
  api.instance().then((i) => (inst.value = i)).catch(() => (inst.value = null))
  await refresh()
})
</script>

<template>
  <div class="stack-lg">
    <div class="page-h">
      <div class="ttl">
        <h1>{{ t('nav.cloud') }}</h1>
        <p class="faint" data-testid="cloud-sub">
          <template v-if="paired">{{ t('cloud.linkedTo', { cloud: cloudHost, env: link.env_id, ago: lastAgo }) }}</template>
          <template v-else>{{ t('cloud.notPairedSub') }}</template>
        </p>
      </div>
    </div>
    <p v-if="unavailable" class="hint" role="status">{{ t('cloud.stateUnavailable') }}</p>

    <!-- ==== SYNCED / STALE ==== -->
    <div v-if="paired" class="panel cloud-link">
      <div class="panel-h">
        <span v-if="state === 'synced'" class="status big-status" data-testid="cloud-state"><span class="led ok" />{{ t('cloud.synced') }}</span>
        <span v-else class="status big-status" data-testid="cloud-state"><span class="led warn" />{{ t('cloud.staleSince', { at: lastAt || lastAgo }) }}</span>
      </div>
      <div class="panel-b stack">
        <p v-if="state === 'stale'"><b>{{ t('cloud.staleKeep') }}</b></p>
        <dl class="kv">
          <dt>{{ t('cloud.consoleUrl') }}</dt>
          <dd><a :href="link.cloud_url" target="_blank" rel="noopener">{{ link.cloud_url }} ↗</a></dd>
          <dt>{{ t('cloud.envId') }}</dt>
          <dd class="mono env-id">{{ link.env_id }}</dd>
          <dt>{{ t('cloud.lastSync') }}</dt>
          <dd>{{ lastAgo }}<template v-if="lastAt"> · {{ lastAt }}</template></dd>
          <template v-if="keenrigName">
            <dt>{{ t('cloud.keenrigName') }}</dt><dd class="mono">{{ keenrigName }}</dd>
          </template>
          <template v-if="state === 'stale'">
            <dt>{{ t('cloud.stillWorks') }}</dt><dd>{{ t('cloud.stillWorksList') }}</dd>
            <dt>{{ t('cloud.paused') }}</dt><dd>{{ t('cloud.pausedList') }}</dd>
          </template>
        </dl>
        <template v-if="state === 'stale'">
          <span class="label">{{ t('cloud.seeWhy') }}</span>
          <CmdBox :cmd="DIAG_CMD" data-testid="diag-cmd" />
        </template>
        <div class="row">
          <a class="btn" :href="link.cloud_url" target="_blank" rel="noopener"><Icon name="ext" />{{ t('cloud.openConsoleBtn') }}</a>
          <span class="spacer" />
          <button type="button" class="btn ghost" :aria-expanded="preflight" @click="openPreflight"><Icon name="plug" />{{ t('cloud.whatIfUnplug') }}</button>
        </div>
      </div>
    </div>

    <!-- Preflight rút cloud: thông tin thật, không nút giả -->
    <div v-if="paired && preflight" class="panel" data-testid="preflight">
      <div class="panel-h"><span class="ic-circle danger"><Icon name="plug" /></span><h3>{{ t('cloud.pfTitle') }}</h3></div>
      <div class="panel-b stack">
        <div class="split">
          <div class="stops">
            <span class="label">{{ t('cloud.pfStops') }}</span>
            <ul class="feat no">
              <li v-if="keenrigName"><Icon name="x" /><span>{{ t('cloud.pfStopName', { name: keenrigName }) }}</span></li>
              <li><Icon name="x" /><span>{{ t('cloud.pfStopConsole') }}</span></li>
              <li><Icon name="x" /><span>{{ t('cloud.pfStopAi') }}</span></li>
            </ul>
          </div>
          <div class="keeps">
            <span class="label">{{ t('cloud.pfKeeps') }}</span>
            <ul class="feat ok">
              <li><Icon name="check" /><span>{{ t('cloud.keep1') }}</span></li>
              <li><Icon name="check" /><span>{{ t('cloud.keep2') }}</span></li>
              <li><Icon name="check" /><span>{{ t('cloud.keep3') }}</span></li>
              <li><Icon name="check" /><span>{{ t('cloud.keep4') }}</span></li>
              <li><Icon name="check" /><span>{{ t('cloud.keep5') }}</span></li>
            </ul>
          </div>
        </div>
        <template v-if="keenrigName">
          <p v-if="pfApps === null" class="faint">{{ t('common.loading') }}</p>
          <ul v-else-if="pfApps.length" class="list panel inner">
            <li v-for="a in pfApps" :key="a.id">
              <span class="appicon sm" :style="{ '--h': hue(a.slug) }">{{ initials(a.slug) }}</span>
              <div class="grow"><span class="t">{{ a.slug }}</span><span class="s mono wrap">{{ a.own || a.cloudName }}</span></div>
              <span v-if="a.own" class="status"><span class="led ok" />{{ t('cloud.pfHasOwn') }}</span>
              <template v-else>
                <span class="status"><span class="led" />{{ t('cloud.pfOnlyKeenrig') }}</span>
                <router-link class="btn sm" :to="`/apps/${a.id}?tab=access`">{{ t('domains.add') }}</router-link>
              </template>
            </li>
          </ul>
          <div v-if="pfAtRisk.length" class="note danger">
            <Icon name="alert" />
            <p><b>{{ t('cloud.pfAtRisk', { apps: pfAtRisk.map((a) => a.slug).join(', ') }) }}</b> {{ t('cloud.pfDataKept') }}</p>
          </div>
        </template>
        <div class="note">
          <Icon name="info" />
          <p><b>{{ t('cloud.pfNotInUiTitle') }}</b> {{ t('cloud.pfNotInUiBody') }}</p>
        </div>
      </div>
    </div>

    <!-- ==== STANDALONE ==== -->
    <div v-if="!paired" class="grid-2">
      <div class="panel">
        <div class="panel-h">
          <span class="status big-status" data-testid="cloud-state"><span class="led" />{{ t('cloud.standalone') }}</span>
        </div>
        <div class="panel-b stack">
          <p><b>{{ t('cloud.ownTitle') }}</b> {{ t('cloud.whatTitle') }}</p>
          <ul class="feat">
            <li><Icon name="globe" /><span>{{ t('cloud.what1') }} <span class="badge cloud">Cloud</span></span></li>
            <li><Icon name="cloud" /><span>{{ t('cloud.what2') }} <span class="badge cloud">Cloud</span></span></li>
            <li><Icon name="sparkle" /><span>{{ t('cloud.what3') }} <span class="badge cloud">Cloud</span></span></li>
          </ul>
          <span class="label">{{ t('cloud.alwaysOn') }}</span>
          <ul class="feat ok">
            <li><Icon name="check" /><span>{{ t('cloud.keep1') }}</span></li>
            <li><Icon name="check" /><span>{{ t('cloud.keep2') }}</span></li>
            <li><Icon name="check" /><span>{{ t('cloud.keep3') }}</span></li>
            <li><Icon name="check" /><span>{{ t('cloud.keep4') }}</span></li>
            <li><Icon name="check" /><span>{{ t('cloud.keep5') }}</span></li>
          </ul>
          <p class="hint">{{ t('cloud.undoHint') }}</p>
        </div>
      </div>

      <div class="panel">
        <div class="panel-h"><h3>{{ t('cloud.tokenTitle') }}</h3></div>
        <div class="panel-b stack">
          <!-- Đã dán token, Console đã nhận: chờ agent sync THẬT rồi mới đổi sang
               thẻ "Synced". -->
          <template v-if="pairedEnv">
            <span class="status"><span class="led busy" />{{ t('cloud.waitingSync', { env: pairedEnv }) }}</span>
            <template v-if="syncSlow">
              <p class="err">{{ t('cloud.syncSlow') }}</p>
              <CmdBox :cmd="DIAG_CMD" />
            </template>
          </template>

          <template v-else>
            <ol class="ol-steps">
              <li>
                <div>
                  {{ t('cloud.step1') }}
                  <a class="btn sm self-start" :href="consoleNewEnv" target="_blank" rel="noopener"><Icon name="ext" />{{ t('cloud.openConsole') }}</a>
                </div>
              </li>
              <li>
                <div>
                  <label for="join-token">{{ t('cloud.step2') }}</label>
                  <form class="row" @submit.prevent="pair">
                    <input
                      id="join-token"
                      v-model="token"
                      class="input mono grow"
                      type="text"
                      autocomplete="off"
                      autocapitalize="none"
                      spellcheck="false"
                      :placeholder="t('cloud.tokenPh')"
                      :aria-invalid="!!pairErr"
                    />
                    <button type="submit" class="btn primary" :disabled="pairBusy || !token.trim()">
                      {{ pairBusy ? t('cloud.pairing') : t('cloud.pairBtn') }}
                    </button>
                  </form>
                  <p v-if="pairErr" class="err" role="alert">{{ pairErr }}</p>
                </div>
              </li>
            </ol>

            <details class="disc">
              <summary>{{ t('cloud.altTitle') }}</summary>
              <div class="in">
                <p class="hint">{{ t('cloud.altBody') }}</p>
                <CmdBox :cmd="JOIN_CMD" data-testid="join-cmd" />
              </div>
            </details>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>
