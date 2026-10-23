<script setup>
// CmdBox — một lệnh thật kèm nút Copy (P8: "nút không giả vờ").
//
// Khi một việc chưa có API, Admin không vẽ nút làm như đã có: nó in đúng lệnh
// chạy được trên máy, và nút duy nhất là nút chép lệnh đó. Nền terminal tối ở
// CẢ HAI theme — đó là màu của terminal thật, người dùng nhận ra ngay.
//
// Trình duyệt chặn clipboard (http không TLS, iframe…) thì KHÔNG giả vờ đã
// chép: nút nói "Ctrl+C" và lệnh được bôi đen sẵn để người dùng tự chép.
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Icon from './Icon.vue'

const props = defineProps({
  cmd: { type: String, required: true },
  // '$' cho lệnh người dùng thường, '#' cho lệnh phải chạy bằng root.
  prompt: { type: String, default: '$' },
})
const { t } = useI18n()
const state = ref('') // '' | 'ok' | 'manual'
const codeEl = ref(null)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.cmd)
    state.value = 'ok'
  } catch {
    state.value = 'manual'
    const sel = window.getSelection?.()
    if (sel && codeEl.value) {
      const r = document.createRange()
      r.selectNodeContents(codeEl.value)
      sel.removeAllRanges()
      sel.addRange(r)
    }
  }
  window.setTimeout(() => (state.value = ''), 1800)
}
</script>

<template>
  <div class="cmdbox">
    <!-- tabindex: lệnh dài cuộn ngang trong ô — bàn phím cũng phải cuộn được. -->
    <code ref="codeEl" tabindex="0"><span class="p">{{ prompt }}</span>{{ cmd }}</code>
    <button type="button" class="btn sm" @click="copy">
      <Icon :name="state === 'ok' ? 'check' : 'copy'" />{{ state === 'ok' ? t('common.copiedShort') : state === 'manual' ? t('common.pressCtrlC') : t('common.copy') }}
    </button>
  </div>
</template>
