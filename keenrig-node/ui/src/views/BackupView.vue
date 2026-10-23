<script setup>
// A7b — Backups, bản "hôm nay" của design/v2/admin.html#a7.
//
// Thiết kế có hai pha: A7a (đích, chờ GET/PUT /backup/config,
// GET /backup/snapshots, POST /backup/run|restore) và A7b (thứ ship hôm nay).
// internal/api CHƯA có route backup nào, nên màn này là A7b: nói thẳng
// "chưa có gì chạy theo lịch", và chỉ in những lệnh đã chạy được trên máy,
// mỗi lệnh một nút Copy. Không form giả, không nút "Back up now" chết (P8).
//
// Lệnh phải chạy được khi dán: đúng binary (/var/lib/keenrig/bin/keenrig-box —
// không nằm trong PATH), đúng --data (mặc định ./data là sai chỗ), đúng ba biến
// môi trường; --app nhận ID app, không phải slug (cmd/keenrig-box/backup.go).
import { useI18n } from 'vue-i18n'
import Icon from '../components/Icon.vue'
import CmdBox from '../components/CmdBox.vue'

const { t } = useI18n()
const BOX = '/var/lib/keenrig/bin/keenrig-box'
const CMDS = [
  { key: 'backup.cmdBackup', cmd: `${BOX} backup --data /var/lib/keenrig` },
  { key: 'backup.cmdList', note: 'backup.cmdListNote', cmd: `${BOX} backups` },
  { key: 'backup.cmdRestoreApp', note: 'backup.cmdRestoreAppNote', cmd: `${BOX} restore --data /var/lib/keenrig --from <id> --app <app-id>` },
  { key: 'backup.cmdMove', note: 'backup.cmdMoveNote', cmd: `${BOX} restore --data /var/lib/keenrig --from <id>` },
]
</script>

<template>
  <div class="stack-lg">
    <div class="page-h">
      <div class="ttl">
        <h1>{{ t('backup.title') }}</h1>
        <p class="faint">{{ t('backup.sub') }}</p>
      </div>
    </div>

    <div class="note" data-testid="backup-state">
      <Icon name="info" />
      <p><b>{{ t('backup.noScheduleTitle') }}</b> {{ t('backup.noScheduleBody') }}</p>
    </div>

    <!-- Người đọc trang này thường KHÔNG phải người gõ lệnh: nói thẳng ai làm
         được, và rằng gửi trang này cho họ là đủ. -->
    <p class="muted">{{ t('backup.who') }}</p>

    <div class="panel">
      <div class="panel-b cmdl">
        <p class="hint">
          {{ t('backup.rootHint') }}
          <span class="mono">KEENRIG_BACKUP_TARGET</span>, <span class="mono">KEENRIG_BACKUP_CONFIG</span>,
          <span class="mono">KEENRIG_BACKUP_PASSPHRASE</span>.
        </p>
        <div v-for="c in CMDS" :key="c.key">
          <span class="label">{{ t(c.key) }} <small v-if="c.note">{{ t(c.note) }}</small></span>
          <CmdBox :cmd="c.cmd" prompt="#" />
        </div>
      </div>
    </div>

    <div class="note danger">
      <Icon name="key" />
      <p><b>{{ t('backup.passWarn') }}</b> {{ t('backup.passWarnBody') }}</p>
    </div>

    <div class="grid-2">
      <div class="panel">
        <div class="panel-h"><h3>{{ t('backup.encTitle') }}</h3><span class="badge ok"><Icon name="lock" />{{ t('backup.alwaysOn') }}</span></div>
        <div class="panel-b stack">
          <p class="muted">{{ t('backup.encBody') }}</p>
          <p class="hint">{{ t('backup.noDefault') }}</p>
        </div>
      </div>
      <div class="panel">
        <!-- Sắp có: đồng hồ + chữ nhạt (cùng hình "sắp có" của Console/Web), không
             phải dấu X đỏ-xám như thể một tính năng hỏng. -->
        <div class="panel-h"><h3>{{ t('backup.notYetTitle') }}</h3><span class="badge"><Icon name="clock" />{{ t('common.soon') }}</span></div>
        <div class="panel-b">
          <ul class="feat soon">
            <li><Icon name="clock" /><span>{{ t('backup.notYet1') }}</span></li>
            <li><Icon name="clock" /><span>{{ t('backup.notYet2') }}</span></li>
            <li><Icon name="clock" /><span>{{ t('backup.notYet3') }}</span></li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
