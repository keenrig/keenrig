// Dọn hạ tầng bộ đo Admin — "cố hết sức": teardown ném lỗi thì báo cáo test
// bị che mất bởi một chuyện dọn dẹp.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { TMP } from './global-setup'

export default async function globalTeardown(): Promise<void> {
  try {
    const st = JSON.parse(readFileSync(join(TMP, 'state.json'), 'utf-8')) as { boxPid?: number }
    if (st.boxPid) process.kill(st.boxPid)
  } catch {
    /* tiến trình đã chết hoặc chưa từng lên */
  }
}
