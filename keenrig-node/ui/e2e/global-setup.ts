// Dựng hạ tầng THẬT cho bộ đo Admin: build SPA → build keenrig-box → chạy binary.
//
// Thứ tự là thứ tự của một lần phát hành thật:
//  1. `vite build` — dist/ là thứ go:embed nhúng vào binary.
//  2. `go build` — binary mang đúng dist vừa build.
//  3. Chạy với --data TRẮNG: màn setup owner là trạng thái đầu tiên người
//     dùng thật gặp, nên nó cũng là trạng thái đầu tiên bộ test gặp.
import { execFileSync, spawn, type ChildProcess } from 'node:child_process'
import { createWriteStream, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))

export const BOX_PORT = 18085
export const TMP = resolve(HERE, '.tmp')
export const BOX_LOG = join(TMP, 'box.log')
export const DATA_DIR = join(TMP, 'box-data')

const UI = resolve(HERE, '..') // keenrig-node/ui
const REPO = resolve(HERE, '..', '..', '..') // keenrig/

function sh(cmd: string, args: string[], cwd: string): void {
  execFileSync(cmd, args, { stdio: 'inherit', cwd, shell: process.platform === 'win32' })
}

async function waitFor(what: string, ms: number, ok: () => Promise<boolean>): Promise<void> {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    try {
      if (await ok()) return
    } catch {
      /* thử lại */
    }
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error(`hết giờ chờ: ${what}`)
}

export default async function globalSetup(): Promise<void> {
  rmSync(TMP, { recursive: true, force: true })
  mkdirSync(DATA_DIR, { recursive: true })

  // 1+2: artifact thật. Build UI trước để go:embed lấy đúng bản đang test.
  sh('npm', ['run', 'build'], UI)
  const bin = join(TMP, process.platform === 'win32' ? 'keenrig-box.exe' : 'keenrig-box')
  sh('go', ['build', '-o', bin, './keenrig-node/cmd/keenrig-box'], REPO)

  // 3: chạy thật, data trắng, không Docker.
  const log = createWriteStream(BOX_LOG)
  const box: ChildProcess = spawn(
    bin,
    ['serve', '--data', DATA_DIR, '--http', `127.0.0.1:${BOX_PORT}`, '--reconcile=false', '--secure-cookies=false'],
    { detached: false, stdio: ['ignore', 'pipe', 'pipe'] },
  )
  box.stdout?.pipe(log)
  box.stderr?.pipe(log)

  await waitFor('keenrig-box /healthz', 30_000, async () => {
    const res = await fetch(`http://127.0.0.1:${BOX_PORT}/healthz`)
    return res.ok
  })

  writeFileSync(join(TMP, 'state.json'), JSON.stringify({ boxPid: box.pid }))
}
