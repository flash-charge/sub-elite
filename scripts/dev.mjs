import { spawn } from 'node:child_process'

const child = spawn(process.execPath, ['--experimental-strip-types', 'server/index.ts'], {
  stdio: 'inherit',
  shell: false,
})

child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal)
  process.exit(code ?? 0)
})
