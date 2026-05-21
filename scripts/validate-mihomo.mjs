import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { convertToClashMeta } from '../lib/converter.ts'

const mihomoBin = process.env.MIHOMO_BIN || 'mihomo'
const sample = 'trojan://secret@example.com:443?sni=example.com#MihomoCheck'
const { yaml } = convertToClashMeta(sample)
const dir = await mkdtemp(join(tmpdir(), 'sub-elite-mihomo-'))
const configPath = join(dir, 'config.yaml')

try {
  await writeFile(configPath, yaml)
  const result = spawnSync(mihomoBin, ['-t', '-f', configPath], { encoding: 'utf8' })
  if (result.error?.code === 'ENOENT') {
    console.error(`Mihomo binary not found: ${mihomoBin}. Set MIHOMO_BIN or install mihomo.`)
    process.exit(127)
  }
  if (result.status !== 0) {
    process.stderr.write(result.stdout || '')
    process.stderr.write(result.stderr || '')
    process.exit(result.status || 1)
  }
  process.stdout.write(result.stdout || '')
  process.stderr.write(result.stderr || '')
} finally {
  await rm(dir, { recursive: true, force: true })
}
