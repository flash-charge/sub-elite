import { readdir, readFile, stat, writeFile } from 'node:fs/promises'
import { basename, join, relative, sep } from 'node:path'
import process from 'node:process'

const [, , sourceArg, outputArg] = process.argv

if (!sourceArg || !outputArg) {
  console.error('Usage: node scripts/make-zip.mjs <source-dir> <output.zip>')
  process.exit(1)
}

const sourceDir = join(process.cwd(), sourceArg)
const outputPath = join(process.cwd(), outputArg)
const files = await collectFiles(sourceDir)
const localParts = []
const centralParts = []
const table = Array.from({ length: 256 }, (_, index) => {
  let value = index
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
  }
  return value >>> 0
})
const { dosTime, dosDate } = toDosDateTime(new Date())
let offset = 0

for (const filePath of files) {
  const name = relative(sourceDir, filePath).split(sep).join('/')
  const nameBytes = Buffer.from(name)
  const content = await readFile(filePath)
  const checksum = crc32(content)
  const localHeader = Buffer.alloc(30)

  localHeader.writeUInt32LE(0x04034b50, 0)
  localHeader.writeUInt16LE(20, 4)
  localHeader.writeUInt16LE(0x0800, 6)
  localHeader.writeUInt16LE(0, 8)
  localHeader.writeUInt16LE(dosTime, 10)
  localHeader.writeUInt16LE(dosDate, 12)
  localHeader.writeUInt32LE(checksum, 14)
  localHeader.writeUInt32LE(content.length, 18)
  localHeader.writeUInt32LE(content.length, 22)
  localHeader.writeUInt16LE(nameBytes.length, 26)
  localHeader.writeUInt16LE(0, 28)

  localParts.push(localHeader, nameBytes, content)

  const centralHeader = Buffer.alloc(46)
  centralHeader.writeUInt32LE(0x02014b50, 0)
  centralHeader.writeUInt16LE(20, 4)
  centralHeader.writeUInt16LE(20, 6)
  centralHeader.writeUInt16LE(0x0800, 8)
  centralHeader.writeUInt16LE(0, 10)
  centralHeader.writeUInt16LE(dosTime, 12)
  centralHeader.writeUInt16LE(dosDate, 14)
  centralHeader.writeUInt32LE(checksum, 16)
  centralHeader.writeUInt32LE(content.length, 20)
  centralHeader.writeUInt32LE(content.length, 24)
  centralHeader.writeUInt16LE(nameBytes.length, 28)
  centralHeader.writeUInt16LE(0, 30)
  centralHeader.writeUInt16LE(0, 32)
  centralHeader.writeUInt16LE(0, 34)
  centralHeader.writeUInt16LE(0, 36)
  centralHeader.writeUInt32LE(0, 38)
  centralHeader.writeUInt32LE(offset, 42)

  centralParts.push(centralHeader, nameBytes)
  offset += localHeader.length + nameBytes.length + content.length
}

const centralOffset = offset
const centralSize = centralParts.reduce((total, part) => total + part.length, 0)
const end = Buffer.alloc(22)
end.writeUInt32LE(0x06054b50, 0)
end.writeUInt16LE(0, 4)
end.writeUInt16LE(0, 6)
end.writeUInt16LE(files.length, 8)
end.writeUInt16LE(files.length, 10)
end.writeUInt32LE(centralSize, 12)
end.writeUInt32LE(centralOffset, 16)
end.writeUInt16LE(0, 20)

await writeFile(outputPath, Buffer.concat([...localParts, ...centralParts, end]))
console.log(`ZIP written to ${basename(outputPath)} (${files.length} files)`)

async function collectFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  const paths = []

  for (const entry of entries) {
    const fullPath = join(dir, entry.name)
    if (entry.isDirectory()) {
      paths.push(...(await collectFiles(fullPath)))
    } else if (entry.isFile()) {
      const info = await stat(fullPath)
      if (info.size <= 0xffffffff) paths.push(fullPath)
    }
  }

  return paths.sort()
}

function crc32(buffer) {
  let crc = 0xffffffff
  for (const byte of buffer) {
    crc = (crc >>> 8) ^ table[(crc ^ byte) & 0xff]
  }
  return (crc ^ 0xffffffff) >>> 0
}

function toDosDateTime(date) {
  const year = Math.max(date.getFullYear(), 1980)
  return {
    dosTime: (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2),
    dosDate: ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate(),
  }
}
