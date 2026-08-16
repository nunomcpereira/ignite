'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const zlib = require('node:zlib');

const { withServerEnv, makeTempProject } = require('./helpers');

// Hand-builds a single-entry ZIP whose local-header and central-directory
// "uncompressed size" fields lie (declare a small size) while the real
// compressed payload decompresses to something much larger - the exact
// shape extractZip's guard must not be fooled by.
function buildLyingZip({ name, realData, declaredSize }) {
  const nameBuf = Buffer.from(name, 'utf8');
  const compressed = zlib.deflateRawSync(realData);
  const crc = zlib.crc32(realData);

  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4); // version needed
  localHeader.writeUInt16LE(0, 6); // flags
  localHeader.writeUInt16LE(8, 8); // method: deflate
  localHeader.writeUInt16LE(0, 10); // mod time
  localHeader.writeUInt16LE(0, 12); // mod date
  localHeader.writeUInt32LE(crc, 14);
  localHeader.writeUInt32LE(compressed.length, 18); // compressed size (real)
  localHeader.writeUInt32LE(declaredSize, 22); // uncompressed size (LIE)
  localHeader.writeUInt16LE(nameBuf.length, 26);
  localHeader.writeUInt16LE(0, 28);

  const localOffset = 0;
  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4); // version made by
  centralHeader.writeUInt16LE(20, 6); // version needed
  centralHeader.writeUInt16LE(0, 8); // flags
  centralHeader.writeUInt16LE(8, 10); // method: deflate
  centralHeader.writeUInt16LE(0, 12); // mod time
  centralHeader.writeUInt16LE(0, 14); // mod date
  centralHeader.writeUInt32LE(crc, 16);
  centralHeader.writeUInt32LE(compressed.length, 20); // compressed size (real)
  centralHeader.writeUInt32LE(declaredSize, 24); // uncompressed size (LIE)
  centralHeader.writeUInt16LE(nameBuf.length, 28);
  centralHeader.writeUInt16LE(0, 30); // extra length
  centralHeader.writeUInt16LE(0, 32); // comment length
  centralHeader.writeUInt16LE(0, 34); // disk number start
  centralHeader.writeUInt16LE(0, 36); // internal attrs
  centralHeader.writeUInt32LE(0, 38); // external attrs
  centralHeader.writeUInt32LE(localOffset, 42);

  const localEntry = Buffer.concat([localHeader, nameBuf, compressed]);
  const centralEntry = Buffer.concat([centralHeader, nameBuf]);
  const cdOffset = localEntry.length;

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(1, 8); // entries on this disk
  eocd.writeUInt16LE(1, 10); // total entries
  eocd.writeUInt32LE(centralEntry.length, 12); // cd size
  eocd.writeUInt32LE(cdOffset, 16); // cd offset
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([localEntry, centralEntry, eocd]);
}

test('extractZip: a lying declared uncompressed-size cannot bypass the zip-bomb cap', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({});
  const zipPath = `${dir}/bomb.zip`;
  const destDir = `${dir}/out`;
  await fs.mkdir(destDir, { recursive: true });

  // Real decompressed payload is bigger than the cap; declared size lies
  // and says it's tiny (1 byte) - highly compressible so the ZIP itself
  // stays small on disk. Rejection can come from either layer: node-
  // stream-zip's own CrcVerify throws as soon as accumulated bytes exceed
  // the declared size (it re-checks crc/size on every chunk once past
  // that point, so surviving with a full adversarial payload is not
  // practically achievable), or - if that ever changed upstream -
  // extractZip's own running-byte-count guard, which never trusts
  // declared metadata for the cap. Either is an acceptable rejection;
  // the point of this test is that extraction must NOT complete and must
  // NOT silently write the full oversized payload to disk.
  const realSize = mod.MAX_EXTRACTED_BYTES + 1024;
  const realData = Buffer.alloc(realSize, 'a');
  const zipBuf = buildLyingZip({ name: 'payload.txt', realData, declaredSize: 1 });
  await fs.writeFile(zipPath, zipBuf);

  await assert.rejects(() => mod.extractZip(zipPath, destDir, () => {}));
  const stat = await fs.stat(`${destDir}/payload.txt`).catch(() => null);
  assert.ok(!stat || stat.size < mod.MAX_EXTRACTED_BYTES, 'the full oversized payload must not land on disk');
}));

test('extractZip: a normal small archive with honest sizes still extracts fine', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({});
  const zipPath = `${dir}/normal.zip`;
  const destDir = `${dir}/out`;
  await fs.mkdir(destDir, { recursive: true });

  const realData = Buffer.from('hello world\n');
  const zipBuf = buildLyingZip({ name: 'hello.txt', realData, declaredSize: realData.length });
  await fs.writeFile(zipPath, zipBuf);

  const { fileCount, totalBytes } = await mod.extractZip(zipPath, destDir, () => {});
  assert.equal(fileCount, 1);
  assert.equal(totalBytes, realData.length);
  const written = await fs.readFile(`${destDir}/hello.txt`, 'utf8');
  assert.equal(written, 'hello world\n');
}));
