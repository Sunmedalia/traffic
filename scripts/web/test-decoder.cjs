const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { gzipSync, deflateSync } = require('node:zlib');
const source = fs.readFileSync(path.join(__dirname, '../../cmd/traffic-console/web/app.js'), 'utf8');
const code = source.slice(source.indexOf("const utf8Out ="), source.indexOf('// Cheap synchronous check'));
const context = vm.createContext({ TextDecoder, TextEncoder, Blob, DecompressionStream });
vm.runInContext(code, context);
(async () => {
  context.input = 'a'.repeat(1 << 20) + '%20中文';
  assert.equal(vm.runInContext('utf8Out.decode(percentBytes(input, true))', context), 'a'.repeat(1 << 20) + ' 中文');
  for (const compressed of [gzipSync(Buffer.from('中文 payload')), deflateSync(Buffer.from('中文 payload'))]) {
    context.compressed = compressed;
    const result = await vm.runInContext("DECODERS.find(x => x.key === 'gzip').run(compressed)", context);
    assert.equal(new TextDecoder().decode(result), '中文 payload');
  }
  context.compressed = gzipSync(Buffer.alloc((16 << 20) + 1));
  assert(context.compressed.length < 1 << 20);
  await assert.rejects(vm.runInContext("DECODERS.find(x => x.key === 'gzip').run(compressed)", context), /16 MiB/);
  console.log('Web decoder bounds and large URL regression tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
