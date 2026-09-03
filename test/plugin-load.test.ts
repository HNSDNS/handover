import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const worktree = fileURLToPath(new URL('..', import.meta.url));

describe('plugin loading (hsd loader: require)', () => {
  it('is require()able as CommonJS, mirroring hsd bin/node', () => {
    // hsd's bin/node loads plugins via `loader: require` (a CJS require of
    // the package entry). On Node >=23.6 this also handles the ESM .ts entry
    // via require(esm) + native type stripping. Surface shape: { id, init }.
    const script = [
      "const p = require('./src/handover.ts');",
      "console.log(JSON.stringify({ id: p.id, init: typeof p.init }));"
    ].join(' ');

    const out = execFileSync(process.execPath, ['-e', script], {
      cwd: worktree,
      encoding: 'utf8'
    });

    expect(JSON.parse(out.trim())).toEqual({ id: 'handover', init: 'function' });
  });
});
