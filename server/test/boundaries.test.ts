/**
 * "The server has no decryption code at all" (PLAN.md §8), as a test: no server source may import
 * the protocol's end-to-end entry point or reach into its sources. Only tests act as phones.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SRC = fileURLToPath(new URL('../src', import.meta.url));

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : path.endsWith('.ts') ? [path] : [];
  });
}

describe('the server', () => {
  it.each(sources(SRC).map((path) => [path.slice(SRC.length + 1), path]))('%s imports only the API side of the protocol', (_, path) => {
    const imports = [...readFileSync(path, 'utf8').matchAll(/from\s+'([^']+)'/g)].map((match) => match[1]!);
    for (const specifier of imports.filter((s) => s.includes('protocol'))) {
      expect(specifier).toBe('@tamodak/protocol/api');
    }
  });
});
