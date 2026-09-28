import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {YamlTransformer} from '../../src/common/zod-utils.js';

describe('YamlTransformer', () => {

  it('parses valid YAML', () => {
    const result = YamlTransformer.safeParse('key: value');
    assert.ok(result.success);
    assert.deepEqual(result.data, {key: 'value'});
  });

  it('returns a parse error for invalid YAML', () => {
    const result = YamlTransformer.safeParse(': invalid: yaml:');
    assert.equal(result.success, false);
  });

  it('rejects YAML with excessive alias expansion (billion-laughs DoS)', () => {
    // Each level multiplies by 10; four levels of 10 produce 10^4 = 10,000 expansions,
    // well above the maxAliasCount: 100 limit.
    const yaml = [
      'a: &a [x, x, x, x, x, x, x, x, x, x]',
      'b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]',
      'c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]',
      'd: [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]',
    ].join('\n');

    const result = YamlTransformer.safeParse(yaml);
    assert.equal(result.success, false);
  });
});
