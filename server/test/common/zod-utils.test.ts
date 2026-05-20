import {describe, expect, it} from '@jest/globals';
import {YamlTransformer} from '../../src/common/zod-utils.js';

describe('YamlTransformer', () => {

  it('parses valid YAML', () => {
    const result = YamlTransformer.safeParse('key: value');
    expect(result.success).toBe(true);
    expect(result.data).toEqual({key: 'value'});
  });

  it('returns a parse error for invalid YAML', () => {
    const result = YamlTransformer.safeParse(': invalid: yaml:');
    expect(result.success).toBe(false);
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
    expect(result.success).toBe(false);
  });
});
