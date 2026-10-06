import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {findFirstNotNull} from '../../src/common/common-utils.js';

describe('findFirstNotNull', () => {

  it('returns the first value that is not null', async () => {
    const calls: string[] = [];
    const result = await findFirstNotNull(['a', 'b', 'c'], async (value) => {
      calls.push(value);
      return value === 'a' ? null : value.toUpperCase();
    });
    assert.equal(result, 'B');
    assert.deepEqual(calls, ['a', 'b']);
  });

  it('returns null if all values are null', async () => {
    const result = await findFirstNotNull(['a', 'b'], async () => null);
    assert.equal(result, null);
  });

  it('returns null for an empty input', async () => {
    const result = await findFirstNotNull([], async () => 'value');
    assert.equal(result, null);
  });

  it('treats an empty string as a value and does not continue with the next input value', async () => {
    const calls: string[] = [];
    const result = await findFirstNotNull(['a', 'b'], async (value) => {
      calls.push(value);
      return value === 'a' ? '' : 'fallback';
    });
    assert.equal(result, '');
    assert.deepEqual(calls, ['a']);
  });

  it('treats falsy values other than null as values', async () => {
    assert.equal(await findFirstNotNull([1, 2], async (value) => value === 1 ? 0 : value), 0);
    assert.equal(await findFirstNotNull([1, 2], async (value) => value === 1 ? false : value), false);
  });
});
