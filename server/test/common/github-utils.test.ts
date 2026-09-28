import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {parseRepository} from '../../src/common/github-utils';

describe('parseRepository', () => {
  it('should throw an Error for an invalid repository format', () => {
    // --- Given ---
    const invalidRepository = 'invalid';

    // --- When ---
    const call = () => {
      parseRepository(invalidRepository);
    };

    // --- Then ---
    assert.throws(call, Error);
  });
});
