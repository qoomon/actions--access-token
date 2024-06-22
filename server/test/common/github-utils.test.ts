import {describe, expect, it} from '@jest/globals';
import {parseRepository} from '../../src/common/github-utils.js';

describe('parseRepository', () => {
  it('should response with status FORBIDDEN', async () => {
    // --- Given ---
    const invalidRepository = 'invalid';

    // --- When ---
    const call = () => {
      parseRepository(invalidRepository);
    };

    // --- Then ---
    expect(call).toThrow(Error);
  });
});
