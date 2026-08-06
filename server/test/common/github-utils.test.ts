import {describe, expect, it} from '@jest/globals';
import {normalizeImmutableOIDCSubject, parseRepository} from '../../src/common/github-utils.js';

describe('parseRepository', () => {
  it('should throw an Error for an invalid repository format', () => {
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

describe('normalizeImmutableOIDCSubject', () => {
  it('strips immutable owner and repository IDs from an immutable subject', () => {
    // --- Given ---
    const subject = 'repo:octocat@123456/sandbox@789012:ref:refs/heads/main';

    // --- When ---
    const result = normalizeImmutableOIDCSubject(subject);

    // --- Then ---
    expect(result).toBe('repo:octocat/sandbox:ref:refs/heads/main');
  });

  it('strips immutable owner and repository IDs for pull_request subjects', () => {
    // --- Given ---
    const subject = 'repo:octocat@123456/sandbox@789012:pull_request';

    // --- When ---
    const result = normalizeImmutableOIDCSubject(subject);

    // --- Then ---
    expect(result).toBe('repo:octocat/sandbox:pull_request');
  });

  it('strips immutable owner and repository IDs for environment subjects', () => {
    // --- Given ---
    const subject = 'repo:octocat@123456/sandbox@789012:environment:production';

    // --- When ---
    const result = normalizeImmutableOIDCSubject(subject);

    // --- Then ---
    expect(result).toBe('repo:octocat/sandbox:environment:production');
  });

  it('leaves classic mutable subjects unchanged', () => {
    // --- Given ---
    const subject = 'repo:octocat/sandbox:ref:refs/heads/main';

    // --- When ---
    const result = normalizeImmutableOIDCSubject(subject);

    // --- Then ---
    expect(result).toBe(subject);
  });

  it('leaves unrelated subjects unchanged', () => {
    // --- Given ---
    const subject = 'not-a-repo-subject';

    // --- When ---
    const result = normalizeImmutableOIDCSubject(subject);

    // --- Then ---
    expect(result).toBe(subject);
  });
});
