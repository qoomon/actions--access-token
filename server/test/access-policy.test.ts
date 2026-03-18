import {describe, expect, it} from '@jest/globals';
import {resolveAccessPolicyStatementSubjects} from '../src/access-policy.js';

// ---------------------------------------------------------------------------
// resolveAccessPolicyStatementSubjects
// ---------------------------------------------------------------------------

describe('resolveAccessPolicyStatementSubjects', () => {

  const OWNER = 'octocat';
  const REPO = 'sandbox';
  const ORIGIN = `${OWNER}/${REPO}`;

  function resolve(subjects: string[]): string[] {
    const statement = {subjects};
    resolveAccessPolicyStatementSubjects(statement, {owner: OWNER, repo: REPO});
    return statement.subjects;
  }

  describe('${origin} variable substitution', () => {
    it('replaces ${origin} with owner/repo', () => {
      const result = resolve(['repo:${origin}:ref:refs/heads/main']);
      expect(result).toContain(`repo:${ORIGIN}:ref:refs/heads/main`);
    });

    it('replaces ${origin} in multiple subjects', () => {
      const result = resolve([
        'repo:${origin}:ref:refs/heads/main',
        'repo:${origin}:ref:refs/heads/dev',
      ]);
      expect(result).toContain(`repo:${ORIGIN}:ref:refs/heads/main`);
      expect(result).toContain(`repo:${ORIGIN}:ref:refs/heads/dev`);
    });
  });

  describe('fully-qualified subjects (no legacy expansion needed)', () => {
    it('leaves a full repo:…:ref:… subject unchanged', () => {
      const subject = `repo:${ORIGIN}:ref:refs/heads/main`;
      const result = resolve([subject]);
      // The subject itself should be present; no duplicate artificial subjects
      expect(result).toContain(subject);
    });
  });

  describe('LEGACY: prefix-less subjects get repo: prepended', () => {
    it('prefixes a bare ref:… subject with repo:owner/repo:', () => {
      const result = resolve(['ref:refs/heads/main']);
      expect(result).toContain(`repo:${ORIGIN}:ref:refs/heads/main`);
    });

    it('prefixes a bare environment subject with repo:owner/repo:', () => {
      const result = resolve(['environment:production']);
      expect(result).toContain(`repo:${ORIGIN}:environment:production`);
    });
  });

  describe('LEGACY: relative workflow_ref values get repo prefix', () => {
    it('prefixes a /…workflow path in workflow_ref with the policy repo', () => {
      // A legacy pattern like "workflow_ref:/.github/workflows/build.yml@refs/heads/main"
      // should become "workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/heads/main"
      const result = resolve(['workflow_ref:/.github/workflows/build.yml@refs/heads/main']);
      expect(result.some((s) =>
          s.includes(`workflow_ref:${ORIGIN}/.github/workflows/build.yml@refs/heads/main`)
      )).toBe(true);
    });

    it('does not modify an already-absolute workflow_ref value', () => {
      const subject = `repo:${ORIGIN}:workflow_ref:${ORIGIN}/.github/workflows/build.yml@refs/heads/main`;
      const result = resolve([subject]);
      expect(result).toContain(subject);
    });
  });

  describe('deduplication of subjects is preserved by the caller', () => {
    it('does not duplicate an already-correct full subject', () => {
      const subject = `repo:${ORIGIN}:ref:refs/heads/main`;
      const result = resolve([subject]);
      const count = result.filter((s) => s === subject).length;
      expect(count).toBe(1);
    });
  });
});
