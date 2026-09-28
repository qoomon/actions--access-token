/* eslint-disable max-len */
import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {matchSubject, resolveAccessPolicyStatementSubjects} from '../src/access-policy.js';

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
      assert.ok(result.includes(`repo:${ORIGIN}:ref:refs/heads/main`));
    });

    it('replaces ${origin} in multiple subjects', () => {
      const result = resolve([
        'repo:${origin}:ref:refs/heads/main',
        'repo:${origin}:ref:refs/heads/dev',
      ]);
      assert.ok(result.includes(`repo:${ORIGIN}:ref:refs/heads/main`));
      assert.ok(result.includes(`repo:${ORIGIN}:ref:refs/heads/dev`));
    });
  });

  describe('fully-qualified subjects (no legacy expansion needed)', () => {
    it('leaves a full repo:…:ref:… subject unchanged', () => {
      const subject = `repo:${ORIGIN}:ref:refs/heads/main`;
      const result = resolve([subject]);
      // The subject itself should be present; no duplicate artificial subjects
      assert.ok(result.includes(subject));
    });
  });

  describe('LEGACY: prefix-less subjects get repo: prepended', () => {
    it('prefixes a bare ref:… subject with repo:owner/repo:', () => {
      const result = resolve(['ref:refs/heads/main']);
      assert.ok(result.includes(`repo:${ORIGIN}:ref:refs/heads/main`));
    });

    it('prefixes a bare environment subject with repo:owner/repo:', () => {
      const result = resolve(['environment:production']);
      assert.ok(result.includes(`repo:${ORIGIN}:environment:production`));
    });
  });

  describe('LEGACY: relative workflow_ref values get repo prefix', () => {
    it('prefixes a /…workflow path in workflow_ref with the policy repo', () => {
      // A legacy pattern like "workflow_ref:/.github/workflows/build.yml@refs/heads/main"
      // should become "workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/heads/main"
      const result = resolve(['workflow_ref:/.github/workflows/build.yml@refs/heads/main']);
      assert.equal(result.some((s) =>
          s.includes(`workflow_ref:${ORIGIN}/.github/workflows/build.yml@refs/heads/main`)
      ), true);
    });

    it('does not modify an already-absolute workflow_ref value', () => {
      const subject = `repo:${ORIGIN}:workflow_ref:${ORIGIN}/.github/workflows/build.yml@refs/heads/main`;
      const result = resolve([subject]);
      assert.ok(result.includes(subject));
    });
  });

  describe('deduplication of subjects is preserved by the caller', () => {
    it('does not duplicate an already-correct full subject', () => {
      const subject = `repo:${ORIGIN}:ref:refs/heads/main`;
      const result = resolve([subject]);
      const count = result.filter((s) => s === subject).length;
      assert.equal(count, 1);
    });
  });
});

// ---------------------------------------------------------------------------
// matchSubject
// ---------------------------------------------------------------------------

describe('matchSubject', () => {

  describe('exact matching', () => {
    it('returns true for an exact match', () => {
      const subject = 'repo:octocat/sandbox:ref:refs/heads/main';
      assert.equal(matchSubject(subject, subject), true);
    });

    it('returns false for a non-matching subject', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox:ref:refs/heads/main',
          'repo:octocat/other:ref:refs/heads/main',
      ), false);
    });
  });

  describe('* wildcard (matches any chars except ":")', () => {
    it('matches a single segment with *', () => {
      assert.equal(matchSubject(
          'repo:octocat/*:ref:refs/heads/main',
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), true);
    });

    it('does NOT match across ":" boundaries with *', () => {
      assert.equal(matchSubject(
          'repo:octocat/*',
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), false);
    });
  });

  describe('** wildcard (matches any chars including ":")', () => {
    it('matches across ":" boundaries with **', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox:**',
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), true);
    });

    it('matches an empty tail with **', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox:**',
          'repo:octocat/sandbox:',
      ), true);
    });
  });

  describe('security: patterns with wildcards in claim names', () => {
    it('rejects a pattern where a claim name contains *', () => {
      // e.g. "repo:foo/bar:*" – the claim key is "*" which is a wildcard claim name
      assert.equal(matchSubject('repo:foo/bar:*', 'repo:foo/bar:ref:refs/heads/main'), false);
    });

    it('allows repo:owner/*:** (wildcard in value, not in claim name)', () => {
      assert.equal(matchSubject(
          'repo:octocat/*:**',
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), true);
    });
  });

  describe('pull request matching', () => {
    it('rejects implicit wildcard matching (ref claim)', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox:ref:refs/*',
          'repo:octocat/sandbox:ref:refs/pull/123/head',
      ), false);
    });

    it('allow explicit matching (ref claim)', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox:ref:refs/pull/*',
          'repo:octocat/sandbox:ref:refs/pull/123/head',
      ), true);
    });

    it('rejects implicit wildcard matching (workflow_ref claim)', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox/.github/workflows/example.yml@refs/*',
          'repo:octocat/sandbox/.github/workflows/example.yml@refs/pull/123/head',
      ), false);
    });

    it('allow explicit matching (workflow_ref claim)', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox/.github/workflows/example.yml@refs/pull/*',
          'repo:octocat/sandbox/.github/workflows/example.yml@refs/pull/123/head',
      ), true);
    });

  });

  describe('array overloads', () => {
    it('accepts an array of patterns and returns true if any match', () => {
      assert.equal(matchSubject(
          ['repo:other/*:**', 'repo:octocat/*:**'],
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), true);
    });

    it('accepts an array of subjects and returns true if any match', () => {
      assert.equal(matchSubject(
          'repo:octocat/*:**',
          ['repo:nobody/sandbox:ref:refs/heads/main', 'repo:octocat/sandbox:ref:refs/heads/main'],
      ), true);
    });

    it('returns false when no subject in the array matches', () => {
      assert.equal(matchSubject(
          'repo:octocat/*:**',
          ['repo:spongebob/sandbox:ref:refs/heads/main'],
      ), false);
    });
  });

  describe('case insensitivity', () => {
    it('matches case-insensitively', () => {
      assert.equal(matchSubject(
          'repo:OCTOCAT/sandbox:ref:refs/heads/main',
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), true);
    });
  });

  describe('immutable claims matching', () => {
    it('matches exact immutable subject', () => {
      assert.equal(matchSubject(
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), true);
    });

    it('matches immutable subject with wildcard in repository name', () => {
      assert.equal(matchSubject(
          'repo:octocat@123456/*@654321:ref:refs/heads/main',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), true);
    });

    it('matches immutable subject with ** wildcard', () => {
      assert.equal(matchSubject(
          'repo:octocat@123456/sandbox@654321:**',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), true);
    });

    it('matches immutable immutable workflow_ref subject', () => {
      assert.equal(matchSubject(
          'repo:octocat@123456/sandbox@654321:workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/heads/main',
          'repo:octocat@123456/sandbox@654321:workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/heads/main',
      ), true);
    });

    it('matches immutable job_workflow_ref subject', () => {
      assert.equal(matchSubject(
          'repo:octocat@123456/sandbox@654321:job_workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/heads/main',
          'repo:octocat@123456/sandbox@654321:job_workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/heads/main',
      ), true);
    });

    it('does NOT match immutable subject with different owner ID', () => {
      assert.equal(matchSubject(
          'repo:octocat@111111/sandbox@654321:ref:refs/heads/main',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), false);
    });

    it('does NOT match immutable subject with different repository ID', () => {
      assert.equal(matchSubject(
          'repo:octocat@123456/sandbox@111111:ref:refs/heads/main',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), false);
    });

    it('matches immutable subject with wildcard owner ID', () => {
      assert.equal(matchSubject(
          'repo:octocat@*/sandbox@654321:ref:refs/heads/main',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), true);
    });

    it('matches immutable subject with wildcard repository ID', () => {
      assert.equal(matchSubject(
          'repo:octocat@123456/sandbox@*:ref:refs/heads/main',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), true);
    });

    it('does NOT match immutable subject when pattern has wildcard in owner claim name', () => {
      // Wildcard in the claim key (before ':') is not allowed for security
      assert.equal(matchSubject(
          'repo:octocat@*:/sandbox@654321:ref:refs/heads/main',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), false);
    });

    it('matches immutable subject with ** suffix', () => {
      assert.equal(matchSubject(
          'repo:octocat@123456/sandbox@654321:workflow_ref:**',
          'repo:octocat@123456/sandbox@654321:workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/heads/main',
      ), true);
    });

    it('matches immutable subject case-insensitively', () => {
      assert.equal(matchSubject(
          'repo:OCTOCAT@123456/SANDBOX@654321:ref:refs/heads/main',
          'repo:octocat@123456/sandbox@654321:ref:refs/heads/main',
      ), true);
    });
  });
});
