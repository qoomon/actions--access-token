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

  describe('LEGACY: completed subjects replace the abbreviated subjects', () => {
    // The abbreviated subject must not be kept next to the completed subject, otherwise it would also match the raw
    // `sub` claim of any repository that customized its OIDC `sub` claim template (e.g. to only contain the ref claim).

    it('replaces a bare ref:… subject', () => {
      assert.deepEqual(resolve(['ref:refs/heads/main']), [`repo:${ORIGIN}:ref:refs/heads/main`]);
    });

    it('replaces a bare environment subject', () => {
      assert.deepEqual(resolve(['environment:production']), [`repo:${ORIGIN}:environment:production`]);
    });

    it('replaces a relative workflow_ref subject', () => {
      assert.deepEqual(
          resolve(['workflow_ref:/.github/workflows/build.yml@refs/heads/main']),
          [`repo:${ORIGIN}:workflow_ref:${ORIGIN}/.github/workflows/build.yml@refs/heads/main`],
      );
    });

    it('replaces a relative job_workflow_ref subject of another repository', () => {
      assert.deepEqual(
          resolve(['repo:other/repo:job_workflow_ref:/.github/workflows/build.yml@refs/heads/main']),
          ['repo:other/repo:job_workflow_ref:other/repo/.github/workflows/build.yml@refs/heads/main'],
      );
    });

    it('does NOT match the raw custom sub claim of another repository', () => {
      const subjects = resolve(['ref:refs/heads/main', 'environment:production']);
      assert.equal(matchSubject(subjects, 'ref:refs/heads/main'), false);
      assert.equal(matchSubject(subjects, 'environment:production'), false);
      assert.equal(matchSubject(subjects, 'repo:octocat/other:ref:refs/heads/main'), false);
      assert.equal(matchSubject(subjects, `repo:${ORIGIN}:ref:refs/heads/main`), true);
      assert.equal(matchSubject(subjects, `repo:${ORIGIN}:environment:production`), true);
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

    it('rejects implicit wildcard matching of pull request refs for every claim', () => {
      for (const subject of [
        'repo:octocat/sandbox:ref:refs/pull/123/merge',
        'repo:octocat/sandbox:workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/pull/123/merge',
        'repo:octocat/sandbox:job_workflow_ref:octocat/sandbox/.github/workflows/build.yml@refs/pull/123/merge',
      ]) {
        assert.equal(matchSubject('repo:octocat/sandbox:**', subject), false, subject);
        assert.equal(matchSubject('repo:octocat/*:**', subject), false, subject);
      }
    });

    it('rejects implicit wildcard matching of pull request refs if a workflow file name contains ":"', () => {
      // a ':' in a workflow file name shifts the pairing of claim names and claim values
      const subject = 'repo:octocat/sandbox:workflow_ref:octocat/sandbox/.github/workflows/build:pr.yml@refs/pull/123/merge';
      assert.equal(matchSubject('repo:octocat/sandbox:**', subject), false);
      assert.equal(matchSubject('repo:octocat/*:**', subject), false);
      assert.equal(matchSubject('repo:octocat/sandbox:workflow_ref:**', subject), false);
    });

    it('allows explicit matching of pull request refs if a workflow file name contains ":"', () => {
      const subject = 'repo:octocat/sandbox:workflow_ref:octocat/sandbox/.github/workflows/build:pr.yml@refs/pull/123/merge';
      assert.equal(matchSubject(subject, subject), true);
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

  describe('case sensitivity', () => {
    // GitHub treats owner, repository and environment names case-insensitively,
    // but git refs and file paths are case-sensitive, e.g. the branches `main` and `Main` are different branches

    it('does NOT match a branch name with different case', () => {
      const pattern = 'repo:octocat/sandbox:ref:refs/heads/main';
      assert.equal(matchSubject(pattern, 'repo:octocat/sandbox:ref:refs/heads/main'), true);
      assert.equal(matchSubject(pattern, 'repo:octocat/sandbox:ref:refs/heads/Main'), false);
      assert.equal(matchSubject(pattern, 'repo:octocat/sandbox:ref:refs/heads/MAIN'), false);
      assert.equal(matchSubject('repo:octocat/sandbox:ref:refs/heads/Main', 'repo:octocat/sandbox:ref:refs/heads/main'), false);
    });

    it('does NOT match a branch name with different case (wildcard pattern)', () => {
      const pattern = 'repo:octocat/sandbox:ref:refs/heads/release/*';
      assert.equal(matchSubject(pattern, 'repo:octocat/sandbox:ref:refs/heads/release/1.0'), true);
      assert.equal(matchSubject(pattern, 'repo:octocat/sandbox:ref:refs/heads/Release/1.0'), false);
      assert.equal(matchSubject('repo:octocat/sandbox:ref:refs/heads/**', 'repo:octocat/sandbox:ref:REFS/heads/main'), false);
    });

    it('does NOT match a tag name with different case', () => {
      const pattern = 'repo:octocat/sandbox:ref:refs/tags/v*';
      assert.equal(matchSubject(pattern, 'repo:octocat/sandbox:ref:refs/tags/v1'), true);
      assert.equal(matchSubject(pattern, 'repo:octocat/sandbox:ref:refs/tags/V1'), false);
    });

    it('does NOT match a workflow file path or workflow ref with different case', () => {
      for (const claim of ['workflow_ref', 'job_workflow_ref']) {
        const pattern = `repo:octocat/sandbox:${claim}:octocat/sandbox/.github/workflows/release.yml@refs/heads/main`;
        assert.equal(matchSubject(pattern, pattern), true);
        assert.equal(matchSubject(pattern, pattern.replace('release.yml', 'RELEASE.yml')), false);
        assert.equal(matchSubject(pattern, pattern.replace('.github', '.GITHUB')), false);
        assert.equal(matchSubject(pattern, pattern.replace('@refs/heads/main', '@refs/heads/Main')), false);
      }
    });

    it('does NOT match claim names with different case', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox:REF:refs/heads/main',
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), false);
    });

    it('matches owner and repository names case-insensitively', () => {
      assert.equal(matchSubject(
          'repo:OCTOCAT/Sandbox:ref:refs/heads/main',
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), true);
      assert.equal(matchSubject(
          'repo:OCTOCAT/*:ref:refs/heads/main',
          'repo:octocat/sandbox:ref:refs/heads/main',
      ), true);
    });

    it('matches owner and repository names of workflow_ref claims case-insensitively', () => {
      for (const claim of ['workflow_ref', 'job_workflow_ref']) {
        assert.equal(matchSubject(
            `repo:octocat/sandbox:${claim}:OCTOCAT/Sandbox/.github/workflows/release.yml@refs/heads/main`,
            `repo:octocat/sandbox:${claim}:octocat/sandbox/.github/workflows/release.yml@refs/heads/main`,
        ), true);
      }
    });

    it('matches environment names case-insensitively', () => {
      assert.equal(matchSubject(
          'repo:octocat/sandbox:environment:Production',
          'repo:octocat/sandbox:environment:production',
      ), true);
    });

    it('does NOT apply unicode case folding', () => {
      // the Kelvin sign (U+212A) is not the letter k
      assert.equal(matchSubject('repo:octocat/k:**', 'repo:octocat/\u212A:ref:refs/heads/main'), false);
      assert.equal(matchSubject(
          'repo:octocat/sandbox:environment:k',
          'repo:octocat/sandbox:environment:\u212A',
      ), false);
      assert.equal(matchSubject(
          'repo:octocat/sandbox:ref:refs/heads/k',
          'repo:octocat/sandbox:ref:refs/heads/\u212A',
      ), false);
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
