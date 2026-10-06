import assert from 'node:assert/strict';
import process from 'node:process';
import {describe, it} from 'node:test';
import * as Fixtures from './fixtures.js';
import {GitHubActionsJwtPayload} from '../src/common/github-utils.js';

process.env.GITHUB_APP_ID = Fixtures.GITHUB_APP_AUTH.appId;
process.env.GITHUB_APP_PRIVATE_KEY = Fixtures.GITHUB_APP_AUTH.privateKey;
process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE = Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.aud;

const {getEffectiveCallerIdentitySubjects} = await import('../src/access-token-manager.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIdentity(overrides: Partial<GitHubActionsJwtPayload> = {}): GitHubActionsJwtPayload {
  const repository = overrides.repository ?? 'octocat/sandbox';
  const ref = overrides.ref ?? 'refs/heads/main';
  const workflowFile = 'octocat/sandbox/.github/workflows/build.yml';
  const repository_owner = repository.split('/')[0];
  const repository_owner_id = overrides.repository_owner_id ?? '583231';
  const repository_id = overrides.repository_id ?? '1234567';

  return {
    sub: overrides.sub
        ?? `repo:${repository_owner}@${repository_owner_id}/${repository.split('/')[1]}@${repository_id}:ref:${ref}`,
    repository,
    repository_owner,
    repository_owner_id,
    repository_id,
    ref,
    workflow_ref: `${workflowFile}@${ref}`,
    job_workflow_ref: `${workflowFile}@${ref}`,
    ...overrides,
  } as GitHubActionsJwtPayload;
}

// ---------------------------------------------------------------------------
// getEffectiveCallerIdentitySubjects
// ---------------------------------------------------------------------------

describe('getEffectiveCallerIdentitySubjects', () => {

  it('always includes the raw sub claim', () => {
    const identity = makeIdentity();
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    assert.ok(subjects.includes(identity.sub));
  });

  it('adds immutable repository subject for legacy sub claim', () => {
    const identity = makeIdentity({
      sub: 'repo:octocat/sandbox:pull_request',
      ref: 'refs/pull/42/head',
    });
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    assert.ok(subjects.includes(
        `repo:${identity.repository_owner}@${identity.repository_owner_id}` +
        `/${identity.repository.split('/')[1]}@${identity.repository_id}` +
        `:pull_request`));
  });

  it('adds legacy repository subject for immutable sub claim', () => {
    const identity = makeIdentity();
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    assert.ok(subjects.includes(identity.sub));
    assert.ok(subjects.includes(`repo:${identity.repository}:ref:${identity.ref}`));
  });

  describe('sub claim binding', () => {
    // The sub claim can be customized by repository admins, e.g. to `ref:refs/heads/main` or `environment:production`,
    // which is indistinguishable from the sub claim of any other repository.
    // Therefore, the sub claim is only trusted if it is bound to the repository of the caller identity.

    const BOUND_SUBS = [
      'repo:octocat/sandbox',
      'repo:octocat/sandbox:environment:production',
      'repo:octocat/sandbox:pull_request',
      'repo:octocat@583231/sandbox@1234567',
      'repo:octocat@583231/sandbox@1234567:environment:production',
    ];
    for (const sub of BOUND_SUBS) {
      it(`includes the sub claim '${sub}' that is bound to the repository`, () => {
        const identity = makeIdentity({sub});
        const subjects = getEffectiveCallerIdentitySubjects(identity);
        assert.ok(subjects.includes(sub));
        // both formats are included
        const suffix = sub.replace(/^repo:[^:]+/, '');
        assert.ok(subjects.includes(`repo:octocat/sandbox${suffix}`));
        assert.ok(subjects.includes(`repo:octocat@583231/sandbox@1234567${suffix}`));
      });
    }

    const UNBOUND_SUBS = [
      'ref:refs/heads/main',
      'environment:production',
      'repo',
      'octocat/sandbox',
      'workflow:build:repo:octocat/sandbox',
      'x:repo:octocat/sandbox:ref:refs/heads/main',
      'repo:octocat/other:ref:refs/heads/main',
      'repo:octocat/sandbox-other:ref:refs/heads/main',
      'repo:octocat/sandbox2',
      'repo:other/sandbox:ref:refs/heads/main',
      'repo:octocat@583231/other@1234567:ref:refs/heads/main',
      'repo:octocat@583231/sandbox@7654321:ref:refs/heads/main',
      'repo:octocat@111111/sandbox@1234567:ref:refs/heads/main',
      'repo:octocat@583231/sandbox@1234567x:ref:refs/heads/main',
    ];
    for (const sub of UNBOUND_SUBS) {
      it(`does NOT include the sub claim '${sub}' that is not bound to the repository`, () => {
        const identity = makeIdentity({sub});
        const subjects = getEffectiveCallerIdentitySubjects(identity);
        assert.equal(subjects.includes(sub), false);
        // artificial subjects are still available
        assert.ok(subjects.includes('repo:octocat/sandbox:ref:refs/heads/main'));
        assert.ok(subjects.includes('repo:octocat@583231/sandbox@1234567:ref:refs/heads/main'));
        // all subjects are bound to the repository
        for (const subject of subjects) {
          assert.match(subject, /^repo:octocat(@583231)?\/sandbox(@1234567)?:/);
        }
      });
    }
  });

  it('adds repo:…:ref:… for branch refs', () => {
    const identity = makeIdentity({ref: 'refs/heads/main'});
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    assert.ok(subjects.includes(`repo:${identity.repository}:ref:${identity.ref}`));
  });

  it('adds repo:…:ref:… for tag refs', () => {
    const identity = makeIdentity({ref: 'refs/tags/v1.0.0'});
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    assert.ok(subjects.includes(`repo:${identity.repository}:ref:${identity.ref}`));
  });

  it('adds repo:…:workflow_ref:… for branch-based workflow refs', () => {
    const identity = makeIdentity();
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    assert.ok(subjects.includes(
        `repo:${identity.repository}:workflow_ref:${identity.workflow_ref}`));
  });

  it('adds repo:…:job_workflow_ref:… for branch-based job workflow refs', () => {
    const identity = makeIdentity();
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    assert.ok(subjects.includes(
        `repo:${identity.repository}:job_workflow_ref:${identity.job_workflow_ref}`));
  });

  it('returns deduplicated subjects when workflow_ref and job_workflow_ref are equal', () => {
    // The fixture helper sets workflow_ref === job_workflow_ref, so we get 4 unique subjects
    // (sub, ref, workflow_ref, job_workflow_ref) — but workflow_ref and job_workflow_ref being
    // identical produces a duplicate that should be removed
    const identity = makeIdentity({
      workflow_ref: 'octocat/sandbox/.github/workflows/build.yml@refs/heads/main',
      job_workflow_ref: 'octocat/sandbox/.github/workflows/build.yml@refs/heads/main',
    });
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    const uniqueSubjects = new Set(subjects);
    assert.equal(subjects.length, uniqueSubjects.size);
  });
});
