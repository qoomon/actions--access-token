import {describe, expect, it} from '@jest/globals';
import {getEffectiveCallerIdentitySubjects} from '../src/access-token-manager.js';
import {GitHubActionsJwtPayload} from '../src/common/github-utils.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIdentity(overrides: Partial<GitHubActionsJwtPayload> = {}): GitHubActionsJwtPayload {
  const repository = overrides.repository ?? 'octocat/sandbox';
  const ref = overrides.ref ?? 'refs/heads/main';
  const workflowFile = 'octocat/sandbox/.github/workflows/build.yml';
  return {
    sub: `repo:${repository}:ref:${ref}`,
    repository,
    repository_owner: repository.split('/')[0],
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
    expect(subjects).toContain(identity.sub);
  });

  it('adds repo:…:ref:… for branch refs', () => {
    const identity = makeIdentity({ref: 'refs/heads/main'});
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    expect(subjects).toContain(`repo:${identity.repository}:ref:${identity.ref}`);
  });

  it('adds repo:…:ref:… for tag refs', () => {
    const identity = makeIdentity({ref: 'refs/tags/v1.0.0'});
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    expect(subjects).toContain(`repo:${identity.repository}:ref:${identity.ref}`);
  });

  it('does NOT add repo:…:ref:… for pull-request refs', () => {
    // For PR events, the real OIDC sub claim is something like
    // "repo:octocat/sandbox:pull_request", NOT "repo:…:ref:refs/pull/…".
    // The function should not add the artificial ref subject for PR refs.
    const identity = makeIdentity({
      ref: 'refs/pull/42/head',
      sub: 'repo:octocat/sandbox:pull_request',
    });
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    expect(subjects).not.toContain(`repo:${identity.repository}:ref:${identity.ref}`);
  });

  it('adds repo:…:workflow_ref:… for branch-based workflow refs', () => {
    const identity = makeIdentity();
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    expect(subjects).toContain(
        `repo:${identity.repository}:workflow_ref:${identity.workflow_ref}`);
  });

  it('does NOT add workflow_ref subject for pull-request workflow refs', () => {
    const ref = 'refs/pull/42/head';
    const workflowRef = `octocat/sandbox/.github/workflows/build.yml@${ref}`;
    const identity = makeIdentity({ref, workflow_ref: workflowRef, job_workflow_ref: workflowRef});
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    expect(subjects).not.toContain(`repo:${identity.repository}:workflow_ref:${workflowRef}`);
    expect(subjects).not.toContain(`repo:${identity.repository}:job_workflow_ref:${workflowRef}`);
  });

  it('adds repo:…:job_workflow_ref:… for branch-based job workflow refs', () => {
    const identity = makeIdentity();
    const subjects = getEffectiveCallerIdentitySubjects(identity);
    expect(subjects).toContain(
        `repo:${identity.repository}:job_workflow_ref:${identity.job_workflow_ref}`);
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
    expect(subjects.length).toBe(uniqueSubjects.size);
  });
});
