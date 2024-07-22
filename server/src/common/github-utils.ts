import {components} from '@octokit/openapi-types';
import {z} from 'zod';
import {mapObjectEntries, tuplesOf} from './common-utils.js';
import {zStringRegex} from './zod-utils.js';

// --- Functions -------------------------------------------------------------------------------------------------------

/**
 * Parse repository string to owner and repo
 * @param repository - repository string e.g. 'spongebob/sandbox'
 * @return object with owner and repo
 */
export function parseRepository(repository: string) {
  const separatorIndex = repository.indexOf('/');
  if (separatorIndex === -1) throw Error(`Invalid repository format '${repository}'`);
  return {
    owner: repository.substring(0, separatorIndex),
    repo: repository.substring(separatorIndex + 1),
  };
}

/**
 * Parse subject to claims
 * @param subject - subject string e.g. 'repo:spongebob/sandbox:ref:refs/heads/main'
 * @return object with claims
 */
export function parseOIDCSubject(subject: string): Record<string, string | undefined> {
  const claims = tuplesOf(subject.split(':'));
  return Object.fromEntries(claims);
}

/**
 * Aggregated permission sets to a most permissive permission set
 * @param permissionSets - permission sets
 * @return aggregated permissions
 */
export function aggregatePermissions(permissionSets: Record<string, string>[]) {
  return permissionSets.reduce((result, permissions) => {
    Object.entries(permissions).forEach(([scope, permission]) => {
      const _scope = scope;
      if (!result[_scope] || verifyPermission({
        granted: permission,
        requested: result[_scope],
      })) {
        (result[_scope] satisfies string | undefined) = permission;
      }
    });
    return result;
  }, {});
}

/**
 * Verify permission is granted (admin > write > read)
 * @param granted - granted permission
 * @param requested - requested permission
 * @return true if permission was granted
 */
export function verifyPermission({requested, granted}: {
  requested?: string,
  granted?: string,
}): boolean {
  const PERMISSION_RANKING: string[] = ['read', 'write', 'admin'];

  if (!granted) return false;
  const grantedRank = PERMISSION_RANKING.indexOf(granted);
  if (grantedRank < 0) return false;

  if (!requested) return false;
  const requestedRank = PERMISSION_RANKING.indexOf(requested);
  if (requestedRank < 0) return false;

  return requestedRank <= grantedRank;
}

/**
 * Verify permissions
 * @see verifyPermission
 * @param requested - requested permissions
 * @param granted - granted permissions
 * @return granted and denied permissions
 */
export function verifyPermissions({requested, granted}: {
  requested: GitHubAppPermissions,
  granted: GitHubAppPermissions,
}): {
  granted: { scope: string, permission: 'read' | 'write' | 'admin' }[],
  denied: { scope: string, permission: 'read' | 'write' | 'admin' }[],
} {
  const result = {
    granted: [] as { scope: string, permission: 'read' | 'write' | 'admin' }[],
    denied: [] as { scope: string, permission: 'read' | 'write' | 'admin' }[],
  };
  Object.entries(requested).forEach(([scope, _requestedPermission]) => {
    const requestedPermission = {scope, permission: _requestedPermission};
    if (verifyPermission({
      granted: granted[scope as keyof GitHubAppPermissions],
      requested: requestedPermission.permission,
    })) {
      result.granted.push(requestedPermission);
    } else {
      result.denied.push(requestedPermission);
    }
  });

  return result;
}

/**
 * Verify repository permissions
 * @param permissions - permissions
 * @return invalid repository permissions
 */
export function verifyRepositoryPermissions(permissions: GitHubAppRepositoryPermissions) {
  const valid: GitHubAppRepositoryPermissions = {};
  const invalid: GitHubAppPermissions = {};

  Object.entries(permissions).forEach(([scope, permission]) => {
    if (GitHubAppRepositoryPermissionsSchema.keyof()
        .safeParse(scope).success) {
      (valid as Record<string, string>)[scope] = permission;
    } else {
      (invalid as Record<string, string>)[scope] = permission;
    }
  });
  return {valid, invalid};
}

/**
 * Normalise permission scopes to dash case
 * @param permissions - permission object
 * @return normalised permission object
 */
export function normalizePermissionScopes(permissions: components['schemas']['app-permissions']): GitHubAppPermissions {
  return mapObjectEntries(permissions, ([scope, permission]) => [
    scope.replaceAll('_', '-'), permission,
  ]) as GitHubAppPermissions;
}

/**
 * Get workflow run url from OIDC token payload
 * @param token - OIDC token payload
 * @return workflow run url
 */
export function buildWorkflowRunUrl(token: GitHubActionsJwtPayload) {
  // workflowRunUrl example: https://github.com/qoomon/actions--access-token/actions/runs/9192965843/attempts/2
  return `https://github.com/${token.repository}/actions/runs/${token.run_id}` +
      `${token.attempts ? `/attempts/${token.attempts}` : ''}`;
}

// --- Schemas ---------------------------------------------------------------------------------------------------------

const GitHubRepositoryOwnerRegex = /^[a-z\d](-?[a-z\d])+$/i;
export const GitHubRepositoryOwnerSchema = zStringRegex(GitHubRepositoryOwnerRegex);
const GitHubRepositoryNameRegex = /^[a-z\d-._]+$/i;
export const GitHubRepositoryNameSchema = zStringRegex(GitHubRepositoryNameRegex);

export const GitHubRepositorySchema = zStringRegex(
    new RegExp(`^${GitHubRepositoryOwnerRegex.source.replace(/^\^|\$$/g, '')}` +
        `/${GitHubRepositoryNameRegex.source.replace(/^\^|\$$/g, '')}$`, 'i'),
);

export const GitHubAppPermissionsSchema = z.strictObject({
  // ---- Repository Permissions ----
  'actions': z.enum(['read', 'write']),
  'actions-variables': z.enum(['read', 'write']),
  'administration': z.enum(['read', 'write']),
  'checks': z.enum(['read', 'write']),
  'codespaces': z.enum(['read', 'write']),
  'codespaces-lifecycle-admin': z.enum(['read', 'write']),
  'codespaces-metadata': z.enum(['read', 'write']),
  'codespaces-secrets': z.enum(['write']),
  'contents': z.enum(['read', 'write']),
  'custom-properties': z.enum(['read', 'write']),
  'dependabot-secrets': z.enum(['read', 'write']),
  'deployments': z.enum(['read', 'write']),
  'discussions': z.enum(['read', 'write']),
  'environments': z.enum(['read', 'write']),
  'issues': z.enum(['read', 'write']),
  'merge-queues': z.enum(['read', 'write']),
  'metadata': z.enum(['read', 'write']),
  'packages': z.enum(['read', 'write']),
  'pages': z.enum(['read', 'write']),
  'projects': z.enum(['read', 'write', 'admin']),
  'pull-requests': z.enum(['read', 'write']),
  'repository-advisories': z.enum(['read', 'write']),
  'repository-hooks': z.enum(['read', 'write']),
  'repository-projects': z.enum(['read', 'write', 'admin']),
  'secret-scanning-alerts': z.enum(['read', 'write']),
  'secrets': z.enum(['read', 'write']),
  'security-events': z.enum(['read', 'write']),
  'single-file': z.enum(['read', 'write']),
  'statuses': z.enum(['read', 'write']),
  'team-discussions': z.enum(['read', 'write']),
  'vulnerability-alerts': z.enum(['read', 'write']),
  'workflows': z.enum(['write']),
  // ---- Organization Permissions ----
  'members': z.enum(['read', 'write']),
  'organization-actions-variables': z.enum(['read', 'write']),
  'organization-administration': z.enum(['read', 'write']),
  'organization-announcement-banners': z.enum(['read', 'write']),
  'organization-codespaces': z.enum(['read', 'write']),
  'organization-codespaces-secrets': z.enum(['read', 'write']),
  'organization-codespaces-settings': z.enum(['read', 'write']),
  'organization-copilot-seat-management': z.enum(['read', 'write']),
  'organization-custom-org-roles': z.enum(['read', 'write']),
  'organization-custom-properties': z.enum(['read', 'write', 'admin']),
  'organization-custom-roles': z.enum(['read', 'write']),
  'organization-dependabot-secrets': z.enum(['read', 'write']),
  'organization-events': z.enum(['read']),
  'organization-hooks': z.enum(['read', 'write']),
  'organization-personal-access-token-requests': z.enum(['read', 'write']),
  'organization-personal-access-tokens': z.enum(['read', 'write']),
  'organization-plan': z.enum(['read']),
  'organization-projects': z.enum(['read', 'write', 'admin']),
  'organization-secrets': z.enum(['read', 'write']),
  'organization-self-hosted-runners': z.enum(['read', 'write']),
  'organization-user-blocking': z.enum(['read', 'write']),
}).partial();
export type GitHubAppPermissions = z.infer<typeof GitHubAppPermissionsSchema>;

/**
 * === BE AWARE ===
 * - 'administration' scope can not be completely limited to a repository e.g. create new repositories is still possible
 * - repository scopes do not start with 'organization-'
 * - 'member' scope is an organization scope
 */
export const GitHubAppRepositoryPermissionsSchema = GitHubAppPermissionsSchema.pick({
  'actions': true,
  'actions-variables': true,
  'administration': true,
  'checks': true,
  'codespaces': true,
  'codespaces-lifecycle-admin': true,
  'codespaces-metadata': true,
  'codespaces-secrets': true,
  'contents': true,
  'custom-properties': true,
  'dependabot-secrets': true,
  'deployments': true,
  'discussions': true,
  'environments': true,
  'issues': true,
  'merge-queues': true,
  'metadata': true,
  'packages': true,
  'pages': true,
  'projects': true,
  'pull-requests': true,
  'repository-advisories': true,
  'repository-hooks': true,
  'repository-projects': true,
  'secret-scanning-alerts': true,
  'secrets': true,
  'security-events': true,
  'single-file': true,
  'statuses': true,
  'team-discussions': true,
  'vulnerability-alerts': true,
  'workflows': true,
});
export type GitHubAppRepositoryPermissions = z.infer<typeof GitHubAppRepositoryPermissionsSchema>;

// --- Types -----------------------------------------------------------------------------------------------------------

export type GitHubActionsJwtPayload = {
  aud: string, // e.g. "actions.github.com",
  iss: string, // e.g. "https://token.actions.githubusercontent.com",
  sub: string, // e.g. "repo:qoomon/sandbox:ref:refs/heads/aws-github-access-manager",

  exp: string, // e.g. "1629780000",
  iat: string,
  jti: string, // e.g. "MjAyMS0wOC0xMlQxNTo0NDo0MC4wNzQyNzI0NjNa",
  nbf: string, // e.g. "1629776400",

  event_name: string, // e.g. "push",

  actor: string, // e.g. "qoomon",
  actor_id: string, // e.g. "3963394",

  base_ref: string, // e.g. "",
  head_ref: string, // e.g. "",
  sha: string, // e.g. "a61bd32ec51ea98212227f4bff728667f0ae340e",
  ref: string, // e.g. "refs/heads/aws-github-access-manager",
  ref_type: string, // e.g. "branch",
  ref_protected: string, // e.g. "false",

  repository_visibility: string, // e.g. "private",
  repository: string, // e.g. "qoomon/sandbox",
  repository_id: string, // e.g. "35282741",
  repository_owner: string, // e.g. "qoomon",
  repository_owner_id: string, // e.g. "3963394",

  environment: string, // e.g. "production",

  workflow: string, // e.g. "GitHub Actions Access Manager Example",
  workflow_ref: string, // e.g. "qoomon/sandbox/.github/workflows/github_actions_access_manager.example.yml@refs/heads/aws-github-access-manager",
  workflow_sha: string, // e.g. "a61bd32ec51ea98212227f4bff728667f0ae340e",

  job_workflow_ref: string, // e.g. "qoomon/sandbox/.github/workflows/github_actions_access_manager.example.yml@refs/heads/aws-github-access-manager",
  job_workflow_sha: string, // e.g. "a61bd32ec51ea98212227f4bff728667f0ae340e",

  run_id: string, // e.g. "6370333187",
  run_number: string, // e.g. "107",
  run_attempt: string, // e.g. "4",
  runner_environment: string, // e.g. "github-hosted",
} & Record<string, string>;
