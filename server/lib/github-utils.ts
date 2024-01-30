import type {GitHubAppPermission, GitHubAppPermissions, GitHubRepository} from './types.js'
import {objectOfTuples, tuplesOf} from './common-utils.js'

/**
 * Parse repository string to owner and repo
 * @param repository - repository string e.g. 'spongebob/sandbox'
 * @return object with owner and repo
 */
export function parseRepository(repository: string) {
  const [owner, repo] = repository.split('/')
  if (!owner || !repo) throw Error(`Invalid repository format '${repository}'`)
  return {owner, repo} as GitHubRepository
}

/**
 * Parse subject to claims
 * @param subject - subject string e.g. 'repo:spongebob/sandbox:ref:refs/heads/main'
 * @return object with claims
 */
export function parseSubject(subject: string): Record<string, string | undefined> {
  const claims = tuplesOf(subject.split(':'))
  return objectOfTuples(claims)
}

/**
 * Aggregated permission sets to a most permissive permission set
 * @param permissionSets - permission sets
 * @return aggregated permissions
 */
export function aggregatePermissions(permissionSets: GitHubAppPermissions[]) {
  return permissionSets.reduce((result, permissions) => {
    Object.entries(permissions).forEach(([scope, permission]) => {
      const _scope = scope as keyof GitHubAppPermissions
      if (!result[_scope] || verifyPermission({
        granted: permission,
        requested: result[_scope],
      })) {
        (result[_scope] satisfies string | undefined) = permission
      }
    })
    return result
  }, <GitHubAppPermissions>{})
}

/**
 * Verify permission is granted (admin > write > read)
 * @param granted - granted permission
 * @param requested - requested permission
 * @returns true if permission was granted
 */
export function verifyPermission({requested, granted}: {
  requested?: GitHubAppPermission,
  granted?: GitHubAppPermission,
}): boolean {
  if (!granted) return false
  if (!requested) return false

  const PERMISSION_RANKING: string[] = ['read', 'write', 'admin'] satisfies GitHubAppPermission[]

  const grantedRank = PERMISSION_RANKING.indexOf(granted)
  const requestedRank = PERMISSION_RANKING.indexOf(requested)

  if (grantedRank < 0) return false
  if (requestedRank < 0) return false

  return requestedRank <= grantedRank
}

export const GitHubAppPermissionScopes = {
  repository: [
    'administration',
    'actions',
    'actions_variables',
    'checks',
    'codespaces',
    'codespaces_lifecycle_admin',
    'codespaces_metadata',
    'codespaces_secrets',
    'contents',
    'custom_properties',
    'dependabot_secrets',
    'deployments',
    'discussions',
    'environments',
    'issues',
    'merge_queues',
    'metadata',
    'packages',
    'pages',
    'projects',
    'pull_requests',
    'repository_advisories',
    'repository_hooks',
    'repository_projects',
    'secret_scanning_alerts',
    'secrets',
    'security_events',
    'statuses',
    'team_discussions',
    'vulnerability_alerts',
    'workflows',
  ],
}
