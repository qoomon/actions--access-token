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
 * Verify if requested permissions are granted
 * @param requested permissions
 * @param granted permissions
 * @return denied permissions or null if all permissions are granted
 */
export function verifyPermissions({requested, granted}: {
  requested: GitHubAppPermissions,
  granted: GitHubAppPermissions,
}): GitHubAppPermissions | null {
  const deniedPermissions = <GitHubAppPermissions>{}
  for (const [requestedScope, requestedPermission] of Object.entries(requested)) {
    const _granted = granted as { [index: string]: GitHubAppPermission }
    if (comparePermission(requestedPermission, _granted[requestedScope]) < 0) {
      const _deniedPermissions = deniedPermissions as { [index: string]: GitHubAppPermission }
      _deniedPermissions[requestedScope] = requestedPermission
    }
  }

  return Object.keys(deniedPermissions).length > 0 ? deniedPermissions :
      null
}

/**
 * Aggregate permission sets, the most permissive permission is applied
 * @param permissionSets - permission sets
 * @return aggregated permissions
 */
export function aggregatePermissions(permissionSets: GitHubAppPermissions[]) {
  const resultingPermissions = <GitHubAppPermissions>{}
  for (const permissions of permissionSets) {
    // eslint-disable-next-line max-len
    for (const [scope, permission] of Object.entries(permissions) as [keyof GitHubAppPermissions, GitHubAppPermission][]) {
      if (comparePermission(resultingPermissions[scope], permission) > 0) {
        (resultingPermissions[scope] as string) = permission
      }
    }
  }
  return resultingPermissions
}

/**
 * Compare permissions by rank (admin > write > read)
 * @param left - 1st permission
 * @param right - 2nd permission
 * @returns comparison result
 * - if left is more permissive: -1
 * - if right is more permissive: +1
 * - else 0
 */
export function comparePermission(
    left: GitHubAppPermission | undefined,
    right: GitHubAppPermission | undefined,
): 1 | 0 | -1 {
  const PERMISSION_RANKING: (GitHubAppPermission | undefined)[] = [undefined, 'read', 'write', 'admin']

  if (!left && !right) throw Error('Can not compare two undefined permissions')

  const leftRank = PERMISSION_RANKING.indexOf(left)
  if (leftRank < 0) throw Error(`Invalid permission '${left}'`)

  const rightRank = PERMISSION_RANKING.indexOf(right)
  if (rightRank < 0) throw Error(`Invalid permission '${right}'`)

  if (leftRank > rightRank) return -1
  if (leftRank < rightRank) return +1

  return 0
}
