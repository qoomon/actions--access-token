import type {
  ConditionalUndefined,
  GitHubAppPermission,
  GitHubAppPermissions,
  GitHubAppRepositoryPermissions,
  GitHubRepository,
} from '../types'
import {mapObjectEntries, objectOfTuples, tuplesOf} from './common-utils.js'
import {GitHubAppRepositoryPermissionsSchema} from '../schemas'
import {components} from '@octokit/openapi-types';

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
export function aggregatePermissions(permissionSets: Record<string, string>[]) {
  return permissionSets.reduce((result, permissions) => {
    Object.entries(permissions).forEach(([scope, permission]) => {
      const _scope = scope
      if (!result[_scope] || verifyPermission({
        granted: permission,
        requested: result[_scope],
      })) {
        (result[_scope] satisfies string | undefined) = permission
      }
    })
    return result
  }, {})
}

/**
 * Verify permission is granted (admin > write > read)
 * @param granted - granted permission
 * @param requested - requested permission
 * @returns true if permission was granted
 */
export function verifyPermission({requested, granted}: {
  requested?: string,
  granted?: string,
}): boolean {
  const PERMISSION_RANKING: string[] = ['read', 'write', 'admin'] satisfies GitHubAppPermission[]

  if (!granted) return false
  const grantedRank = PERMISSION_RANKING.indexOf(granted)
  if (grantedRank < 0) return false

  if (!requested) return false
  const requestedRank = PERMISSION_RANKING.indexOf(requested)
  if (requestedRank < 0) return false

  return requestedRank <= grantedRank
}

/**
 * Verify permissions
 * @see verifyPermission
 * @param requested - requested permissions
 * @param granted - granted permissions
 * @returns granted and denied permissions
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
  }
  Object.entries(requested).forEach(([scope, _requestedPermission]) => {
    const requestedPermission = {scope, permission: _requestedPermission}
    if (verifyPermission({
      granted: granted[scope as keyof GitHubAppPermissions],
      requested: requestedPermission.permission,
    })) {
      result.granted.push(requestedPermission)
    } else {
      result.denied.push(requestedPermission)
    }
  })

  return result
}

/**
 * Verify repository permissions
 * @param permissions - permissions
 * @returns invalid repository permissions
 */
export function verifyRepositoryPermissions(permissions: GitHubAppRepositoryPermissions) {
  const valid: GitHubAppRepositoryPermissions = {}
  const invalid: GitHubAppPermissions = {}

  Object.entries(permissions).forEach(([scope, permission]) => {
    if (GitHubAppRepositoryPermissionsSchema.keyof()
        .safeParse(scope).success) {
      (valid as Record<string, string>)[scope] = permission
    } else {
      (invalid as Record<string, string>)[scope] = permission
    }
  })
  return {valid, invalid}
}

/**
 * Normalise permission scopes to dash case
 * @param permissions - permission object
 * @returns normalised permission object
 */
export function normalizePermissionScopes<
    PERMISSIONS extends components['schemas']['app-permissions']
>(permissions?: PERMISSIONS): ConditionalUndefined<GitHubAppPermissions, PERMISSIONS> {
  if (!permissions) return undefined as ConditionalUndefined<GitHubAppPermissions, PERMISSIONS>

  return mapObjectEntries(permissions, ([scope, permission]) => [
    scope.replaceAll('_', '-'), permission,
  ]) as GitHubAppPermissions
}
