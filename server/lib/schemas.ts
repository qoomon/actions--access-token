import {z} from 'zod'

export const GitHubRepositorySchema = zStringRegex(/^[a-z\d](-?[a-z\d])+\/[a-z\d-._]+$/i).trim().min(3)
export const GitHubOwnerSchema = zStringRegex(/^[a-z\d](-?[a-z\d])+$/i).trim().min(1)
export const GitHubRepositoryNameSchema = zStringRegex(/^[a-z\d-._]+$/i).trim().min(1)

export const GitHubAppPermissionSchema = z.enum(['read', 'write', 'admin'])
type GitHubAppPermission = z.infer<typeof GitHubAppPermissionSchema>
type GitHubPermissions = NonEmptyArray<GitHubAppPermission>

export const GitHubAppPermissionsSchema = z.strictObject({
  // ---- Repository Permissions ----
  'actions': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'actions-variables': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'administration': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'checks': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'codespaces': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'codespaces-lifecycle-admin': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'codespaces-metadata': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'codespaces-secrets': z.enum(['write'] satisfies GitHubPermissions),
  'contents': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'custom-properties': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'dependabot-secrets': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'deployments': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'discussions': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'environments': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'issues': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'merge-queues': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'metadata': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'packages': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'pages': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'projects': z.enum(['read', 'write', 'admin'] satisfies GitHubPermissions),
  'pull-requests': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'repository-advisories': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'repository-hooks': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'repository-projects': z.enum(['read', 'write', 'admin'] satisfies GitHubPermissions),
  'secret-scanning-alerts': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'secrets': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'security-events': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'single-file': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'statuses': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'team-discussions': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'vulnerability-alerts': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'workflows': z.enum(['write'] satisfies GitHubPermissions),
  // ---- Organization Permissions ----
  'members': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-actions-variables': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-administration': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-announcement-banners': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-codespaces': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-codespaces-secrets': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-codespaces-settings': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-copilot-seat-management': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-custom-org-roles': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-custom-properties': z.enum(['read', 'write', 'admin'] satisfies GitHubPermissions),
  'organization-custom-roles': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-dependabot-secrets': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-events': z.enum(['read'] satisfies GitHubPermissions),
  'organization-hooks': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-personal-access-token-requests': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-personal-access-tokens': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-plan': z.enum(['read'] satisfies GitHubPermissions),
  'organization-projects': z.enum(['read', 'write', 'admin'] satisfies GitHubPermissions),
  'organization-secrets': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-self-hosted-runners': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'organization-user-blocking': z.enum(['read', 'write'] satisfies GitHubPermissions),
}).partial()

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
})

// ---------------------------------------------------------------------------------------------------------------------

// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
export const GitHubSubjectClaimSchema = z.string().trim()


const GitHubBaseStatementSchema = z.strictObject({
  subjects: z.array(GitHubSubjectClaimSchema),
})

export const GitHubAccessStatementSchema = GitHubBaseStatementSchema.merge(z.strictObject({
  permissions: GitHubAppPermissionsSchema,
}))

export const GitHubRepositoryAccessStatementSchema = GitHubBaseStatementSchema.merge(z.strictObject({
  permissions: GitHubAppRepositoryPermissionsSchema,
}))


export const GitHubBaseAccessPolicySchema = z.strictObject({
  origin: GitHubRepositorySchema,
})

export const GitHubOwnerAccessPolicySchema = GitHubBaseAccessPolicySchema
    .merge(z.strictObject({
      'statements': z.array(GitHubAccessStatementSchema).default([]),
      'allowed-subjects': z.array(GitHubSubjectClaimSchema).default([]),
      'allowed-repository-permissions': GitHubAppRepositoryPermissionsSchema.default({}),
    }))

export const GitHubRepositoryAccessPolicySchema = GitHubBaseAccessPolicySchema
    .merge(z.strictObject({
      'statements': z.array(GitHubRepositoryAccessStatementSchema).default([]),
    }))

export const AccessTokenRequestBodySchema = z.strictObject({
  owner: GitHubOwnerSchema.optional(),
  scope: z.enum(['repos', 'owner']).default('repos'),
  permissions: GitHubAppPermissionsSchema,
  repositories: z.array(GitHubRepositoryNameSchema).default([]),
})

// ---------------------------------------------------------------------------------------------------------------------


/**
 * Ensures non empty array
 */
type NonEmptyArray<T> = [T, ...T[]]

// ---------------------------------------------------------------------------------------------------------------------

/**
 * Shortcut for creating a zod string with regex validation
 * @param regex - regex
 * @returns zod string
 */
function zStringRegex(regex: RegExp) {
  // Invalid enum value. Expected 'read' | 'write', received 'invalid',
  return z.string().regex(regex, `Invalid format. Expected format ${regex}`)
}

