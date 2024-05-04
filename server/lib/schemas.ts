import {z} from 'zod'

export const GitHubRepositorySchema = zStringRegex(/^[a-z\d](-?[a-z\d])+\/[a-z\d-._]+$/i).trim().min(3)
export const GitHubOwnerSchema = zStringRegex(/^[a-z\d](-?[a-z\d])+$/i).trim().min(1)
export const GitHubRepositoryNameSchema = zStringRegex(/^[a-z\d-._]+$/i).trim().min(1)

export const GitHubAppPermissionSchema = z.enum(['read', 'write', 'admin'])
type GitHubAppPermission = z.infer<typeof GitHubAppPermissionSchema>
type GitHubPermissions = NonEmptyArray<GitHubAppPermission>

export const GitHubAppPermissionsSchema = z.strictObject({
  // ---- Repository Permissions ----
  'administration': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'actions': z.enum(['read', 'write'] satisfies GitHubPermissions),
  'actions-variables': z.enum(['read', 'write'] satisfies GitHubPermissions),
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

// ---------------------------------------------------------------------------------------------------------------------

// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
export const GitHubSubjectClaimSchema = z.string().trim()

export const GitHubAccessStatementSchema = z.strictObject({
  subjects: z.array(GitHubSubjectClaimSchema),
  permissions: GitHubAppPermissionsSchema,
})

export const GitHubAccessPolicySchema = z.strictObject({
  origin: GitHubRepositorySchema,
  statements: z.array(GitHubAccessStatementSchema),
})

export const AccessTokenRequestBodySchema = z.strictObject({
  owner: GitHubOwnerSchema.optional(),
  scope: z.enum(['repos', 'owner']).default('repos'),
  permissions: GitHubAppPermissionsSchema,
  repositories: z.array(GitHubRepositoryNameSchema).optional().default([]),
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

