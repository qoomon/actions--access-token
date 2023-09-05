import {z} from 'zod'
import YAML from 'yaml'
import {mapObject} from './common-utils.js'

export const GitHubRepositorySchema = zStringRegex(/^[a-z\d](-?[a-z\d])+\/[a-z\d-._]+$/i).trim()
export const GitHubOrganizationSchema = zStringRegex(/^[a-z\d](-?[a-z\d])+$/i).trim()

export const GitHubAppPermissionSchema = z.enum(['read', 'write', 'admin'])
type GitHubAppPermission = z.infer<typeof GitHubAppPermissionSchema>
type _GitHubAppPermission = [GitHubAppPermission, ...GitHubAppPermission[]]
export const GitHubAppRepositoryPermissionsSchema = z.object({
  administration: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  actions: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  actions_variables: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  checks: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  codespaces: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  codespaces_lifecycle_admin: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  codespaces_metadata: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  codespaces_secrets: z.enum(['write'] satisfies _GitHubAppPermission),
  contents: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  custom_properties: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  dependabot_secrets: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  deployments: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  discussions: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  environments: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  issues: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  merge_queues: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  metadata: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  packages: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  pages: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  projects: z.enum(['read', 'write', 'admin'] satisfies _GitHubAppPermission),
  pull_requests: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  repository_advisories: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  repository_hooks: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  repository_projects: z.enum(['read', 'write', 'admin'] satisfies _GitHubAppPermission),
  secret_scanning_alerts: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  secrets: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  security_events: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  single_file: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  statuses: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  team_discussions: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  vulnerability_alerts: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  workflows: z.enum(['write'] satisfies _GitHubAppPermission),
}).strict().partial()
export const GitHubAppOrganizationPermissionsSchema = z.object({
  members: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_actions_variables: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_administration: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_announcement_banners: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_codespaces: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_codespaces_secrets: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_codespaces_settings: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_copilot_seat_management: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_custom_org_roles: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_custom_properties: z.enum(['read', 'write', 'admin'] satisfies _GitHubAppPermission),
  organization_custom_roles: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_dependabot_secrets: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_events: z.enum(['read'] satisfies _GitHubAppPermission),
  organization_hooks: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_personal_access_token_requests: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_personal_access_tokens: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_plan: z.enum(['read'] satisfies _GitHubAppPermission),
  organization_projects: z.enum(['read', 'write', 'admin'] satisfies _GitHubAppPermission),
  organization_secrets: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_self_hosted_runners: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
  organization_user_blocking: z.enum(['read', 'write'] satisfies _GitHubAppPermission),
}).strict().partial()
export const GitHubAppPermissionsSchema = z.strictObject({})
    .merge(GitHubAppRepositoryPermissionsSchema)
    .merge(GitHubAppOrganizationPermissionsSchema)
    .strict()

// ---------------------------------------------------------------------------------------------------------------------

// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
export const GitHubSubjectClaimSchema = z.string().trim()

export const GitHubRepoAccessStatementSchema = z.strictObject({
  subjects: z.array(GitHubSubjectClaimSchema),
  permissions: GitHubAppPermissionsSchema,
})

export const GitHubRepoAccessPolicySchema = z.strictObject({
  origin: GitHubRepositorySchema,
  statements: z.array(GitHubRepoAccessStatementSchema),
})

export const GitHubOrgAccessStatementSchema = z.strictObject({
  subjects: z.array(GitHubSubjectClaimSchema),
  permissions: GitHubAppPermissionsSchema,
})

export const GitHubOrgAccessPolicySchema = z.strictObject({
  origin: GitHubRepositorySchema,
  statements: z.array(GitHubOrgAccessStatementSchema),
})

export const AccessTokenRequestBodySchema = z.strictObject({
  organization: GitHubOrganizationSchema.optional(),
  repositories: z.array(GitHubRepositorySchema).optional().default([]),
  permissions: z.record(z.any()).transform((obj) => {
    return mapObject(obj, ([key, value]) => [key.replaceAll('-', '_'), value])
  }).pipe(GitHubAppPermissionsSchema),
})

// ---------------------------------------------------------------------------------------------------------------------

export const JsonTransformer = z.string().transform((str, ctx) => {
  try {
    return JSON.parse(str)
  } catch (error: unknown) {
    ctx.addIssue({code: 'custom', message: (error as { message?: string }).message})
    return z.NEVER
  }
})

export const YamlTransformer = z.string().transform((str, ctx) => {
  try {
    return YAML.parse(str)
  } catch (error: unknown) {
    ctx.addIssue({code: 'custom', message: (error as { message?: string }).message})
    return z.NEVER
  }
})

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

