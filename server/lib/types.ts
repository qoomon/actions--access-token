import {z} from 'zod'
import {
  AccessTokenRequestBodySchema,
  GitHubAccessStatementSchema,
  GitHubAppPermissionSchema,
  GitHubAppPermissionsSchema,
  GitHubAppRepositoryPermissionsSchema,
  GitHubOwnerAccessPolicySchema,
  GitHubRepositoryAccessPolicySchema,
} from './schemas.js'
import type {
  RestEndpointMethodTypes,
} from '@octokit/plugin-rest-endpoint-methods/dist-types/generated/parameters-and-response-types'

export type Subset<T extends _U, _U> = T
export type ConditionalUndefined<T, C > = C extends undefined ? T | undefined : T

// ---------------------------------------------------------------------------------------------------------------------

export type GitHubAppInstallation = RestEndpointMethodTypes['apps']['getUserInstallation']['response']['data']
// eslint-disable-next-line max-len
export type GitHubAppInstallationAccessToken = RestEndpointMethodTypes['apps']['createInstallationAccessToken']['response']['data']

export type GitHubRepository = {
  owner: string,
  repo: string,
}

export type GitHubAccessStatement = z.infer<typeof GitHubAccessStatementSchema>
export type GitHubOwnerAccessPolicy = z.infer<typeof GitHubOwnerAccessPolicySchema>
export type GitHubRepositoryAccessPolicy = z.infer<typeof GitHubRepositoryAccessPolicySchema>
export type GitHubAppPermission = z.infer<typeof GitHubAppPermissionSchema>
export type GitHubAppPermissions = z.infer<typeof GitHubAppPermissionsSchema>
export type GitHubAppRepositoryPermissions = z.infer<typeof GitHubAppRepositoryPermissionsSchema>
export type AccessTokenRequestBody = z.infer<typeof AccessTokenRequestBodySchema>

// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
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
} & Record<string, string>

/**
 * Access Policy Error
 */
export class PolicyError extends Error {
  public issues?: string[]

  /**
   * @param message - error message
   * @param issues - list of issues
   */
  constructor(message: string, issues?: string[]) {
    super(message)
    this.issues = issues
  }
}
