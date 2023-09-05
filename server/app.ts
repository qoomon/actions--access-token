import Koa, {HttpError} from 'koa'
import StatusCodes from 'http-status-codes'
import {createVerifier, TokenError} from 'fast-jwt'
import process from 'process'
import log from 'loglevel'
import {Octokit} from '@octokit/rest'
import {createAppAuth} from '@octokit/auth-app'
import {z, ZodTypeAny} from 'zod'
import {formatPEMKey} from './lib/ras-key-utils.js'
import type {
  GitHubActionsJwtPayload,
  GitHubAppInstallation,
  GitHubAppInstallationAccessToken,
  GitHubAppOrganizationPermissions,
  GitHubAppPermissions,
  GitHubAppRepositoryPermissions,
} from './lib/types.js'
import {
  AccessTokenRequestBodySchema,
  GitHubAppOrganizationPermissionsSchema,
  GitHubAppRepositoryPermissionsSchema,
  JsonTransformer,
} from './lib/schemas.js'
import {formatZodIssue} from './lib/zod-utils.js'
import {_throw, ensureHasEntries, formatArray, regexpOfWildcardPattern} from './lib/common-utils.js'
import {logLevelOf} from './lib/log-utils.js'
import {buildJwksKeyFetcher} from './lib/jwt-utils.js'
import getRawBody from 'raw-body'
import {parseRepository, verifyPermissions} from './lib/github-utils.js'

/**
 * This function will initialize the application
 * @returns application
 */
export async function appInit(): Promise<Koa> {
  // --- Configuration -------------------------------------------------------------------------------------------------
  log.setDefaultLevel(logLevelOf(process.env['LOG_LEVEL']) || 'info')

  const ALLOWED_TOKEN_PERMISSIONS = {
    // Repository permissions, these permissions CAN be restricted to specific repositories
    repository: <GitHubAppRepositoryPermissions>{
      // 'administration', // BE AWARE create repository CAN NOT be restricted to specific repositories
      actions: 'write',
      actions_variables: 'write',
      checks: 'write',
      codespaces: 'write',
      codespaces_lifecycle_admin: 'write',
      codespaces_metadata: 'write',
      codespaces_secrets: 'write',
      contents: 'write',
      custom_properties: 'write',
      dependabot_secrets: 'write',
      deployments: 'write',
      discussions: 'write',
      environments: 'write',
      issues: 'write',
      merge_queues: 'write',
      metadata: 'read',
      packages: 'write',
      pages: 'write',
      projects: 'admin',
      pull_requests: 'write',
      repository_advisories: 'write',
      repository_hooks: 'write',
      repository_projects: 'write',
      secret_scanning_alerts: 'write',
      secrets: 'write',
      security_events: 'write',
      // single_file: 'read', // only meant for GitHub app to read access policy files
      statuses: 'write',
      team_discussions: 'write',
      vulnerability_alerts: 'write',
      workflows: 'write',
    },
    // Organization permissions, these permissions CAN NOT be restricted to specific repositories
    organization: <GitHubAppOrganizationPermissions>{
      members: 'write',
      organization_actions_variables: 'write',
      organization_administration: 'write',
      organization_announcement_banners: 'write',
      organization_codespaces: 'write',
      organization_codespaces_secrets: 'write',
      organization_codespaces_settings: 'write',
      organization_copilot_seat_management: 'write',
      organization_custom_org_roles: 'write',
      organization_custom_properties: 'write',
      organization_custom_roles: 'write',
      organization_dependabot_secrets: 'write',
      organization_events: 'read',
      organization_hooks: 'write',
      organization_personal_access_token_requests: 'write',
      organization_personal_access_tokens: 'write',
      organization_plan: 'read',
      organization_projects: 'write',
      organization_secrets: 'write',
      organization_self_hosted_runners: 'write',
      organization_user_blocking: 'write',
    },
  }
  log.trace('Allowed token permissions:', ALLOWED_TOKEN_PERMISSIONS)

  const ACCESS_POLICY_FILE_LOCATIONS = {
    repository: {
      path: '.github/access-policy.yaml',
    },
    organization: {
      path: '.github/organization-access-policy.yaml',
      repository: '.github',
    },
  }
  log.trace('Access policy file locations:', ACCESS_POLICY_FILE_LOCATIONS)

  const GITHUB_APP_AUTH = {
    appId: process.env['GITHUB_APP_ID'] ??
        _throw(new Error('Environment variable GITHUB_APP_ID is required')),
    // depending on the environment multiple environment variables are not supported,
    // due to this limitation formatPEMKey ensure the right format
    privateKey: formatPEMKey(process.env['GITHUB_APP_PRIVATE_KEY'] ??
        _throw(new Error('Environment variable GITHUB_APP_ID is required'))),
  }
  log.trace('GitHub app id: ' + GITHUB_APP_AUTH.appId)

  const GITHUB_ACTIONS_TOKEN_VERIFIER_OPTIONS = {
    allowedAud: process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE'] ??
        _throw(new Error('Environment variable GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE is required')),
    allowedSub: process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS']
        ?.split(/\s*,\s*/)
        ?.map((subjectPattern) => regexpOfWildcardPattern(subjectPattern, 'i')),
  }
  log.trace('GitHub OIDC token verify options:', GITHUB_ACTIONS_TOKEN_VERIFIER_OPTIONS)

  // --- Initialization ------------------------------------------------------------------------------------------------

  const GITHUB_OIDC_TOKEN_VERIFIER = createVerifier({
    key: buildJwksKeyFetcher({providerDiscovery: true}),
    allowedIss: 'https://token.actions.githubusercontent.com',
    allowedAud: GITHUB_ACTIONS_TOKEN_VERIFIER_OPTIONS.allowedAud,
    allowedSub: GITHUB_ACTIONS_TOKEN_VERIFIER_OPTIONS.allowedSub,
  })

  const GITHUB_APP_CLIENT = new Octokit({authStrategy: createAppAuth, auth: GITHUB_APP_AUTH})
  const GITHUB_APP_INFOS = await GITHUB_APP_CLIENT.apps.getAuthenticated()
      .then((res) => res.data)
  log.trace('GitHub app infos:', GITHUB_APP_INFOS)

  // --- Server Setup --------------------------------------------------------------------------------------------------

  const app = new Koa()
  app.use(debugLogger())
  app.use(httpErrorHandler())

  app.use(async (ctx) => {
    if (ctx.path !== '/access_tokens') {
      throw ctx.throw(StatusCodes.FORBIDDEN)
    }
    if (ctx.method !== 'POST') {
      throw ctx.throw(StatusCodes.METHOD_NOT_ALLOWED)
    }

    const callerIdentity = await verifyAuthorizationToken(ctx, GITHUB_OIDC_TOKEN_VERIFIER) as GitHubActionsJwtPayload
    log.info('Caller Identity: ' + callerIdentity.workflow_ref, {callerIdentity})

    const tokenRequest = await parseBody(ctx, AccessTokenRequestBodySchema)
    log.info('Token Request:', {tokenRequest})

    if (Object.entries(tokenRequest.permissions).length === 0) {
      throw ctx.throw(StatusCodes.BAD_REQUEST, 'Token permissions must not be empty.')
    }

    if (tokenRequest.organization) {
      const permissionParseResult = GitHubAppOrganizationPermissionsSchema.safeParse(tokenRequest.permissions)
      if (!permissionParseResult.success) {
        throw ctx.throw(StatusCodes.BAD_REQUEST, 'Invalid organization permissions.\n' +
            permissionParseResult.error.issues.map(formatZodIssue).map((it) => '- ' + it).join('\n'))
      } else {
        const targetOwner = tokenRequest.organization
        const targetRepositories = tokenRequest.repositories
        if (targetRepositories.length > 0) {
          const targetRepositoriesOwner = _determineRepositoriesOwner(targetRepositories)
          if (targetRepositoriesOwner !== targetOwner) {
            throw ctx.throw(StatusCodes.BAD_REQUEST, 'Some repositories are not owned by the target organization.')
          }
        }

        const targetPermissions = permissionParseResult.data

        const targetInstallation = await _getAppInstallation({
          owner: targetOwner, ownerType: 'Organization', permissions: targetPermissions,
        })

        // TODO
        //
        // await ensureOrganizationAccessPermissionsAreGranted({
        //   installation: targetInstallation,
        //   target: {
        //     permissions: tokenRequest.permissions,
        //     organization: tokenRequest.organization,
        //     repositories: tokenRequest.repositories,
        //   },
        //   callerIdentity,
        // })
        //
        // --- create requested GitHub access token
        const targetInstallationAccessToken = await createInstallationAccessToken(
            GITHUB_APP_CLIENT, targetInstallation, {
              // BE AWARE that an empty object will result in a token with all app installation permissions
              permissions: ensureHasEntries(targetPermissions),
              // repository permissions can be limited to specific repositories
              repositories: targetRepositories,
            })

        ctx.body = JSON.stringify(targetInstallationAccessToken, null, 2)
      }
    } else {
      const permissionParseResult = GitHubAppRepositoryPermissionsSchema.safeParse(tokenRequest.permissions)
      if (!permissionParseResult.success) {
        throw ctx.throw(StatusCodes.BAD_REQUEST, 'Invalid repository permissions.\n' +
            permissionParseResult.error.issues.map(formatZodIssue).map((it) => '- ' + it).join('\n'))
      } else {
        const targetRepositories = tokenRequest.repositories.length > 0 ? tokenRequest.repositories :
            [callerIdentity.repository] // if no repositories are specified use the caller repository as default
        const targetOwner = _determineRepositoriesOwner(targetRepositories)
        const targetPermissions = permissionParseResult.data
        const targetInstallation = await _getAppInstallation({
          owner: targetOwner, permissions: targetPermissions,
        })

        // TODO
        //
        // await ensureRepositoryAccessPermissionsAreGranted({
        //   installation: targetInstallation,
        //   target: {
        //     permissions: tokenRequest.permissions,
        //     repositories: tokenRequest.repositories,
        //   },
        //   callerIdentity,
        // })
        //
        // --- create requested GitHub access token
        const targetInstallationAccessToken = await createInstallationAccessToken(
            GITHUB_APP_CLIENT, targetInstallation, {
              // BE AWARE that an empty object will result in a token with all app installation permissions
              permissions: ensureHasEntries(targetPermissions),
              // BE AWARE that an empty array will result in a token with access to all app installation repositories
              repositories: ensureHasEntries(targetRepositories),
            })

        ctx.body = {
          owner: targetOwner,
          permissions: targetInstallationAccessToken.permissions,
          repositories: targetInstallationAccessToken.repositories?.map((it) => it.full_name),
          token: targetInstallationAccessToken.token,
          expires_at: targetInstallationAccessToken.expires_at,

        }
      }
    }

    /**
     * This function will determine the repositories owner
     * @param repositories - repositories
     * @returns owner
     */
    function _determineRepositoriesOwner(repositories: string[]): string {
      const targetRepositoriesOwners = repositories
          .map(parseRepository).map((it) => it.owner)
      if (new Set(targetRepositoriesOwners).size > 1) {
        throw ctx.throw(StatusCodes.BAD_REQUEST, 'Token can only be requested for repositories of a single owner.')
      }
      return targetRepositoriesOwners[0]
    }

    /**
     * This function will return the app installation for the given owner
     * @param owner - owner
     * @param targetType - target type (User or Organization)
     * @param permissions - requested permissions
     * @returns installation
     */
    async function _getAppInstallation({owner, ownerType, permissions}: {
      owner: string,
      ownerType?: 'User' | 'Organization',
      permissions: GitHubAppPermissions
    }): Promise<GitHubAppInstallation> {
      const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {owner})
      if (!appInstallation) {
        throw ctx.throw(StatusCodes.FORBIDDEN,
            `${GITHUB_APP_INFOS.name} has not been installed for ${owner}.\n` +
            `Install from ${GITHUB_APP_INFOS.html_url}`)
      }
      log.debug(`App installation`, appInstallation)

      if (ownerType && appInstallation.target_type !== ownerType) {
        throw ctx.throw(StatusCodes.BAD_REQUEST,
            `'${tokenRequest.organization}' is not an ${ownerType.toLowerCase()}.`)
      }

      if (appInstallation.target_type !== 'Organization') {
        // TODO ensure no organization permissions are requested
      }

      const missingInstallationPermissions = verifyPermissions({
        requested: permissions,
        granted: appInstallation.permissions,
      })
      if (missingInstallationPermissions) {
        throw ctx.throw(StatusCodes.FORBIDDEN,
            `${GITHUB_APP_INFOS.name} installation for ${owner} is missing some permissions.\n` +
            'Owner: ' + owner + '\n' +
            'Missing permissions: ' + formatArray(Object.entries(missingInstallationPermissions)
                .map(([scope]) => scope)))
      }

      return appInstallation
    }
  })

  return app
}


// --- Server Functions ------------------------------------------------------------------------------------------------

/**
 * This function will verify the authorization header and return the decoded token
 * @param ctx - koa context
 * @param verifier - verifier function
 * @returns decoded token
 */
async function verifyAuthorizationToken<T extends object>(
    ctx: Koa.Context,
    verifier: (token: string) => Promise<T>,
): Promise<T> {
  // In addition to Authorization header the X-Authorization header can be used for situations,
  // where the Authorization header cannot be used
  // (e.g. when using an AWS IAM authorizer (SignatureV4) in front of this endpoint)
  const authorizationHeaderValue = ctx.request.get('X-Authorization') || ctx.get('Authorization')
  if (!authorizationHeaderValue) {
    throw ctx.throw(StatusCodes.UNAUTHORIZED, 'Missing authorization header')
  }

  const [authorizationScheme, tokenValue] = authorizationHeaderValue.split(' ')
  if (authorizationScheme !== 'Bearer') {
    throw ctx.throw(StatusCodes.UNAUTHORIZED, `Unexpected authorization scheme ${authorizationScheme}`)
  }

  return await verifier(tokenValue)
      .catch((error) => {
        if (error instanceof TokenError) {
          throw ctx.throw(StatusCodes.UNAUTHORIZED, error.message)
        }
        throw error
      })
}

/**
 * This function will validate the request body against the given schema
 * @param ctx - koa context
 * @param schema - zod schema
 * @returns parsed body
 */
async function parseBody<T extends ZodTypeAny>(
    ctx: Koa.Context, schema: T,
): Promise<z.infer<T>> {
  const bodyTransformer = getBodyTransformer(ctx.headers['content-type'])
  if (!bodyTransformer) {
    throw ctx.throw(StatusCodes.UNSUPPORTED_MEDIA_TYPE)
  }
  const body = await getRawBody(ctx.req, {
    length: ctx.req.headers['content-length'],
    limit: '1mb',
    encoding: 'utf-8', // without this option getRawBody will return a buffer
  })

  const bodyParseResult = bodyTransformer.pipe(schema).safeParse(body)
  if (!bodyParseResult.success) {
    throw ctx.throw(StatusCodes.BAD_REQUEST, 'Invalid request body.\n' +
        bodyParseResult.error.issues.map(formatZodIssue)
            .map((it) => '- ' + it).join('\n'))
  }
  return bodyParseResult.data

  /**
   * This function will return the body transformer for the given context
   * @param contentType - content type
   * @returns body transformer
   */
  function getBodyTransformer(contentType?: string) {
    if (!contentType ||
        contentType === 'application/json' ||
        contentType === 'text/plain') {
      return JsonTransformer
    }
    return undefined
  }
}

/**
 * This function will return a middleware to handle http errors
 * @returns middleware
 */
function httpErrorHandler(): Koa.Middleware {
  return async (ctx: Koa.Context, next: Koa.Next) => {
    try {
      await next()
    } catch (err: unknown) {
      if (err instanceof HttpError && 400 <= ctx.status && ctx.status < 500) {
        log.info('Http Client Error: ' + err.message)
        ctx.status = err.status
        ctx.body = err.message
      } else {
        log.error('Internal Server Error:' + (err instanceof Error ? err.message : err), {error: err})
        ctx.status = StatusCodes.INTERNAL_SERVER_ERROR
        ctx.body = StatusCodes.getStatusText(ctx.status)
        ctx.app.emit('error', err, ctx)
      }
    }
  }
}

/**
 * This function will return a middleware to log http requests and responses
 * @returns middleware
 */
function debugLogger(): Koa.Middleware {
  return async (ctx: Koa.Context, next: Koa.Next) => {
    const requestLog = ctx.request.toJSON()
    log.debug('Http Request', JSON.stringify(requestLog, null, 2))
    await next().finally(() => {
      const responseLog = ctx.response.toJSON()
      log.debug('Http Response', JSON.stringify(responseLog, null, 2))
    })
  }
}

// --- GitHub Functions ------------------------------------------------------------------------------------------------

/**
 * Get GitHub app installation for a repository or owner
 * @param client - GitHub client
 * @param owner - app installation owner
 * @returns installation or null if app is not installed for target
 */
async function getAppInstallation(client: Octokit, {owner}: { owner: string }): Promise<GitHubAppInstallation | null> {
  return await client.apps.getUserInstallation({username: owner})
      .then((res) => res.data)
      .catch(async (error) => error.status === StatusCodes.NOT_FOUND ? null : _throw(error))
}

/**
 * Create installation access token
 * @param client - GitHub client
 * @param installation - target installation id
 * @param repositories - target repositories
 * @param permissions - requested permissions
 * @returns access token
 */
async function createInstallationAccessToken(client: Octokit, installation: GitHubAppInstallation, {
  repositories, // TODO change to repo names without owner
  permissions,
}: {
  repositories?: string[],
  permissions: GitHubAppPermissions
}): Promise<GitHubAppInstallationAccessToken> {
  // noinspection TypeScriptValidateJSTypes
  return await client.apps.createInstallationAccessToken({
    installation_id: installation.id,
    // BE AWARE that an empty object will result in a token with all app installation permissions
    permissions: ensureHasEntries(permissions),
    repositories: repositories?.map((it) => parseRepository(it).repo),
  }).then((res) => res.data)
}
