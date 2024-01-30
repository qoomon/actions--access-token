import Koa, {HttpError} from 'koa'
import StatusCodes from 'http-status-codes'
import {createVerifier, TokenError} from 'fast-jwt'
import process from 'process'
import log from 'loglevel'
import {Octokit} from '@octokit/rest'
import {createAppAuth} from '@octokit/auth-app'
import {z, ZodTypeAny} from 'zod'
import {formatPEMKey} from './lib/ras-key-utils.js'
import {
  GitHubAccessPolicy,
  GitHubAccessStatement,
  GitHubActionsJwtPayload,
  GitHubAppInstallation,
  GitHubAppInstallationAccessToken,
  GitHubAppPermission,
  GitHubAppPermissions,
  GitHubAppRepositoryPermissions,
  PolicyError,
} from './lib/types.js'
import {
  AccessTokenRequestBodySchema,
  GitHubAccessPolicySchema,
  JsonTransformer,
  YamlTransformer,
} from './lib/schemas.js'
import {formatZodIssue} from './lib/zod-utils.js'
import {_throw, ensureHasEntries, indent, mapObject, regexpOfWildcardPattern, unique} from './lib/common-utils.js'
import {logLevelOf} from './lib/log-utils.js'
import {buildJwksKeyFetcher} from './lib/jwt-utils.js'
import getRawBody from 'raw-body'
import {
  aggregatePermissions,
  GitHubAppPermissionScopes,
  parseRepository,
  parseSubject,
  verifyPermission,
} from './lib/github-utils.js'
import {components} from '@octokit/openapi-types'

// TODO ensure access.yaml is owned by repository admins

/**
 * This function will initialize the application
 * @returns application
 */
export async function appInit(): Promise<Koa> {
  // --- Configuration -------------------------------------------------------------------------------------------------
  log.setDefaultLevel(logLevelOf(process.env['LOG_LEVEL']) || 'info')

  // TODO maybe read from owner access policy (.github/access.yaml)
  // --- Repository level permissions, these permissions can be granted by repository maintainers
  const ALLOWED_REPOSITORY_TOKEN_PERMISSIONS: GitHubAppRepositoryPermissions = {
    // administration: 'write', // BE AWARE CAN NOT be completely limited to a repository e.g. create new repositories
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
    statuses: 'write',
    team_discussions: 'write',
    vulnerability_alerts: 'write',
    workflows: 'write',
  }

  log.debug('Allowed repository token permissions:', ALLOWED_REPOSITORY_TOKEN_PERMISSIONS)

  const ACCESS_POLICY_FILE_LOCATIONS = {
    repository: {
      path: '.github/access-policy.yaml',
    },
    owner: {
      path: 'access.yaml',
      repo: '.github',
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

    const tokenRequest = await parseBody(ctx, AccessTokenRequestBodySchema).then((it) => {
      if (!it.owner) {
        // use caller repository owner as default target owner
        it.owner = callerIdentity.repository_owner
      }
      return it as typeof it & { owner: string }
    })

    log.info('Token Request:', {tokenRequest})

    if (Object.entries(tokenRequest.permissions).length === 0) {
      throw ctx.throw(StatusCodes.BAD_REQUEST, 'Token permissions must not be empty.')
    }

    // TODO implement explicit granted token { permissions, repositories }
    const pendingPermissions = new Set(Object.entries(tokenRequest.permissions)
        .map(([scope, permission]) => `${scope}:${permission}`))
    const rejectedPermissions = <{
      repo: string | null,
      scope: string | null, permission: string | null,
      reason: string
    }[]>[]

    const targetInstallation = await _getAppInstallation({
      owner: tokenRequest.owner, permissions: tokenRequest.permissions,
    })
    // TODO maybe move logic from _getAppInstallation to here
    const targetAppClient = await createOctokit(GITHUB_APP_CLIENT, targetInstallation, {
      permissions: {single_file: 'read'}, // single_file:read to read access policy files
    })

    // --- handle owner access policy ----------------------------------------------------------------------------------
    {
      const ownerAccessPolicy = await getAccessPolicy(targetAppClient, {
        owner: tokenRequest.owner,
        repo: ACCESS_POLICY_FILE_LOCATIONS.owner.repo,
        path: ACCESS_POLICY_FILE_LOCATIONS.owner.path,
      }).catch((error) => {
        if (error instanceof PolicyError) {
          // TODO maybe ignore if owner has invalid access policy
          const ownerAccessPolicyRepository = `${tokenRequest.owner}/${ACCESS_POLICY_FILE_LOCATIONS.owner.repo}`
          throw ctx.throw(StatusCodes.FORBIDDEN, 'Invalid owner access policy.' +
              // only return details, if target repository is equal to request identity repository
              (ownerAccessPolicyRepository === callerIdentity.repository ?
                  '\n' + error.issues?.map((issue) => '- ' + issue).join('\n') : ''),
          )
        }
        throw error
      })
      if (!ownerAccessPolicy) {
        // TODO maybe ignore if owner has no access policy
        // throw ctx.throw(StatusCodes.FORBIDDEN, `Owner ${tokenRequest.owner} has no access policy.`)
        log.debug(`No owner access policy for ${tokenRequest.owner}`)
      } else {
        log.debug(`Owner access policy for ${tokenRequest.owner}`, {
          accessPolicy: ownerAccessPolicy,
        })
      }

      const ownerGrantedPermissions = ownerAccessPolicy ?
          evaluateGrantedPermissions({
            statements: ownerAccessPolicy.statements,
            callerIdentity,
          }) : {}

      // TODO use pendingPermissions instead of tokenRequest.permissions
      Object.entries(tokenRequest.permissions).forEach(([scope, requestedPermission]) => {
        const _scope = scope as keyof GitHubAppPermissions

        if (verifyPermission({
          granted: ownerGrantedPermissions[_scope],
          requested: requestedPermission,
        })) {
          pendingPermissions.delete(`${scope}:${requestedPermission}`)
          return // permission granted
        }

        // ensure owner permissions are granted by owner access policy
        // and can not be granted by repository access policies
        // TODO maybe move down
        if (!GitHubAppPermissionScopes.repository.includes(scope)) {
          rejectedPermissions.push({
            repo: ACCESS_POLICY_FILE_LOCATIONS.owner.repo,
            scope, permission: requestedPermission,
            reason: 'Permission rejected by owner access policy.',
          })
          return // permission rejected
        }

        // ensure repository permissions are allowed by owner access policy
        // and can not be granted by repository access policies if not allowed
        if (!verifyPermission({
          // @ts-expect-error - ALLOWED_REPOSITORY_TOKEN_PERMISSIONS is a subset of GitHubAppPermissions
          granted: ALLOWED_REPOSITORY_TOKEN_PERMISSIONS[_scope],
          requested: requestedPermission,
        })) {
          rejectedPermissions.push({
            repo: ACCESS_POLICY_FILE_LOCATIONS.owner.repo,
            scope, permission: requestedPermission,
            reason: 'Permission is not allowed by owner access policy.',
          })
          return // permission rejected
        }
      })
    }

    // --- handle repository access policies ---------------------------------------------------------------------------
    if (rejectedPermissions.length === 0 && pendingPermissions.size > 0) {
      if (tokenRequest.repositories.length === 0) {
        // if no repositories are specified, use caller repository as default target repository
        tokenRequest.repositories.push(parseRepository(callerIdentity.repository).repo)
      }

      const pendingPermissionsRepositories = new Map(Array.from(pendingPermissions)
          .map((it) => ([it, new Set(tokenRequest.repositories)])))
      {
        // TODO limit parallel requests
        await Promise.all(tokenRequest.repositories.map(async (repo) => {
          await getAccessPolicy(targetAppClient, {
            owner: tokenRequest.owner, repo,
            path: ACCESS_POLICY_FILE_LOCATIONS.repository.path,
          }).then((accessPolicy) => {
            if (!accessPolicy) {
              rejectedPermissions.push({
                repo,
                scope: null, permission: null,
                reason: 'No access policy.',
              })
              return // permission rejected
            }

            log.debug(`Access policy for ${tokenRequest.owner}/${repo}`, {
              accessPolicy,
            })

            const grantedPermissions = evaluateGrantedPermissions({
              statements: accessPolicy.statements,
              callerIdentity,
            })

            Array.from(pendingPermissionsRepositories.keys()).map((it) => it.split(':'))
                .map(([scope, requestedPermission]) => {
                  if (verifyPermission({
                    granted: grantedPermissions[scope as keyof GitHubAppPermissions],
                    requested: requestedPermission as GitHubAppPermission,
                  })) {
                    pendingPermissionsRepositories.get(`${scope}:${requestedPermission}`)?.delete(repo)
                    return
                  }

                  rejectedPermissions.push({
                    repo,
                    scope, permission: requestedPermission,
                    reason: 'Permission is not granted.',
                  })
                })
          }).catch((error) => {
            if (error instanceof PolicyError) {
              const accessPolicyRepository = `${tokenRequest.owner}/${repo}`
              rejectedPermissions.push({
                repo, scope: null, permission: null,
                reason: 'Invalid repository access policy.' +
                    // only return details, if target repository is equal to request identity repository
                    (accessPolicyRepository === callerIdentity.repository ?
                        '\n' + error.issues?.map((issue) => '- ' + issue).join('\n') : ''),
              })
            } else {
              throw error
            }
          })
        }))
      }


      pendingPermissionsRepositories.forEach((repositories, permission) => {
        if (repositories.size === 0) {
          pendingPermissions.delete(permission)
        }
      })
    }

    // if rejectedPermissions is not empty, throw forbidden
    if (rejectedPermissions.length > 0) {
      throw ctx.throw(StatusCodes.FORBIDDEN, 'Some requested permissions are not granted.\n' +
          'Denied permissions:\n' +
          rejectedPermissions
              .map((it) => `- ${it.scope || '*'}:${it.permission || '*'}${it.repo ? ` (${it.repo})` : ''}\n` +
                  indent(it.reason))
              .join('\n'))
    }

    // this is just a safeguard, should never happen
    if (pendingPermissions.size > 0) {
      throw new Error('Unexpected pending permissions.\n' +
          [...pendingPermissions]
              .map((it) => `- ${it}`)
              .join('\n'))
    }

    const targetInstallationAccessToken = await createInstallationAccessToken(
        GITHUB_APP_CLIENT, targetInstallation, {
          // BE AWARE that an empty object will result in a token with all app installation permissions
          permissions: ensureHasEntries(tokenRequest.permissions),
          // repository permissions can be limited to specific repositories
          repositories: tokenRequest.repositories, // TODO add safe guard to prevent requesting token for all repositories
        })

    ctx.body = {
      token: targetInstallationAccessToken.token,
      expires_at: targetInstallationAccessToken.expires_at,
      permissions: targetInstallationAccessToken.permissions,
      owner: tokenRequest.owner, // TODO maybe change to targetInstallation.account?.name,
      repositories: targetInstallationAccessToken.repositories?.map((it) => it.name),
    }

    // --- context functions -------------------------------------------------------------------------------------------

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
    async function _getAppInstallation({owner, permissions}: {
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

      const missingInstallationPermissions = <{
        scope: string, permission: string,
      }[]>[]

      Object.entries(permissions).forEach(([scope, requestedPermission]) => {
        if (!verifyPermission({
          granted: appInstallation.permissions[scope as keyof components['schemas']['app-permissions']],
          requested: requestedPermission,
        })) {
          missingInstallationPermissions.push({
            scope, permission: requestedPermission,
          })
        }
      })

      if (missingInstallationPermissions.length > 0) {
        throw ctx.throw(StatusCodes.FORBIDDEN,
            `${GITHUB_APP_INFOS.name} installation for ${appInstallation.target_type.toLowerCase()} ${owner} ` +
            'is missing some permissions.\n' +
            'Missing permissions:\n' +
            missingInstallationPermissions
                .map((it) => `- ${it.scope}:${it.permission}`)
                .join('\n'))
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
async function getAppInstallation(client: Octokit, {owner}: {
  owner: string
}): Promise<GitHubAppInstallation | null> {
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
    repositories: repositories,
  }).then((res) => res.data)
}

/**
 * Create octokit instance for app installation
 * @param client - GitHub client
 * @param installation - app installation
 * @param permissions - requested permissions
 * @param repositories - requested repositories
 * @returns octokit instance
 */
async function createOctokit(client: Octokit, installation: GitHubAppInstallation, {permissions, repositories}: {
  permissions: GitHubAppPermissions,
  repositories?: string[]
}): Promise<Octokit> {
  const installationAccessToken = await createInstallationAccessToken(client, installation, {
    permissions,
    repositories,
  })
  return new Octokit({auth: installationAccessToken.token})
}

/**
 * Get repository access policy
 * @param client - github client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @returns access policy
 */
async function getAccessPolicy(client: Octokit, {owner, repo, path}: {
  owner: string,
  repo: string,
  path: string,
}): Promise<GitHubAccessPolicy | null> {
  const policyValue = await getRepositoryFileContent(client, {
    owner, repo, path,
  })
  if (!policyValue) {
    return null
  }

  const policyParseResult = YamlTransformer
      .pipe(GitHubAccessPolicySchema)
      .safeParse(policyValue)

  if (!policyParseResult.success) {
    throw new PolicyError('Invalid repository access policy', policyParseResult.error.issues.map(formatZodIssue))
  }

  const policy = policyParseResult.data
  const policyOrigin = `${owner}/${repo}`
  if (policy.origin.toLowerCase() !== policyOrigin.toLowerCase()) { // TODO change to repository id
    throw new PolicyError('Invalid repository access policy',
        [`policy field 'origin' needs to be set to '${policyOrigin}'`])
  }

  policy.statements.forEach((statement: GitHubAccessStatement) => {
    normaliseAccessPolicyStatement(statement, {owner, repo})
  })

  return policy

  /**
   * Get repository file content
   * @param client - github client for target repository
   * @param owner - repository owner
   * @param repo - repository name
   * @param path - file path
   * @returns file content or null if file does not exist
   */
  async function getRepositoryFileContent(client: Octokit, {owner, repo, path}: {
    owner: string,
    repo: string,
    path: string,
  }): Promise<string | null> {
    return await client.repos.getContent({owner, repo, path})
        .then((res) => Buffer.from(
            // @ts-expect-error - content will not be null, because we request a file
            res.data.content ?? '',
            'base64').toString(),
        ).catch((error) => {
          if (error.status === StatusCodes.NOT_FOUND) return null
          throw error
        })
  }

  /**
   * Normalise access policy statement
   * @param statement - access policy statement
   * @param owner - policy owner
   * @param repo - policy repository
   * @returns void
   */
  async function normaliseAccessPolicyStatement(statement: GitHubAccessStatement, {
    owner, repo,
  }: {
    owner: string,
    repo: string,
  }) {
    statement.subjects = statement.subjects
        .map((it) => normaliseAccessPolicyStatementSubject(it, {owner, repo}))
    statement.permissions = normalizePermissionScopes(statement.permissions)
  }

  /**
   * Normalise access policy statement subject
   * @param subject - access policy statement subject
   * @param owner - policy owner
   * @param repo - policy repository
   * @returns normalised subject
   */
  function normaliseAccessPolicyStatementSubject(subject: string, {owner, repo}: {
    owner: string,
    repo: string
  }): string {
    let effectiveSubject = subject
    // prefix subject with repo claim if not already prefixed
    if (!effectiveSubject.startsWith('repo:')) {
      effectiveSubject = `repo:${owner}/${repo}:` + effectiveSubject
    }

    const subjectRepo = effectiveSubject.match(/^repo:(?<repo>[^:]+)/)!.groups!.repo

    // resolve repo relative workflow refs (starting with a `/`)
    effectiveSubject = effectiveSubject.replaceAll(
        /:(?<claim>(job_)?workflow_ref):(?<relative_ref>\/[^:]+)/g,
        `:$<claim>:${subjectRepo}$<relative_ref>`,
    )
    return effectiveSubject
  }

  /**
   * Normalize permissions by replacing all '-' with '_'
   * @param permissions - permissions object
   * @returns normalized permissions
   */
  function normalizePermissionScopes(permissions: Record<string, GitHubAppPermission>) {
    return mapObject(permissions, ([key, value]) => [
      key.replaceAll('-', '_'),
      value,
    ])
  }
}


/**
 * Evaluate granted permissions for caller identity
 * @param accessPolicy - access policy
 * @param callerIdentity - caller identity
 * @returns granted permissions
 */
function evaluateGrantedPermissions({statements, callerIdentity}: {
  statements: GitHubAccessStatement[],
  callerIdentity: GitHubActionsJwtPayload,
}): GitHubAppPermissions {
  const effectiveCallerIdentitySubjects = unique([
    callerIdentity.sub,
    // --- add artificial subjects
    // repo : ref
    // => repo:qoomon/sandbox:ref:refs/heads/main
    `repo:${callerIdentity.repository}:ref:${callerIdentity.ref}`, // e.g. repo:qoomon/sandbox:ref:refs/heads/main
    // repo : workflow_ref
    // => repo:qoomon/sandbox:workflow_ref:qoomon/sandbox/.github/workflows/build.yml@refs/heads/main
    `repo:${callerIdentity.repository}:workflow_ref:${callerIdentity.workflow_ref}`,
    // repo : job_workflow_ref
    // => repo:qoomon/sandbox:job_workflow_ref:qoomon/sandbox/.github/workflows/build.yml@refs/heads/main
    `repo:${callerIdentity.repository}:job_workflow_ref:${callerIdentity.job_workflow_ref}`,
  ])

  const permissions = statements
      .filter(statementSubjectPredicate(effectiveCallerIdentitySubjects))
      .map((it) => it.permissions)

  return aggregatePermissions(permissions)

  /**
   * Create statement subject predicate
   * @param subjects - caller identity subjects
   * @returns true if statement subjects match any of the given subject patterns
   */
  function statementSubjectPredicate(subjects: string[]) {
    return (statement: GitHubAccessStatement) => subjects
        .some((subject) => statement.subjects
            .some((subjectPattern) => matchSubjectPattern(subjectPattern, subject)))
  }

  /**
   * Verify if subject is granted by grantedSubjectPatterns
   * @param subjectPattern - subject pattern
   * @param subject - subject e.g. 'repo:spongebob/sandbox:ref:refs/heads/main'
   * @returns true if subject matches any granted subject pattern
   */
  function matchSubjectPattern(subjectPattern: string, subject: string): boolean {
    // claims must not contain wildcards to prevent granting access accidentally e.g. pull requests
    // e.g. repo:foo/bar:* is not allowed
    if (Object.keys(parseSubject(subjectPattern)).some((claim) => claim.includes('*'))) {
      return false
    }

    // grantedSubjectPattern example: repo:qoomon/sandbox:ref:refs/heads/*
    // identity.sub example:     repo:qoomon/sandbox:ref:refs/heads/main
    return regexpOfSubjectPattern(subjectPattern).test(subject)
  }

  /**
   * Create regexp of wildcard subject pattern
   * @param subjectPattern - wildcard subject pattern
   * @returns regexp
   */
  function regexpOfSubjectPattern(subjectPattern: string): RegExp {
    return regexpOfWildcardPattern(subjectPattern, 'i')
  }
}

// --- Error Classes ---------------------------------------------------------------------------------------------------
