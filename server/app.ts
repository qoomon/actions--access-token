import Koa, {HttpError} from 'koa'
import StatusCodes from 'http-status-codes'
import {createVerifier, TokenError} from 'fast-jwt'
import process from 'process'
import log from 'loglevel'
import {Octokit} from '@octokit/rest'
import {createAppAuth} from '@octokit/auth-app'
import {z, ZodTypeAny} from 'zod'
import {formatPEMKey} from './lib/ras-key-utils.js'
import {components} from '@octokit/openapi-types'
import {
  GitHubAccessPolicy,
  GitHubAccessStatement,
  GitHubActionsJwtPayload,
  GitHubAppInstallation,
  GitHubAppInstallationAccessToken,
  GitHubAppPermissions,
  PolicyError,
} from './lib/types.js'
import {
  AccessTokenRequestBodySchema,
  GitHubAccessPolicySchema,
  GitHubAccessStatementSchema,
  GitHubAppPermissionsSchema,
  GitHubSubjectClaimSchema,
  JsonTransformer,
  YamlTransformer,
} from './lib/schemas.js'
import {formatZodIssue} from './lib/zod-utils.js'
import {
  _throw,
  ensureHasEntries,
  filterObject,
  hasEntries,
  indent,
  isRecord,
  mapObject,
  regexpOfWildcardPattern,
  unique,
} from './lib/common-utils.js'
import {logLevelOf} from './lib/log-utils.js'
import {buildJwksKeyFetcher} from './lib/jwt-utils.js'
import getRawBody from 'raw-body'
import {
  aggregatePermissions,
  parseRepository,
  parseSubject,
  verifyPermission,
  verifyPermissions,
} from './lib/github-utils.js'
import retry from 'p-retry'
import limit from 'p-limit'

/**
 * This function will initialize the application
 * @returns application
 */
export async function appInit(): Promise<Koa> {
  // --- Configuration -------------------------------------------------------------------------------------------------
  log.setDefaultLevel(logLevelOf(process.env['LOG_LEVEL']) || 'info')

  const ACCESS_POLICY_FILE_LOCATIONS = {
    repository: {
      path: '.github/access-policy.yml',
    },
    owner: {
      path: 'access-policy.yml',
      repo: '.github-access-tokens',
    },
  }
  log.debug('Access policy file locations:', ACCESS_POLICY_FILE_LOCATIONS)

  const GITHUB_APP_AUTH = {
    appId: process.env['GITHUB_APP_ID'] ??
        _throw(new Error('Environment variable GITHUB_APP_ID is required')),
    // depending on the environment multiple environment variables are not supported,
    // due to this limitation formatPEMKey ensure the right format
    privateKey: formatPEMKey(process.env['GITHUB_APP_PRIVATE_KEY'] ??
        _throw(new Error('Environment variable GITHUB_APP_ID is required'))),
  }
  log.debug('GitHub app id: ' + GITHUB_APP_AUTH.appId)

  const GITHUB_ACTIONS_TOKEN_VERIFIER_OPTIONS = {
    allowedAud: process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE'] ??
        _throw(new Error('Environment variable GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE is required')),
    allowedSub: process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS']
        ?.split(/\s*,\s*/)
        ?.map((subjectPattern) => regexpOfWildcardPattern(subjectPattern, 'i')),
  }
  log.debug('GitHub OIDC token verify options:', GITHUB_ACTIONS_TOKEN_VERIFIER_OPTIONS)

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
  log.debug('GitHub app infos:', GITHUB_APP_INFOS)

  // --- Server Setup --------------------------------------------------------------------------------------------------

  const app = new Koa()
  app.use(requestId())
  app.use(debugLogger())
  app.use(httpErrorHandler())

  app.use(async (ctx) => {
    const requestId = ctx.state['id']

    if (ctx.path !== '/access_tokens') {
      throw ctx.throw(StatusCodes.FORBIDDEN)
    }
    if (ctx.method !== 'POST') {
      throw ctx.throw(StatusCodes.METHOD_NOT_ALLOWED)
    }

    // TODO remove debug log
    log.warn('GitHub OIDC token verify options:', {
      allowedAud: GITHUB_ACTIONS_TOKEN_VERIFIER_OPTIONS.allowedAud,
      token: ctx.get('Authorization'),
    })
    const callerIdentity = await verifyAuthorizationToken(ctx, GITHUB_OIDC_TOKEN_VERIFIER) as GitHubActionsJwtPayload
    log.info('Caller Identity: ' + callerIdentity.workflow_ref, {callerIdentity, requestId})

    const tokenRequest = await parseBody(ctx, AccessTokenRequestBodySchema)
        .then((it) => {
          // use caller repository owner as default target owner
          it.owner = it.owner || callerIdentity.repository_owner
          return it as typeof it & { owner: string, permissions: Record<string, string> }
        })

    log.info('Token Request:', {tokenRequest, requestId})

    if (Object.entries(tokenRequest.permissions).length === 0) {
      throw ctx.throw(StatusCodes.BAD_REQUEST, 'Token permissions must not be empty.')
    }

    const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {
      owner: tokenRequest.owner,
    })
    if (!appInstallation) {
      throw ctx.throw(StatusCodes.FORBIDDEN,
          `${GITHUB_APP_INFOS.name} has not been installed for ${tokenRequest.owner}.\n` +
          `Install from ${GITHUB_APP_INFOS.html_url}`)
    }
    log.debug(`App installation`, {appInstallation, requestId})

    const verifiedTargetInstallationPermissions = verifyPermissions({
      requested: tokenRequest.permissions,
      granted: appInstallation.permissions,
    })

    if (verifiedTargetInstallationPermissions.denied.length > 0) {
      throw ctx.throw(StatusCodes.FORBIDDEN,
          // eslint-disable-next-line max-len
          `${GITHUB_APP_INFOS.name} installation for ${appInstallation.target_type.toLowerCase()} ${tokenRequest.owner} ` +
          'is missing some permissions.\n' +
          verifiedTargetInstallationPermissions.denied
              .map((it) => `- ${it.scope}: ${it.permission}`)
              .join('\n'))
    }

    const appInstallationClient = await createOctokit(GITHUB_APP_CLIENT, appInstallation, {
      permissions: {
        single_file: 'read', // to read access policy files
      },
    })

    // --- verify requested token permissions --------------------------------------------------------------------------

    const pendingTokenPermissions: Record<string, string> = Object.fromEntries(Object.entries(tokenRequest.permissions))
    const rejectedTokenPermissions: {
      reason: string,
      scope: string, permission: string,
    }[] = []
    // granted token permission object will be used as safeguard to prevent unintentional permission granting
    const grantedTokenPermissions: Record<string, string> = {}

    // --- handle owner access policy ----------------------------------------------------------------------------------
    const ownerAccessPolicy = await getAccessPolicy(appInstallationClient, {
      owner: tokenRequest.owner, repo: ACCESS_POLICY_FILE_LOCATIONS.owner.repo,
      path: ACCESS_POLICY_FILE_LOCATIONS.owner.path,
      strict: false, // ignore invalid access policy entries
    }).then((policy) => ({
      ...policy,
      accessControl: {
        subjects: [`repo:${tokenRequest.owner}`],
        permissions: getAllowedRepositoryScopedTokenPermissions(),
      },
    }))
    log.debug(`${tokenRequest.owner} access policy:`, {ownerAccessPolicy, requestId})

    const ownerGrantedPermissions = evaluateGrantedPermissions({
      statements: ownerAccessPolicy.statements,
      callerIdentity,
    })

    Object.entries(pendingTokenPermissions).forEach(([scope, permission]) => {
      if (verifyPermission({
        granted: ownerGrantedPermissions[scope],
        requested: permission,
      })) {
        // permission granted
        grantedTokenPermissions[scope] = permission
        delete pendingTokenPermissions[scope]
      } else if (!ownerAccessPolicy.accessControl.permissions[scope]) {
        // permission rejected
        rejectedTokenPermissions.push({
          reason: `Permission has not been granted by ${tokenRequest.owner}.`,
          scope, permission,
        })
      }
    })

    // --- handle repository access policies ---------------------------------------------------------------------------
    if (!hasEntries(rejectedTokenPermissions) && hasEntries(pendingTokenPermissions)) {
      if (!hasEntries(tokenRequest.repositories)) {
        tokenRequest.repositories = [parseRepository(callerIdentity.repository).repo]
      }

      const pendingRepositoryTokenPermissions: Record<string, Set<string>> =
          Object.fromEntries(Object.keys(pendingTokenPermissions)
              .map((scope) => [scope, new Set(tokenRequest.repositories)]))

      const limitRepoPermissionRequests = limit(8)
      await Promise.all(
          tokenRequest.repositories.map((repo) => limitRepoPermissionRequests(async () => {
            const repoAccessPolicy = await getAccessPolicy(appInstallationClient, {
              owner: tokenRequest.owner, repo,
              path: ACCESS_POLICY_FILE_LOCATIONS.repository.path,
              strict: false, // ignore invalid access policy entries
            })
            log.debug(`${tokenRequest.owner}/${repo} access policy:`, {repoAccessPolicy, requestId})

            const repoGrantedPermissions = evaluateGrantedPermissions({
              statements: repoAccessPolicy.statements,
              callerIdentity,
            })

            Object.entries(pendingTokenPermissions).forEach(([scope, requestedPermission]) => {
              if (verifyPermission({
                granted: repoGrantedPermissions[scope],
                requested: requestedPermission,
              })) {
                // permission granted
                pendingRepositoryTokenPermissions[scope].delete(repo)
              } else {
                rejectedTokenPermissions.push({
                  reason: `Permission has not been granted by ${tokenRequest.owner}/${repo}.`,
                  scope, permission: requestedPermission,
                })
              }
            })
          })),
      )

      Object.entries(pendingRepositoryTokenPermissions).forEach(([scope, repositories]) => {
        if (repositories.size == 0) {
          grantedTokenPermissions[scope] = pendingTokenPermissions[scope]
          delete pendingTokenPermissions[scope]
        }
      })
    }

    // --- final permission check --------------------------------------------------------------------------------------
    if (hasEntries(rejectedTokenPermissions)) {
      throw ctx.throw(StatusCodes.FORBIDDEN, 'Some requested permissions got rejected.\n' +
          rejectedTokenPermissions.map((it) => '' +
              '- ' + `${it.scope}: ${it.permission}\n` +
              indent(it.reason),
          ).join('\n'))
    }
    // this is just a safeguard, pending permissions should only occur due to rejected permissions (see above check)
    if (hasEntries(pendingTokenPermissions)) {
      throw new Error('Unexpected pending permissions.')
    }

    // --- create requested access token -------------------------------------------------------------------------------
    const appInstallationAccessToken = await createInstallationAccessToken(
        GITHUB_APP_CLIENT, appInstallation, {
          // BE AWARE that an empty object will result in a token with all app installation permissions
          permissions: ensureHasEntries(grantedTokenPermissions),
          // BE AWARE that an empty array will result in a token with access to all app installation repositories
          repositories: tokenRequest.repositories,
        })

    // --- response with requested access token ------------------------------------------------------------------------
    ctx.body = {
      token: appInstallationAccessToken.token,
      expires_at: appInstallationAccessToken.expires_at,
      permissions: appInstallationAccessToken.permissions,
      repositories: appInstallationAccessToken.repositories?.map((it) => it.name),
      owner: appInstallation.account?.name ?? tokenRequest.owner,
    }
  })

  return app
}

// --- Server Functions ------------------------------------------------------------------------------------------------

/**
 * Normalise permission scopes to dash case
 * @param permissions - permission object
 * @returns normalised permission object
 */
function normalizePermissionScopes(permissions: Record<string, string>): Record<string, string> {
  return mapObject(permissions, ([scope, permission]) => [
    scope.replaceAll('_', '-'), permission,
  ])
}

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
        log.info('Http Client Error: ' + err.message, JSON.stringify({
          requestId: ctx.state['id'],
          status: err.status,
        }, null, 2))
        ctx.status = err.status
        ctx.body = {
          requestId: ctx.state['id'],
          error: StatusCodes.getStatusText(ctx.status),
          message: err.message,
        }
      } else {
        log.error('Internal Server Error:' + (err instanceof Error ? err.message : err), JSON.stringify({
          error: err,
          status: StatusCodes.INTERNAL_SERVER_ERROR,
          requestId: ctx.state['id'],
        }, null, 2))
        ctx.status = StatusCodes.INTERNAL_SERVER_ERROR
        ctx.body = {
          requestId: ctx.state['id'],
          error: StatusCodes.getStatusText(ctx.status),
        }
        ctx.app.emit('error', err, ctx)
      }
    }
  }
}

/**
 * This function will return a middleware to generate a request ids
 * @param header - header name
 * @returns middleware
 */
function requestId(header: string = 'X-Request-Id'): Koa.Middleware {
  return async (ctx: Koa.Context, next: Koa.Next) => {
    const id = ctx.get(header) || crypto.randomUUID()
    ctx.set(header, id)
    ctx.state['id'] = id

    await next()
  }
}

/**
 * This function will return a middleware to log http requests and responses
 * @returns middleware
 */
function debugLogger(): Koa.Middleware {
  return async (ctx: Koa.Context, next: Koa.Next) => {
    log.debug('Http Request', JSON.stringify({
      ...ctx.request.toJSON(),
      requestId: ctx.state['id'],
    }, null, 2))
    await next().finally(() => {
      log.debug('Http Response', JSON.stringify({
        ...ctx.response.toJSON(),
        requestId: ctx.state['id'],
      }, null, 2))
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
  // WORKAROUND: for some reason sometimes the request connection get closed unexpectedly (line closed),
  // therefore we retry on any error
  return await retry(
      async () => client.apps.getUserInstallation({username: owner})
          .then((res) => res.data)
          .catch(async (error) => error.status === StatusCodes.NOT_FOUND ? null : _throw(error))
          .then((data) => {
            if (!data) return data
            return {
              ...data,
              permissions: normalizePermissionScopes(data.permissions),
            }
          }),
      {retries: 3})
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
  repositories, permissions,
}: {
  repositories?: string[],
  permissions: GitHubAppPermissions
}): Promise<GitHubAppInstallationAccessToken> {
  // noinspection TypeScriptValidateJSTypes
  return await client.apps.createInstallationAccessToken({
    installation_id: installation.id,
    // BE AWARE that an empty object will result in a token with all app installation permissions
    permissions: ensureHasEntries(mapObject(permissions, ([scope, permission]) => [
      scope.replaceAll('-', '_'), permission,
    ])),
    repositories,
  })
      .then((res) => res.data)
      .then((data) => {
        if (!data) return data
        return {
          ...data,
          permissions: data.permissions ? normalizePermissionScopes(data.permissions) : data.permissions,
        }
      })
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
  permissions: components['schemas']['app-permissions'],
  repositories?: string[]
}): Promise<Octokit> {
  const installationAccessToken = await createInstallationAccessToken(client, installation, {
    permissions,
    repositories,
  })
  return new Octokit({auth: installationAccessToken.token})
}


/**
 * Get allowed repository scoped token permissions
 * @returns allowed token permissions
 */
function getAllowedRepositoryScopedTokenPermissions() {
  return filterObject(
      {
        // administration: 'write', // BE AWARE CAN NOT be completely limited to a repository e.g. create new repositories
        'actions': 'write',
        'actions-variables': 'write',
        'checks': 'write',
        'codespaces': 'write',
        'codespaces-lifecycle-admin': 'write',
        'codespaces-metadata': 'write',
        'codespaces-secrets': 'write',
        'contents': 'write',
        'custom-properties': 'write',
        'dependabot-secrets': 'write',
        'deployments': 'write',
        'discussions': 'write',
        'environments': 'write',
        'issues': 'write',
        'merge-queues': 'write',
        'metadata': 'read',
        'packages': 'write',
        'pages': 'write',
        'projects': 'admin',
        'pull-requests': 'write',
        'repository-advisories': 'write',
        'repository-hooks': 'write',
        'repository-projects': 'write',
        'secret-scanning-alerts': 'write',
        'secrets': 'write',
        'security-events': 'write',
        'statuses': 'write',
        'team-discussions': 'write',
        'vulnerability-alerts': 'write',
        'workflows': 'write',
      } satisfies GitHubAppPermissions,
      ([scope]) => !scope.startsWith('organization-') && scope !== 'member')
}

/**
 * Get repository access policy
 * @param client - github client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @param strict - throw error on invalid access policy
 * @returns access policy
 */
async function getAccessPolicy(client: Octokit, {owner, repo, path, strict}: {
  owner: string,
  repo: string,
  path: string,
  strict: boolean,
}): Promise<Omit<GitHubAccessPolicy, 'origin'>> {
  const policyValue = await getRepositoryFileContent(client, {
    owner, repo, path,
  })
  if (!policyValue) {
    return {statements: []}
  }

  const policyParseResult = YamlTransformer
      .transform((policyObject) => {
        if (strict) return policyObject
        // ignore invalid subjects and permissions or hole statements
        if (typeof policyObject === 'object' && !Array.isArray(policyObject)) {
          if (Array.isArray(policyObject.statements)) {
            policyObject.statements = policyObject.statements
                .map((statementObject: unknown) => {
                  if (isRecord(statementObject)) {
                    // ---- subjects
                    if ('subjects' in statementObject && Array.isArray(statementObject.subjects)) {
                      // ignore invalid subjects
                      statementObject.subjects = statementObject.subjects.filter(
                          (it: unknown) => GitHubSubjectClaimSchema.safeParse(it).success)
                    }
                    // ---- permissions
                    if ('permissions' in statementObject && isRecord(statementObject.permissions)) {
                      // ignore invalid permissions
                      statementObject.permissions = filterObject(statementObject.permissions,
                          ([key, value]) => GitHubAppPermissionsSchema.safeParse({[key]: value}).success)
                    }
                  }
                  return statementObject
                })
                .filter((statementObject: unknown) => GitHubAccessStatementSchema.safeParse(statementObject).success)
          }
          return policyObject
        }
      })
      .pipe(GitHubAccessPolicySchema)
      .safeParse(policyValue)

  if (!policyParseResult.success) {
    const issues = policyParseResult.error.issues.map(formatZodIssue)
    if (strict) {
      throw new PolicyError(`${owner} access policy is invalid.`, issues)
    }
    log.debug(`${owner} access policy is invalid:`, {issues, requestId})
    return {statements: []}
  }

  const policy = policyParseResult.data

  const expectedPolicyOrigin = `${owner}/${repo}`
  if (policy.origin.toLowerCase() !== expectedPolicyOrigin.toLowerCase()) {
    const issues = [`policy origin '${policy.origin}' does not match repository '${expectedPolicyOrigin}'`]
    if (strict) {
      throw new PolicyError(`${owner} access policy is invalid.`, issues)
    }
    log.debug(`${owner} access policy is invalid:`, {issues, requestId})
    return {statements: []}
  }

  policy.statements.forEach((statement) => {
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
        )
        .catch((error) => {
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
  async function normaliseAccessPolicyStatement(statement: { subjects: string[] }, {
    owner, repo,
  }: {
    owner: string,
    repo: string,
  }) {
    statement.subjects = statement.subjects
        .map((it) => normaliseAccessPolicyStatementSubject(it, {owner, repo}))
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
}): Record<string, string> {
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

