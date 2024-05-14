import {createVerifier} from 'fast-jwt'
import process from 'process'
import log from 'loglevel'
import {Octokit} from '@octokit/rest'
import {createAppAuth} from '@octokit/auth-app'
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
} from './lib/schemas.js'
import {formatZodIssue, YamlTransformer} from './lib/zod-utils.js'
import {
  _throw,
  ensureHasEntries,
  escapeRegexp,
  filterObject,
  hasEntries,
  indent,
  isRecord,
  mapObject,
  retry,
  unique,
} from './lib/common-utils.js'
import {logLevelOf} from './lib/log-utils.js'
import {buildJwksKeyFetcher} from './lib/jwt-utils.js'
import {
  aggregatePermissions,
  GitHubAppRepositoryPermissions,
  parseRepository,
  parseSubject,
  verifyPermissions,
} from './lib/github-utils.js'
import limit from 'p-limit'
import {Hono} from 'hono'
import {prettyJSON} from 'hono/pretty-json'
import {debugLogger, errorHandler, notFoundHandler, parseJsonBody, requestId, tokenVerifier} from './lib/hono-utils.js'
import {Status} from './lib/http-utils.js'
import {HTTPException} from 'hono/http-exception'
import {bodyLimit} from 'hono/body-limit'

/**
 * This function will initialize the application
 * @returns application
 */
// --- Configuration -------------------------------------------------------------------------------------------------
log.setDefaultLevel(logLevelOf(process.env['LOG_LEVEL']) || (process.env['NODE_ENV'] === 'test' ? 'warn' : 'info'))

const {config} = await import('./config.js')
log.debug('Config', {
  ...config,
  githubAppAuth: {...config.githubAppAuth, privateKey: '***'},
})

// --- Initialization ------------------------------------------------------------------------------------------------

const GITHUB_OIDC_TOKEN_VERIFIER = createVerifier({
  key: buildJwksKeyFetcher({providerDiscovery: true}),
  allowedIss: 'https://token.actions.githubusercontent.com',
  allowedAud: config.githubActionsTokenVerifier.allowedAud,
  allowedSub: config.githubActionsTokenVerifier.allowedSub,
})

const GITHUB_APP_CLIENT = new Octokit({authStrategy: createAppAuth, auth: config.githubAppAuth})
const GITHUB_APP_INFOS = await GITHUB_APP_CLIENT.apps.getAuthenticated()
    .then((res) => res.data)
log.debug('GitHub app infos:', GITHUB_APP_INFOS)

// --- Server Setup --------------------------------------------------------------------------------------------------

export const app = new Hono<{ Variables: { id: string, token: GitHubActionsJwtPayload } }>()
app.use(requestId())
app.use(debugLogger(log))
app.onError(errorHandler(log))
app.notFound(notFoundHandler())
app.use(bodyLimit({maxSize: 100 * 1024})) // 100kb
app.use(prettyJSON())

app.post('/access_tokens',
    tokenVerifier<GitHubActionsJwtPayload>(GITHUB_OIDC_TOKEN_VERIFIER),
    async (context) => {
      const requestId = context.get('id')
      const callerIdentity = context.get('token')
      log.info(`${requestId} - Caller Identity: ${callerIdentity.workflow_ref}`,
          JSON.stringify({callerIdentity}))

      const tokenRequest = await parseJsonBody(context.req, AccessTokenRequestBodySchema)
          .then((it) => {
            // use caller repository owner as default target owner
            it.owner = it.owner || callerIdentity.repository_owner

            // use caller repository as default repository
            if (it.scope === 'repos' &&
                it.owner === callerIdentity.repository_owner &&
                !hasEntries(it.repositories)) {
              it.repositories = [parseRepository(callerIdentity.repository).repo]
            }

            return it as typeof it & {
              owner: string,
              permissions: Record<string, string>
            }
          })

      log.info(`${requestId} - Token Request:`,
          JSON.stringify({tokenRequest}))

      if (Object.entries(tokenRequest.permissions).length === 0) {
        throw new HTTPException(Status.BAD_REQUEST, {
          message: 'Token permissions must not be empty.',
        })
      }

      if (tokenRequest.scope === 'repos') {
        // ensure only repository permissions are requested
        const nonRepositoryPermissions = verifyPermissions({
          requested: tokenRequest.permissions,
          granted: GitHubAppRepositoryPermissions,
        }).denied

        if (hasEntries(nonRepositoryPermissions)) {
          throw new HTTPException(Status.BAD_REQUEST, {
            message: 'Invalid permissions scopes for token scope \'repos\'.\n' +
                nonRepositoryPermissions.map(({scope}) => `- ${scope}`).join('\n'),
          })
        }
      }

      // --- verify requested token permissions --------------------------------------------------------------------------
      // eslint-disable-next-line max-len
      const pendingTokenPermissions: Record<string, string> = Object.fromEntries(Object.entries(tokenRequest.permissions))
      const rejectedTokenPermissions: {
        reason: string,
        scope: string, permission: string,
      }[] = []
      // granted token permission object will be used as safeguard to prevent unintentional permission granting
      const grantedTokenPermissions: Record<string, string> = {}

      // --- handle app installation ---------------------------------------------------------------------------------
      const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {
        owner: tokenRequest.owner,
      })
      if (!appInstallation) {
        throw new HTTPException(Status.FORBIDDEN, {
          message: `${GITHUB_APP_INFOS.name} has not been installed for ${tokenRequest.owner}.\n` +
              `Install from ${GITHUB_APP_INFOS.html_url}`,
        })
      }
      log.debug(`${requestId} - App installation`,
          JSON.stringify({appInstallation}))

      const verifiedTargetInstallationPermissions = verifyPermissions({
        requested: tokenRequest.permissions,
        granted: appInstallation.permissions,
      })
      verifiedTargetInstallationPermissions.denied.forEach(({scope, permission}) => {
        rejectedTokenPermissions.push({
          scope, permission,
          // eslint-disable-next-line max-len
          reason: `Permission has not been granted to ${GITHUB_APP_INFOS.name} installation for ${tokenRequest.owner}.`,
        })
      })

      if (hasEntries(rejectedTokenPermissions)) {
        throw createPermissionRejectedHttpException(rejectedTokenPermissions)
      }

      const appInstallationClient = await createOctokit(GITHUB_APP_CLIENT, appInstallation, {
        permissions: {
          single_file: 'read', // to read access policy files
        },
      })

      // --- handle owner access policy ------------------------------------------------------------------------------
      {
        const ownerAccessPolicy = await getAccessPolicy(appInstallationClient, {
          owner: tokenRequest.owner, repo: config.accessPolicyLocation.owner.repo,
          path: config.accessPolicyLocation.owner.path,
          strict: false, // ignore invalid access policy entries
        })
        log.debug(`${requestId} - ${tokenRequest.owner} access policy:`,
            JSON.stringify({ownerAccessPolicy}))

        const ownerGrantedPermissions = evaluateGrantedPermissions({
          statements: ownerAccessPolicy.statements,
          callerIdentity,
        })

        // verify requested token permissions by owner permissions
        verifyPermissions({
          granted: ownerGrantedPermissions,
          requested: tokenRequest.permissions,
        }).granted.forEach(({scope, permission}) => {
          // permission granted
          grantedTokenPermissions[scope] = permission
          delete pendingTokenPermissions[scope]
        })

        if (tokenRequest.scope === 'owner') {
          // reject all pending permissions
          Object.entries(pendingTokenPermissions).forEach(([scope, permission]) => {
            rejectedTokenPermissions.push({
              reason: `Permission has not been granted by ${tokenRequest.owner}.`,
              scope, permission,
            })
          })
        }

        if (hasEntries(rejectedTokenPermissions)) {
          throw createPermissionRejectedHttpException(rejectedTokenPermissions)
        }
      }

      // --- handle repository access policies -----------------------------------------------------------------------
      if (tokenRequest.scope === 'repos' &&
          hasEntries(pendingTokenPermissions) && // BE AWARE to ensure only repository permissions are pending
          hasEntries(tokenRequest.repositories)
      ) {
        const pendingRepositoryTokenPermissions: Record<string, Set<string>> =
            Object.fromEntries(Object.keys(pendingTokenPermissions)
                .map((scope) => [scope, new Set(tokenRequest.repositories)]))

        const limitRepoPermissionRequests = limit(8)
        await Promise.all(
            tokenRequest.repositories.map((repo) => limitRepoPermissionRequests(async () => {
              const repoAccessPolicy = await getAccessPolicy(appInstallationClient, {
                owner: tokenRequest.owner, repo,
                path: config.accessPolicyLocation.repository.path,
                strict: false, // ignore invalid access policy entries
              })
              log.debug(`${requestId} - ${tokenRequest.owner}/${repo} access policy:`,
                  JSON.stringify({repoAccessPolicy}))

              const repoGrantedPermissions = evaluateGrantedPermissions({
                statements: repoAccessPolicy.statements,
                callerIdentity,
              })

              // verify requested token permissions by repository permissions
              const verifiedRepoPermissions = verifyPermissions({
                granted: repoGrantedPermissions,
                requested: pendingTokenPermissions,
              })
              verifiedRepoPermissions.granted.forEach(({scope}) => {
                // permission granted
                pendingRepositoryTokenPermissions[scope].delete(repo)
              })
              verifiedRepoPermissions.denied.forEach(({scope, permission}) => {
                // permission rejected
                rejectedTokenPermissions.push({
                  reason: `Permission has not been granted by ${tokenRequest.owner}/${repo}.`,
                  scope, permission,
                })
              })
            })),
        )

        Object.entries(pendingRepositoryTokenPermissions).forEach(([scope, repositories]) => {
          if (repositories.size == 0) {
            grantedTokenPermissions[scope] = pendingTokenPermissions[scope]
            delete pendingTokenPermissions[scope]
          }
        })

        if (hasEntries(rejectedTokenPermissions)) {
          throw createPermissionRejectedHttpException(rejectedTokenPermissions)
        }
      }

      // --- create requested access token ---------------------------------------------------------------------------
      // SAFEGUARD, pending permissions should only occur due to rejected permissions (see above check)
      if (hasEntries(pendingTokenPermissions)) {
        throw new Error('Unexpected pending permissions.')
      }
      const appInstallationAccessToken = await createInstallationAccessToken(
          GITHUB_APP_CLIENT, appInstallation, {
            // BE AWARE that an empty object will result in a token with all app installation permissions
            permissions: ensureHasEntries(grantedTokenPermissions),
            // BE AWARE that an empty array will result in a token with access to all app installation repositories
            repositories: tokenRequest.repositories,
          })

      // --- response with requested access token --------------------------------------------------------------------
      return context.json({
        token: appInstallationAccessToken.token,
        expires_at: appInstallationAccessToken.expires_at,
        permissions: appInstallationAccessToken.permissions,
        repositories: appInstallationAccessToken.repositories?.map((it) => it.name),
        owner: appInstallation.account?.name ?? tokenRequest.owner,
      })
    })

/**
 * Create permission rejected http exception
 * @param rejectedTokenPermissions - rejected token permissions
 * @returns http exception
 */
function createPermissionRejectedHttpException(rejectedTokenPermissions: {
  reason: string,
  scope: string, permission: string,
}[]) {
  return new HTTPException(Status.FORBIDDEN, {
    message: 'Some requested permissions got rejected.\n' +
        rejectedTokenPermissions.map(({scope, permission, reason}) => '' +
            '- ' + `${scope}: ${permission}\n` +
            indent(reason),
        ).join('\n'),
  })
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
          .catch(async (error) => error.status === Status.NOT_FOUND ? null : _throw(error))
          .then((data) => {
            if (!data) return data
            return {
              ...data,
              permissions: normalizePermissionScopes(data.permissions),
            }
          }),
      {
        delay: 1000,
        retries: 3,
      })
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
    log.debug(`${requestId} - ${owner} access policy is invalid:`,
        JSON.stringify({issues}))
    return {statements: []}
  }

  const policy = policyParseResult.data

  const expectedPolicyOrigin = `${owner}/${repo}`
  if (policy.origin.toLowerCase() !== expectedPolicyOrigin.toLowerCase()) {
    const issues = [`policy origin '${policy.origin}' does not match repository '${expectedPolicyOrigin}'`]
    if (strict) {
      throw new PolicyError(`${owner} access policy is invalid.`, issues)
    }
    log.debug(`${requestId} - ${owner} access policy is invalid:`,
        JSON.stringify({issues}))
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
          if (error.status === Status.NOT_FOUND) return null
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
      effectiveSubject = 'repo:${origin}:' + effectiveSubject
    }
    effectiveSubject = effectiveSubject.replaceAll('${origin}', `${owner}/${repo}`)

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
    const regexp = escapeRegexp(subjectPattern)
        .replace(/\\\*/g, '[^:]+') // replace * with match one or more characters except ':' char
        .replace(/\\\?/g, '[^:]') // replace ? with match one characters except ':' char
    return RegExp(`^${regexp}$`, 'i')
  }
}
