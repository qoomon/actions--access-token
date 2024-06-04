import {createVerifier} from 'fast-jwt'
import process from 'process'
import {Octokit} from '@octokit/rest'
import {createAppAuth} from '@octokit/auth-app'
import {components} from '@octokit/openapi-types'
import {
  GitHubAccessStatement,
  GitHubActionsJwtPayload,
  GitHubAppInstallation,
  GitHubAppInstallationAccessToken,
  GitHubAppPermissions, GitHubAppRepositoryPermissions, GitHubOwnerAccessPolicy, GitHubRepositoryAccessPolicy,
  PolicyError,
} from './lib/types.js'
import {
  AccessTokenRequestBodySchema,
  GitHubOwnerAccessPolicySchema,
  GitHubRepositoryAccessPolicySchema,
  GitHubAccessStatementSchema,
  GitHubAppPermissionsSchema,
  GitHubSubjectClaimSchema, GitHubAppRepositoryPermissionsSchema,
} from './lib/schemas.js'
import {formatZodIssue, YamlTransformer} from './lib/zod-utils.js'
import {
  _throw,
  ensureHasEntries,
  escapeRegexp,
  filterObjectEntries,
  hasEntries,
  indent,
  isRecord,
  mapObjectEntries,
  retry,
  unique,
} from './lib/common-utils.js'
import {buildJwksKeyFetcher} from './lib/jwt-utils.js'
import {
  aggregatePermissions,
  parseRepository,
  parseSubject,
  verifyPermissions, verifyRepositoryPermissions,
} from './lib/github-utils.js'
import limit from 'p-limit'
import {Hono} from 'hono'
import {prettyJSON} from 'hono/pretty-json'
import {
  debugLogger,
  errorHandler,
  notFoundHandler,
  parseJsonBody,
  setRequestId,
  setRequestLogger,
  tokenVerifier,
} from './lib/hono-utils.js'
import {Status} from './lib/http-utils.js'
import {HTTPException} from 'hono/http-exception'
import {bodyLimit} from 'hono/body-limit'
import {sha256} from 'hono/utils/crypto'
import {ZodSchema} from 'zod'
import pino, {Logger} from 'pino'

/**
 * This function will initialize the application
 * @returns application
 */

// --- Configuration -------------------------------------------------------------------------------------------------
const log = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => ({level: label.toUpperCase()}),
  },
  transport: process.env.LOG_PRETTY === 'true' ? {target: 'pino-pretty', options: {sync: true}} : undefined,

})

const {config} = await import('./config.js')
log.debug({
  config: {
    ...config, githubAppAuth: {
      ...config.githubAppAuth, privateKey: '***',
    },
  },
}, 'Config')

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
log.debug({githubApp: GITHUB_APP_INFOS}, 'GitHub app')

// --- Server Setup --------------------------------------------------------------------------------------------------

export const app = new Hono<{
  Variables: {
    log: Logger
    id: string
  }
}>()
app.use(setRequestId())
app.use(setRequestLogger(log))
app.use(debugLogger())
app.onError(errorHandler())
app.notFound(notFoundHandler())

app.use(bodyLimit({maxSize: 100 * 1024})) // 100kb
app.use(prettyJSON())

app.post('/access_tokens',
    tokenVerifier<GitHubActionsJwtPayload>(GITHUB_OIDC_TOKEN_VERIFIER),
    async (context) => {
      const requestLog = context.get('log')
      const callerIdentity = context.get('token')
      requestLog.info({
        callerIdentity: {
          workflow_ref: callerIdentity.workflow_ref,
          run_id: callerIdentity.run_id,
          attempts: callerIdentity.attempts,
        },
        // workflowRunUrl example: https://github.com/qoomon/actions--access-token/actions/runs/9192965843/attempts/2
        workflowRunUrl: `https://github.com/${callerIdentity.repository}/actions` +
            `/runs/${callerIdentity.run_id}/attempts/${callerIdentity.attempts}`,
      }, `Caller Identity: ${callerIdentity.workflow_ref}`)

      const callerIdentitySubjects = getEffectiveCallerIdentitySubjects(callerIdentity)

      const tokenRequest = await parseJsonBody(context.req, AccessTokenRequestBodySchema)
          .then((it) => {
            // use caller repository owner as default target owner
            it.owner = it.owner || callerIdentity.repository_owner

            if (Object.entries(it.permissions).length === 0) {
              throw new HTTPException(Status.BAD_REQUEST, {
                message: 'Token permissions must not be empty.',
              })
            }

            switch (it.scope) {
              case 'owner': {
                return it as typeof it & { scope: 'owner', owner: string, permissions: GitHubAppPermissions }
              }
              case 'repos': {
                if (!hasEntries(it.repositories)) {
                  if (it.owner !== callerIdentity.repository_owner) {
                    throw new HTTPException(Status.BAD_REQUEST, {
                      message: 'Token repositories must not be empty for remote \'owner\' and  scope \'repos\'.',
                    })
                  }

                  // use caller repository as default repository
                  it.repositories = [parseRepository(callerIdentity.repository).repo]
                }

                // ensure only repository permissions are requested
                const invalidRepositoryPermissionScopes = verifyRepositoryPermissions(it.permissions).invalid
                if (hasEntries(invalidRepositoryPermissionScopes)) {
                  throw new HTTPException(Status.BAD_REQUEST, {
                    message: 'Invalid permissions scopes for token scope \'repos\'.\n' +
                        Object.keys(invalidRepositoryPermissionScopes).map((scope) => `- ${scope}`).join('\n'),
                  })
                }

                return it as typeof it & { scope: 'repos', owner: string, permissions: GitHubAppRepositoryPermissions }
              }
              default:
                throw new HTTPException(Status.BAD_REQUEST, {message: 'Invalid token scope.'})
            }
          })
      requestLog.info({tokenRequest},
          'Token Request')

      // --- verify app installation ---------------------------------------------------------------------------------

      const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {
        owner: tokenRequest.owner,
      })
      if (!appInstallation) {
        throw new HTTPException(Status.FORBIDDEN, {
          message: `${GITHUB_APP_INFOS.name} has not been installed for ${tokenRequest.owner}.\n` +
              `Install from ${GITHUB_APP_INFOS.html_url}`,
        })
      }
      requestLog.debug({appInstallation},
          'App installation')

      const rejectedAppInstallationPermissions = verifyPermissions({
        requested: tokenRequest.permissions,
        granted: appInstallation.permissions,
      }).denied.map(({scope, permission}) => ({
        scope, permission,
        // eslint-disable-next-line max-len
        reason: `Permission has not been granted to ${GITHUB_APP_INFOS.name} installation for ${tokenRequest.owner}.`,
      }))

      if (hasEntries(rejectedAppInstallationPermissions)) {
        throw createPermissionRejectedHttpException(rejectedAppInstallationPermissions)
      }

      const appInstallationClient = await createOctokit(GITHUB_APP_CLIENT, appInstallation, {
        // single_file to read access policy files
        permissions: {single_file: 'read'},
      })

      // --- verify requested token permissions --------------------------------------------------------------------------

      const pendingTokenPermissions: Record<string, string> = {...tokenRequest.permissions}
      const rejectedTokenPermissions: {
        reason: string,
        scope: string, permission: string,
      }[] = []
      // granted token permission object will be used as safeguard to prevent unintentional permission granting
      const grantedTokenPermissions: Record<string, string> = {}

      // --- handle owner access policy ------------------------------------------------------------------------------

      const ownerAccessPolicy = await getOwnerAccessPolicy(appInstallationClient, {
        owner: tokenRequest.owner, repo: config.accessPolicyLocation.owner.repo,
        path: config.accessPolicyLocation.owner.path,
        strict: false, // ignore invalid access policy entries
      })
      requestLog.debug({ownerAccessPolicy},
          `${tokenRequest.owner} access policy:`)

      if (ownerAccessPolicy['allowed-subjects'].length > 0) {
        if (!ownerAccessPolicy['allowed-subjects'].some((it) => callerIdentitySubjects
            .some((subject) => matchSubjectPattern(it, subject, false)))) {
          throw new HTTPException(Status.FORBIDDEN, {
            message: `OIDC token subject is not allowed by ${tokenRequest.owner} owner access policy.\n` +
                'Effective token subjects:\n' +
                callerIdentitySubjects.map((subject) => `- ${subject}`,).join('\n'),
          })
        }
      }

      const ownerGrantedPermissions = evaluateGrantedPermissions({
        statements: ownerAccessPolicy.statements,
        callerIdentitySubjects,
      })

      switch (tokenRequest.scope) {
        case 'owner': {
          verifyPermissions({
            granted: ownerGrantedPermissions,
            requested: tokenRequest.permissions,
          }).granted.forEach(({scope, permission}) => {
            // permission granted
            grantedTokenPermissions[scope] = permission
            delete pendingTokenPermissions[scope]
          })

          // reject all pending permissions
          Object.entries(pendingTokenPermissions).forEach(([scope, permission]) => {
            rejectedTokenPermissions.push({
              reason: `Permission has not been granted by ${tokenRequest.owner}.`,
              scope, permission,
            })
          })
          break
        }
        case 'repos': {
          // --- handle owner granted permissions
          verifyPermissions({
            granted: verifyRepositoryPermissions(ownerGrantedPermissions).valid,
            requested: tokenRequest.permissions,
          }).granted.forEach(({scope, permission}) => {
            // permission granted
            grantedTokenPermissions[scope] = permission
            delete pendingTokenPermissions[scope]
          })

          // --- handle repository granted permissions

          // restrict repository permissions to allowed by owner access policy
          verifyPermissions({
            granted: verifyRepositoryPermissions(ownerAccessPolicy['allowed-repository-permissions']).valid,
            requested: pendingTokenPermissions,
          }).denied.forEach(({scope, permission}) => {
            // reject permission
            rejectedTokenPermissions.push({
              reason: `Permission is not allowed by ${tokenRequest.owner} owner policy.`,
              scope, permission,
            })
          })

          // --- handle repository access policies -----------------------------------------------------------------------
          if (!hasEntries(rejectedTokenPermissions)) {
            const pendingRepositoryTokenPermissions = verifyRepositoryPermissions(pendingTokenPermissions).valid
            if (hasEntries(pendingRepositoryTokenPermissions)) {
              const pendingRepositoryTokenScopesByRepository: Record<string, Set<string>> =
                  Object.fromEntries(Object.keys(pendingRepositoryTokenPermissions)
                      .map((scope) => [scope, new Set(tokenRequest.repositories)]))

              const limitRepoPermissionRequests = limit(8)
              await Promise.all(
                  tokenRequest.repositories.map((repo) => limitRepoPermissionRequests(async () => {
                    const repoAccessPolicy = await getRepoAccessPolicy(appInstallationClient, {
                      owner: tokenRequest.owner, repo,
                      path: config.accessPolicyLocation.repo.path,
                      strict: false, // ignore invalid access policy entries
                    })
                    requestLog.debug({repoAccessPolicy},
                        `${tokenRequest.owner}/${repo} access policy`)

                    const repoGrantedPermissions = evaluateGrantedPermissions({
                      statements: repoAccessPolicy.statements,
                      callerIdentitySubjects,
                    })

                    // verify requested token permissions by repository permissions
                    const verifiedRepoPermissions = verifyPermissions({
                      granted: repoGrantedPermissions,
                      requested: pendingTokenPermissions,
                    })
                    verifiedRepoPermissions.granted.forEach(({scope}) => {
                      // permission granted
                      pendingRepositoryTokenScopesByRepository[scope].delete(repo)
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

              // grant repository permission only if all repositories have granted the specific permission
              Object.entries(pendingRepositoryTokenScopesByRepository).forEach(([scope, repositories]) => {
                if (repositories.size == 0) {
                  grantedTokenPermissions[scope] = pendingTokenPermissions[scope]
                  delete pendingTokenPermissions[scope]
                }
              })
            }
          }
          break
        }
        default:
          throw new Error('Invalid token scope.')
      }


      if (hasEntries(rejectedTokenPermissions)) {
        throw createPermissionRejectedHttpException(rejectedTokenPermissions, callerIdentitySubjects)
      }

      // --- create requested access token ---------------------------------------------------------------------------

      // SAFEGUARD, should never happen
      if (hasEntries(pendingTokenPermissions)) {
        throw new Error('Unexpected pending permissions.')
      }

      const appInstallationAccessToken = await createInstallationAccessToken(
          GITHUB_APP_CLIENT, appInstallation, {
            // BE AWARE that an empty object will result in a token with all app installation permissions
            permissions: ensureHasEntries(grantedTokenPermissions),
            // BE AWARE that an empty array will result in a token with access to all app installation repositories
            repositories: tokenRequest.scope === 'repos' ?
                ensureHasEntries(tokenRequest.repositories) :
                undefined,
          })

      // --- response with requested access token --------------------------------------------------------------------
      const tokenResponseBody = {
        token: appInstallationAccessToken.token,
        expires_at: appInstallationAccessToken.expires_at,
        permissions: appInstallationAccessToken.permissions,
        repositories: appInstallationAccessToken.repositories?.map((it) => it.name),
        owner: appInstallation.account?.name ?? tokenRequest.owner,
      }
      requestLog.info({
        ...tokenResponseBody,
        token: '***',
        token_hash: await sha256(appInstallationAccessToken.token)
            .then((it) => Buffer.from(it!).toString('base64')),
      }, `Action access token`)

      return context.json(tokenResponseBody)
    })

/**
 * Create permission rejected http exception
 * @param rejectedTokenPermissions - rejected token permissions
 * @param callerIdentitySubjects - caller identity subjects
 * @returns http exception
 */
function createPermissionRejectedHttpException(rejectedTokenPermissions: {
  reason: string,
  scope: string, permission: string,
}[], callerIdentitySubjects?: string[]): HTTPException {
  let message = 'Some requested permissions got rejected.\n' +
      rejectedTokenPermissions.map(({scope, permission, reason}) => '' +
          '- ' + `${scope}: ${permission}\n` +
          indent(reason),
      ).join('\n')

  if (callerIdentitySubjects?.length) {
    message += '\n' +
        'Effective token subjects:\n' +
        callerIdentitySubjects.map((subject) => `- ${subject}`,).join('\n')
  }
  return new HTTPException(Status.FORBIDDEN, {message})
}

// --- Server Functions ------------------------------------------------------------------------------------------------

/**
 * Normalise permission scopes to dash case
 * @param permissions - permission object
 * @returns normalised permission object
 */
function normalizePermissionScopes(permissions: Record<string, string>): Record<string, string> {
  return mapObjectEntries(permissions, ([scope, permission]) => [
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
    permissions: ensureHasEntries(mapObjectEntries(permissions, ([scope, permission]) => [
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
 * Get owner access policy
 * @param client - github client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @param strict - throw error on invalid access policy
 * @returns access policy
 */
async function getOwnerAccessPolicy(client: Octokit, {owner, repo, path, strict}: {
  owner: string,
  repo: string,
  path: string,
  strict: boolean,
}): Promise<Omit<GitHubOwnerAccessPolicy, 'origin'>> {
  const emptyPolicy: Omit<GitHubOwnerAccessPolicy, 'origin'> = {
    'statements': [],
    'allowed-subjects': [],
    'allowed-repository-permissions': {},
  }
  const policyValue = await getRepositoryFileContent(client, {
    owner, repo, path,
    maxSize: 100 * 1024, // 100kb
  })

  if (!policyValue) {
    return emptyPolicy
  }

  const policyParseResult = YamlTransformer
      .transform((policyObject) => {
        if (strict) return policyObject

        // ignore invalid entries
        if (isRecord(policyObject)) {
          if (Array.isArray(policyObject['allowed-subjects'])) {
            policyObject['allowed-subjects'] = filterValidSubjects(
                policyObject['allowed-subjects'])
          }
          if (isRecord(policyObject['allowed-repository-permissions'])) {
            policyObject['allowed-repository-permissions'] = filterValidPermissions(
                policyObject['allowed-repository-permissions'], 'owner')
          }
          if (Array.isArray(policyObject.statements)) {
            policyObject.statements = filterValidStatements(
                policyObject.statements, 'owner')
          }
        }

        return policyObject
      })
      .pipe(GitHubOwnerAccessPolicySchema)
      .safeParse(policyValue)

  if (policyParseResult.error) {
    const issues = policyParseResult.error.issues.map(formatZodIssue)
    if (strict) {
      throw new PolicyError(`${owner} access policy is invalid.`, issues)
    }
    log.debug({issues}, `${owner} access policy is invalid.`)
    return emptyPolicy
  }

  const policy = policyParseResult.data

  const expectedPolicyOrigin = `${owner}/${repo}`
  if (policy.origin.toLowerCase() !== expectedPolicyOrigin.toLowerCase()) {
    const issues = [`policy origin '${policy.origin}' does not match repository '${expectedPolicyOrigin}'`]
    if (strict) {
      throw new PolicyError(`${owner} owner access policy is invalid.`, issues)
    }
    log.debug({issues}, `${owner} owner access policy is invalid.`)
    return emptyPolicy
  }

  policy.statements.forEach((statement) => {
    normaliseAccessPolicyStatement(statement, {owner, repo})
  })

  return policy
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
async function getRepoAccessPolicy(client: Octokit, {owner, repo, path, strict}: {
  owner: string,
  repo: string,
  path: string,
  strict: boolean,
}): Promise<Omit<GitHubRepositoryAccessPolicy, 'origin'>> {
  const emptyPolicy: Omit<GitHubRepositoryAccessPolicy, 'origin'> = {
    statements: [],
  }
  const policyValue = await getRepositoryFileContent(client, {
    owner, repo, path,
    maxSize: 100 * 1024, // 100kb
  })
  if (!policyValue) {
    return emptyPolicy
  }

  const policyParseResult = YamlTransformer
      .transform((policyObject) => {
        if (strict) return policyObject
        // ignore invalid entries
        if (isRecord(policyObject) && Array.isArray(policyObject.statements)) {
          policyObject.statements = filterValidStatements(
              policyObject.statements, 'repo')
        }
        return policyObject
      })
      .pipe(GitHubRepositoryAccessPolicySchema)
      .safeParse(policyValue)

  if (policyParseResult.error) {
    const issues = policyParseResult.error.issues.map(formatZodIssue)
    if (strict) {
      throw new PolicyError(`${owner}/${repo} repository access policy is invalid.`, issues)
    }
    log.debug({issues}, `${owner}/${repo} repository access policy is invalid.`)
    return emptyPolicy
  }

  const policy = policyParseResult.data

  const expectedPolicyOrigin = `${owner}/${repo}`
  if (policy.origin.toLowerCase() !== expectedPolicyOrigin.toLowerCase()) {
    const issues = [`policy origin '${policy.origin}' does not match repository '${expectedPolicyOrigin}'`]
    if (strict) {
      throw new PolicyError(`${owner} access policy is invalid.`, issues)
    }
    log.debug({issues}, `${owner} access policy is invalid.`)
    return emptyPolicy
  }

  policy.statements.forEach((statement) => {
    normaliseAccessPolicyStatement(statement, {owner, repo})
  })

  return policy
}

/**
 * Filter invalid access policy statements
 * @param statements - access policy statements
 * @param permissionsType - permission type
 * @returns valid statements
 */
function filterValidStatements(
    statements: unknown[],
    permissionsType: 'owner' | 'repo'
): unknown | GitHubAccessStatement[] {
  return statements
      .map((statementObject: unknown) => {
        if (isRecord(statementObject)) {
          // ---- subjects
          if ('subjects' in statementObject && Array.isArray(statementObject.subjects)) {
            // ignore invalid subjects
            statementObject.subjects = filterValidSubjects(statementObject.subjects)
          }
          // ---- permissions
          if ('permissions' in statementObject && isRecord(statementObject.permissions)) {
            // ignore invalid permissions
            statementObject.permissions = filterValidPermissions(statementObject.permissions, permissionsType)
          }
        }
        return statementObject
      })
      .filter((statementObject: unknown) => GitHubAccessStatementSchema.safeParse(statementObject).success)
}

/**
 * Filter invalid subjects
 * @param subjects - access policy subjects
 * @returns valid subjects
 */
function filterValidSubjects(subjects: unknown[]): unknown[] {
  return subjects.filter((it: unknown) => GitHubSubjectClaimSchema.safeParse(it).success)
}

/**
 * Filter invalid permissions
 * @param permissions - access policy permissions
 * @param type - permission type
 * @returns valid permissions
 */
function filterValidPermissions(
    permissions: Record<string, unknown>,
    type: 'owner' | 'repo'
): Record<string, unknown> {
  let permissionSchema: ZodSchema
  switch (type) {
    case 'owner':
      permissionSchema = GitHubAppPermissionsSchema
      break
    case 'repo':
      permissionSchema = GitHubAppRepositoryPermissionsSchema
      break
    default:
      throw new Error('Invalid permission type.')
  }

  return filterObjectEntries(permissions, ([key, value]) => permissionSchema.safeParse({[key]: value}).success)
}

/**
 * Get repository file content
 * @param client - GitHub client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @param maxSize - max file size
 * @returns file content or null if file does not exist
 */
async function getRepositoryFileContent(client: Octokit, {owner, repo, path, maxSize}: {
  owner: string,
  repo: string,
  path: string,
  maxSize?: number
}): Promise<string | null> {
  return await client.repos.getContent({owner, repo, path})
      .then((res) => {
        if ('type' in res.data && res.data.type !== 'file') {
          if (maxSize !== undefined && res.data.size > maxSize) {
            throw new Error(`Expect file size to be less than ${maxSize}b, but was ${res.data.size}b` +
                `${owner}/${repo}/${path}`)
          }
          return Buffer.from(
              // @ts-expect-error - content will not be null, because we request a file
              res.data.content ?? '',
              'base64').toString()
        }

        throw new Error('unexpected response')
      })
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
  return subject.replaceAll('${origin}', `${owner}/${repo}`)
}

/**
 * Evaluate granted permissions for caller identity
 * @param accessPolicy - access policy
 * @param callerIdentity - caller identity
 * @returns granted permissions
 */
function evaluateGrantedPermissions({statements, callerIdentitySubjects}: {
  statements: GitHubAccessStatement[],
  callerIdentitySubjects: string[],
}): Record<string, string> {
  const permissions = statements
      .filter(statementSubjectPredicate(callerIdentitySubjects))
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
}

/**
 * Get effective caller identity subjects
 * @param callerIdentity - caller identity
 * @returns effective caller identity subjects
 */
function getEffectiveCallerIdentitySubjects(callerIdentity: GitHubActionsJwtPayload): string[] {
  const subjects = [callerIdentity.sub]

  // --- add artificial subjects

  // repo : ref
  // => repo:qoomon/sandbox:ref:refs/heads/main
  subjects.push(`repo:${callerIdentity.repository}:ref:${callerIdentity.ref}`)

  // repo : workflow_ref
  // => repo:qoomon/sandbox:workflow_ref:qoomon/sandbox/.github/workflows/build.yml@refs/heads/main
  subjects.push(`repo:${callerIdentity.repository}:workflow_ref:${callerIdentity.workflow_ref}`)

  // repo : job_workflow_ref
  // => repo:qoomon/sandbox:job_workflow_ref:qoomon/sandbox/.github/workflows/build.yml@refs/heads/main
  subjects.push(`repo:${callerIdentity.repository}:job_workflow_ref:${callerIdentity.job_workflow_ref}`)

  if (callerIdentity.environment) {
    // repo : environment
    // => repo:qoomon/sandbox:environment:production
    subjects.push(`repo:${callerIdentity.repository}:environment:${callerIdentity.environment}`)
  }

  return unique(subjects)
}

/**
 * Verify if subject is granted by grantedSubjectPatterns
 * @param subjectPattern - subject pattern
 * @param subject - subject e.g. 'repo:spongebob/sandbox:ref:refs/heads/main'
 * @param strict - strict mode does not allow ** wildcards
 * @returns true if subject matches any granted subject pattern
 */
function matchSubjectPattern(subjectPattern: string, subject: string, strict: boolean = true): boolean {
  if (strict && subjectPattern.includes('**')) {
    return false
  }

  // claims must not contain wildcards to prevent granting access accidentally e.g. pull requests
  // e.g. repo:foo/bar:* is not allowed
  if (Object.keys(parseSubject(subjectPattern))
      .some((claim) => claim !== '**' && claim.includes('*'))) {
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
      .replace(/\\\*\\\*/g, '.*')
      .replace(/\\\*/g, '[^:]*') // replace * with match one or more characters except ':' char
      .replace(/\\\?/g, '[^:]') // replace ? with match one characters except ':' char
  return RegExp(`^${regexp}$`, 'i')
}
