import {Octokit} from '@octokit/rest'
import {
  GitHubAccessStatement,
  GitHubActionsJwtPayload,
  GitHubAppInstallation,
  GitHubAppInstallationAccessToken,
  GitHubAppPermissions,
  GitHubAppRepositoryPermissions,
  GitHubOwnerAccessPolicy,
  GitHubRepositoryAccessPolicy,
  PolicyError,
} from './common/types.js'
import {formatZodIssue, YamlTransformer} from './common/zod-utils.js'
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
} from './common/common-utils.js'
import {
  GitHubAccessStatementSchema,
  GitHubAppPermissionsSchema,
  GitHubAppRepositoryPermissionsSchema,
  GitHubOwnerAccessPolicySchema,
  GitHubRepositoryAccessPolicySchema,
  GitHubSubjectClaimSchema,
} from './common/schemas.js'
import {ZodSchema} from 'zod'
import {
  aggregatePermissions,
  normalizePermissionScopes,
  parseSubject,
  verifyPermissions,
  verifyRepositoryPermissions,
} from './common/github-utils.js'
import {Status} from './common/http-utils.js'
import {components} from '@octokit/openapi-types'
import {createAppAuth} from '@octokit/auth-app'
import limit from 'p-limit'
import {config} from './config.js'
import log from './logger.js'

/**
 * GitHub Access Manager
 * @param appAuth - GitHub App authentication
 * @returns access token manager
 */
export async function accessTokenManager(appAuth: {
  appId: string,
  privateKey: string,
}) {
  const GITHUB_APP_CLIENT = new Octokit({authStrategy: createAppAuth, auth: appAuth})
  const GITHUB_APP = await GITHUB_APP_CLIENT.apps.getAuthenticated()
      .then((res) => res.data!)

  /**
   * Creates a GitHub Actions Access Token
   * @param callerIdentity - caller identity
   * @param tokenRequest - token request
   * @returns access token
   */
  async function createGitHubActionsAccessToken(
      callerIdentity: GitHubActionsJwtPayload,
      tokenRequest: {
        owner: string, repositories?: string[],
        scope: 'owner', permissions: GitHubAppPermissions,
      } | {
        owner: string, repositories: string[],
        scope: 'repos', permissions: GitHubAppRepositoryPermissions
      },
  ) {
    // TODO ensure tokenRequest permissions are for scope

    // --- verify app installation ---------------------------------------------------------------------------------

    const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {
      owner: tokenRequest.owner,
    })
    if (!appInstallation) {
      throw new GithubAccessTokenError(`${GITHUB_APP.name} has not been installed for ${tokenRequest.owner}.\n` +
          `Install from ${GITHUB_APP.html_url}`)
    }
    log.debug({appInstallation}, 'App installation')

    const rejectedAppInstallationPermissions = verifyPermissions({
      requested: tokenRequest.permissions,
      granted: normalizePermissionScopes(appInstallation.permissions),
    }).denied.map(({scope, permission}) => ({
      scope, permission,
      // eslint-disable-next-line max-len
      reason: `Permission has not been granted to ${GITHUB_APP.name} installation for ${tokenRequest.owner}.`,
    }))

    if (hasEntries(rejectedAppInstallationPermissions)) {
      throw new GithubAccessTokenError(createErrorMessage(rejectedAppInstallationPermissions))
    }

    const appInstallationClient = await createOctokit(GITHUB_APP_CLIENT, appInstallation, {
      // single_file to read access policy files
      permissions: {single_file: 'read'},
    })

    // --- verify requested token permissions ------------------------------------------------------------------------

    const pendingTokenPermissions: Record<string, string> = {...tokenRequest.permissions}
    const rejectedTokenPermissions: {
      reason: string,
      scope: string, permission: string,
    }[] = []
    // granted token permission object will be used as safeguard to prevent unintentional permission granting
    const grantedTokenPermissions: Record<string, string> = {}

    const ownerAccessPolicy = await getOwnerAccessPolicy(appInstallationClient, {
      owner: tokenRequest.owner, repo: config.accessPolicyLocation.owner.repo,
      path: config.accessPolicyLocation.owner.path,
      strict: false, // ignore invalid access policy entries
    })
    log.debug({ownerAccessPolicy}, `${tokenRequest.owner} access policy:`)

    // --- verify allowed caller identities --------------------------------------------------------------------------
    const effectiveCallerIdentitySubjects = getEffectiveCallerIdentitySubjects(callerIdentity)

    if (ownerAccessPolicy['allowed-subjects'].length > 0) {
      if (!ownerAccessPolicy['allowed-subjects'].some((it) => effectiveCallerIdentitySubjects
          .some((subject) => matchSubjectPattern(it, subject, false)))) {
        throw new GithubAccessTokenError(
            `OIDC token subject is not allowed by ${tokenRequest.owner} owner access policy.\n` +
            'Effective token subjects:\n' +
            effectiveCallerIdentitySubjects.map((subject) => `- ${subject}`,).join('\n'))
      }
    }

    const ownerGrantedPermissions = evaluateGrantedPermissions({
      statements: ownerAccessPolicy.statements,
      callerIdentitySubjects: effectiveCallerIdentitySubjects,
    })

    switch (tokenRequest.scope) {
      case 'owner': {
        // === owner scope permission verification ===================================================================

        verifyPermissions({
          granted: ownerGrantedPermissions,
          requested: pendingTokenPermissions,
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
        // === repo scope permission verification ====================================================================

        // --- handle owner granted permissions
        verifyPermissions({
          // BE AWARE to grant repository permissions only
          granted: verifyRepositoryPermissions(ownerGrantedPermissions).valid,
          requested: pendingTokenPermissions,
        }).granted.forEach(({scope, permission}) => {
          // permission granted
          grantedTokenPermissions[scope] = permission
          delete pendingTokenPermissions[scope]
        })

        // --- handle repository granted permissions
        verifyPermissions({
          // restrict repository permissions to allowed repository permissions by owner access policy
          // BE AWARE to grant repository permissions only
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
                  log.debug({repoAccessPolicy}, `${tokenRequest.owner}/${repo} access policy`)

                  const repoGrantedPermissions = evaluateGrantedPermissions({
                    statements: repoAccessPolicy.statements,
                    callerIdentitySubjects: effectiveCallerIdentitySubjects,
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
      throw new GithubAccessTokenError(createErrorMessage(rejectedTokenPermissions, effectiveCallerIdentitySubjects))
    }

    // --- create requested access token ---------------------------------------------------------------------------

    // SAFEGUARD, should never happen
    if (hasEntries(pendingTokenPermissions)) {
      throw new Error('Unexpected pending permissions.')
    }

    return {
      ...await createInstallationAccessToken(
          GITHUB_APP_CLIENT, appInstallation, {
            // BE AWARE that an empty object will result in a token with all app installation permissions
            permissions: ensureHasEntries(grantedTokenPermissions),
            // BE AWARE that an empty array will result in a token with access to all app installation repositories
            repositories: tokenRequest.scope === 'repos' ?
                ensureHasEntries(tokenRequest.repositories) :
                undefined,
          }),
      owner: appInstallation.account?.name ?? tokenRequest.owner,
    }
  }

  /**
   * Create error message
   * @param rejectedTokenPermissions - rejected token permissions
   * @param callerIdentitySubjects - caller identity subjects
   * @returns error message
   */
  function createErrorMessage(
      rejectedTokenPermissions: {
        reason: string,
        scope: string, permission: string,
      }[],
      callerIdentitySubjects?: string[]
  ): string {
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
    return message
  }

  /**
   * Get owner access policy
   * @param client - GitHub client for target repository
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
   * @param client - GitHub client for target repository
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
  function filterValidStatements(statements: unknown[], permissionsType: 'owner' | 'repo')
      : unknown | GitHubAccessStatement[] {
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
  function filterValidPermissions(permissions: Record<string, unknown>, type: 'owner' | 'repo')
      : Record<string, unknown> {
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
   * Normalise access policy statement
   * @param statement - access policy statement
   * @param owner - policy owner
   * @param repo - policy repository
   * @returns void
   */
  function normaliseAccessPolicyStatement(statement: { subjects: string[] }, {owner, repo}: {
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
   * @param callerIdentitySubjects - caller identity subjects
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

  return {
    createAccessToken: createGitHubActionsAccessToken,
  }
}


// --- GitHub Functions ----------------------------------------------------------------------------------------------

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
          .catch(async (error) => error.status === Status.NOT_FOUND ? null : _throw(error)),
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
        if ('type' in res.data && res.data.type === 'file') {
          if (maxSize !== undefined && res.data.size > maxSize) {
            throw new Error(`Expect file size to be less than ${maxSize}b, but was ${res.data.size}b` +
                `${owner}/${repo}/${path}`)
          }
          return Buffer.from(
              res.data.content,
              'base64').toString()
        }

        throw new Error('Unexpected file content')
      })
      .catch((error) => {
        if (error.status === Status.NOT_FOUND) return null
        throw error
      })
}


// --- Errors ------------------------------------------------------------------------------------------------------

/**
 * Represents a GitHub access token error
 */
export class GithubAccessTokenError extends Error {
  /**
   * Creates a new GitHub access token error
   * @param msg - error message
   */
  constructor(msg: string,) {
    super(msg)

    Object.setPrototypeOf(this, GithubAccessTokenError.prototype)
  }
}
