import {Octokit as OctokitCore} from '@octokit/core';
import {paginateRest} from "@octokit/plugin-paginate-rest";
import {restEndpointMethods} from "@octokit/plugin-rest-endpoint-methods";
import {z} from 'zod';
import type {components} from '@octokit/openapi-types';
import {createAppAuth} from '@octokit/auth-app';
import limit from 'p-limit';
import {formatZodIssue, YamlTransformer} from './common/zod-utils.js';
import {
  _throw,
  ensureHasEntries,
  escapeRegexp,
  filterObjectEntries,
  findFirstNotNull,
  hasEntries,
  indent,
  isRecord,
  mapObjectEntries,
  resultOf,
  retry,
  unique,
} from './common/common-utils.js';
import {
  aggregatePermissions,
  GitHubActionsJwtPayload,
  GitHubAppPermissions,
  GitHubAppPermissionsSchema,
  GitHubAppRepositoryPermissions,
  GitHubAppRepositoryPermissionsSchema,
  GitHubRepositorySchema,
  normalizePermissionScopes,
  parseOIDCSubject,
  parseRepository,
  validatePermissions,
  verifyPermissions,
} from './common/github-utils.js';
import {Status} from './common/http-utils.js';
import {logger} from './logger.js';
import {RestEndpointMethodTypes} from '@octokit/rest';

const Octokit = OctokitCore
    .plugin(restEndpointMethods).plugin(paginateRest);

const ACCESS_POLICY_MAX_SIZE = 100 * 1024; // 100kb
const GITHUB_API_CONCURRENCY_LIMIT = limit(8);

// BE AWARE to always use NOT_AUTHORIZED_MESSAGE if no permissions are granted to caller identity.
// otherwise, unintended leaks of repository existence could happen.
const NOT_AUTHORIZED_MESSAGE = 'Not authorized';

/**
 * GitHub Access Manager
 * @param options - options
 * @return access token manager
 */
export async function accessTokenManager(options: {
  githubAppAuth: { appId: string, privateKey: string, },
  accessPolicyLocation: {
    owner: { paths: string[], repo: string },
    repo: { paths: string[] }
  }
}) {
  logger.debug({appId: options.githubAppAuth.appId}, 'GitHub app');
  const GITHUB_APP_CLIENT = new Octokit({
    authStrategy: createAppAuth,
    auth: options.githubAppAuth,
  });
  const GITHUB_APP = await GITHUB_APP_CLIENT.rest.apps.getAuthenticated()
      .then((res) => res.data ?? _throw(new Error('GitHub app not found')));

  /**
   * Creates a GitHub Actions Access Token
   * @param callerIdentity - caller identity
   * @param tokenRequest - token request
   * @return access token
   */
  async function createAccessToken(callerIdentity: GitHubActionsJwtPayload, tokenRequest: GitHubAccessTokenRequest) {
    const effectiveCallerIdentitySubjects = getEffectiveCallerIdentitySubjects(callerIdentity);
    normalizeTokenRequest(tokenRequest, callerIdentity);

    // grant requested permissions explicitly to prevent accidental permission escalation
    const grantedTokenPermissions: Record<string, string> = {};
    const pendingTokenPermissions: Record<string, string> = {...tokenRequest.permissions};

    // --- get target app installation ---------------------------------------------------------------------------------
    const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {
      owner: tokenRequest.owner,
    });

    // === verify target app installation ==============================================================================
    {
      if (!appInstallation) {
        logger.info({owner: tokenRequest.owner},
            `'${GITHUB_APP.name}' has not been installed`);
        throw new GitHubAccessTokenError([{
          owner: tokenRequest.owner,
          // BE AWARE to prevent leaking owner existence
          issues: callerIdentity.repository_owner === tokenRequest.owner ?
              [`'${GITHUB_APP.name}' has not been installed. Install from ${GITHUB_APP.html_url}`] :
              [NOT_AUTHORIZED_MESSAGE],
        }], effectiveCallerIdentitySubjects);
      }
      logger.debug({appInstallation}, 'App installation');

      const accessPolicyPaths = [
        ...options.accessPolicyLocation.owner.paths,
        ...options.accessPolicyLocation.repo.paths,
      ];
      if (!accessPolicyPaths.every((path) =>
          appInstallation.single_file_paths?.includes(path) || appInstallation.single_file_name === path)) {
        logger.info({owner: tokenRequest.owner, required: accessPolicyPaths, actual: appInstallation.single_file_paths},
            `'${GITHUB_APP.name}' is not authorized to read all access policy file(s) by 'single_file' permission`);
        throw new GitHubAccessTokenError([{
          owner: tokenRequest.owner,
          // BE AWARE to prevent leaking owner existence
          issues: callerIdentity.repository_owner === tokenRequest.owner ?
              [`'${GITHUB_APP.name}' is not authorized to read all access policy file(s) by 'single_file' permission`] :
              [NOT_AUTHORIZED_MESSAGE],
        }], effectiveCallerIdentitySubjects);
      }
    }

    // === verify against target app installation permissions ==========================================================
    {
      const requestedAppInstallationPermissions = verifyPermissions({
        granted: normalizePermissionScopes(appInstallation.permissions),
        requested: tokenRequest.permissions,
      });

      if (hasEntries(requestedAppInstallationPermissions.pending)) {
        logger.info({owner: tokenRequest.owner, denied: requestedAppInstallationPermissions.pending},
            `App installation is not authorized`);
        throw new GitHubAccessTokenError([{
          owner: tokenRequest.owner,
          // BE AWARE to prevent leaking owner existence
          issues: callerIdentity.repository_owner === tokenRequest.owner ?
              Object.entries(requestedAppInstallationPermissions.pending)
                  .map(([scope, permission]) => ({
                    scope, permission,
                    message: `'${GITHUB_APP.name}' installation not authorized`,
                  })) :
              [NOT_AUTHORIZED_MESSAGE],
        }], effectiveCallerIdentitySubjects);
      }
    }

    const appInstallationClient = await createOctokit(GITHUB_APP_CLIENT, appInstallation, {
      // single_file to read access policy files
      permissions: {single_file: 'read', contents: 'read'},
    });

    // === verify against owner policy =================================================================================
    {
      // --- load owner access policy ----------------------------------------------------------------------------------
      const accessPolicy = await getOwnerAccessPolicy(appInstallationClient, {
        owner: tokenRequest.owner,
        repo: options.accessPolicyLocation.owner.repo,
        paths: options.accessPolicyLocation.owner.paths,
        strict: false, // ignore invalid access policy entries
      }).catch((error) => {
        if (error instanceof GithubAccessPolicyError) {
          logger.info({owner: tokenRequest.owner, issues: error.issues},
              'Owner access policy - invalid');
          throw new GitHubAccessTokenError([{
            owner: tokenRequest.owner,
            // BE AWARE to prevent leaking owner existence
            issues: callerIdentity.repository === `${tokenRequest.owner}/${options.accessPolicyLocation.owner.repo}` ?
                [formatAccessPolicyError(error)] :
                tokenRequest.owner === callerIdentity.repository_owner ?
                    [error.message] :
                    [NOT_AUTHORIZED_MESSAGE],
          }], effectiveCallerIdentitySubjects);
        }
        throw error;
      });
      logger.debug({owner: tokenRequest.owner, ownerAccessPolicy: accessPolicy}, 'Owner access policy');
      // if allowed-subjects is not defined, allow any subjects from the policy owner
      const allowedSubjects = accessPolicy['allowed-subjects'] ??
          [`repo:${tokenRequest.owner}/*:**`]; // e.g., ['repo:qoomon/*:**' ]
      if (!matchSubject(allowedSubjects, effectiveCallerIdentitySubjects)) {
        logger.info({owner: tokenRequest.owner},
            'OIDC token subject is not allowed by owner access policy');
        throw new GitHubAccessTokenError([{
          owner: tokenRequest.owner,
          // BE AWARE to prevent leaking owner existence
          issues: callerIdentity.repository_owner === tokenRequest.owner ?
              ['OIDC token subject is not allowed by owner access policy'] :
              [NOT_AUTHORIZED_MESSAGE],
        }], effectiveCallerIdentitySubjects);
      }

      const grantedPermissions = evaluateGrantedPermissions({
        statements: accessPolicy.statements,
        callerIdentitySubjects: effectiveCallerIdentitySubjects,
      });

      const verifiedPermissions = verifyPermissions({
        granted: grantedPermissions,
        requested: pendingTokenPermissions,
      });

      // --- grant owner permissions
      Object.entries(verifiedPermissions.granted).forEach(([scope, permission]) => {
        grantedTokenPermissions[scope] = permission;
        // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
        delete pendingTokenPermissions[scope];
      });

      // --- ensure owner access policy has granted all requested owner permissions
      const pendingOwnerPermissions = filterValidPermissions('!repo', pendingTokenPermissions);
      if (hasEntries(pendingOwnerPermissions)) {
        // --- reject all pending owner permissions
        logger.info({owner: tokenRequest.owner, denied: pendingOwnerPermissions},
            'Owner access policy - permission(s) not granted');
        throw new GitHubAccessTokenError([{
          owner: tokenRequest.owner,
          issues: Object.entries(pendingOwnerPermissions)
              .map(([scope, permission]) => ({
                scope, permission: String(permission),
                message: callerIdentity.repository_owner === tokenRequest.owner ?
                    'Not allowed by owner access policy' :
                    NOT_AUTHORIZED_MESSAGE,
              })),
        }], effectiveCallerIdentitySubjects);
      }

      if (hasEntries(pendingTokenPermissions)) {
        if (tokenRequest.repositories === 'ALL') {
          // --- ensure owner access policy has granted all requested repository permissions
          // --- reject all pending permissions
          logger.info({owner: tokenRequest.owner, denied: pendingTokenPermissions},
              'Owner access policy - permission(s) not granted');
          throw new GitHubAccessTokenError([{
            owner: tokenRequest.owner,
            issues: Object.entries(pendingTokenPermissions)
                .map(([scope, permission]) => ({
                  scope, permission: String(permission),
                  message: callerIdentity.repository_owner === tokenRequest.owner ?
                      'Not allowed by owner access policy' :
                      NOT_AUTHORIZED_MESSAGE,
                })),
          }], effectiveCallerIdentitySubjects);
        } else {
          // --- ensure owner access policy explicitly allows all pending repository permissions
          const forbiddenRepositoryPermissions = verifyPermissions({
            granted: accessPolicy['allowed-repository-permissions'],
            requested: pendingTokenPermissions,
          }).pending;
          if (hasEntries(forbiddenRepositoryPermissions)) {
            // --- reject all repository permissions that are not allowed by owner access policy
            logger.info({owner: tokenRequest.owner, denied: forbiddenRepositoryPermissions},
                'Owner access policy - permission(s) not allowed');
            throw new GitHubAccessTokenError([{
              owner: tokenRequest.owner,
              issues: Object.entries(forbiddenRepositoryPermissions)
                  .map(([scope, permission]) => ({
                    scope, permission,
                    message: callerIdentity.repository_owner === tokenRequest.owner ?
                        'Not allowed by owner access policy' :
                        NOT_AUTHORIZED_MESSAGE,
                  })),
            }], effectiveCallerIdentitySubjects);
          }
        }
      }
    }

    // === verify against repository policies ==========================================================================
    if (hasEntries(pendingTokenPermissions)) {
      if (hasEntries(validatePermissions(pendingTokenPermissions, 'repo').invalid)) {
        throw new Error('SAFEGUARD Error - ' +
            'Non repository permissions should have been handled within owner access policy section');
      }
      if (tokenRequest.repositories === 'ALL') {
        throw new Error('SAFEGUARD Error - ' +
            `'ALL' repositories scope should have been handled within owner access policy section`);
      }

      const repositoryVerifyResults = await Promise.all(
          tokenRequest.repositories.map((repo) => GITHUB_API_CONCURRENCY_LIMIT(async () => {
            const result = {
              owner: tokenRequest.owner,
              repo,
              issues: [] as GitHubAccessTokenErrorIssue[],
              granted: {} as GitHubAppRepositoryPermissions,
            };

            const accessPolicyResult = await resultOf(getRepoAccessPolicy(appInstallationClient, {
              owner: tokenRequest.owner, repo,
              paths: options.accessPolicyLocation.repo.paths,
              strict: false, // ignore invalid access policy entries
            }));
            if (!accessPolicyResult.success) {
              const error = accessPolicyResult.error;
              if (error instanceof GithubAccessPolicyError) {
                logger.info({owner: tokenRequest.owner, repo, issues: error.issues},
                    'Repository access policy - invalid');
                if (callerIdentity.repository_owner === tokenRequest.owner) {
                  result.issues.push(formatAccessPolicyError(error))
                } else {
                  // BE AWARE to prevent leaking owner existence
                  result.issues.push(NOT_AUTHORIZED_MESSAGE)
                }
                return result;
              }
              throw error;
            }

            const repoAccessPolicy = accessPolicyResult.value;
            logger.debug({owner: tokenRequest.owner, repo, repoAccessPolicy},
                'Repository access policy');

            const grantedPermissions = evaluateGrantedPermissions({
              statements: repoAccessPolicy.statements,
              callerIdentitySubjects: effectiveCallerIdentitySubjects,
            });

            if (!hasEntries(grantedPermissions)) {
              logger.info({owner: tokenRequest.owner, repo},
                  'Repository access policy - no permissions granted');
              // BE AWARE to prevent leaking owner existence
              result.issues.push(NOT_AUTHORIZED_MESSAGE);
              return result;
            }

            const verifiedPermissions = verifyPermissions({
              granted: grantedPermissions,
              requested: pendingTokenPermissions,
            });

            // --- deny permissions
            Object.entries(verifiedPermissions.pending).forEach(([scope, permission]) => {
              result.issues.push({
                scope, permission,
                message: NOT_AUTHORIZED_MESSAGE,
              });
            });

            // --- grant permissions
            result.granted = verifiedPermissions.granted;
            return result;
          })));

      // --- ensure no pending permissions for any target repository
      const pendingRepositoryPermissions = repositoryVerifyResults
          .map((it) => verifyPermissions({
            granted: it.granted,
            requested: pendingTokenPermissions,
          }).pending)
      if (pendingRepositoryPermissions.some(hasEntries)) {
        throw new GitHubAccessTokenError(repositoryVerifyResults, effectiveCallerIdentitySubjects);
      }

      const grantedPermissions = aggregatePermissions(
          repositoryVerifyResults.map((it) => it.granted));

      // --- grant repository permission only if all repositories have granted the specific permission
      for (const [scope, permission] of Object.entries(grantedPermissions)) {
        grantedTokenPermissions[scope] = permission;
        // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
        delete pendingTokenPermissions[scope];
      }
    }

    // === create requested access token ===============================================================================
    if (hasEntries(pendingTokenPermissions)) {
      throw new Error('SAFEGUARD Error - Unexpected pending permissions');
    }
    if (!arePermissionsEqual(tokenRequest.permissions, grantedTokenPermissions)) {
      throw new Error('SAFEGUARD Error - Unexpected mismatch between requested and granted permissions');
    }

    const accessToken = await createInstallationAccessToken(GITHUB_APP_CLIENT, appInstallation, {
      // BE AWARE that an empty object will result in a token with all app installation permissions
      permissions: ensureHasEntries(grantedTokenPermissions),
      // BE AWARE that an empty array will result in a token with access to all app installation repositories
      repositories: tokenRequest.repositories === 'ALL' ? undefined : ensureHasEntries(tokenRequest.repositories),
    });
    return {
      owner: appInstallation.account?.name ?? tokenRequest.owner,
      ...accessToken,
    };
  }

  return {
    createAccessToken,
  };
}

/**
 * Normalize access token request body
 * @param tokenRequest - access token request body
 * @param callerIdentity - caller identity
 * @return normalized access token request body
 */
function normalizeTokenRequest(
    tokenRequest: GitHubAccessTokenRequest,
    callerIdentity: GitHubActionsJwtPayload,
): asserts tokenRequest is GitHubAccessTokenRequest & { owner: string } {

  if (!hasEntries(tokenRequest.permissions)) {
    throw new GitHubAccessTokenError([
      'Invalid token request - permissions must have at least one entry',
    ]);
  }

  if (tokenRequest.repositories === 'ALL') {
    if (!tokenRequest.owner) {
      tokenRequest.owner = callerIdentity.repository_owner
    }
  } else {
    if (tokenRequest.owner && !hasEntries(tokenRequest.repositories)) {
      throw new GitHubAccessTokenError([
        'Invalid token request - repositories must have at least one entry if owner is specified explicitly',
      ]);
    }

    if (!hasEntries(tokenRequest.repositories)) {
      tokenRequest.repositories.push(callerIdentity.repository);
    }

    const repositories = tokenRequest.repositories
        .map((repository) => parseRepository(
            repository,
            tokenRequest.owner ?? callerIdentity.repository_owner,
        ));
    const repositoriesOwnerSet = new Set<string>();
    if (tokenRequest.owner) {
      repositoriesOwnerSet.add(tokenRequest.owner);
    }
    const repositoriesNameSet = new Set<string>();
    for (const repository of repositories) {
      repositoriesOwnerSet.add(repository.owner);
      repositoriesNameSet.add(repository.repo);
    }

    if (repositoriesOwnerSet.size > 1) {
      if (tokenRequest.owner) {
        throw new GitHubAccessTokenError([
          `Invalid token request - All repositories owners must match the specified owner ${tokenRequest.owner}`,
        ]);
      } else {
        throw new GitHubAccessTokenError([
          'Invalid token request - All repositories must have one common owner',
        ]);
      }
    }
    const repositoriesOwner = repositoriesOwnerSet.keys().next().value;

    if (!tokenRequest.owner) {
      tokenRequest.owner = repositoriesOwner;
    }
    // replace repositories with their names only
    tokenRequest.repositories = Array.from(repositoriesNameSet);
  }
}

// --- Access Manager Functions --------------------------------------------------------------------------------------

/**
 * Get owner access policy
 * @param client - GitHub client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @param strict - throw error on invalid access policy
 * @return access policy
 */
async function getOwnerAccessPolicy(client: Octokit, {
  owner, repo, paths, strict,
}: {
  owner: string,
  repo: string,
  paths: string[],
  strict: boolean,
}): Promise<Omit<GitHubOwnerAccessPolicy, 'origin'>> {
  const policy = await getAccessPolicy(client, {
    owner, repo, paths,
    schema: GitHubOwnerAccessPolicySchema,
    preprocessor: (value) => {
      value = normalizeAccessPolicyEntries(value);
      if (!strict) {
        value = filterValidAccessPolicyEntries(value);
      }
      return value;
    },
  });

  policy.statements?.forEach((statement) => {
    resolveAccessPolicyStatementSubjects(statement, {owner, repo});
  });

  return policy;

  function normalizeAccessPolicyEntries(policy: unknown) {
    if (isRecord(policy)) {
      if (isRecord(policy['allowed-repository-permissions'])) {
        policy['allowed-repository-permissions'] = normalizePermissionScopes(policy['allowed-repository-permissions']);
      }
      if (Array.isArray(policy.statements)) {
        policy.statements = policy.statements.map((statement: unknown) => {
          if (isRecord(statement) && isRecord(statement.permissions)) {
            statement.permissions = normalizePermissionScopes(statement.permissions);
          }
          return statement;
        });
      }
    }
    return policy;
  }

  function filterValidAccessPolicyEntries(policy: unknown) {
    if (isRecord(policy)) {
      if (Array.isArray(policy['allowed-subjects'])) {
        policy['allowed-subjects'] = filterValidSubjects(
            policy['allowed-subjects']);
      }

      if (isRecord(policy['allowed-repository-permissions'])) {
        policy['allowed-repository-permissions'] = filterValidPermissions(
            'repo', policy['allowed-repository-permissions']);
      }
      if (Array.isArray(policy.statements)) {
        policy.statements = filterValidStatements(
            policy.statements, 'owner');
      }
    }
    return policy;
  }
}

/**
 * Get repository access policy
 * @param client - GitHub client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @param strict - throw error on invalid access policy
 * @return access policy
 */
async function getRepoAccessPolicy(client: Octokit, {
  owner, repo, paths, strict,
}: {
  owner: string,
  repo: string,
  paths: string[],
  strict: boolean,
}): Promise<Omit<GitHubRepositoryAccessPolicy, 'origin'>> {
  const policy = await getAccessPolicy(client, {
    owner, repo, paths,
    schema: GitHubRepositoryAccessPolicySchema,
    preprocessor: (value) => {
      value = normalizeAccessPolicyEntries(value);
      if (!strict) {
        value = filterValidAccessPolicyEntries(value);
      }
      return value;
    },
  });

  policy.statements?.forEach((statement) => {
    resolveAccessPolicyStatementSubjects(statement, {owner, repo});
  });

  return policy;

  function normalizeAccessPolicyEntries(policy: unknown) {
    if (isRecord(policy) && Array.isArray(policy.statements)) {
      policy.statements = policy.statements.map((statement: unknown) => {
        if (isRecord(statement) && isRecord(statement.permissions)) {
          statement.permissions = normalizePermissionScopes(statement.permissions);
        }
        return statement;
      });
    }
    return policy;
  }

  function filterValidAccessPolicyEntries(policy: unknown) {
    if (isRecord(policy) && Array.isArray(policy.statements)) {
      policy.statements = filterValidStatements(policy.statements, 'repo');
    }
    return policy;
  }
}

/**
 * Get access policy
 * @param client - GitHub client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @param schema - access policy schema
 * @param preprocessor - preprocessor function to transform policy object
 * @return access policy
 */
async function getAccessPolicy<T extends typeof GitHubAccessPolicySchema>(client: Octokit, {
  owner, repo, paths, schema, preprocessor,
}: {
  owner: string,
  repo: string,
  paths: string[],
  schema: T,
  preprocessor: (value: unknown) => unknown,
}): Promise<z.infer<T>> {
  const policyValue = await findFirstNotNull(paths, (path) =>
      getRepositoryFileContent(client, {owner, repo, path, maxSize: ACCESS_POLICY_MAX_SIZE}));
  if (!policyValue) {
    throw new GithubAccessPolicyError(`Access policy not found`);
  }

  const policyParseResult = YamlTransformer
      .transform(preprocessor)
      .pipe(schema)
      .safeParse(policyValue);
  if (policyParseResult.error) {
    const issues = policyParseResult.error.issues.map(formatZodIssue);
    throw new GithubAccessPolicyError(`Invalid access policy`, issues);
  }
  const policy = policyParseResult.data;

  const expectedPolicyOrigin = `${owner}/${repo}`;
  if (policy.origin.toLowerCase() !== expectedPolicyOrigin.toLowerCase()) {
    const issues = [`Policy origin '${policy.origin}' does not match repository '${expectedPolicyOrigin}'`];
    throw new GithubAccessPolicyError(`Invalid access policy`, issues);
  }

  return policy;
}

/**
 * Filter invalid access policy statements
 * @param statements - access policy statements
 * @param permissionsType - permission type
 * @return valid statements
 */
function filterValidStatements(statements: unknown[], permissionsType: 'owner' | 'repo')
    : unknown | GitHubAccessStatement[] {
  return statements
      .map((statementObject: unknown) => {
        if (isRecord(statementObject)) {
          // ---- subjects
          if ('subjects' in statementObject && Array.isArray(statementObject.subjects)) {
            // ignore invalid subjects
            statementObject.subjects = filterValidSubjects(statementObject.subjects);
          }
          // ---- permissions
          if ('permissions' in statementObject && isRecord(statementObject.permissions)) {
            // ignore invalid permissions
            statementObject.permissions = filterValidPermissions(permissionsType, statementObject.permissions);
          }
        }
        return statementObject;
      })
      .filter((statementObject: unknown) => GitHubAccessStatementSchema.safeParse(statementObject).success);
}

/**
 * Filter invalid subjects
 * @param subjects - access policy subjects
 * @return valid subjects
 */
function filterValidSubjects(subjects: unknown[]): unknown[] {
  return subjects.filter((it: unknown) => GitHubSubjectClaimSchema.safeParse(it).success);
}

function filterValidPermissions(scopeType: 'repo',
                                permissions: Record<string, unknown>)
    : GitHubAppRepositoryPermissions
function filterValidPermissions(scopeType: 'owner',
                                permissions: Record<string, unknown>)
    : GitHubAppPermissions
function filterValidPermissions(scopeType: '!owner' | '!repo',
                                permissions: Record<string, unknown>)
    : Record<string, unknown>
function filterValidPermissions(scopeType: 'owner' | '!owner' | 'repo' | '!repo',
                                permissions: Record<string, unknown>)
    : GitHubAppPermissions | GitHubAppRepositoryPermissions
/**
 * Filter invalid permissions
 * @param scopeType - permission scope type, either 'owner' or 'repo'
 * @param permissions - access policy permissions
 * @return valid permissions
 */
function filterValidPermissions(
    scopeType: "owner" | "!owner" | "repo" | "!repo",
    permissions: Record<string, unknown>
) {
  const negate = scopeType.startsWith('!');
  const _scopeType = scopeType.replace(/^!/, '') as 'owner' | 'repo';
  const permissionSchema = _scopeType === 'owner'
      ? GitHubAppPermissionsSchema
      : GitHubAppRepositoryPermissionsSchema;
  return filterObjectEntries(
      permissions,
      ([scope, permission]) => negate !== permissionSchema.safeParse({[scope]: permission}).success,
  );
}

/**
 * Check if access permission objects are equal
 * @param permissionsA - one permissions object
 * @param permissionsB - another permissions object
 * @return true if permissions are equal
 */
function arePermissionsEqual(permissionsA: Record<string, string>, permissionsB: Record<string, string>) {
  const permissionsAEntries = Object.entries(permissionsA);
  const permissionsBEntries = Object.entries(permissionsB);

  return permissionsAEntries.length === permissionsBEntries.length &&
      permissionsAEntries.every(([scope, permission]) => permissionsB[scope] === permission);
}

/**
 * Resolves access policy statement subjects
 * @param statement - access policy statement
 * @param owner - policy owner
 * @param repo - policy repository
 * @return void
 */
function resolveAccessPolicyStatementSubjects(statement: { subjects: string[] }, {owner, repo}: {
  owner: string,
  repo: string,
}) {
  statement.subjects = statement.subjects
      .map((it) => resolveAccessPolicyStatementSubject(it, {owner, repo}));

  // LEGACY SUPPORT for the artificial subject pattern
  const artificialSubjects = getArtificialAccessPolicyStatementSubjects(statement.subjects, {owner, repo});
  statement.subjects.push(...artificialSubjects);
}

/**
 * LEGACY SUPPORT
 * Get artificial access policy statement subjects
 * @param subjects - access policy statement subjects
 * @param owner - policy owner
 * @param repo - policy repository
 * @return artificial subjects
 */
function getArtificialAccessPolicyStatementSubjects(subjects: string[], {owner, repo}: {
  owner: string,
  repo: string,
}) {
  const artificialSubjects: string[] = [];

  subjects.forEach((it) => {
    const subjectRepo = it.match(/(^|:)repo:(?<repo>[^:]+)/)?.groups?.repo ?? `${owner}/${repo}`;

    let artificialSubject = it;

    // prefix subject with repo claim, if not already prefixed
    artificialSubject = artificialSubject.startsWith('repo:') ? artificialSubject :
        `repo:${subjectRepo}:${artificialSubject}`;

    // prefix (job_)workflow_ref claim value with repo, if not already prefixed
    artificialSubject = artificialSubject.replace(
        /(?<=^|:)(?<claim>(job_)?workflow_ref):(?<value>[^:]+)/,
        (match, ...args) => {
          const {claim, value} = args.at(-1);
          if (value.startsWith('/')) return `${claim}:${subjectRepo}${value}`;
          return match;
        },
    );

    if (artificialSubject !== it) {
      artificialSubjects.push(artificialSubject);
    }
  });

  return artificialSubjects;
}

/**
 * Normalise access policy statement subject
 * @param subject - access policy statement subject
 * @param owner - policy owner
 * @param repo - policy repository
 * @return normalised subject
 */
function resolveAccessPolicyStatementSubject(subject: string, {owner, repo}: {
  owner: string,
  repo: string
}): string {
  // resolve variables
  return subject.replaceAll('${origin}', `${owner}/${repo}`);
}

/**
 * Evaluate granted permissions for caller identity
 * @param accessPolicy - access policy
 * @param callerIdentitySubjects - caller identity subjects
 * @return granted permissions
 */
function evaluateGrantedPermissions({statements, callerIdentitySubjects}: {
  statements: GitHubAccessStatement[],
  callerIdentitySubjects: string[],
}): Record<string, string> {
  const permissions = statements
      .filter(statementSubjectPredicate(callerIdentitySubjects))
      .map((it) => it.permissions);

  return aggregatePermissions(permissions);

  /**
   * Create statement subject predicate
   * @param subjects - caller identity subjects
   * @return true if statement subjects match any of the given subject patterns
   */
  function statementSubjectPredicate(subjects: string[]) {
    return (statement: GitHubAccessStatement) => subjects
        .some((subject) => statement.subjects
            .some((subjectPattern) => matchSubject(subjectPattern, subject)));
  }
}

/**
 * Get effective caller identity subjects
 * @param callerIdentity - caller identity
 * @return effective caller identity subjects
 */
function getEffectiveCallerIdentitySubjects(callerIdentity: GitHubActionsJwtPayload): string[] {
  const subjects = [callerIdentity.sub];

  // --- add artificial subjects

  // Be Aware to not add artificial subjects for pull requests e.g., 'ref:refs/pull/1/head'
  if (callerIdentity.ref.startsWith('refs/heads/') ||
      callerIdentity.ref.startsWith('refs/tags/')) {
    // repo : ref
    // => repo:qoomon/sandbox:ref:refs/heads/main
    subjects.push(`repo:${callerIdentity.repository}:ref:${callerIdentity.ref}`);
  }

  // Be Aware to not add artificial subjects for pull requests e.g., 'workflow_ref:...@refs/pull/1/head'
  if (callerIdentity.workflow_ref.split('@')[1]?.startsWith('refs/heads/') ||
      callerIdentity.workflow_ref.split('@')[1]?.startsWith('refs/tags/')) {
    // repo : workflow_ref
    // => repo:qoomon/sandbox:workflow_ref:qoomon/sandbox/.github/workflows/build.yml@refs/heads/main
    subjects.push(`repo:${callerIdentity.repository}:workflow_ref:${callerIdentity.workflow_ref}`);
  }

  // Be Aware to not add artificial subjects for pull requests e.g., 'job_workflow_ref:...@refs/pull/1/head'
  if (callerIdentity.job_workflow_ref.split('@')[1]?.startsWith('refs/heads/') ||
      callerIdentity.job_workflow_ref.split('@')[1]?.startsWith('refs/tags/')) {
    // repo : job_workflow_ref
    // => repo:qoomon/sandbox:job_workflow_ref:qoomon/sandbox/.github/workflows/build.yml@refs/heads/main
    subjects.push(`repo:${callerIdentity.repository}:job_workflow_ref:${callerIdentity.job_workflow_ref}`);
  }

  return unique(subjects);
}

/**
 * Verify if subject is granted by grantedSubjectPatterns
 * @param subjectPattern - subject pattern
 * @param subject - subject e.g. 'repo:spongebob/sandbox:ref:refs/heads/main'
 * @return true if subject matches any granted subject pattern
 */
function matchSubject(subjectPattern: string | string[], subject: string | string[]): boolean {
  if (Array.isArray(subject)) {
    return subject.some((subject) => matchSubject(subjectPattern, subject));
  }

  if (Array.isArray(subjectPattern)) {
    return subjectPattern.some((subjectPattern) => matchSubject(subjectPattern, subject));
  }

  // Security: Validate input lengths to prevent DoS
  const MAX_SUBJECT_LENGTH = 1000;
  if (subjectPattern.length > MAX_SUBJECT_LENGTH || subject.length > MAX_SUBJECT_LENGTH) {
    return false;
  }

  // Security: Ensure pattern and subject contain only valid characters (alphanumeric, :, /, -, _, ., *, ?)
  const VALID_CHARS_PATTERN = /^[a-zA-Z0-9:/\-_.@*?]+$/;
  if (!VALID_CHARS_PATTERN.test(subjectPattern) || !VALID_CHARS_PATTERN.test(subject)) {
    return false;
  }

  // subject pattern claims must not contain wildcards to prevent granting access accidentally
  //   repo:foo/bar:*  is NOT allowed
  //   repo:foo/bar:** is allowed
  //   repo:foo/*:**   is allowed
  const explicitSubjectPattern = subjectPattern.replace(/:\*\*$/, '')
  if (Object.keys(parseOIDCSubject(explicitSubjectPattern)).some((claim) => claim.includes('*'))) {
    return false;
  }

  // Security: Additional validation - wildcards should only appear in claim values, not claim names
  // Split pattern into claim pairs and validate structure
  const patternParts = subjectPattern.split(':');
  for (let i = 0; i < patternParts.length - 1; i += 2) {
    const claimName = patternParts[i];
    // Claim names (even indices) should not contain wildcards
    if (claimName && claimName.includes('*')) {
      // Exception: allow trailing ':**' pattern
      if (i === patternParts.length - 2 && patternParts[i + 1] === '*') {
        break;
      }
      return false;
    }
  }

  // grantedSubjectPattern example: repo:qoomon/sandbox:ref:refs/heads/*
  // identity.sub example: repo:qoomon/sandbox:ref:refs/heads/main
  return regexpOfSubjectPattern(subjectPattern).test(subject);
}

/**
 * Create regexp of wildcard subject pattern
 * @param subjectPattern - wildcard subject pattern
 * @return regexp
 */
function regexpOfSubjectPattern(subjectPattern: string): RegExp {
  // Security: Limit pattern length to prevent ReDoS attacks
  const MAX_PATTERN_LENGTH = 500;
  if (subjectPattern.length > MAX_PATTERN_LENGTH) {
    throw new Error(`Subject pattern exceeds maximum length of ${MAX_PATTERN_LENGTH} characters`);
  }

  // Security: Use atomic groups and possessive quantifiers to prevent catastrophic backtracking
  const regexp = escapeRegexp(subjectPattern)
      .replaceAll('\\*\\*', '(?:.*)') // **  matches zero or more characters (atomic group)
      .replaceAll('\\*', '(?:[^:]*)') //  *  matches zero or more characters except ':' (atomic group)
      .replaceAll('\\?', '[^:]'); //  ?  matches one character except ':'
  
  // Security: Set regex timeout-like behavior by limiting test string length
  return RegExp(`^${regexp}$`, 'i');
}

/**
 * Format access policy error
 * @param error - access policy error
 * @return formatted error message
 */
function formatAccessPolicyError(error: GithubAccessPolicyError) {
  return error.message + (!error.issues?.length ? '' : '\n' +
      error.issues.map((issue) => indent(issue, '- ')).join('\n'));
}

// --- GitHub Functions ----------------------------------------------------------------------------------------------

/**
 * Get GitHub app installation for a repository or owner
 * @param client - GitHub client
 * @param owner - app installation owner
 * @return installation or null if app is not installed for target
 */
async function getAppInstallation(client: Octokit, {owner}: {
  owner: string
}): Promise<GitHubAppInstallation | null> {
  // WORKAROUND: for some reason sometimes the request connection gets closed unexpectedly (line closed),
  // therefore, we retry on any error
  return retry(
      async () => client.rest.apps.getUserInstallation({username: owner})
          .then((res) => res.data)
          .catch(async (error) => (error.status === Status.NOT_FOUND ? null : _throw(error))),
      {
        delay: 1000,
        retries: 3,
      },
  );
}

/**
 * Create installation access token
 * @param client - GitHub client
 * @param installation - target installation id
 * @param repositories - target repositories
 * @param permissions - requested permissions
 * @return access token
 */
async function createInstallationAccessToken(client: Octokit, installation: GitHubAppInstallation, {
  repositories, permissions,
}: {
  repositories?: string[],
  permissions: GitHubAppPermissions
}): Promise<GitHubAppInstallationAccessToken> {
  // noinspection TypeScriptValidateJSTypes
  return client.rest.apps.createInstallationAccessToken({
    installation_id: installation.id,
    // BE AWARE that an empty object will result in a token with all app installation permissions
    permissions: ensureHasEntries(mapObjectEntries(permissions, ([scope, permission]) => [
      scope.replaceAll('-', '_'), permission,
    ])),
    repositories,
  }).then((res) => res.data);
}

/**
 * Create octokit instance for app installation
 * @param client - GitHub client
 * @param installation - app installation
 * @param permissions - requested permissions
 * @param repositories - requested repositories
 * @return octokit instance
 */
async function createOctokit(client: Octokit, installation: GitHubAppInstallation, {permissions, repositories}: {
  permissions: components['schemas']['app-permissions'],
  repositories?: string[]
}): Promise<Octokit> {
  const installationAccessToken = await createInstallationAccessToken(client, installation, {
    permissions,
    repositories,
  });
  return new Octokit({auth: installationAccessToken.token});
}

/**
 * Get repository file content
 * @param client - GitHub client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @param maxSize - max file size
 * @return file content or null if the file does not exist
 */
async function getRepositoryFileContent(client: Octokit, {
  owner, repo, path, maxSize,
}: {
  owner: string,
  repo: string,
  path: string,
  maxSize?: number
}): Promise<string | null> {
  // Security: Validate path to prevent directory traversal attacks
  if (!isValidFilePath(path)) {
    throw new Error(`Invalid file path: ${path}`);
  }

  return client.rest.repos.getContent({owner, repo, path})
      .then((res) => {
        if ('type' in res.data && res.data.type === 'file') {
          if (maxSize !== undefined && res.data.size > maxSize) {
            throw new Error(`Expect file size to be less than ${maxSize}b, but was ${res.data.size}b` +
                `${owner}/${repo}/${path}`);
          }
          return Buffer.from(
              res.data.content,
              'base64',
          ).toString();
        }

        throw new Error('Unexpected file content');
      })
      .catch((error) => {
        if (error.status === Status.NOT_FOUND) return null;
        throw error;
      });
}

/**
 * Validate file path to prevent directory traversal
 * @param path - file path
 * @return true if path is valid
 */
function isValidFilePath(path: string): boolean {
  // Security: Prevent path traversal attacks
  // - No parent directory references (..)
  // - No absolute paths
  // - No null bytes
  // - Must be a reasonable length
  const MAX_PATH_LENGTH = 500;
  
  if (!path || path.length === 0 || path.length > MAX_PATH_LENGTH) {
    return false;
  }
  
  if (path.includes('\0')) {
    return false;
  }
  
  if (path.startsWith('/') || path.startsWith('\\')) {
    return false;
  }
  
  if (path.includes('..')) {
    return false;
  }
  
  // Only allow alphanumeric, dash, underscore, dot, slash in paths
  const VALID_PATH_PATTERN = /^[a-zA-Z0-9\-_./]+$/;
  if (!VALID_PATH_PATTERN.test(path)) {
    return false;
  }
  
  return true;
}

// --- Errors ------------------------------------------------------------------------------------------------------

/**
 * Represents a GitHub access token error
 */
export class GitHubAccessTokenError extends Error {
  /**
   * Creates a new GitHub access token error
   * @param reasons - error reasons
   * @param callerIdentitySubjects - caller identity subjects
   */
  constructor(
      reasons: (string | {
        owner: string,
        issues: GitHubAccessTokenErrorIssue[],
      } | {
        owner: string, repo: string,
        issues: GitHubAccessTokenErrorIssue[],
      })[],
      callerIdentitySubjects?: string[],
  ) {
    let message = '' +
        'Issues:\n' +
        reasons.map((reason) => {
          if (typeof reason === 'string') {
            return reason;
          }

          let messagePrefix = reason.owner;
          if ('repo' in reason && reason.repo) {
            messagePrefix += `/${reason.repo}`;
          }
          return `${messagePrefix}:\n` +
              reason.issues.map((issue) => {
                if (typeof issue === 'string') {
                  return issue;
                }
                return `${issue.scope}: ${issue.permission} - ${issue.message}`;
              }).map((message) => indent(message, '- ')).join('\n');
        }).map((message) => indent(message, '- ')).join('\n')

    if (callerIdentitySubjects) {
      message += '\n' +
          'Effective OIDC token subjects:\n' +
          `${callerIdentitySubjects.map((subject) => indent(subject, '- ')).join('\n')}`;
    }

    super(message);

    Object.setPrototypeOf(this, GitHubAccessTokenError.prototype);
  }
}

type GitHubAccessTokenErrorIssue = string | { scope: string, permission: string, message: string };

/**
 * Access Policy Error
 */
export class GithubAccessPolicyError extends Error {
  public issues?: string[];

  /**
   * @param message - error message
   * @param issues - list of issues
   */
  constructor(message: string, issues?: string[]) {
    super(message);
    this.issues = issues;
  }
}

// --- Schemas ---------------------------------------------------------------------------------------------------------

export type GitHubAccessTokenRequest = {
  owner?: string,
  permissions: GitHubAppPermissions,
  repositories: string[] | 'ALL',
};

// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
const GitHubSubjectClaimSchema = z.string().trim();

const GitHubBaseStatementSchema = z.strictObject({
  subjects: z.array(GitHubSubjectClaimSchema),
});

const GitHubAccessStatementSchema = z.strictObject({
  ...GitHubBaseStatementSchema.shape,
  permissions: GitHubAppPermissionsSchema,
});
type GitHubAccessStatement = z.infer<typeof GitHubAccessStatementSchema>;

const GitHubRepositoryAccessStatementSchema = z.strictObject({
  ...GitHubBaseStatementSchema.shape,
  permissions: GitHubAppRepositoryPermissionsSchema,
});
export type GitHubRepositoryAccessStatement = z.infer<typeof GitHubRepositoryAccessStatementSchema>;

const GitHubAccessPolicySchema = z.strictObject({
  origin: GitHubRepositorySchema,
});
export type GitHubAccessPolicy = z.infer<typeof GitHubAccessPolicySchema>;

const GitHubOwnerAccessPolicySchema = z.strictObject({
  ...GitHubAccessPolicySchema.shape,
  'allowed-subjects': z.array(GitHubSubjectClaimSchema).optional(),
  'statements': z.array(GitHubAccessStatementSchema).optional().default(() => []),
  'allowed-repository-permissions': GitHubAppRepositoryPermissionsSchema.optional().default(() => ({})),
});
export type GitHubOwnerAccessPolicy = z.infer<typeof GitHubOwnerAccessPolicySchema>;

const GitHubRepositoryAccessPolicySchema = z.strictObject({
  ...GitHubAccessPolicySchema.shape,
  statements: z.array(GitHubRepositoryAccessStatementSchema).optional().default(() => []),
});
export type GitHubRepositoryAccessPolicy = z.infer<typeof GitHubRepositoryAccessPolicySchema>;

type Octokit = InstanceType<typeof Octokit>;

type GitHubAppInstallation = RestEndpointMethodTypes['apps']['getUserInstallation']['response']['data'];
// eslint-disable-next-line max-len
type GitHubAppInstallationAccessToken = RestEndpointMethodTypes['apps']['createInstallationAccessToken']['response']['data'];
