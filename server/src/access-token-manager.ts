import {Octokit, RestEndpointMethodTypes} from '@octokit/rest';
import {z, ZodSchema} from 'zod';
import {components} from '@octokit/openapi-types';
import {createAppAuth} from '@octokit/auth-app';
import limit from 'p-limit';
import {formatZodIssue, YamlTransformer} from './common/zod-utils.js';
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
  safePromise,
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
  verifyPermissions,
  verifyRepositoryPermissions,
} from './common/github-utils.js';
import {Status} from './common/http-utils.js';
import {logger as log} from './logger.js';

const ACCESS_POLICY_MAX_SIZE = 100 * 1024; // 100kb

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
  log.debug({appId: options.githubAppAuth.appId}, 'GitHub app');
  const GITHUB_APP_CLIENT = new Octokit({authStrategy: createAppAuth, auth: options.githubAppAuth});
  const GITHUB_APP = await GITHUB_APP_CLIENT.apps.getAuthenticated()
      .then((res) => res.data ?? _throw(new Error('GitHub app not found')));

  /**
   * Creates a GitHub Actions Access Token
   * @param callerIdentity - caller identity
   * @param tokenRequest - token request
   * @return access token
   */
  async function createAccessToken(
      callerIdentity: GitHubActionsJwtPayload,
      tokenRequest: {
        scope: 'owner', owner: string, permissions: GitHubAppPermissions,
        repositories?: string[],
      } | {
        scope: 'repos', owner: string, permissions: GitHubAppRepositoryPermissions,
        repositories: string[],
      },
  ) {
    const effectiveCallerIdentitySubjects = getEffectiveCallerIdentitySubjects(callerIdentity);

    const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {
      owner: tokenRequest.owner,
    });
    if (!appInstallation) {
      throw new GithubAccessTokenError([{
        owner: tokenRequest.owner,
        // BE AWARE to prevent leaking owner existence
        issues: tokenRequest.owner !== callerIdentity.repository_owner ?
            [NOT_AUTHORIZED_MESSAGE] :
            [`'${GITHUB_APP.name}' has not been installed. Install from ${GITHUB_APP.html_url}`],
      }], effectiveCallerIdentitySubjects);
    }
    log.debug({appInstallation}, 'App installation');

    const accessPolicyPaths = [...options.accessPolicyLocation.owner.paths, ...options.accessPolicyLocation.repo.paths];
    if (!accessPolicyPaths.every((path) => appInstallation.single_file_paths?.includes(path))) {
      log.debug({required: accessPolicyPaths, actual: appInstallation.single_file_paths},
          `App installation is missing 'single_file' permission for access policy file(s)`);
      throw new GithubAccessTokenError([{
        owner: tokenRequest.owner,
        // BE AWARE to prevent leaking owner existence
        issues: callerIdentity.repository !== `${tokenRequest.owner}/${options.accessPolicyLocation.owner.repo}` ?
            [NOT_AUTHORIZED_MESSAGE] :
            [`'${GITHUB_APP.name}' installation is missing 'single_file' permission for access policy file(s)`],
      }], effectiveCallerIdentitySubjects);
    }

    // --- verify requested token permissions ------------------------------------------------------------------------

    // --- verify app installation permissions ---------------------------------------------------------------------
    const requestedAppInstallationPermissions = verifyPermissions({
      granted: normalizePermissionScopes(appInstallation.permissions),
      requested: tokenRequest.permissions,
    });

    if (requestedAppInstallationPermissions.denied.length > 0) {
      // TODO potential security issue: Do not leak app installation permissions
      throw new GithubAccessTokenError([{
        owner: tokenRequest.owner,
        // BE AWARE to prevent leaking owner existence
        issues: callerIdentity.repository !== `${tokenRequest.owner}/${options.accessPolicyLocation.owner.repo}` ?
            [NOT_AUTHORIZED_MESSAGE] :
            requestedAppInstallationPermissions.denied.map(({scope, permission}) => ({
              scope, permission,
              message: `Permission has not been granted to '${GITHUB_APP.name}' installation`,
            })),
      }], effectiveCallerIdentitySubjects);
    }

    const appInstallationClient = await createOctokit(GITHUB_APP_CLIENT, appInstallation, {
      // single_file to read access policy files
      permissions: {single_file: 'read'},
    });

    // --- load owner access policy ----------------------------------------------------------------------------------
    const ownerAccessPolicy = await getOwnerAccessPolicy(appInstallationClient, {
      owner: tokenRequest.owner,
      repo: options.accessPolicyLocation.owner.repo,
      paths: options.accessPolicyLocation.owner.paths,
      strict: false, // ignore invalid access policy entries
    }).catch((error) => {
      if (error instanceof GithubAccessPolicyError) {
        log.debug({issues: error.issues}, `'${tokenRequest.owner}' access policy`);
        throw new GithubAccessTokenError([{
          owner: tokenRequest.owner,
          // BE AWARE to prevent leaking owner existence
          issues: tokenRequest.owner !== callerIdentity.repository_owner ?
              [NOT_AUTHORIZED_MESSAGE] :
              [formatAccessPolicyError(error)],

        }], effectiveCallerIdentitySubjects);
      }
      throw error;
    });
    log.debug({ownerAccessPolicy}, `${tokenRequest.owner} access policy:`);

    // --- verify allowed caller identities --------------------------------------------------------------------------

    // if allowed-subjects is not defined, allow any subjects from the policy owner
    const allowedSubjects = ownerAccessPolicy['allowed-subjects'] ??
        [`repo:${tokenRequest.owner}/*:**`]; // e.g., ['repo:qoomon/*:**' ]

    if (!matchSubject(allowedSubjects, effectiveCallerIdentitySubjects)) {
      throw new GithubAccessTokenError([{
        owner: tokenRequest.owner,
        // BE AWARE to prevent leaking owner existence
        issues: tokenRequest.owner !== callerIdentity.repository_owner ?
            [NOT_AUTHORIZED_MESSAGE] :
            ['OIDC token subject is not allowed by owner access policy'],
      }], effectiveCallerIdentitySubjects);
    }

    // grant requested permissions explicitly to prevent accidental permission escalation
    const grantedTokenPermissions: Record<string, string> = {};
    const pendingTokenPermissions: Record<string, string> = {...tokenRequest.permissions};

    const ownerGrantedPermissions = evaluateGrantedPermissions({
      statements: ownerAccessPolicy.statements,
      callerIdentitySubjects: effectiveCallerIdentitySubjects,
    });

    // --- verify scope permissions ----------------------------------------------------------------------------------
    switch (tokenRequest.scope) {
      case 'owner': {
        // --- verify requested permissions against owner access policy ----------------------------------------------

        if (!hasEntries(ownerGrantedPermissions)) {
          throw new GithubAccessTokenError([{
            owner: tokenRequest.owner,
            // BE AWARE to prevent leaking owner existence
            issues: [NOT_AUTHORIZED_MESSAGE],
          }], effectiveCallerIdentitySubjects);
        }

        const requestedOwnerPermissions = verifyPermissions({
          granted: ownerGrantedPermissions,
          requested: tokenRequest.permissions,
        });

        // -- deny permissions
        if (requestedOwnerPermissions.denied.length > 0) {
          throw new GithubAccessTokenError([{
            owner: tokenRequest.owner,
            issues: requestedOwnerPermissions.denied.map(({scope, permission}) => ({
              scope, permission,
              message: NOT_AUTHORIZED_MESSAGE,
            })),
          }], effectiveCallerIdentitySubjects);
        }

        // --- grant permissions
        requestedOwnerPermissions.granted.forEach(({scope, permission}) => {
          grantedTokenPermissions[scope] = permission;
          // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
          delete pendingTokenPermissions[scope];
        });

        break;
      }
      case 'repos': {
        // --- verify requested permissions against OWNER access policy ----------------------------------------------
        {
          // --- grant repository permissions that are granted by OWNER access policy
          {
            const requestedRepositoryPermissions = verifyPermissions({
              // BE AWARE to grant repository permissions only
              granted: verifyRepositoryPermissions(ownerGrantedPermissions).valid,
              requested: pendingTokenPermissions,
            });

            // --- grant permissions
            requestedRepositoryPermissions.granted.forEach(({scope, permission}) => {
              grantedTokenPermissions[scope] = permission;
              // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
              delete pendingTokenPermissions[scope];
            });
          }

          // --- deny pending repository permissions that are not allowed by OWNER access policy
          {
            const requestedRepositoryPermissions = verifyPermissions({
              // BE AWARE to grant repository permissions only
              granted: verifyRepositoryPermissions(ownerAccessPolicy['allowed-repository-permissions']).valid,
              requested: pendingTokenPermissions,
            });

            // -- deny permissions
            if (requestedRepositoryPermissions.denied.length > 0) {
              throw new GithubAccessTokenError([{
                owner: tokenRequest.owner,
                issues: requestedRepositoryPermissions.denied.map(({scope, permission}) => ({
                  scope, permission,
                  message: NOT_AUTHORIZED_MESSAGE, // TODO set detailed message, if tokenRequest.owner === callerIdentity.repository_owner
                })),
              }], effectiveCallerIdentitySubjects);
            }
          }
        }

        // --- verify requested permissions against target REPOSITORY access policies ----------------------------------
        if (hasEntries(pendingTokenPermissions)) {
          if (hasEntries(verifyRepositoryPermissions(pendingTokenPermissions).invalid)) {
            throw new Error('SAFEGUARD Error - Unexpected repository permissions');
          }

          const requestedTokenIssues: ({
            owner: string,
            issues: (string | { message: string, scope: string, permission: string })[],
          } | {
            owner: string, repo: string,
            issues: (string | { message: string, scope: string, permission: string })[],
          })[] = [];

          const pendingTokenPermissionsByRepository = Object.fromEntries(
              Object.keys(pendingTokenPermissions)
                  .map((scope) => [scope, new Set(tokenRequest.repositories)]));

          const limitRepoPermissionRequests = limit(8);
          await Promise.all(
              tokenRequest.repositories.map((repo) => limitRepoPermissionRequests(async () => {
                const targetRepository = `${tokenRequest.owner}/${repo}`;
                const repoAccessPolicyResult = await safePromise(getRepoAccessPolicy(appInstallationClient, {
                  ...parseRepository(targetRepository),
                  paths: options.accessPolicyLocation.repo.paths,
                  strict: false, // ignore invalid access policy entries
                }));

                if (!repoAccessPolicyResult.success) {
                  const error = repoAccessPolicyResult.error;
                  if (error instanceof GithubAccessPolicyError) {
                    log.debug({issues: error.issues}, `'${targetRepository}' access policy`);
                    requestedTokenIssues.push({
                      owner: tokenRequest.owner, repo,
                      issues: tokenRequest.owner !== callerIdentity.repository_owner ?
                          [NOT_AUTHORIZED_MESSAGE] :
                          [formatAccessPolicyError(error)],
                    });
                    return;
                  }
                  throw error;
                }

                const repoAccessPolicy = repoAccessPolicyResult.data;
                log.debug({repoAccessPolicy}, `'${targetRepository}' access policy`);

                const repoGrantedPermissions = evaluateGrantedPermissions({
                  statements: repoAccessPolicy.statements,
                  callerIdentitySubjects: effectiveCallerIdentitySubjects,
                });
                if (!hasEntries(repoGrantedPermissions)) {
                  requestedTokenIssues.push({
                    owner: tokenRequest.owner, repo,
                    // BE AWARE to prevent leaking owner existence
                    issues: [NOT_AUTHORIZED_MESSAGE],
                  });
                  return;
                }

                const verifiedRepoPermissions = verifyPermissions({
                  granted: repoGrantedPermissions,
                  requested: pendingTokenPermissions,
                });

                // --- grant repo permissions that are granted by repo access policy
                verifiedRepoPermissions.granted.forEach(({scope}) => {
                  pendingTokenPermissionsByRepository[scope].delete(repo);
                });

                // --- deny repo permissions that are not granted by repo access policy
                verifiedRepoPermissions.denied.forEach(({scope, permission}) => {
                  requestedTokenIssues.push({
                    owner: tokenRequest.owner, repo,
                    issues: [{
                      scope, permission,
                      message: NOT_AUTHORIZED_MESSAGE,
                    }],
                  });
                });
              })),
          );

          // --- grant repository permission only if all repositories have granted the specific permission
          Object.entries(pendingTokenPermissionsByRepository).forEach(([scope, repositories]) => {
            if (repositories.size == 0) {
              grantedTokenPermissions[scope] = pendingTokenPermissions[scope];
              // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
              delete pendingTokenPermissions[scope];
            }
          });

          if (hasEntries(requestedTokenIssues)) {
            throw new GithubAccessTokenError(requestedTokenIssues, effectiveCallerIdentitySubjects);
          }
        }

        break;
      }
      default:
        throw new Error('SAFEGUARD Error - Unexpected token scope');
    }

    // --- create requested access token -------------------------------------------------------------------------------
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
      repositories: tokenRequest.scope === 'repos' ? ensureHasEntries(tokenRequest.repositories) :
          tokenRequest.repositories,
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

// --- Access Manager Functions --------------------------------------------------------------------------------------

/**
 * Format access policy error
 * @param error - access policy error
 * @return formatted error message
 */
function formatAccessPolicyError(error: GithubAccessPolicyError) {
  return error.message + (!error.issues?.length ? '' : '\n' +
      error.issues.map((issue) => indent(issue, '- ')).join('\n'));
}

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
  let policyValue = null;
  for (const path of paths) {
    policyValue = await getRepositoryFileContent(client, {
      owner, repo, path, maxSize: ACCESS_POLICY_MAX_SIZE,
    });
    if (policyValue) {
      break;
    }
  }
  if (!policyValue) {
    throw new GithubAccessPolicyError(`Access policy not found`);
  }

  const filterInvalidAccessPolicyEntries = (policy: unknown) => {
    if (isRecord(policy)) {
      if (Array.isArray(policy['allowed-subjects'])) {
        policy['allowed-subjects'] = filterValidSubjects(
            policy['allowed-subjects']);
      }
      if (isRecord(policy['allowed-repository-permissions'])) {
        policy['allowed-repository-permissions'] = filterValidPermissions(
            policy['allowed-repository-permissions'], 'owner');
      }
      if (Array.isArray(policy.statements)) {
        policy.statements = filterValidStatements(
            policy.statements, 'owner');
      }
    }

    return policy;
  };

  const policyParseResult = YamlTransformer
      .transform(strict ? (it) => it : filterInvalidAccessPolicyEntries)
      .pipe(GitHubOwnerAccessPolicySchema)
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

  policy.statements?.forEach((statement) => {
    normaliseAccessPolicyStatement(statement, {owner, repo});
  });

  return policy;
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
  let policyValue = null;
  for (const path of paths) {
    policyValue = await getRepositoryFileContent(client, {
      owner, repo, path, maxSize: ACCESS_POLICY_MAX_SIZE,
    });
    if (policyValue) {
      break;
    }
  }
  if (!policyValue) {
    throw new GithubAccessPolicyError(`Access policy not found`);
  }

  const filterInvalidAccessPolicyEntries = (policy: unknown) => {
    if (isRecord(policy)) {
      if (Array.isArray(policy.statements)) {
        policy.statements = filterValidStatements(
            policy.statements, 'repo');
      }
    }

    return policy;
  };

  const policyParseResult = YamlTransformer
      .transform(strict ? (it) => it : filterInvalidAccessPolicyEntries)
      .pipe(GitHubRepositoryAccessPolicySchema)
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

  policy.statements?.forEach((statement) => {
    normaliseAccessPolicyStatement(statement, {owner, repo});
  });

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
            statementObject.permissions = filterValidPermissions(statementObject.permissions, permissionsType);
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

/**
 * Filter invalid permissions
 * @param permissions - access policy permissions
 * @param type - permission type
 * @return valid permissions
 */
function filterValidPermissions(permissions: Record<string, unknown>, type: 'owner' | 'repo')
    : Record<string, unknown> {
  let permissionSchema: ZodSchema;
  switch (type) {
    case 'owner':
      permissionSchema = GitHubAppPermissionsSchema;
      break;
    case 'repo':
      permissionSchema = GitHubAppRepositoryPermissionsSchema;
      break;
    default:
      throw new Error('Invalid permission type');
  }

  return filterObjectEntries(permissions, ([key, value]) => permissionSchema.safeParse({[key]: value}).success);
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
 * Normalise access policy statement
 * @param statement - access policy statement
 * @param owner - policy owner
 * @param repo - policy repository
 * @return void
 */
function normaliseAccessPolicyStatement(statement: { subjects: string[] }, {owner, repo}: {
  owner: string,
  repo: string,
}) {
  statement.subjects = statement.subjects
      .map((it) => normaliseAccessPolicyStatementSubject(it, {owner, repo}));

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
function normaliseAccessPolicyStatementSubject(subject: string, {owner, repo}: {
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

  // repo : ref
  // => repo:qoomon/sandbox:ref:refs/heads/main
  subjects.push(`repo:${callerIdentity.repository}:ref:${callerIdentity.ref}`);

  // repo : workflow_ref
  // => repo:qoomon/sandbox:workflow_ref:qoomon/sandbox/.github/workflows/build.yml@refs/heads/main
  subjects.push(`repo:${callerIdentity.repository}:workflow_ref:${callerIdentity.workflow_ref}`);

  // repo : job_workflow_ref
  // => repo:qoomon/sandbox:job_workflow_ref:qoomon/sandbox/.github/workflows/build.yml@refs/heads/main
  subjects.push(`repo:${callerIdentity.repository}:job_workflow_ref:${callerIdentity.job_workflow_ref}`);

  if (callerIdentity.environment) {
    // repo : environment
    // => repo:qoomon/sandbox:environment:production
    subjects.push(`repo:${callerIdentity.repository}:environment:${callerIdentity.environment}`);
  }

  return unique(subjects);
}

/**
 * Verify if subject is granted by grantedSubjectPatterns
 * @param subjectPattern - subject pattern
 * @param subject - subject e.g. 'repo:spongebob/sandbox:ref:refs/heads/main'
 * @param strict - strict mode does not allow ** wildcards
 * @return true if subject matches any granted subject pattern
 */
function matchSubject(subjectPattern: string | string[], subject: string | string[], strict = true): boolean {
  if (Array.isArray(subject)) {
    return subject.some((subject) => matchSubject(subjectPattern, subject, false));
  }

  if (Array.isArray(subjectPattern)) {
    return subjectPattern.some((subjectPattern) => matchSubject(subjectPattern, subject, false));
  }

  if (strict && subjectPattern.includes('**')) {
    return false;
  }

  // claims must not contain wildcards to prevent granting access accidentally
  // e.g., repo:foo/bar:* is not allowed
  if (Object.keys(parseOIDCSubject(subjectPattern))
      .some((claim) => !claim.includes('**') && claim.includes('*'))) {
    return false;
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
  const regexp = escapeRegexp(subjectPattern)
      .replace(/\\\*\\\*/g, '.*') // ** matches zero or more characters
      .replace(/\\\*/g, '[^:]*') //  *  matches zero or more characters except ':'
      .replace(/\\\?/g, '[^:]'); //  ?  matches one character except ':'
  return RegExp(`^${regexp}$`, 'i');
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
      async () => client.apps.getUserInstallation({username: owner})
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
  return client.apps.createInstallationAccessToken({
    installation_id: installation.id,
    // BE AWARE that an empty object will result in a token with all app installation permissions
    permissions: ensureHasEntries(mapObjectEntries(permissions, ([scope, permission]) => [
      scope.replaceAll('-', '_'), permission,
    ])),
    repositories,
  })
      .then((res) => res.data);
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
  return client.repos.getContent({owner, repo, path})
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

// --- Errors ------------------------------------------------------------------------------------------------------

/**
 * Represents a GitHub access token error
 */
export class GithubAccessTokenError extends Error {
  /**
   * Creates a new GitHub access token error
   * @param reasons - error reasons
   * @param callerIdentitySubjects - caller identity subjects
   */
  constructor(
      reasons: ({
        owner: string,
        issues: (string | { scope: string, permission: string, message: string })[],
      } | {
        owner: string, repo: string,
        issues: (string | { scope: string, permission: string, message: string })[],
      })[],
      callerIdentitySubjects: string[],
  ) {
    const message = '' +
        'Issues:\n' +
        reasons.map((reason) => {
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
        }).map((message) => indent(message, '- ')).join('\n') + '\n' +

        'Effective OIDC token subjects:\n' +
        `${callerIdentitySubjects.map((subject) => indent(subject, '- ')).join('\n')}`;

    super(message);

    Object.setPrototypeOf(this, GithubAccessTokenError.prototype);
  }
}

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

// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
const GitHubSubjectClaimSchema = z.string().trim();

const GitHubBaseStatementSchema = z.strictObject({
  subjects: z.array(GitHubSubjectClaimSchema),
});

const GitHubAccessStatementSchema = GitHubBaseStatementSchema.merge(z.strictObject({
  permissions: GitHubAppPermissionsSchema,
}));
type GitHubAccessStatement = z.infer<typeof GitHubAccessStatementSchema>;

const GitHubRepositoryAccessStatementSchema = GitHubBaseStatementSchema.merge(z.strictObject({
  permissions: GitHubAppRepositoryPermissionsSchema,
}));
export type GitHubRepositoryAccessStatement = z.infer<typeof GitHubRepositoryAccessStatementSchema>;

const GitHubOwnerAccessPolicySchema = z.strictObject({
  'origin': GitHubRepositorySchema,
  'allowed-subjects': z.array(GitHubSubjectClaimSchema).optional(),
  'statements': z.array(GitHubAccessStatementSchema).optional().default([]),
  'allowed-repository-permissions': GitHubAppRepositoryPermissionsSchema.optional().default({}),
});
export type GitHubOwnerAccessPolicy = z.infer<typeof GitHubOwnerAccessPolicySchema>;

const GitHubRepositoryAccessPolicySchema = z.strictObject({
  origin: GitHubRepositorySchema,
  statements: z.array(GitHubRepositoryAccessStatementSchema).optional().default([]),
});
export type GitHubRepositoryAccessPolicy = z.infer<typeof GitHubRepositoryAccessPolicySchema>;

type GitHubAppInstallation = RestEndpointMethodTypes['apps']['getUserInstallation']['response']['data'];
// eslint-disable-next-line max-len
type GitHubAppInstallationAccessToken = RestEndpointMethodTypes['apps']['createInstallationAccessToken']['response']['data'];
