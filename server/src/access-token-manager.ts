import limit from 'p-limit';
import {createAppAuth} from '@octokit/auth-app';
import {RestEndpointMethodTypes} from '@octokit/rest';
import {
  ensureHasEntries,
  filterObjectEntries,
  hasEntries,
  indent,
  resultOf,
  unique,
} from './common/common-utils.js';
import {
  aggregatePermissions, arePermissionsEqual,
  GitHubActionsJwtPayload,
  GitHubAppPermissions,
  GitHubAppRepositoryPermissions,
  normalizePermissionScopes,
  parseRepository,
  validatePermissions,
  verifyPermissions,
} from './common/github-utils.js';
import {logger} from './logger.js';
import {
  createInstallationAccessToken,
  createOctokit,
  getAppInstallation,
  GitHubAppInstallation,
  Octokit,
} from './github-app-client.js';
import {
  evaluateGrantedPermissions,
  filterValidPermissions,
  formatAccessPolicyError,
  getOwnerAccessPolicy,
  getRepoAccessPolicy,
  GithubAccessPolicyError, matchSubject,
} from './access-policy.js';

// Public re-exports kept for backward compatibility
export type {
  GitHubOwnerAccessPolicy,
  GitHubRepositoryAccessPolicy,
  GitHubRepositoryAccessStatement,
  GitHubAccessPolicy,
} from './access-policy.js';
export {GithubAccessPolicyError} from './access-policy.js';

const GITHUB_API_CONCURRENCY_LIMIT = limit(8);

// BE AWARE to always use NOT_AUTHORIZED_MESSAGE if no permissions are granted to caller identity.
// otherwise, unintended leaks of repository existence could happen.
const NOT_AUTHORIZED_MESSAGE = 'Not authorized';

type GitHubApp = RestEndpointMethodTypes['apps']['getAuthenticated']['response']['data'];
type AccessPolicyOptions = {
  owner: { paths: string[], repo: string },
  repo: { paths: string[] }
};

// Convenience alias for a token request that has been through normalizeTokenRequest
type NormalizedTokenRequest = GitHubAccessTokenRequest & { owner: string };

/**
 * GitHub Access Manager factory
 * @param options - configuration options
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
  const GITHUB_APP: NonNullable<GitHubApp> = await GITHUB_APP_CLIENT.rest.apps.getAuthenticated()
      .then((res) => {
        if (!res.data) throw new Error('Failed to get authenticated GitHub App');
        return res.data;
      });

  // --- createAccessToken -----------------------------------------------------------------------------------------

  /**
   * Creates a GitHub Actions Access Token
   * @param callerIdentity - caller identity from the GitHub Actions OIDC token
   * @param tokenRequest - token request
   * @return access token
   */
  async function createAccessToken(callerIdentity: GitHubActionsJwtPayload, tokenRequest: GitHubAccessTokenRequest) {
    const effectiveSubjects = getEffectiveCallerIdentitySubjects(callerIdentity);
    normalizeTokenRequest(tokenRequest, callerIdentity);

    // --- Verify app installation -----------------------------------------------------------------------------------
    const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {owner: tokenRequest.owner});
    assertAppInstallation(
        appInstallation, tokenRequest, callerIdentity, effectiveSubjects, GITHUB_APP,
        options.accessPolicyLocation);
    assertInstallationPermissions(
        appInstallation, tokenRequest, callerIdentity, effectiveSubjects, GITHUB_APP);

    // --- Create installation-scoped client for reading access policy files -----------------------------------------
    const appInstallationClient = await createOctokit(GITHUB_APP_CLIENT, appInstallation, {
      // single_file to read access policy files
      permissions: {single_file: 'read', contents: 'read'},
    });

    // --- Evaluate permissions: owner policy then per-repo policies ------------------------------------------------
    const ownerGranted = await grantFromOwnerPolicy(
        appInstallationClient, tokenRequest, callerIdentity, effectiveSubjects, tokenRequest.permissions,
        options.accessPolicyLocation);

    const pendingAfterOwner = filterObjectEntries(
        tokenRequest.permissions, ([k]) => !(k in ownerGranted));

    const repoGranted = hasEntries(pendingAfterOwner)
        ? await grantFromRepositoryPolicies(
            appInstallationClient,
            tokenRequest as NormalizedTokenRequest & { repositories: string[] },
            callerIdentity, effectiveSubjects, pendingAfterOwner, options.accessPolicyLocation.repo.paths)
        : {};

    const allGranted = {...ownerGranted, ...repoGranted};

    // --- Safety checks --------------------------------------------------------------------------------------------
    if (!arePermissionsEqual(tokenRequest.permissions, allGranted)) {
      throw new Error('SAFEGUARD Error - Unexpected mismatch between requested and granted permissions');
    }

    // --- Create the installation access token ---------------------------------------------------------------------
    const accessToken = await createInstallationAccessToken(GITHUB_APP_CLIENT, appInstallation, {
      // BE AWARE that an empty object will result in a token with all app installation permissions
      permissions: ensureHasEntries(allGranted),
      // BE AWARE that an empty array will result in a token with access to all app installation repositories
      repositories: tokenRequest.repositories === 'ALL' ? undefined : ensureHasEntries(tokenRequest.repositories),
    });

    return {
      owner: appInstallation.account?.name ?? tokenRequest.owner,
      ...accessToken,
    };
  }

  return {createAccessToken};
}

// --- createAccessToken helpers ------------------------------------------------------------------------------------

/**
 * Asserts the GitHub App is installed for the target owner and authorised to
 * read all required access policy files via the `single_file` permission.
 * Throws `GitHubAccessTokenError` on failure.
 */
function assertAppInstallation(
    appInstallation: GitHubAppInstallation | null,
    tokenRequest: NormalizedTokenRequest,
    callerIdentity: GitHubActionsJwtPayload,
    effectiveSubjects: string[],
    githubApp: NonNullable<GitHubApp>,
    accessPolicyLocation: AccessPolicyOptions,
): asserts appInstallation is GitHubAppInstallation {

  if (!appInstallation) {
    logger.info({owner: tokenRequest.owner}, `'${githubApp.name}' has not been installed`);
    throw new GitHubAccessTokenError([{
      owner: tokenRequest.owner,
      // BE AWARE to prevent leaking owner existence
      issues: callerIdentity.repository_owner === tokenRequest.owner
          ? [`'${githubApp.name}' has not been installed. Install from ${githubApp.html_url}`]
          : [NOT_AUTHORIZED_MESSAGE],
    }], effectiveSubjects);
  }

  logger.debug({appInstallation}, 'App installation');

  const accessPolicyPaths = [
    ...accessPolicyLocation.owner.paths,
    ...accessPolicyLocation.repo.paths,
  ];
  if (!accessPolicyPaths.every((path) =>
      appInstallation.single_file_paths?.includes(path) || appInstallation.single_file_name === path)) {
    logger.info(
        {owner: tokenRequest.owner, required: accessPolicyPaths, actual: appInstallation.single_file_paths},
        `'${githubApp.name}' is not authorized to read all access policy file(s) by 'single_file' permission`,
    );
    throw new GitHubAccessTokenError([{
      owner: tokenRequest.owner,
      // BE AWARE to prevent leaking owner existence
      issues: callerIdentity.repository_owner === tokenRequest.owner
          ? [`'${githubApp.name}' is not authorized to read all access policy file(s) by 'single_file' permission`]
          : [NOT_AUTHORIZED_MESSAGE],
    }], effectiveSubjects);
  }
}

/**
 * Asserts the GitHub App installation has all permissions requested in the token request.
 * Throws `GitHubAccessTokenError` on failure.
 */
function assertInstallationPermissions(
    appInstallation: GitHubAppInstallation,
    tokenRequest: NormalizedTokenRequest,
    callerIdentity: GitHubActionsJwtPayload,
    effectiveSubjects: string[],
    githubApp: NonNullable<GitHubApp>,
) {
  const {pending} = verifyPermissions({
    granted: normalizePermissionScopes(appInstallation.permissions),
    requested: tokenRequest.permissions,
  });

  if (hasEntries(pending)) {
    logger.info({owner: tokenRequest.owner, denied: pending}, `App installation is not authorized`);
    throw new GitHubAccessTokenError([{
      owner: tokenRequest.owner,
      // BE AWARE to prevent leaking owner existence
      issues: callerIdentity.repository_owner === tokenRequest.owner
          ? Object.entries(pending).map(([scope, permission]) => ({
            scope, permission,
            message: `'${githubApp.name}' installation not authorized`,
          }))
          : [NOT_AUTHORIZED_MESSAGE],
    }], effectiveSubjects);
  }
}

/**
 * Evaluates which of the `requestedPermissions` are granted by the owner access policy.
 *
 * Also validates that:
 * - The caller identity is allowed by the policy's `allowed-subjects`
 * - All non-repository (owner-level) permissions are covered
 * - When `repositories === 'ALL'`, all remaining repo permissions are covered too
 * - When specific repos are targeted, pending repo permissions are listed in `allowed-repository-permissions`
 *
 * @return permissions explicitly granted by the owner policy statements
 * @throws `GitHubAccessTokenError` on any denial
 */
async function grantFromOwnerPolicy(
    client: Octokit,
    tokenRequest: NormalizedTokenRequest,
    callerIdentity: GitHubActionsJwtPayload,
    effectiveSubjects: string[],
    requestedPermissions: Record<string, string>,
    accessPolicyLocation: AccessPolicyOptions,
): Promise<Record<string, string>> {

  const accessPolicy = await getOwnerAccessPolicy(client, {
    owner: tokenRequest.owner,
    repo: accessPolicyLocation.owner.repo,
    paths: accessPolicyLocation.owner.paths,
    strict: false, // ignore invalid access policy entries
  }).catch((error) => {
    if (error instanceof GithubAccessPolicyError) {
      logger.info({owner: tokenRequest.owner, issues: error.issues},
          `Owner access policy - ${error.message}`);
      throw new GitHubAccessTokenError([{
        owner: tokenRequest.owner,
        // BE AWARE to prevent leaking owner existence
        issues: callerIdentity.repository === `${tokenRequest.owner}/${accessPolicyLocation.owner.repo}`
            ? [formatAccessPolicyError(error)]
            : tokenRequest.owner === callerIdentity.repository_owner
                ? [error.message]
                : [NOT_AUTHORIZED_MESSAGE],
      }], effectiveSubjects);
    }
    throw error;
  });
  logger.debug({owner: tokenRequest.owner, ownerAccessPolicy: accessPolicy}, 'Owner access policy');

  // --- Check allowed-subjects ---
  // if allowed-subjects is not defined, allow any subjects from the policy owner
  const allowedSubjects = accessPolicy['allowed-subjects'] ?? [`repo:${tokenRequest.owner}/*:**`];
  if (!matchSubject(allowedSubjects, effectiveSubjects)) {
    logger.info({owner: tokenRequest.owner}, 'OIDC token subject is not allowed by owner access policy');
    throw new GitHubAccessTokenError([{
      owner: tokenRequest.owner,
      // BE AWARE to prevent leaking owner existence
      issues: callerIdentity.repository_owner === tokenRequest.owner
          ? ['OIDC token subject is not allowed by owner access policy']
          : [NOT_AUTHORIZED_MESSAGE],
    }], effectiveSubjects);
  }

  // --- Evaluate owner policy grants ---
  const statementsGranted = evaluateGrantedPermissions({
    statements: accessPolicy.statements,
    callerIdentitySubjects: effectiveSubjects,
  });
  const {granted: ownerGranted, pending} = verifyPermissions({
    granted: statementsGranted,
    requested: requestedPermissions,
  });

  // --- Ensure all owner-scoped (non-repo) permissions are covered ---
  const pendingOwnerPermissions = filterValidPermissions('!repo', pending);
  if (hasEntries(pendingOwnerPermissions)) {
    logger.info({owner: tokenRequest.owner, denied: pendingOwnerPermissions},
        'Owner access policy - permission(s) not granted');
    throw new GitHubAccessTokenError([{
      owner: tokenRequest.owner,
      issues: Object.entries(pendingOwnerPermissions).map(([scope, permission]) => ({
        scope, permission: String(permission),
        message: callerIdentity.repository_owner === tokenRequest.owner
            ? 'Not allowed by owner access policy'
            : NOT_AUTHORIZED_MESSAGE,
      })),
    }], effectiveSubjects);
  }

  // --- Check any remaining repo-scoped permissions ---
  if (hasEntries(pending)) {
    if (tokenRequest.repositories === 'ALL') {
      // For ALL repos, owner policy must grant every requested permission
      logger.info({owner: tokenRequest.owner, denied: pending},
          'Owner access policy - permission(s) not granted');
      throw new GitHubAccessTokenError([{
        owner: tokenRequest.owner,
        issues: Object.entries(pending).map(([scope, permission]) => ({
          scope, permission: String(permission),
          message: callerIdentity.repository_owner === tokenRequest.owner
              ? 'Not allowed by owner access policy'
              : NOT_AUTHORIZED_MESSAGE,
        })),
      }], effectiveSubjects);
    }

    // For specific repos, pending permissions must be whitelisted in allowed-repository-permissions
    const forbiddenPermissions = verifyPermissions({
      granted: accessPolicy['allowed-repository-permissions'],
      requested: pending,
    }).pending;
    if (hasEntries(forbiddenPermissions)) {
      logger.info({owner: tokenRequest.owner, denied: forbiddenPermissions},
          'Owner access policy - permission(s) not allowed');
      throw new GitHubAccessTokenError([{
        owner: tokenRequest.owner,
        issues: Object.entries(forbiddenPermissions).map(([scope, permission]) => ({
          scope, permission,
          message: callerIdentity.repository_owner === tokenRequest.owner
              ? 'Not allowed by owner access policy'
              : NOT_AUTHORIZED_MESSAGE,
        })),
      }], effectiveSubjects);
    }
  }

  return ownerGranted;
}

/**
 * Evaluates which of the `pendingPermissions` are granted by each target repository's access policy.
 * All repositories must grant every pending permission; if any deny, a `GitHubAccessTokenError` is thrown.
 *
 * @return permissions granted (aggregated across all repositories)
 * @throws `GitHubAccessTokenError` if any repository denies any permission
 */
async function grantFromRepositoryPolicies(
    client: Octokit,
    tokenRequest: NormalizedTokenRequest & { repositories: string[] },
    callerIdentity: GitHubActionsJwtPayload,
    effectiveSubjects: string[],
    pendingPermissions: Record<string, string>,
    repoPolicyPaths: string[],
): Promise<Record<string, string>> {

  if (hasEntries(validatePermissions(pendingPermissions, 'repo').invalid)) {
    throw new Error('SAFEGUARD Error - ' +
        'Non repository permissions should have been handled within owner access policy section');
  }

  const repositoryResults = await Promise.all(
      tokenRequest.repositories.map((repo) => GITHUB_API_CONCURRENCY_LIMIT(async () => {
        const result = {
          owner: tokenRequest.owner,
          repo,
          issues: [] as GitHubAccessTokenErrorIssue[],
          granted: {} as GitHubAppRepositoryPermissions,
        };

        const accessPolicyResult = await resultOf(getRepoAccessPolicy(client, {
          owner: tokenRequest.owner, repo,
          paths: repoPolicyPaths,
          strict: false, // ignore invalid access policy entries
        }));

        if (!accessPolicyResult.success) {
          const error = accessPolicyResult.error;
          if (error instanceof GithubAccessPolicyError) {
            logger.info({owner: tokenRequest.owner, repo, issues: error.issues},
                `Repository access policy - ${error.message}`);
            // BE AWARE to prevent leaking owner existence
            result.issues.push(callerIdentity.repository_owner === tokenRequest.owner
                ? formatAccessPolicyError(error)
                : NOT_AUTHORIZED_MESSAGE);
            return result;
          }
          throw error;
        }

        const repoAccessPolicy = accessPolicyResult.value;
        logger.debug({owner: tokenRequest.owner, repo, repoAccessPolicy}, 'Repository access policy');

        const statementsGranted = evaluateGrantedPermissions({
          statements: repoAccessPolicy.statements,
          callerIdentitySubjects: effectiveSubjects,
        });

        if (!hasEntries(statementsGranted)) {
          logger.info({owner: tokenRequest.owner, repo}, 'Repository access policy - no permissions granted');
          // BE AWARE to prevent leaking owner existence
          result.issues.push(NOT_AUTHORIZED_MESSAGE);
          return result;
        }

        const {granted, pending} = verifyPermissions({
          granted: statementsGranted,
          requested: pendingPermissions,
        });

        // Collect denied permissions as issues
        Object.entries(pending).forEach(([scope, permission]) => {
          result.issues.push({scope, permission, message: NOT_AUTHORIZED_MESSAGE});
        });

        result.granted = granted;
        return result;
      })));

  // Ensure every repository granted every pending permission
  const anyDenials = repositoryResults
      .map((it) => verifyPermissions({granted: it.granted, requested: pendingPermissions}).pending)
      .some(hasEntries);
  if (anyDenials) {
    throw new GitHubAccessTokenError(repositoryResults, effectiveSubjects);
  }

  return aggregatePermissions(repositoryResults.map((it) => it.granted));
}

// --- Token request normalisation ----------------------------------------------------------------------------------

/**
 * Normalize the token request in-place: resolve the `owner` field and
 * reduce `repositories` to a de-duplicated list of plain repository names.
 *
 * Throws `GitHubAccessTokenError` for invalid requests (e.g. mixed owners).
 */
function normalizeTokenRequest(
    tokenRequest: GitHubAccessTokenRequest,
    callerIdentity: GitHubActionsJwtPayload,
): asserts tokenRequest is NormalizedTokenRequest {

  if (!hasEntries(tokenRequest.permissions)) {
    throw new GitHubAccessTokenError([
      'Invalid token request - permissions must have at least one entry',
    ]);
  }

  if (tokenRequest.repositories === 'ALL') {
    if (!tokenRequest.owner) {
      tokenRequest.owner = callerIdentity.repository_owner;
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
    // Replace repository strings with plain names (no owner prefix)
    tokenRequest.repositories = Array.from(repositoriesNameSet);
  }
}

// --- Caller Identity --------------------------------------------------------------------------------------------

/**
 * Build the effective set of OIDC subjects for the caller identity.
 *
 * Adds artificial compound subjects (`repo:…:ref:…`, `repo:…:workflow_ref:…`,
 * `repo:…:job_workflow_ref:…`) alongside the raw `sub` claim so that access
 * policy patterns can use shorter forms.  Pull-request refs are excluded
 * because they are not trusted for access grants.
 *
 * @param callerIdentity - caller identity from GitHub Actions OIDC token
 * @return deduplicated list of effective subjects
 */
export function getEffectiveCallerIdentitySubjects(callerIdentity: GitHubActionsJwtPayload): string[] {
  const subjects = [callerIdentity.sub];

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

// --- Errors --------------------------------------------------------------------------------------------------------

/**
 * Represents a GitHub access token error with per-owner/repo issue details
 */
export class GitHubAccessTokenError extends Error {
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
              }).map((msg) => indent(msg, '- ')).join('\n');
        }).map((msg) => indent(msg, '- ')).join('\n');

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

// --- Types ---------------------------------------------------------------------------------------------------------

export type GitHubAccessTokenRequest = {
  owner?: string,
  permissions: GitHubAppPermissions,
  repositories: string[] | 'ALL',
};
