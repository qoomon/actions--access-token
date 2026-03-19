import {z} from 'zod';
import {formatZodIssue, YamlTransformer} from './common/zod-utils.js';
import {escapeRegexp, filterObjectEntries, findFirstNotNull, indent, isRecord,} from './common/common-utils.js';
import {
  aggregatePermissions,
  GitHubAppPermissions,
  GitHubAppPermissionsSchema,
  GitHubAppRepositoryPermissions,
  GitHubAppRepositoryPermissionsSchema,
  GitHubRepositorySchema,
  normalizePermissionScopes,
  parseOIDCSubject,
} from './common/github-utils.js';
import {logger} from './logger.js';
import {getRepositoryFileContent, Octokit} from './github-app-client.js';

export const ACCESS_POLICY_MAX_SIZE = 100 * 1024; // 100kb

// --- Access Policy Loading -----------------------------------------------------------------------------------------

/**
 * Get owner access policy
 * @param client - GitHub client for target repository
 * @param owner - repository owner
 * @param repo - repository name containing the owner access policy
 * @param paths - candidate file paths (first found is used)
 * @param strict - when false, silently drop invalid entries instead of throwing
 * @return access policy (without the `origin` field)
 */
export async function getOwnerAccessPolicy(client: Octokit, {
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
      value = normalizeOwnerPolicyEntries(value);
      if (!strict) {
        value = filterValidOwnerPolicyEntries(value);
      }
      return value;
    },
  });

  policy.statements?.forEach((statement) => {
    resolveAccessPolicyStatementSubjects(statement, {owner, repo});
  });

  return policy;
}

/**
 * Get repository access policy
 * @param client - GitHub client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param paths - candidate file paths (first found is used)
 * @param strict - when false, silently drop invalid entries instead of throwing
 * @return access policy (without the `origin` field)
 */
export async function getRepoAccessPolicy(client: Octokit, {
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
      value = normalizeRepoPolicyEntries(value);
      if (!strict) {
        value = filterValidRepoPolicyEntries(value);
      }
      return value;
    },
  });

  policy.statements?.forEach((statement) => {
    resolveAccessPolicyStatementSubjects(statement, {owner, repo});
  });

  return policy;
}

/**
 * Load, parse and validate an access policy file from a repository
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
  const policyValue = await findFirstNotNull(paths, async (path) => {
    return getRepositoryFileContent(client, {owner, repo, path, maxSize: ACCESS_POLICY_MAX_SIZE})
        .catch((error) => {
          logger.error({owner, repo, path, error: String(error)}, 'Failed to get access policy file content');
          return null;
        });
  });
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

// --- Normalisation --------------------------------------------------------------------------------------------------

function normalizeOwnerPolicyEntries(policy: unknown): unknown {
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

function filterValidOwnerPolicyEntries(policy: unknown): unknown {
  if (isRecord(policy)) {
    if (Array.isArray(policy['allowed-subjects'])) {
      policy['allowed-subjects'] = filterValidSubjects(policy['allowed-subjects']);
    }
    if (isRecord(policy['allowed-repository-permissions'])) {
      policy['allowed-repository-permissions'] = filterValidPermissions(
          'repo', policy['allowed-repository-permissions']);
    }
    if (Array.isArray(policy.statements)) {
      policy.statements = filterValidStatements(policy.statements, 'owner');
    }
  }
  return policy;
}

function normalizeRepoPolicyEntries(policy: unknown): unknown {
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

function filterValidRepoPolicyEntries(policy: unknown): unknown {
  if (isRecord(policy) && Array.isArray(policy.statements)) {
    policy.statements = filterValidStatements(policy.statements, 'repo');
  }
  return policy;
}

// --- Filtering helpers --------------------------------------------------------------------------------------------

/**
 * Remove invalid statements from a raw statements array
 * @param statements - raw statements
 * @param permissionsType - whether to validate as owner or repo permissions
 * @return only valid statements
 */
function filterValidStatements(statements: unknown[], permissionsType: 'owner' | 'repo')
    : unknown | GitHubAccessStatement[] {
  return statements
      .map((statementObject: unknown) => {
        if (isRecord(statementObject)) {
          if ('subjects' in statementObject && Array.isArray(statementObject.subjects)) {
            statementObject.subjects = filterValidSubjects(statementObject.subjects);
          }
          if ('permissions' in statementObject && isRecord(statementObject.permissions)) {
            statementObject.permissions = filterValidPermissions(permissionsType, statementObject.permissions);
          }
        }
        return statementObject;
      })
      .filter((statementObject: unknown) => GitHubAccessStatementSchema.safeParse(statementObject).success);
}

function filterValidSubjects(subjects: unknown[]): unknown[] {
  return subjects.filter((it: unknown) => GitHubSubjectPatternSchema.safeParse(it).success);
}

export function filterValidPermissions(scopeType: 'repo', permissions: Record<string, unknown>):
    GitHubAppRepositoryPermissions
export function filterValidPermissions(scopeType: 'owner', permissions: Record<string, unknown>):
    GitHubAppPermissions
export function filterValidPermissions(scopeType: '!owner' | '!repo', permissions: Record<string, unknown>):
    Record<string, unknown>
export function filterValidPermissions(
    scopeType: 'owner' | '!owner' | 'repo' | '!repo',
    permissions: Record<string, unknown>): GitHubAppPermissions | GitHubAppRepositoryPermissions
/**
 * Keep only permissions that are valid for the given scope type
 * @param scopeType - 'owner', 'repo', '!owner' (non-owner only), or '!repo' (non-repo only)
 * @param permissions - raw permissions record
 * @return filtered permissions
 */
export function filterValidPermissions(
    scopeType: 'owner' | '!owner' | 'repo' | '!repo',
    permissions: Record<string, unknown>,
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

// --- Subject resolution -------------------------------------------------------------------------------------------

/**
 * Expand and resolve subjects in an access policy statement.
 *
 * Substitutes `${origin}` variables and adds legacy artificial subjects so
 * that abbreviated patterns written before the full OIDC subject format was
 * required continue to match.
 *
 * @param statement - access policy statement (mutated in place)
 * @param owner - policy file owner
 * @param repo - policy file repository
 */
export function resolveAccessPolicyStatementSubjects(statement: { subjects: string[] }, {owner, repo}: {
  owner: string,
  repo: string,
}) {
  statement.subjects = statement.subjects
      .map((it) => resolveSubjectVariables(it, {owner, repo}));

  // LEGACY SUPPORT for the artificial subject pattern
  const artificialSubjects = buildLegacyArtificialSubjects(statement.subjects, {owner, repo});
  statement.subjects.push(...artificialSubjects);
}

/**
 * Substitute `${origin}` placeholder with `owner/repo`
 */
function resolveSubjectVariables(subject: string, {owner, repo}: {
  owner: string,
  repo: string,
}): string {
  return subject.replaceAll('${origin}', `${owner}/${repo}`);
}

/**
 * LEGACY SUPPORT
 * Generate additional subject patterns that match older abbreviated subject formats
 * @param subjects - resolved subjects
 * @param owner - policy file owner
 * @param repo - policy file repository
 * @return additional legacy subjects (may be empty)
 */
function buildLegacyArtificialSubjects(subjects: string[], {owner, repo}: {
  owner: string,
  repo: string,
}): string[] {
  const artificialSubjects: string[] = [];

  subjects.forEach((it) => {
    const subjectRepo = it.match(/(^|:)repo:(?<repo>[^:]+)/)?.groups?.repo ?? `${owner}/${repo}`;

    let artificialSubject = it;

    // prefix subject with repo claim, if not already prefixed
    artificialSubject = artificialSubject.startsWith('repo:') ? artificialSubject :
        `repo:${subjectRepo}:${artificialSubject}`;

    // prefix (job_)workflow_ref claim value with repo, if not already prefixed
    const workflowRefPattern = /(?<=^|:)(?<claim>(job_)?workflow_ref):(?<value>[^:]+)/;
    const workflowRefMatch = workflowRefPattern.exec(artificialSubject);
    if (workflowRefMatch?.groups) {
      const {claim, value} = workflowRefMatch.groups;
      if (value.startsWith('/')) {
        artificialSubject = artificialSubject.replace(
            `${claim}:${value}`, `${claim}:${subjectRepo}${value}`);
      }
    }

    if (artificialSubject !== it) {
      artificialSubjects.push(artificialSubject);
    }
  });

  return artificialSubjects;
}

// --- Permission evaluation ----------------------------------------------------------------------------------------

/**
 * Evaluate the permissions granted to the caller by the given access policy statements
 * @param statements - access policy statements
 * @param callerIdentitySubjects - effective OIDC subjects of the caller
 * @return aggregated granted permissions
 */
export function evaluateGrantedPermissions({statements, callerIdentitySubjects}: {
  statements: { subjects: string[], permissions: Record<string, string> }[],
  callerIdentitySubjects: string[],
}): Record<string, string> {
  const permissions = statements
      .filter((statement) => matchSubject(statement.subjects, callerIdentitySubjects))
      .map((it) => it.permissions);

  return aggregatePermissions(permissions);
}

/**
 * Returns true if `subject` matches any of the `subjectPattern`(s).
 *
 * Wildcards: `**` matches any characters; `*` matches any characters except `:`;
 * `?` matches a single character except `:`.
 *
 * Subject pattern claims (the key parts) must not themselves contain wildcards
 * (e.g. `repo:foo/bar:*` is rejected) to prevent accidentally broad grants.
 * The trailing `:**` form is allowed as a special case.
 *
 * @param subjectPattern - single pattern or array of patterns
 * @param subject - single subject or array of subjects
 */
export function matchSubject(subjectPattern: string | string[], subject: string | string[]): boolean {
  if (Array.isArray(subject)) {
    return subject.some((s) => matchSubject(subjectPattern, s));
  }

  if (Array.isArray(subjectPattern)) {
    return subjectPattern.some((p) => matchSubject(p, subject));
  }

  // subject pattern claims must not contain wildcards to prevent granting access accidentally
  //   repo:foo/bar:*  is NOT allowed
  //   repo:foo/bar:** is allowed
  //   repo:foo/*:**   is allowed
  const patternWithoutGlobSuffix = subjectPattern.replace(/:\*\*$/, '');
  if (Object.keys(parseOIDCSubject(patternWithoutGlobSuffix)).some((claim) => claim.includes('*'))) {
    return false;
  }

  return regexpOfSubjectPattern(subjectPattern).test(subject);
}

/**
 * Compile a wildcard subject pattern into a regular expression
 */
function regexpOfSubjectPattern(subjectPattern: string): RegExp {
  const regexp = escapeRegexp(subjectPattern)
      .replaceAll('\\*\\*', '(?:.*)') // **  matches zero or more characters
      .replaceAll('\\*', '(?:[^:]*)') //  *  matches zero or more characters except ':'
      .replaceAll('\\?', '[^:]'); //  ?  matches one character except ':'
  return RegExp(`^${regexp}$`, 'i');
}

// --- Error formatting ---------------------------------------------------------------------------------------------

/**
 * Format a policy error into a human-readable string including sub-issues
 * @param error - access policy error
 * @return formatted error message
 */
export function formatAccessPolicyError(error: GithubAccessPolicyError): string {
  return error.message + (!error.issues?.length ? '' : '\n' +
      error.issues.map((issue) => indent(issue, '- ')).join('\n'));
}

// --- Errors -------------------------------------------------------------------------------------------------------

/**
 * Represents a policy file parsing/validation error
 */
export class GithubAccessPolicyError extends Error {
  public issues?: string[];

  constructor(message: string, issues?: string[]) {
    super(message);
    this.issues = issues;
  }
}

// --- Schemas & Types -----------------------------------------------------------------------------------------------

// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
const GitHubSubjectPatternSchema = z.string().trim().max(512);

const GitHubBaseStatementSchema = z.strictObject({
  subjects: z.array(GitHubSubjectPatternSchema),
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
  'allowed-subjects': z.array(GitHubSubjectPatternSchema).optional(),
  'statements': z.array(GitHubAccessStatementSchema).optional().default(() => []),
  'allowed-repository-permissions': GitHubAppRepositoryPermissionsSchema.optional().default(() => ({})),
});
export type GitHubOwnerAccessPolicy = z.infer<typeof GitHubOwnerAccessPolicySchema>;

const GitHubRepositoryAccessPolicySchema = z.strictObject({
  ...GitHubAccessPolicySchema.shape,
  statements: z.array(GitHubRepositoryAccessStatementSchema).optional().default(() => []),
});
export type GitHubRepositoryAccessPolicy = z.infer<typeof GitHubRepositoryAccessPolicySchema>;
