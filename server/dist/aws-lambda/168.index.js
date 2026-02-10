export const id = 168;
export const ids = [168];
export const modules = {

/***/ 5391:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ND: () => (/* binding */ accessTokenManager),
/* harmony export */   Vi: () => (/* binding */ GitHubAccessTokenError)
/* harmony export */ });
/* unused harmony export GithubAccessPolicyError */
/* harmony import */ var _octokit_core__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(3070);
/* harmony import */ var _octokit_plugin_paginate_rest__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(3779);
/* harmony import */ var _octokit_plugin_rest_endpoint_methods__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(9210);
/* harmony import */ var zod__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(3905);
/* harmony import */ var _octokit_auth_app__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(6479);
/* harmony import */ var p_limit__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(8890);
/* harmony import */ var p_limit__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(p_limit__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _common_zod_utils_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(4128);
/* harmony import */ var _common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(7844);
/* harmony import */ var _common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(446);
/* harmony import */ var _common_http_utils_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(1949);
/* harmony import */ var _logger_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(6999);











const Octokit = _octokit_core__WEBPACK_IMPORTED_MODULE_6__/* .Octokit */ .E
    .plugin(_octokit_plugin_rest_endpoint_methods__WEBPACK_IMPORTED_MODULE_7__/* .restEndpointMethods */ ._).plugin(_octokit_plugin_paginate_rest__WEBPACK_IMPORTED_MODULE_8__/* .paginateRest */ .ud);
const ACCESS_POLICY_MAX_SIZE = 100 * 1024; // 100kb
const GITHUB_API_CONCURRENCY_LIMIT = p_limit__WEBPACK_IMPORTED_MODULE_0___default()(8);
// BE AWARE to always use NOT_AUTHORIZED_MESSAGE if no permissions are granted to caller identity.
// otherwise, unintended leaks of repository existence could happen.
const NOT_AUTHORIZED_MESSAGE = 'Not authorized';
/**
 * GitHub Access Manager
 * @param options - options
 * @return access token manager
 */
async function accessTokenManager(options) {
    _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.debug({ appId: options.githubAppAuth.appId }, 'GitHub app');
    const GITHUB_APP_CLIENT = new Octokit({
        authStrategy: _octokit_auth_app__WEBPACK_IMPORTED_MODULE_9__/* .createAppAuth */ .K,
        auth: options.githubAppAuth,
    });
    const GITHUB_APP = await GITHUB_APP_CLIENT.rest.apps.getAuthenticated()
        .then((res) => res.data ?? (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* ._throw */ .o6)(new Error('GitHub app not found')));
    /**
     * Creates a GitHub Actions Access Token
     * @param callerIdentity - caller identity
     * @param tokenRequest - token request
     * @return access token
     */
    async function createAccessToken(callerIdentity, tokenRequest) {
        const effectiveCallerIdentitySubjects = getEffectiveCallerIdentitySubjects(callerIdentity);
        normalizeTokenRequest(tokenRequest, callerIdentity);
        // grant requested permissions explicitly to prevent accidental permission escalation
        const grantedTokenPermissions = {};
        const pendingTokenPermissions = { ...tokenRequest.permissions };
        // --- get target app installation ---------------------------------------------------------------------------------
        const appInstallation = await getAppInstallation(GITHUB_APP_CLIENT, {
            owner: tokenRequest.owner,
        });
        // === verify target app installation ==============================================================================
        {
            if (!appInstallation) {
                _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner }, `'${GITHUB_APP.name}' has not been installed`);
                throw new GitHubAccessTokenError([{
                        owner: tokenRequest.owner,
                        // BE AWARE to prevent leaking owner existence
                        issues: callerIdentity.repository_owner === tokenRequest.owner ?
                            [`'${GITHUB_APP.name}' has not been installed. Install from ${GITHUB_APP.html_url}`] :
                            [NOT_AUTHORIZED_MESSAGE],
                    }], effectiveCallerIdentitySubjects);
            }
            _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.debug({ appInstallation }, 'App installation');
            const accessPolicyPaths = [
                ...options.accessPolicyLocation.owner.paths,
                ...options.accessPolicyLocation.repo.paths,
            ];
            if (!accessPolicyPaths.every((path) => appInstallation.single_file_paths?.includes(path) || appInstallation.single_file_name === path)) {
                _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner, required: accessPolicyPaths, actual: appInstallation.single_file_paths }, `'${GITHUB_APP.name}' is not authorized to read all access policy file(s) by 'single_file' permission`);
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
            const requestedAppInstallationPermissions = (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .verifyPermissions */ .SY)({
                granted: (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .normalizePermissionScopes */ .c0)(appInstallation.permissions),
                requested: tokenRequest.permissions,
            });
            if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(requestedAppInstallationPermissions.pending)) {
                _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner, denied: requestedAppInstallationPermissions.pending }, `App installation is not authorized`);
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
            permissions: { single_file: 'read', contents: 'read' },
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
                    _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner, issues: error.issues }, 'Owner access policy - invalid');
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
            _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.debug({ owner: tokenRequest.owner, ownerAccessPolicy: accessPolicy }, 'Owner access policy');
            // if allowed-subjects is not defined, allow any subjects from the policy owner
            const allowedSubjects = accessPolicy['allowed-subjects'] ??
                [`repo:${tokenRequest.owner}/*:**`]; // e.g., ['repo:qoomon/*:**' ]
            if (!matchSubject(allowedSubjects, effectiveCallerIdentitySubjects)) {
                _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner }, 'OIDC token subject is not allowed by owner access policy');
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
            const verifiedPermissions = (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .verifyPermissions */ .SY)({
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
            if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(pendingOwnerPermissions)) {
                // --- reject all pending owner permissions
                _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner, denied: pendingOwnerPermissions }, 'Owner access policy - permission(s) not granted');
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
            if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(pendingTokenPermissions)) {
                if (tokenRequest.repositories === 'ALL') {
                    // --- ensure owner access policy has granted all requested repository permissions
                    // --- reject all pending permissions
                    _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner, denied: pendingTokenPermissions }, 'Owner access policy - permission(s) not granted');
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
                }
                else {
                    // --- ensure owner access policy explicitly allows all pending repository permissions
                    const forbiddenRepositoryPermissions = (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .verifyPermissions */ .SY)({
                        granted: accessPolicy['allowed-repository-permissions'],
                        requested: pendingTokenPermissions,
                    }).pending;
                    if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(forbiddenRepositoryPermissions)) {
                        // --- reject all repository permissions that are not allowed by owner access policy
                        _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner, denied: forbiddenRepositoryPermissions }, 'Owner access policy - permission(s) not allowed');
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
        if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(pendingTokenPermissions)) {
            if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)((0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .validatePermissions */ .Fe)(pendingTokenPermissions, 'repo').invalid)) {
                throw new Error('SAFEGUARD Error - ' +
                    'Non repository permissions should have been handled within owner access policy section');
            }
            if (tokenRequest.repositories === 'ALL') {
                throw new Error('SAFEGUARD Error - ' +
                    `'ALL' repositories scope should have been handled within owner access policy section`);
            }
            const repositoryVerifyResults = await Promise.all(tokenRequest.repositories.map((repo) => GITHUB_API_CONCURRENCY_LIMIT(async () => {
                const result = {
                    owner: tokenRequest.owner,
                    repo,
                    issues: [],
                    granted: {},
                };
                const accessPolicyResult = await (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .resultOf */ .Bg)(getRepoAccessPolicy(appInstallationClient, {
                    owner: tokenRequest.owner, repo,
                    paths: options.accessPolicyLocation.repo.paths,
                    strict: false, // ignore invalid access policy entries
                }));
                if (!accessPolicyResult.success) {
                    const error = accessPolicyResult.error;
                    if (error instanceof GithubAccessPolicyError) {
                        _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner, repo, issues: error.issues }, 'Repository access policy - invalid');
                        if (callerIdentity.repository_owner === tokenRequest.owner) {
                            result.issues.push(formatAccessPolicyError(error));
                        }
                        else {
                            // BE AWARE to prevent leaking owner existence
                            result.issues.push(NOT_AUTHORIZED_MESSAGE);
                        }
                        return result;
                    }
                    throw error;
                }
                const repoAccessPolicy = accessPolicyResult.value;
                _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.debug({ owner: tokenRequest.owner, repo, repoAccessPolicy }, 'Repository access policy');
                const grantedPermissions = evaluateGrantedPermissions({
                    statements: repoAccessPolicy.statements,
                    callerIdentitySubjects: effectiveCallerIdentitySubjects,
                });
                if (!(0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(grantedPermissions)) {
                    _logger_js__WEBPACK_IMPORTED_MODULE_5__/* .logger */ .v.info({ owner: tokenRequest.owner, repo }, 'Repository access policy - no permissions granted');
                    // BE AWARE to prevent leaking owner existence
                    result.issues.push(NOT_AUTHORIZED_MESSAGE);
                    return result;
                }
                const verifiedPermissions = (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .verifyPermissions */ .SY)({
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
                .map((it) => (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .verifyPermissions */ .SY)({
                granted: it.granted,
                requested: pendingTokenPermissions,
            }).pending);
            if (pendingRepositoryPermissions.some(_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)) {
                throw new GitHubAccessTokenError(repositoryVerifyResults, effectiveCallerIdentitySubjects);
            }
            const grantedPermissions = (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .aggregatePermissions */ .YF)(repositoryVerifyResults.map((it) => it.granted));
            // --- grant repository permission only if all repositories have granted the specific permission
            for (const [scope, permission] of Object.entries(grantedPermissions)) {
                grantedTokenPermissions[scope] = permission;
                // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
                delete pendingTokenPermissions[scope];
            }
        }
        // === create requested access token ===============================================================================
        if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(pendingTokenPermissions)) {
            throw new Error('SAFEGUARD Error - Unexpected pending permissions');
        }
        if (!arePermissionsEqual(tokenRequest.permissions, grantedTokenPermissions)) {
            throw new Error('SAFEGUARD Error - Unexpected mismatch between requested and granted permissions');
        }
        const accessToken = await createInstallationAccessToken(GITHUB_APP_CLIENT, appInstallation, {
            // BE AWARE that an empty object will result in a token with all app installation permissions
            permissions: (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .ensureHasEntries */ .V3)(grantedTokenPermissions),
            // BE AWARE that an empty array will result in a token with access to all app installation repositories
            repositories: tokenRequest.repositories === 'ALL' ? undefined : (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .ensureHasEntries */ .V3)(tokenRequest.repositories),
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
function normalizeTokenRequest(tokenRequest, callerIdentity) {
    if (!(0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(tokenRequest.permissions)) {
        throw new GitHubAccessTokenError([
            'Invalid token request - permissions must have at least one entry',
        ]);
    }
    if (tokenRequest.repositories === 'ALL') {
        if (!tokenRequest.owner) {
            tokenRequest.owner = callerIdentity.repository_owner;
        }
    }
    else {
        if (tokenRequest.owner && !(0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(tokenRequest.repositories)) {
            throw new GitHubAccessTokenError([
                'Invalid token request - repositories must have at least one entry if owner is specified explicitly',
            ]);
        }
        if (!(0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .hasEntries */ .T5)(tokenRequest.repositories)) {
            tokenRequest.repositories.push(callerIdentity.repository);
        }
        const repositories = tokenRequest.repositories
            .map((repository) => (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .parseRepository */ .SU)(repository, tokenRequest.owner ?? callerIdentity.repository_owner));
        const repositoriesOwnerSet = new Set();
        if (tokenRequest.owner) {
            repositoriesOwnerSet.add(tokenRequest.owner);
        }
        const repositoriesNameSet = new Set();
        for (const repository of repositories) {
            repositoriesOwnerSet.add(repository.owner);
            repositoriesNameSet.add(repository.repo);
        }
        if (repositoriesOwnerSet.size > 1) {
            if (tokenRequest.owner) {
                throw new GitHubAccessTokenError([
                    `Invalid token request - All repositories owners must match the specified owner ${tokenRequest.owner}`,
                ]);
            }
            else {
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
async function getOwnerAccessPolicy(client, { owner, repo, paths, strict, }) {
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
        resolveAccessPolicyStatementSubjects(statement, { owner, repo });
    });
    return policy;
    function normalizeAccessPolicyEntries(policy) {
        if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(policy)) {
            if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(policy['allowed-repository-permissions'])) {
                policy['allowed-repository-permissions'] = (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .normalizePermissionScopes */ .c0)(policy['allowed-repository-permissions']);
            }
            if (Array.isArray(policy.statements)) {
                policy.statements = policy.statements.map((statement) => {
                    if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(statement) && (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(statement.permissions)) {
                        statement.permissions = (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .normalizePermissionScopes */ .c0)(statement.permissions);
                    }
                    return statement;
                });
            }
        }
        return policy;
    }
    function filterValidAccessPolicyEntries(policy) {
        if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(policy)) {
            if (Array.isArray(policy['allowed-subjects'])) {
                policy['allowed-subjects'] = filterValidSubjects(policy['allowed-subjects']);
            }
            if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(policy['allowed-repository-permissions'])) {
                policy['allowed-repository-permissions'] = filterValidPermissions('repo', policy['allowed-repository-permissions']);
            }
            if (Array.isArray(policy.statements)) {
                policy.statements = filterValidStatements(policy.statements, 'owner');
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
async function getRepoAccessPolicy(client, { owner, repo, paths, strict, }) {
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
        resolveAccessPolicyStatementSubjects(statement, { owner, repo });
    });
    return policy;
    function normalizeAccessPolicyEntries(policy) {
        if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(policy) && Array.isArray(policy.statements)) {
            policy.statements = policy.statements.map((statement) => {
                if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(statement) && (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(statement.permissions)) {
                    statement.permissions = (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .normalizePermissionScopes */ .c0)(statement.permissions);
                }
                return statement;
            });
        }
        return policy;
    }
    function filterValidAccessPolicyEntries(policy) {
        if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(policy) && Array.isArray(policy.statements)) {
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
async function getAccessPolicy(client, { owner, repo, paths, schema, preprocessor, }) {
    const policyValue = await (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .findFirstNotNull */ .E7)(paths, (path) => getRepositoryFileContent(client, { owner, repo, path, maxSize: ACCESS_POLICY_MAX_SIZE }));
    if (!policyValue) {
        throw new GithubAccessPolicyError(`Access policy not found`);
    }
    const policyParseResult = _common_zod_utils_js__WEBPACK_IMPORTED_MODULE_1__/* .YamlTransformer */ .l0
        .transform(preprocessor)
        .pipe(schema)
        .safeParse(policyValue);
    if (policyParseResult.error) {
        const issues = policyParseResult.error.issues.map(_common_zod_utils_js__WEBPACK_IMPORTED_MODULE_1__/* .formatZodIssue */ .qL);
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
function filterValidStatements(statements, permissionsType) {
    return statements
        .map((statementObject) => {
        if ((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(statementObject)) {
            // ---- subjects
            if ('subjects' in statementObject && Array.isArray(statementObject.subjects)) {
                // ignore invalid subjects
                statementObject.subjects = filterValidSubjects(statementObject.subjects);
            }
            // ---- permissions
            if ('permissions' in statementObject && (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .isRecord */ .u4)(statementObject.permissions)) {
                // ignore invalid permissions
                statementObject.permissions = filterValidPermissions(permissionsType, statementObject.permissions);
            }
        }
        return statementObject;
    })
        .filter((statementObject) => GitHubAccessStatementSchema.safeParse(statementObject).success);
}
/**
 * Filter invalid subjects
 * @param subjects - access policy subjects
 * @return valid subjects
 */
function filterValidSubjects(subjects) {
    return subjects.filter((it) => GitHubSubjectPatternSchema.safeParse(it).success);
}
/**
 * Filter invalid permissions
 * @param scopeType - permission scope type, either 'owner' or 'repo'
 * @param permissions - access policy permissions
 * @return valid permissions
 */
function filterValidPermissions(scopeType, permissions) {
    const negate = scopeType.startsWith('!');
    const _scopeType = scopeType.replace(/^!/, '');
    const permissionSchema = _scopeType === 'owner'
        ? _common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .GitHubAppPermissionsSchema */ .ae
        : _common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .GitHubAppRepositoryPermissionsSchema */ .Eh;
    return (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .filterObjectEntries */ .KO)(permissions, ([scope, permission]) => negate !== permissionSchema.safeParse({ [scope]: permission }).success);
}
/**
 * Check if access permission objects are equal
 * @param permissionsA - one permissions object
 * @param permissionsB - another permissions object
 * @return true if permissions are equal
 */
function arePermissionsEqual(permissionsA, permissionsB) {
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
function resolveAccessPolicyStatementSubjects(statement, { owner, repo }) {
    statement.subjects = statement.subjects
        .map((it) => resolveAccessPolicyStatementSubject(it, { owner, repo }));
    // LEGACY SUPPORT for the artificial subject pattern
    const artificialSubjects = getArtificialAccessPolicyStatementSubjects(statement.subjects, { owner, repo });
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
function getArtificialAccessPolicyStatementSubjects(subjects, { owner, repo }) {
    const artificialSubjects = [];
    subjects.forEach((it) => {
        const subjectRepo = it.match(/(^|:)repo:(?<repo>[^:]+)/)?.groups?.repo ?? `${owner}/${repo}`;
        let artificialSubject = it;
        // prefix subject with repo claim, if not already prefixed
        artificialSubject = artificialSubject.startsWith('repo:') ? artificialSubject :
            `repo:${subjectRepo}:${artificialSubject}`;
        // prefix (job_)workflow_ref claim value with repo, if not already prefixed
        artificialSubject = artificialSubject.replace(/(?<=^|:)(?<claim>(job_)?workflow_ref):(?<value>[^:]+)/, (match, ...args) => {
            const { claim, value } = args.at(-1);
            if (value.startsWith('/'))
                return `${claim}:${subjectRepo}${value}`;
            return match;
        });
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
function resolveAccessPolicyStatementSubject(subject, { owner, repo }) {
    // resolve variables
    return subject.replaceAll('${origin}', `${owner}/${repo}`);
}
/**
 * Evaluate granted permissions for caller identity
 * @param accessPolicy - access policy
 * @param callerIdentitySubjects - caller identity subjects
 * @return granted permissions
 */
function evaluateGrantedPermissions({ statements, callerIdentitySubjects }) {
    const permissions = statements
        .filter(statementSubjectPredicate(callerIdentitySubjects))
        .map((it) => it.permissions);
    return (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .aggregatePermissions */ .YF)(permissions);
    /**
     * Create statement subject predicate
     * @param subjects - caller identity subjects
     * @return true if statement subjects match any of the given subject patterns
     */
    function statementSubjectPredicate(subjects) {
        return (statement) => subjects
            .some((subject) => statement.subjects
            .some((subjectPattern) => matchSubject(subjectPattern, subject)));
    }
}
/**
 * Get effective caller identity subjects
 * @param callerIdentity - caller identity
 * @return effective caller identity subjects
 */
function getEffectiveCallerIdentitySubjects(callerIdentity) {
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
    return (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .unique */ .Am)(subjects);
}
/**
 * Verify if subject is granted by grantedSubjectPatterns
 * @param subjectPattern - subject pattern
 * @param subject - subject e.g. 'repo:spongebob/sandbox:ref:refs/heads/main'
 * @return true if subject matches any granted subject pattern
 */
function matchSubject(subjectPattern, subject) {
    if (Array.isArray(subject)) {
        return subject.some((subject) => matchSubject(subjectPattern, subject));
    }
    if (Array.isArray(subjectPattern)) {
        return subjectPattern.some((subjectPattern) => matchSubject(subjectPattern, subject));
    }
    // subject pattern claims must not contain wildcards to prevent granting access accidentally
    //   repo:foo/bar:*  is NOT allowed
    //   repo:foo/bar:** is allowed
    //   repo:foo/*:**   is allowed
    const explicitSubjectPattern = subjectPattern.replace(/:\*\*$/, '');
    if (Object.keys((0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .parseOIDCSubject */ .VX)(explicitSubjectPattern)).some((claim) => claim.includes('*'))) {
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
function regexpOfSubjectPattern(subjectPattern) {
    const regexp = (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .escapeRegexp */ .bS)(subjectPattern)
        .replaceAll('\\*\\*', '(?:.*)') // **  matches zero or more characters
        .replaceAll('\\*', '(?:[^:]*)') //  *  matches zero or more characters except ':'
        .replaceAll('\\?', '[^:]'); //  ?  matches one character except ':'
    return RegExp(`^${regexp}$`, 'i');
}
/**
 * Format access policy error
 * @param error - access policy error
 * @return formatted error message
 */
function formatAccessPolicyError(error) {
    return error.message + (!error.issues?.length ? '' : '\n' +
        error.issues.map((issue) => (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .indent */ .pZ)(issue, '- ')).join('\n'));
}
// --- GitHub Functions ----------------------------------------------------------------------------------------------
/**
 * Get GitHub app installation for a repository or owner
 * @param client - GitHub client
 * @param owner - app installation owner
 * @return installation or null if app is not installed for target
 */
async function getAppInstallation(client, { owner }) {
    // WORKAROUND: for some reason sometimes the request connection gets closed unexpectedly (line closed),
    // therefore, we retry on any error
    return (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .retry */ .L5)(async () => client.rest.apps.getUserInstallation({ username: owner })
        .then((res) => res.data)
        .catch(async (error) => (error.status === _common_http_utils_js__WEBPACK_IMPORTED_MODULE_4__/* .Status */ .n.NOT_FOUND ? null : (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* ._throw */ .o6)(error))), {
        delay: 1000,
        retries: 3,
    });
}
/**
 * Create installation access token
 * @param client - GitHub client
 * @param installation - target installation id
 * @param repositories - target repositories
 * @param permissions - requested permissions
 * @return access token
 */
async function createInstallationAccessToken(client, installation, { repositories, permissions, }) {
    // noinspection TypeScriptValidateJSTypes
    return client.rest.apps.createInstallationAccessToken({
        installation_id: installation.id,
        // BE AWARE that an empty object will result in a token with all app installation permissions
        permissions: (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .ensureHasEntries */ .V3)((0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .mapObjectEntries */ .s0)(permissions, ([scope, permission]) => [
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
async function createOctokit(client, installation, { permissions, repositories }) {
    const installationAccessToken = await createInstallationAccessToken(client, installation, {
        permissions,
        repositories,
    });
    return new Octokit({ auth: installationAccessToken.token });
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
async function getRepositoryFileContent(client, { owner, repo, path, maxSize, }) {
    return client.rest.repos.getContent({ owner, repo, path })
        .then((res) => {
        if ('type' in res.data && res.data.type === 'file') {
            if (maxSize !== undefined && res.data.size > maxSize) {
                throw new Error(`Expect file size to be less than ${maxSize}b, but was ${res.data.size}b` +
                    `${owner}/${repo}/${path}`);
            }
            return Buffer.from(res.data.content, 'base64').toString();
        }
        throw new Error('Unexpected file content');
    })
        .catch((error) => {
        if (error.status === _common_http_utils_js__WEBPACK_IMPORTED_MODULE_4__/* .Status */ .n.NOT_FOUND)
            return null;
        throw error;
    });
}
// --- Errors ------------------------------------------------------------------------------------------------------
/**
 * Represents a GitHub access token error
 */
class GitHubAccessTokenError extends Error {
    /**
     * Creates a new GitHub access token error
     * @param reasons - error reasons
     * @param callerIdentitySubjects - caller identity subjects
     */
    constructor(reasons, callerIdentitySubjects) {
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
                    }).map((message) => (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .indent */ .pZ)(message, '- ')).join('\n');
            }).map((message) => (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .indent */ .pZ)(message, '- ')).join('\n');
        if (callerIdentitySubjects) {
            message += '\n' +
                'Effective OIDC token subjects:\n' +
                `${callerIdentitySubjects.map((subject) => (0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .indent */ .pZ)(subject, '- ')).join('\n')}`;
        }
        super(message);
        Object.setPrototypeOf(this, GitHubAccessTokenError.prototype);
    }
}
/**
 * Access Policy Error
 */
class GithubAccessPolicyError extends Error {
    issues;
    /**
     * @param message - error message
     * @param issues - list of issues
     */
    constructor(message, issues) {
        super(message);
        this.issues = issues;
    }
}
// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
const GitHubSubjectPatternSchema = zod__WEBPACK_IMPORTED_MODULE_10__/* .string */ .YjP().trim().max(512);
const GitHubBaseStatementSchema = zod__WEBPACK_IMPORTED_MODULE_10__/* .strictObject */ .rej({
    subjects: zod__WEBPACK_IMPORTED_MODULE_10__/* .array */ .YOg(GitHubSubjectPatternSchema),
});
const GitHubAccessStatementSchema = zod__WEBPACK_IMPORTED_MODULE_10__/* .strictObject */ .rej({
    ...GitHubBaseStatementSchema.shape,
    permissions: _common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .GitHubAppPermissionsSchema */ .ae,
});
const GitHubRepositoryAccessStatementSchema = zod__WEBPACK_IMPORTED_MODULE_10__/* .strictObject */ .rej({
    ...GitHubBaseStatementSchema.shape,
    permissions: _common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .GitHubAppRepositoryPermissionsSchema */ .Eh,
});
const GitHubAccessPolicySchema = zod__WEBPACK_IMPORTED_MODULE_10__/* .strictObject */ .rej({
    origin: _common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .GitHubRepositorySchema */ .B6,
});
const GitHubOwnerAccessPolicySchema = zod__WEBPACK_IMPORTED_MODULE_10__/* .strictObject */ .rej({
    ...GitHubAccessPolicySchema.shape,
    'allowed-subjects': zod__WEBPACK_IMPORTED_MODULE_10__/* .array */ .YOg(GitHubSubjectPatternSchema).optional(),
    'statements': zod__WEBPACK_IMPORTED_MODULE_10__/* .array */ .YOg(GitHubAccessStatementSchema).optional().default(() => []),
    'allowed-repository-permissions': _common_github_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .GitHubAppRepositoryPermissionsSchema */ .Eh.optional().default(() => ({})),
});
const GitHubRepositoryAccessPolicySchema = zod__WEBPACK_IMPORTED_MODULE_10__/* .strictObject */ .rej({
    ...GitHubAccessPolicySchema.shape,
    statements: zod__WEBPACK_IMPORTED_MODULE_10__/* .array */ .YOg(GitHubRepositoryAccessStatementSchema).optional().default(() => []),
});


/***/ }),

/***/ 168:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   appInit: () => (/* binding */ appInit)
/* harmony export */ });
/* harmony import */ var hono__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(9610);
/* harmony import */ var hono_request_id__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(9788);
/* harmony import */ var hono_pretty_json__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(3361);
/* harmony import */ var hono_http_exception__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3040);
/* harmony import */ var hono_body_limit__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(2542);
/* harmony import */ var hono_utils_crypto__WEBPACK_IMPORTED_MODULE_15__ = __webpack_require__(7347);
/* harmony import */ var zod__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(3905);
/* harmony import */ var process__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(932);
/* harmony import */ var process__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(process__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _common_common_utils_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(7844);
/* harmony import */ var _common_github_utils_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(446);
/* harmony import */ var _common_hono_utils_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(2507);
/* harmony import */ var _common_http_utils_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(1949);
/* harmony import */ var _access_token_manager_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(5391);
/* harmony import */ var _logger_js__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(6999);
/* harmony import */ var _config_js__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(9219);
/* harmony import */ var _common_zod_utils_js__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(4128);
















// --- Initialization ------------------------------------------------------------------------------------------------
const GITHUB_ACTIONS_ACCESS_MANAGER = await (0,_access_token_manager_js__WEBPACK_IMPORTED_MODULE_8__/* .accessTokenManager */ .ND)(_config_js__WEBPACK_IMPORTED_MODULE_10__/* .config */ .$);
function appInit(prepare) {
    const app = new hono__WEBPACK_IMPORTED_MODULE_0__/* .Hono */ .$();
    prepare?.(app);
    app.use((0,hono_request_id__WEBPACK_IMPORTED_MODULE_12__/* .requestId */ .z)({ headerName: (process__WEBPACK_IMPORTED_MODULE_3___default().env).REQUEST_ID_HEADER }));
    app.use((context, next) => _logger_js__WEBPACK_IMPORTED_MODULE_9__/* .logger */ .v.withAsyncBindings({
        requestId: context.var.requestId,
    }, next));
    app.use((0,_common_hono_utils_js__WEBPACK_IMPORTED_MODULE_6__/* .debugLogger */ .w9)(_logger_js__WEBPACK_IMPORTED_MODULE_9__/* .logger */ .v));
    app.onError((0,_common_hono_utils_js__WEBPACK_IMPORTED_MODULE_6__/* .errorHandler */ .r_)(_logger_js__WEBPACK_IMPORTED_MODULE_9__/* .logger */ .v));
    app.notFound((0,_common_hono_utils_js__WEBPACK_IMPORTED_MODULE_6__/* .notFoundHandler */ .w6)());
    app.use((0,hono_body_limit__WEBPACK_IMPORTED_MODULE_2__/* .bodyLimit */ .k)({ maxSize: 100 * 1024 })); // 100kb
    app.use((0,hono_pretty_json__WEBPACK_IMPORTED_MODULE_13__/* .prettyJSON */ .T)());
    app.get('/', (context) => {
        return context.text('https://github.com/qoomon/actions--access-token');
    });
    // --- handle access token request -----------------------------------------------------------------------------------
    app.post('/access_tokens', (0,_common_hono_utils_js__WEBPACK_IMPORTED_MODULE_6__/* .tokenAuthenticator */ .hy)(new URL('https://token.actions.githubusercontent.com/.well-known/jwks'), {
        issuer: 'https://token.actions.githubusercontent.com',
        audience: _config_js__WEBPACK_IMPORTED_MODULE_10__/* .config */ .$.githubActionsTokenVerifier.allowedAud,
        subjects: _config_js__WEBPACK_IMPORTED_MODULE_10__/* .config */ .$.githubActionsTokenVerifier.allowedSub,
    }), async (context) => {
        const callerIdentity = context.var.token;
        _logger_js__WEBPACK_IMPORTED_MODULE_9__/* .logger */ .v.info({
            identity: {
                repository_owner: callerIdentity.repository_owner,
                repository: callerIdentity.repository,
                job_workflow_ref: callerIdentity.job_workflow_ref,
                run_id: callerIdentity.run_id,
                attempts: callerIdentity.attempts,
            },
            // for debugging only:
            // workflow_run_url: buildWorkflowRunUrl(callerIdentity),
        }, 'Caller Identity');
        const accessTokenRequest = await (0,_common_hono_utils_js__WEBPACK_IMPORTED_MODULE_6__/* .parseJsonBody */ .Y2)(context.req, AccessTokenRequestBodySchema.check(zod__WEBPACK_IMPORTED_MODULE_14__/* .superRefine */ .zni((tokenRequest, ctx) => {
            if (Array.isArray(tokenRequest.repositories)) {
                if (tokenRequest.owner && !(0,_common_common_utils_js__WEBPACK_IMPORTED_MODULE_4__/* .hasEntries */ .T5)(tokenRequest.repositories)) {
                    ctx.issues.push({
                        code: "custom",
                        message: "Must have at least one entry if owner is specified",
                        input: tokenRequest.repositories,
                        path: ['repositories'],
                    });
                }
                const repositories = tokenRequest.repositories
                    .map((repository) => (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_5__/* .parseRepository */ .SU)(repository, tokenRequest.owner ?? callerIdentity.repository_owner));
                const repositoriesOwnerSet = new Set();
                if (tokenRequest.owner) {
                    repositoriesOwnerSet.add(tokenRequest.owner);
                }
                const repositoriesNameSet = new Set();
                for (const repository of repositories) {
                    repositoriesOwnerSet.add(repository.owner);
                    repositoriesNameSet.add(repository.repo);
                }
                if (repositoriesOwnerSet.size > 1) {
                    if (tokenRequest.owner) {
                        repositories.forEach((repository, index) => {
                            if (repository.owner !== tokenRequest.owner) {
                                ctx.issues.push({
                                    code: "custom",
                                    message: `Owner must match the specified owner '${tokenRequest.owner}'`,
                                    input: tokenRequest.repositories,
                                    path: ['repositories', index],
                                });
                            }
                        });
                    }
                    else {
                        ctx.issues.push({
                            code: "custom",
                            message: "Must have one common owner",
                            input: tokenRequest.repositories,
                            path: ['repositories'],
                        });
                    }
                }
            }
        })));
        _logger_js__WEBPACK_IMPORTED_MODULE_9__/* .logger */ .v.info({
            request: accessTokenRequest
        }, 'Access Token Request');
        // TODO check if all repositories belong to the same owner
        const githubActionsAccessToken = await GITHUB_ACTIONS_ACCESS_MANAGER
            .createAccessToken(callerIdentity, accessTokenRequest)
            .catch((error) => {
            if (error instanceof _access_token_manager_js__WEBPACK_IMPORTED_MODULE_8__/* .GitHubAccessTokenError */ .Vi) {
                _logger_js__WEBPACK_IMPORTED_MODULE_9__/* .logger */ .v.info({
                    reason: error.message,
                }, 'Access Token Denied');
                throw new hono_http_exception__WEBPACK_IMPORTED_MODULE_1__/* .HTTPException */ .y(_common_http_utils_js__WEBPACK_IMPORTED_MODULE_7__/* .Status */ .n.FORBIDDEN, { message: error.message });
            }
            throw error;
        });
        // --- response with requested access token --------------------------------------------------------------------
        const tokenResponseBody = {
            token: githubActionsAccessToken.token,
            token_hash: await (0,hono_utils_crypto__WEBPACK_IMPORTED_MODULE_15__/* .sha256 */ .sc)(githubActionsAccessToken.token).then(_common_common_utils_js__WEBPACK_IMPORTED_MODULE_4__/* .toBase64 */ .nk),
            expires_at: githubActionsAccessToken.expires_at,
            permissions: githubActionsAccessToken.permissions ?
                (0,_common_github_utils_js__WEBPACK_IMPORTED_MODULE_5__/* .normalizePermissionScopes */ .c0)(githubActionsAccessToken.permissions) : undefined,
            repositories: githubActionsAccessToken.repositories?.map((it) => it.name),
            owner: githubActionsAccessToken.owner,
        };
        // BE AWARE: do not log the access token
        _logger_js__WEBPACK_IMPORTED_MODULE_9__/* .logger */ .v.info({
            response: {
                ...tokenResponseBody,
                // retract token
                token: undefined,
            }
        }, 'Access Token Response');
        return context.json(tokenResponseBody);
    });
    return app;
}
// --- Schemas & Types -----------------------------------------------------------------------------------------------------------
const LegacyAccessTokenRequestBodyTransformer = zod__WEBPACK_IMPORTED_MODULE_14__/* .any */ .bzn().transform(val => {
    // legacy support for owner input
    if (val !== null && typeof val === 'object') {
        if (val.scope === 'owner') {
            delete val.scope;
            if (val.repositories?.length === 0) {
                val.repositories = 'ALL';
            }
        }
    }
    return val;
});
const AccessTokenRequestBodySchema = LegacyAccessTokenRequestBodyTransformer.pipe(zod__WEBPACK_IMPORTED_MODULE_14__/* .strictObject */ .rej({
    owner: _common_github_utils_js__WEBPACK_IMPORTED_MODULE_5__/* .GitHubRepositoryOwnerSchema */ .k.optional(),
    permissions: _common_github_utils_js__WEBPACK_IMPORTED_MODULE_5__/* .GitHubAppPermissionsSchema */ .ae.check(_common_zod_utils_js__WEBPACK_IMPORTED_MODULE_11__/* .hasEntries */ .T5),
    repositories: zod__WEBPACK_IMPORTED_MODULE_14__/* .array */ .YOg(_common_github_utils_js__WEBPACK_IMPORTED_MODULE_5__/* .GitHubRepositoryNameSchema */ .A2.or(_common_github_utils_js__WEBPACK_IMPORTED_MODULE_5__/* .GitHubRepositorySchema */ .B6))
        .max(_config_js__WEBPACK_IMPORTED_MODULE_10__/* .config */ .$.maxTargetRepositoriesPerRequest)
        .or(zod__WEBPACK_IMPORTED_MODULE_14__/* .literal */ .euz('ALL'))
        .default(() => []),
}));

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } }, 1);

/***/ }),

/***/ 7844:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Am: () => (/* binding */ unique),
/* harmony export */   Bg: () => (/* binding */ resultOf),
/* harmony export */   E7: () => (/* binding */ findFirstNotNull),
/* harmony export */   KO: () => (/* binding */ filterObjectEntries),
/* harmony export */   L5: () => (/* binding */ retry),
/* harmony export */   T5: () => (/* binding */ hasEntries),
/* harmony export */   V3: () => (/* binding */ ensureHasEntries),
/* harmony export */   _K: () => (/* binding */ env),
/* harmony export */   bS: () => (/* binding */ escapeRegexp),
/* harmony export */   nk: () => (/* binding */ toBase64),
/* harmony export */   o6: () => (/* binding */ _throw),
/* harmony export */   pZ: () => (/* binding */ indent),
/* harmony export */   s0: () => (/* binding */ mapObjectEntries),
/* harmony export */   tl: () => (/* binding */ tuplesOf),
/* harmony export */   tv: () => (/* binding */ regexpOfWildcardPattern),
/* harmony export */   u4: () => (/* binding */ isRecord)
/* harmony export */ });
/* unused harmony exports mapValue, sleep, joinRegExp */
/* harmony import */ var process__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(932);
/* harmony import */ var process__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(process__WEBPACK_IMPORTED_MODULE_0__);

function env(name, required) {
    const value = (process__WEBPACK_IMPORTED_MODULE_0___default().env)[name];
    if (required && !value) {
        throw new Error(`Environment variable ${name} is required`);
    }
    return value;
}
/**
 * This function returns true if the given object has entries
 * @param obj - object to check
 * @return true if the given object has entries
 */
function hasEntries(obj) {
    return Object.entries(obj).length > 0;
}
/**
 * This function will return a result data or error
 * @param promise - promise
 * @return result
 */
async function resultOf(promise) {
    return promise
        .then((value) => ({ success: true, value }))
        .catch((error) => ({ success: false, error }));
}
/**
 * This function will return the first non-null value from the given values
 * @param values - input values
 * @param fn - mapping function
 */
async function findFirstNotNull(values, fn) {
    for (const inputValue of values) {
        const outputValue = await fn(inputValue);
        if (outputValue) {
            return outputValue;
        }
    }
    return null;
}
/**
 * This function will throw the given error
 * @param error - error to throw
 * @return never
 */
function _throw(error) {
    throw error;
}
/**
 * This function maps the given value with the given function
 * @param value - value to map
 * @param fn - mapping function
 * @return mapped value
 */
function mapValue(value, fn) {
    return fn(value);
}
/**
 * This function will ensure that the given object is not empty, otherwise it will throw an error
 * @param obj - object to check
 * @param message - error message
 * @return the given object
 */
function ensureHasEntries(obj, message) {
    if (!hasEntries(obj))
        throw Error(message ?? 'Illegal argument, object can not be empty');
    return obj;
}
/**
 * This function will return a new array with unique values
 * @param iterable - an iterable
 * @return array with unique values
 */
function unique(iterable) {
    return Array.from(new Set(iterable));
}
/**
 * This function will transform an array to an array of tuples
 * @param iterable - an iterable
 * @return array of tuples
 */
function tuplesOf(iterable) {
    const result = [];
    const iterator = iterable[Symbol.iterator]();
    let iteratorResult;
    while (!(iteratorResult = iterator.next()).done) {
        result.push([
            iteratorResult.value,
            iterator.next().value,
        ]);
    }
    return result;
}
/**
 * This function will create a regular expression from a wildcard pattern
 * @param pattern - wildcard pattern
 * @param flags - regular expression flags
 * @return regular expression
 */
function regexpOfWildcardPattern(pattern, flags) {
    const regexp = escapeRegexp(pattern)
        .replace(/\\\*/g, '.+') // replace * with match one or more characters
        .replace(/\\\?/g, '.'); // replace ? with match one characters
    return RegExp(`^${regexp}$`, flags);
}
/**
 * Escape regular expression special characters
 * @param string - string to escape
 * @return escaped string
 */
function escapeRegexp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
/**
 * This function will return a new object created from mapped entries of the given object
 * @param object - an object
 * @param fn - mapping function
 * @return new mapped object
 */
function mapObjectEntries(object, fn) {
    return Object.fromEntries(Object.entries(object).map(fn));
}
/**
 * This function will return a new object from filtered entries of the given object
 * @param object - an object
 * @param fn - filter function
 * @return new filtered object
 */
function filterObjectEntries(object, fn) {
    return Object.fromEntries(Object.entries(object).filter(fn));
}
/**
 * This function will return a promise that will resolve after the given time
 * @param ms - time in milliseconds
 * @return promise
 */
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
/**
 * This function will return a promise that will resolve after the given time
 * @param fn - function to retry
 * @param options - retry options
 * @param options.retries - number of retries
 * @param options.delay - delay between retries
 * @param options.onRetry - function to call on retry, return false to stop retrying
 * @param options.onError - function to call on error, return false to stop retrying
 * @return promise
 */
async function retry(fn, options = {
    retries: 1,
    delay: 1000,
}) {
    const { retries, delay } = options;
    for (let attempts = 0; attempts < retries; attempts++) {
        try {
            const result = await fn();
            if (!options.onRetry || !options.onRetry(result)) {
                return result;
            }
        }
        catch (error) {
            if (options.onError && !options.onError(error)) {
                throw error;
            }
            if (attempts >= retries) {
                throw error;
            }
            await sleep(delay);
        }
    }
    throw Error('Illegal state');
}
/**
 * Indent string
 * @param string - string to indent
 * @param indent - indent string
 * @param subsequentIndent - subsequent indent string
 * @return indented string
 */
function indent(string, indent = '  ', subsequentIndent = ' '.repeat(indent.length)) {
    return string.split('\n')
        .map((line, index) => `${index === 0 ? indent : subsequentIndent}${line}`)
        .join('\n');
}
/**
 * Check if the given value is a record
 * @param value - a value
 * @return true if the given object is a record
 */
function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
/**
 * Joins multiple regular expressions into a single regular expression
 * @param regexps - regular expressions
 * @param flags - regular expression flags
 * @return regular expression
 */
function joinRegExp(regexps, flags) {
    return new RegExp(regexps
        .map((r) => typeof r === 'string' ? r : r.source)
        .join(''), flags);
}
/**
 * Convert string to base64
 * @param value - string to convert
 * @return base64 string
 */
function toBase64(value) {
    return Buffer.from(value ?? '').toString('base64');
}


/***/ }),

/***/ 446:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   A2: () => (/* binding */ GitHubRepositoryNameSchema),
/* harmony export */   B6: () => (/* binding */ GitHubRepositorySchema),
/* harmony export */   Eh: () => (/* binding */ GitHubAppRepositoryPermissionsSchema),
/* harmony export */   Fe: () => (/* binding */ validatePermissions),
/* harmony export */   SU: () => (/* binding */ parseRepository),
/* harmony export */   SY: () => (/* binding */ verifyPermissions),
/* harmony export */   VX: () => (/* binding */ parseOIDCSubject),
/* harmony export */   YF: () => (/* binding */ aggregatePermissions),
/* harmony export */   ae: () => (/* binding */ GitHubAppPermissionsSchema),
/* harmony export */   c0: () => (/* binding */ normalizePermissionScopes),
/* harmony export */   k: () => (/* binding */ GitHubRepositoryOwnerSchema)
/* harmony export */ });
/* unused harmony exports verifyPermission, buildWorkflowRunUrl, GitHubAppOrganizationPermissionsSchema */
/* harmony import */ var zod__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3905);
/* harmony import */ var _common_utils_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(7844);


// --- Functions -------------------------------------------------------------------------------------------------------
/**
 * Parse repository string to owner and repo
 * @param repository - repository string e.g. 'spongebob/sandbox'
 * @param owner - optional default owner if repository string does not contain owner
 * @return object with owner and repo
 */
function parseRepository(repository, owner) {
    const separatorIndex = repository.indexOf('/');
    if (separatorIndex === -1) {
        if (owner) {
            return {
                owner,
                repo: repository,
            };
        }
        throw new Error(`Invalid repository string: ${repository}`);
    }
    return {
        owner: repository.substring(0, separatorIndex),
        repo: repository.substring(separatorIndex + 1),
    };
}
/**
 * Parse subject to claims
 * @param subject - subject string e.g. 'repo:spongebob/sandbox:ref:refs/heads/main'
 * @return object with claims
 */
function parseOIDCSubject(subject) {
    const claims = (0,_common_utils_js__WEBPACK_IMPORTED_MODULE_0__/* .tuplesOf */ .tl)(subject.split(':'));
    return Object.fromEntries(claims);
}
/**
 * Aggregated permission sets to a most permissive permission set
 * @param permissionSets - permission sets
 * @return aggregated permissions
 */
function aggregatePermissions(permissionSets) {
    return permissionSets.reduce((result, permissions) => {
        Object.entries(permissions).forEach(([scope, permission]) => {
            const _scope = scope;
            if (!result[_scope] || verifyPermission({
                granted: permission,
                requested: result[_scope],
            })) {
                result[_scope] = permission;
            }
        });
        return result;
    }, {});
}
/**
 * Verify permission is granted (admin > write > read)
 * @param granted - granted permission
 * @param requested - requested permission
 * @return true if permission was granted
 */
function verifyPermission({ requested, granted }) {
    const PERMISSION_RANKING = ['read', 'write', 'admin'];
    if (!granted)
        return false;
    const grantedRank = PERMISSION_RANKING.indexOf(granted);
    if (grantedRank < 0)
        return false;
    if (!requested)
        return false;
    const requestedRank = PERMISSION_RANKING.indexOf(requested);
    if (requestedRank < 0)
        return false;
    return requestedRank <= grantedRank;
}
/**
 * Verify permissions
 * @see verifyPermission
 * @param requested - requested permissions
 * @param granted - granted permissions
 * @return granted and denied permissions
 */
function verifyPermissions({ requested, granted }) {
    const result = {
        granted: {},
        pending: {},
    };
    Object.entries(requested).forEach(([scope, requestedPermission]) => {
        if (verifyPermission({
            granted: granted[scope],
            requested: requestedPermission,
        })) {
            result.granted[scope] = requestedPermission;
        }
        else {
            result.pending[scope] = requestedPermission;
        }
    });
    return result;
}
/**
 * Verify repository permissions
 * @param permissions - permissions
 * @param scopeType - scope type, either 'owner' or 'repo'
 * @return invalid repository permissions
 */
function validatePermissions(permissions, scopeType) {
    const valid = {};
    const invalid = {};
    const permissionsSchema = scopeType === 'owner'
        ? GitHubAppPermissionsSchema
        : GitHubAppRepositoryPermissionsSchema;
    Object.entries(permissions).forEach(([scope, permission]) => {
        if (permissionsSchema.keyof().safeParse(scope).success) {
            valid[scope] = permission;
        }
        else {
            invalid[scope] = permission;
        }
    });
    return { valid, invalid };
}
/**
 * Normalise permission scopes to dash case
 * @param permissions - permission object
 * @return normalised permission object
 */
function normalizePermissionScopes(permissions) {
    return (0,_common_utils_js__WEBPACK_IMPORTED_MODULE_0__/* .mapObjectEntries */ .s0)(permissions, ([scope, permission]) => [
        scope.replaceAll('_', '-'), permission,
    ]);
}
/**
 * Get workflow run url from OIDC token payload
 * @param token - OIDC token payload
 * @return workflow run url
 */
function buildWorkflowRunUrl(token) {
    // workflowRunUrl example: https://github.com/qoomon/actions--access-token/actions/runs/9192965843/attempts/2
    return `https://github.com/${token.repository}/actions/runs/${token.run_id}` +
        `${token.attempts ? `/attempts/${token.attempts}` : ''}`;
}
// --- Schemas ---------------------------------------------------------------------------------------------------------
const GitHubRepositoryOwnerRegex = /^[a-z\d](-?[a-z\d])+$/i;
const GitHubRepositoryOwnerSchema = zod__WEBPACK_IMPORTED_MODULE_1__/* .string */ .YjP().regex(GitHubRepositoryOwnerRegex, { abort: true });
const GitHubRepositoryNameRegex = /^[a-z\d-._]+$/i;
const GitHubRepositoryNameSchema = zod__WEBPACK_IMPORTED_MODULE_1__/* .string */ .YjP().regex(GitHubRepositoryNameRegex, { abort: true });
const GitHubRepositorySchema = zod__WEBPACK_IMPORTED_MODULE_1__/* .string */ .YjP().regex(new RegExp(`^${GitHubRepositoryOwnerRegex.source.replace(/^\^|\$$/g, '')}` +
    `/${GitHubRepositoryNameRegex.source.replace(/^\^|\$$/g, '')}$`, 'i'), { abort: true });
const GitHubAppRepositoryPermissionsSchema = zod__WEBPACK_IMPORTED_MODULE_1__/* .strictObject */ .rej({
    // ---- Repository Permissions ----
    'actions': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'actions-variables': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'administration': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'checks': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'codespaces': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'codespaces-lifecycle-admin': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'codespaces-metadata': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'codespaces-secrets': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['write']),
    'contents': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'custom-properties': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'dependabot-secrets': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'deployments': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'discussions': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'environments': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'issues': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'merge-queues': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'metadata': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'packages': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'pages': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'projects': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write', 'admin']),
    'pull-requests': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'repository-advisories': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'repository-hooks': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'repository-projects': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write', 'admin']),
    'secret-scanning-alerts': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'secrets': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'security-events': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'single-file': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'statuses': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'team-discussions': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'vulnerability-alerts': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'workflows': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['write']),
}).partial();
const GitHubAppOrganizationPermissionsSchema = zod__WEBPACK_IMPORTED_MODULE_1__/* .strictObject */ .rej({
    // ---- Organization Permissions ----
    'members': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-actions-variables': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-administration': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-announcement-banners': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-codespaces': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-codespaces-secrets': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-codespaces-settings': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-copilot-seat-management': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-custom-org-roles': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-custom-properties': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write', 'admin']),
    'organization-custom-roles': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-dependabot-secrets': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-events': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read']),
    'organization-hooks': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-personal-access-token-requests': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-personal-access-tokens': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-plan': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read']),
    'organization-projects': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write', 'admin']),
    'organization-secrets': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-self-hosted-runners': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
    'organization-user-blocking': zod__WEBPACK_IMPORTED_MODULE_1__/* ["enum"] */ .k5n(['read', 'write']),
}).partial();
const GitHubAppPermissionsSchema = zod__WEBPACK_IMPORTED_MODULE_1__/* .strictObject */ .rej({
    ...GitHubAppRepositoryPermissionsSchema.shape,
    ...GitHubAppOrganizationPermissionsSchema.shape,
}).partial();


/***/ }),

/***/ 2507:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Y2: () => (/* binding */ parseJsonBody),
/* harmony export */   hy: () => (/* binding */ tokenAuthenticator),
/* harmony export */   r_: () => (/* binding */ errorHandler),
/* harmony export */   w6: () => (/* binding */ notFoundHandler),
/* harmony export */   w9: () => (/* binding */ debugLogger)
/* harmony export */ });
/* harmony import */ var hono_http_exception__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3040);
/* harmony import */ var hono_factory__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(9498);
/* harmony import */ var _zod_utils_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(4128);
/* harmony import */ var _http_utils_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(1949);
/* harmony import */ var _common_utils_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(7844);
/* harmony import */ var jose__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(9858);
/* harmony import */ var jose__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(5983);
/* harmony import */ var jose_errors__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(5674);







/**
 * Creates a NotFoundHandler that responses with JSON
 * @return NotFoundHandler
 */
function notFoundHandler() {
    return (context) => {
        context.status(_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.NOT_FOUND);
        return context.json({
            status: _http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.NOT_FOUND,
            error: _http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .StatusPhrases */ .f[_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.NOT_FOUND],
        });
    };
}
/**
 * Creates an ErrorHandler that response with JSON
 * @return ErrorHandler
 */
function errorHandler(logger) {
    return (err, context) => {
        const requestId = context.var.requestId;
        if (err instanceof hono_http_exception__WEBPACK_IMPORTED_MODULE_0__/* .HTTPException */ .y && err.status < _http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.INTERNAL_SERVER_ERROR) {
            logger.debug({ err }, 'Http Request Client Error');
            context.status(err.status);
            return context.json({
                requestId,
                status: err.status,
                error: _http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .StatusPhrases */ .f[err.status],
                message: err.message,
            });
        }
        logger.error({ err }, 'Http Request Internal Server Error');
        context.status(_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.INTERNAL_SERVER_ERROR);
        return context.json({
            requestId,
            status: _http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.INTERNAL_SERVER_ERROR,
            error: _http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .StatusPhrases */ .f[_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.INTERNAL_SERVER_ERROR],
        });
    };
}
/**
 * Creates a middleware to log http requests and responses
 * @return middleware
 */
function debugLogger(logger) {
    return (0,hono_factory__WEBPACK_IMPORTED_MODULE_1__/* .createMiddleware */ .Ny)(async (context, next) => {
        logger.debug({
            path: context.req.path,
            method: context.req.method,
            query: context.req.query,
        }, 'Http Request');
        await next();
        logger.debug({
            status: context.res.status,
        }, 'Http Response');
    });
}
/**
 * Creates a middleware that parses the request body as json
 * @param req - request
 * @param schema - zod schema
 * @return middleware
 */
async function parseJsonBody(req, schema) {
    const body = await req.text();
    const bodyParseResult = _zod_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .JsonTransformer */ .Cj.pipe(schema).safeParse(body);
    if (!bodyParseResult.success) {
        throw new hono_http_exception__WEBPACK_IMPORTED_MODULE_0__/* .HTTPException */ .y(_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.BAD_REQUEST, {
            message: `Invalid request body:\n${bodyParseResult.error.issues.map(_zod_utils_js__WEBPACK_IMPORTED_MODULE_2__/* .formatZodIssue */ .qL)
                .map((it) => (0,_common_utils_js__WEBPACK_IMPORTED_MODULE_4__/* .indent */ .pZ)(it, '  ')).join('\n')}`,
        });
    }
    return bodyParseResult.data;
}
/**
 * Creates a middleware that verifies a token and sets the token payload as 'token' context variable
 * @param jwksUrl - URL of the JWKS
 * @param options - fast-jwt createVerifier options
 * @return middleware
 */
function tokenAuthenticator(jwksUrl, options) {
    const jwkSet = (0,jose__WEBPACK_IMPORTED_MODULE_5__/* .createRemoteJWKSet */ .RD)(jwksUrl);
    return (0,hono_factory__WEBPACK_IMPORTED_MODULE_1__/* .createMiddleware */ .Ny)(async (context, next) => {
        const authorizationHeaderValue = context.req.header().authorization;
        if (!authorizationHeaderValue) {
            throw new hono_http_exception__WEBPACK_IMPORTED_MODULE_0__/* .HTTPException */ .y(_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.UNAUTHORIZED, {
                message: 'Missing authorization header',
            });
        }
        const [authorizationScheme, tokenValue] = authorizationHeaderValue.split(' ');
        if (authorizationScheme !== 'Bearer') {
            throw new hono_http_exception__WEBPACK_IMPORTED_MODULE_0__/* .HTTPException */ .y(_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.UNAUTHORIZED, {
                message: `Unexpected authorization scheme ${authorizationScheme}`,
            });
        }
        const token = await (0,jose__WEBPACK_IMPORTED_MODULE_6__/* .jwtVerify */ .V)(tokenValue, jwkSet, options).catch((error) => {
            if (error instanceof jose_errors__WEBPACK_IMPORTED_MODULE_7__/* .JOSEError */ .i4) {
                throw new hono_http_exception__WEBPACK_IMPORTED_MODULE_0__/* .HTTPException */ .y(_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.UNAUTHORIZED, {
                    message: 'Invalid token: ' + error.message,
                });
            }
            throw error;
        });
        if (options.subjects && !options.subjects
            .some((subject) => subject.test(token.payload.sub ?? ''))) {
            throw new hono_http_exception__WEBPACK_IMPORTED_MODULE_0__/* .HTTPException */ .y(_http_utils_js__WEBPACK_IMPORTED_MODULE_3__/* .Status */ .n.UNAUTHORIZED, {
                message: `Invalid Token: unexpected "sub" claim value`,
            });
        }
        context.set('token', token.payload);
        await next();
    });
}


/***/ }),

/***/ 1949:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   f: () => (/* binding */ StatusPhrases),
/* harmony export */   n: () => (/* binding */ Status)
/* harmony export */ });
const StatusPhrases = {
    100: 'Continue',
    101: 'Switching Protocols',
    102: 'Processing',
    103: 'Early Hints',
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non Authoritative Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',
    207: 'Multi-Status',
    208: 'Already Reported',
    226: 'IM Used',
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Moved Temporarily',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy',
    306: 'Switch Proxy',
    307: 'Temporary Redirect',
    308: 'Permanent Redirect',
    400: 'Bad Request',
    401: 'Unauthorized',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Request Entity Too Large',
    414: 'Request-URI Too Long',
    415: 'Unsupported Media Type',
    416: 'Requested Range Not Satisfiable',
    417: 'Expectation Failed',
    418: 'I\'m a teapot',
    421: 'Misdirected Request',
    422: 'Unprocessable Entity',
    423: 'Locked',
    424: 'Failed Dependency',
    425: 'Too Early',
    426: 'Upgrade Required',
    428: 'Precondition Required',
    429: 'Too Many Requests',
    431: 'Request Header Fields Too Large',
    451: 'Unavailable For Legal Reasons',
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported',
    506: 'Variant Also Negotiates',
    507: 'Insufficient Storage',
    508: 'Loop Detected',
    510: 'Not Extended',
    511: 'Network Authentication Required',
};
const Status = {
    CONTINUE: 100,
    SWITCHING_PROTOCOLS: 101,
    PROCESSING: 102,
    EARLY_HINTS: 103,
    OK: 200,
    CREATED: 201,
    ACCEPTED: 202,
    NON_AUTHORITATIVE_INFORMATION: 203,
    NO_CONTENT: 204,
    RESET_CONTENT: 205,
    PARTIAL_CONTENT: 206,
    MULTI_STATUS: 207,
    IM_USED: 226,
    MULTIPLE_CHOICES: 300,
    MOVED_PERMANENTLY: 301,
    MOVED_TEMPORARILY: 302,
    SEE_OTHER: 303,
    NOT_MODIFIED: 304,
    USE_PROXY: 305,
    SWITCH_PROXY: 306,
    TEMPORARY_REDIRECT: 307,
    PERMANENT_REDIRECT: 308,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    PAYMENT_REQUIRED: 402,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    METHOD_NOT_ALLOWED: 405,
    NOT_ACCEPTABLE: 406,
    PROXY_AUTHENTICATION_REQUIRED: 407,
    REQUEST_TIMEOUT: 408,
    CONFLICT: 409,
    GONE: 410,
    LENGTH_REQUIRED: 411,
    PRECONDITION_FAILED: 412,
    REQUEST_TOO_LONG: 413,
    REQUEST_URI_TOO_LONG: 414,
    UNSUPPORTED_MEDIA_TYPE: 415,
    REQUESTED_RANGE_NOT_SATISFIABLE: 416,
    EXPECTATION_FAILED: 417,
    IM_A_TEAPOT: 418,
    MISDIRECTED_REQUEST: 421,
    UNPROCESSABLE_ENTITY: 422,
    LOCKED: 423,
    FAILED_DEPENDENCY: 424,
    UPGRADE_REQUIRED: 426,
    PRECONDITION_REQUIRED: 428,
    TOO_EARLY: 425,
    TOO_MANY_REQUESTS: 429,
    REQUEST_HEADER_FIELDS_TOO_LARGE: 431,
    UNAVAILABLE_FOR_LEGAL_REASONS: 451,
    INTERNAL_SERVER_ERROR: 500,
    NOT_IMPLEMENTED: 501,
    BAD_GATEWAY: 502,
    SERVICE_UNAVAILABLE: 503,
    GATEWAY_TIMEOUT: 504,
    HTTP_VERSION_NOT_SUPPORTED: 505,
    VARIANT_ALSO_NEGOTIATES: 506,
    INSUFFICIENT_STORAGE: 507,
    LOOP_DETECTED: 508,
    NOT_EXTENDED: 510,
    NETWORK_AUTHENTICATION_REQUIRED: 511,
};


/***/ }),

/***/ 4128:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Cj: () => (/* binding */ JsonTransformer),
/* harmony export */   T5: () => (/* binding */ hasEntries),
/* harmony export */   l0: () => (/* binding */ YamlTransformer),
/* harmony export */   qL: () => (/* binding */ formatZodIssue)
/* harmony export */ });
/* harmony import */ var zod__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3905);
/* harmony import */ var yaml__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(8815);


const hasEntries = zod__WEBPACK_IMPORTED_MODULE_1__/* .superRefine */ .zni((obj, ctx) => {
    if (Object.keys(obj).length === 0) {
        ctx.issues.push({
            code: 'custom',
            message: `Invalid ${Array.isArray(obj) ? 'array' : 'object'}: must have at least one entry`,
            input: obj,
        });
    }
});
/**
 * This function will format a zod issue
 * @param issue - zod issue
 * @return formatted issue
 */
function formatZodIssue(issue) {
    let result = '- ';
    if (issue.path.length > 0) {
        result += `${issue.path.join('.')}: `;
    }
    if (issue.code === 'invalid_union') {
        result += `Union errors:\n` + issue.errors
            .map((error) => error
            .map((error) => formatZodIssue(error)
            .split('\n')
            .map((line) => '  ' + line)
            .join('\n')).join('\n')).join('\n');
    }
    else {
        result += issue.message;
    }
    return result;
}
const JsonTransformer = zod__WEBPACK_IMPORTED_MODULE_1__/* .string */ .YjP().transform((val, ctx) => {
    try {
        return JSON.parse(val);
    }
    catch (error) {
        ctx.issues.push({
            code: 'custom',
            message: error.message,
            input: val,
        });
        return zod__WEBPACK_IMPORTED_MODULE_1__/* .NEVER */ .tmp;
    }
});
const YamlTransformer = zod__WEBPACK_IMPORTED_MODULE_1__/* .string */ .YjP().transform((str, ctx) => {
    try {
        return yaml__WEBPACK_IMPORTED_MODULE_0__.parse(str);
    }
    catch (error) {
        ctx.addIssue({ code: 'custom', message: error.message });
        return zod__WEBPACK_IMPORTED_MODULE_1__/* .NEVER */ .tmp;
    }
});


/***/ }),

/***/ 9219:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  $: () => (/* binding */ config)
});

// EXTERNAL MODULE: ./src/common/common-utils.ts
var common_utils = __webpack_require__(7844);
;// CONCATENATED MODULE: ./src/common/ras-key-utils.ts
/**
 * This function will format a single line pem key to a well formatted pem key
 * @param keyString - pem key string
 * @return well formatted pem key
 */
function formatPEMKey(keyString) {
    keyString = keyString.trim(); // remove leading and trailing whitespace
    const header = keyString.match(/^-----BEGIN [\w\s]+ KEY-----/g)?.[0];
    const footer = keyString.match(/-----END [\w\s]+ KEY-----$/g)?.[0];
    if (!header || !footer)
        throw Error('Invalid key format');
    const key = keyString
        .slice(header.length, -footer.length) // remove header and footer
        .replace(/\s+/g, ''); // remove all whitespace
    // format key
    return '' +
        header + '\n' +
        // split key into 64 character lines,
        key.replace(/.{1,64}/g, '$&\n') +
        footer + '\n';
}

// EXTERNAL MODULE: ./node_modules/zod/v4/classic/external.js + 73 modules
var external = __webpack_require__(3905);
// EXTERNAL MODULE: ./src/common/github-utils.ts
var github_utils = __webpack_require__(446);
;// CONCATENATED MODULE: ./src/config.ts




const configSchema = external/* strictObject */.rej({
    githubAppAuth: external/* strictObject */.rej({
        appId: external/* string */.YjP()
            .regex(/^[1-9][0-9]*$/),
        privateKey: external/* string */.YjP()
            .regex(/^\s*-----BEGIN [\w\s]+ KEY-----/, 'Invalid key format')
            .regex(/-----END [\w\s]+ KEY-----\s*$/, 'Invalid key format')
            .transform(formatPEMKey),
    }),
    githubActionsTokenVerifier: external/* strictObject */.rej({
        allowedAud: external/* array */.YOg(external/* string */.YjP().nonempty()).nonempty(),
        allowedSub: external/* array */.YOg(external/* instanceof */.Nlp(RegExp)).optional(),
    }),
    accessPolicyLocation: external/* strictObject */.rej({
        owner: external/* strictObject */.rej({
            repo: github_utils/* GitHubRepositoryNameSchema */.A2,
            paths: external/* array */.YOg(external/* string */.YjP().regex(/(\.yaml|\.yml)$/)).nonempty(),
        }),
        repo: external/* strictObject */.rej({
            paths: external/* array */.YOg(external/* string */.YjP().nonempty()).nonempty(),
        }),
    }),
    maxTargetRepositoriesPerRequest: external/* int */.Whr().min(1),
});
const config = validate({
    githubAppAuth: {
        appId: (0,common_utils/* env */._K)('GITHUB_APP_ID', true),
        // depending on the environment multiline environment variables are not supported,
        // due to this limitation formatPEMKey ensure the right format, even if the key formatted as a single line
        privateKey: formatPEMKey((0,common_utils/* env */._K)('GITHUB_APP_PRIVATE_KEY', true)),
    },
    githubActionsTokenVerifier: {
        allowedAud: (0,common_utils/* env */._K)('GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE', true)
            .split(',')
            .map(aud => aud.trim()),
        allowedSub: (0,common_utils/* env */._K)('GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS')
            ?.split(/\s*,\s*/)
            ?.map((subjectPattern) => (0,common_utils/* regexpOfWildcardPattern */.tv)(subjectPattern, 'i')),
    },
    accessPolicyLocation: {
        owner: {
            repo: '.github-access-token',
            paths: ['access-token.yaml', 'access-token.yml'],
        },
        repo: {
            paths: ['.github/access-token.yaml', '.github/access-token.yml'],
        },
    },
    maxTargetRepositoriesPerRequest: 32,
});
function validate(config) {
    return configSchema.parse(config);
}


/***/ })

};
