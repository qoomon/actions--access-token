import express from 'express'

require('express-async-errors')

const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')
const {Octokit} = require("@octokit/rest")
const {createAppAuth} = require("@octokit/auth-app")
const YAML = require('js-yaml')

// ---------------------------------------------------------------------------------------------------------------------

const IS_DEVELOPMENT_ENV = process.env.NODE_ENV === 'development'
const GITHUB_ACTIONS_ISSUER = 'https://token.actions.githubusercontent.com'
const ACCESS_FILE_LOCATION = '.github/access.yaml'

// ---------------------------------------------------------------------------------------------------------------------

const appClient = new Octokit({
    authStrategy: createAppAuth,
    auth: {
        appId: process.env.GITHUB_APP_ID,
        privateKey: process.env.GITHUB_APP_PRIVATE_KEY,
    }
})

// ---------------------------------------------------------------------------------------------------------------------

const app = express()
app.use(verifyIdToken)
app.use(express.json())

app.post('/v2/access_token', async (request, response) => {
    console.info('[INFO]', `${request.token.repository} requests access token`)

    const requestedRepositories = (request.body.repositories || []).map(repo => repo === 'self' ? request.token.repository : repo)
    console.log('[INFO]', "  requestedRepositories", requestedRepositories)
    if (!requestedRepositories.length) {
        throw new HttpClientError(400, 'Bad Request', 'At least one repository needs to be requested')
    }

    // validate all requested repositories
    for (const repository of requestedRepositories) {
        if (!isValidRepository(repository)) {
            throw new HttpClientError(400, 'Bad Request', `Invalid requested repository: ${repository}`)
        }
    }

    if (!verifySingleOwner(requestedRepositories)) {
        throw new HttpClientError(400, 'Bad Request', 'All repositories must belong to the same owner')
    }

    const requestedPermissions = request.body.permissions || {}
    console.log('[INFO]', "  requestedPermissions", requestedPermissions)
    if (!Object.keys(requestedPermissions).length) {
        throw new HttpClientError(400, 'Bad Request', 'At least one permission needs to be requested')
    }

    // validate all requested permissions
    for (const [scope, permission] of Object.entries(requestedPermissions)) {
        if (!isValidPermission(scope, permission)) {
            throw new HttpClientError(400, 'Bad Request', `Invalid requested permission: ${scope}:${permission}`)
        }
    }

    // -----------------------------------------------------------------------------------------------------------------

    const accessToken = await createInstallationAccessTokenForGithubActions(appClient, {
        repositories: requestedRepositories,
        permissions: requestedPermissions,
    }).catch(err => {
        if(err.name === PermissionError.name){
            throw new HttpClientError(403, 'Forbidden', err.message, err)
        }
        throw err
    })

    // response with access token
    response.json({
        token: accessToken.token,
        expires_at: accessToken.expires_at,
        repositories: accessToken.repositories.map(it => it.full_name),
        permissions: accessToken.permissions,
    })
})

// v1 legacy endpoint
app.post('/access_token', async (request, response) => {
    throw new HttpClientError(410, 'Gone', 'update github action to version >= v2')
})

app.use(errorHandler)

export default app

// ---------------------------------------------------------------------------------------------------------------------

class PermissionError extends Error {
    constructor(message, err) {
        super(message, err);
        this.name = "PermissionError";
    }
}

async function createInstallationAccessTokenForGithubActions(appClient, params) {
    const appInstallation = await appClient.apps.getUserInstallation({
        username: parseRepo(params.repositories[0]).owner
    })
        .then(res => res.data)
        .catch(err => {
            // TODO handle app is not installed
            const app = appClient.apps.getAuthenticated().then(res => res.data)
            // TODO Repository owner needs to install the access manager app first. https://github.com/apps/access-manager-for-github-actions/installations/new
            throw new PermissionError(`The repository owner needs to install access manager app first.`, err)
        })

    // verify if app installation has all requested permissions
    for (const [scope, permission] of Object.entries(params.permissions)) {
        if (!verifyPermission(permission, appInstallation.permissions[scope])) {
            // TODO handle missing permissions
            const app = appClient.apps.getAuthenticated().then(res => res.data)
            // TODO App owner needs to request permission first. https://github.com/settings/apps/access-manager-for-github-actions/permissions
            throw new PermissionError(`The app owner needs to request permission first. ${scope}:${permission}`)
        }
    }

    const accessFileAccessToken = await appClient.apps.createInstallationAccessToken({
        installation_id: appInstallation.id,
        // be aware that an empty array will result in requesting permissions for all repositories
        repositories: ensureNotEmpty(params.repositories).map(repo => parseRepo(repo).name),
        permissions: {single_file: 'read'},
    })
        .then(res => res.data)
        .catch(err => {
            // TODO handle missing permissions for specific repositories
            const app = appClient.apps.getAuthenticated().then(res => res.data)
            // TODO https://github.com/settings/installations/${appInstallation.id} > Repository access
            throw new PermissionError(`The App must be configured to have access to repository.`, err)
        })

    const installationClient = new Octokit({auth: accessFileAccessToken.token});

    // ensure requested permissions are granted for all requested repositories
    await Promise.all(accessFileAccessToken.repositories.map(async repository => {
        // TODO maybe inline
        const repoAccessPermissions = await getRepoAccessPermissions(installationClient, {
            repo: repository.full_name,
            sourceRepo: params.sourceRepo,
        })
        console.log("repoAccessPermissions", repoAccessPermissions)

        // verify if repository grant all requested permissions
        for (const [scope, permission] of Object.entries(params.permissions)) {
            if (!verifyPermission(permission, repoAccessPermissions[scope])) {
                // TODO maybe Aggregate all missing permissions for all repositories
                throw new PermissionError(`${repository.full_name} repository does not grant requested permission: ${scope}:${permission}`)
            }
        }
    }))

    return await appClient.apps.createInstallationAccessToken({
        installation_id: appInstallation.id,
        // be aware that an empty array will result in requesting permissions for all repositories
        repositories: ensureNotEmpty(params.repositories).map(repo => parseRepo(repo).name),
        // be aware that an empty object will result in requesting all granted permissions
        permissions: ensureNotEmpty(params.permissions),
    }).then(res => res.data)
}

function ensureNotEmpty(obj) {
    if (Array.isArray(obj)) {
        if (obj.length === 0) throw Error("Illegal argument")
    } else if (typeof obj === 'object') {
        if (Object.keys(obj).length === 0) throw Error("Illegal argument")
    }
    return obj;
}

function parseRepo(repository) {
    const [owner, name] = repository.split('/')
    return {owner, name}
}

function isValidPermission(scope, permission) {
    return /^[a-z]+$/.test(scope) && /^(write|read|none|)$/.test(permission)
}

function isValidRepository(repository) {
    // valid format owner-name/repo-name
    // (?!-)  - ensure no leading dash
    // (?<!-) - ensure no trailing dash
    return /^(?!-)([a-z\d-]{1,38})(?<!-)\/(?!-)[a-z\d-]{1,100}(?<!-)$/.test(repository)
}

function verifySingleOwner(repositories) {
    return new Set(repositories.map(it => parseRepo(it).owner)).size <= 1
}

function verifyPermission(requested, granted) {
    const permissionRanking = ['read', 'write']
    let requestedRank = permissionRanking.indexOf(requested);
    let grantedRank = permissionRanking.indexOf(granted);
    return requestedRank <= grantedRank
}

async function getRepoAccessPermissions(installationClient, params) {
    const repoAccessConfig = await getRepoAccessConfig(installationClient, {
        repo: params.repo,
    })

    if (!repoAccessConfig) {
        return {}
    }

    if (repoAccessConfig.self !== params.repo) {
        // TODO wrong self reference in access.yaml, needs to be fixed by a repo maintainer
        return {}
    }

    console.log("repoAccessConfig", JSON.stringify(repoAccessConfig, null, 2))

    const repoAccessPolicy = repoAccessConfig.policies?.find(policy => {
        if (policy.repository === 'self') {
            return params.repo === params.sourceRepo;
        }
        const policyRepoPattern = escapeStringRegexp(policy.repository)
            .replaceAll('\\*', '.*')
            .replaceAll('\\?', '.')
        const policyRepoRegExp = new RegExp(`^${policyRepoPattern}$`)
        return policyRepoRegExp.test(params.sourceRepo)
    })

    return repoAccessPolicy?.permissions || {}
}

async function getRepoAccessConfig(installationClient, params) {
    const repoObject = parseRepo(params.repo)
    const repoAccessFile = await installationClient.repos.getContent({
        owner: repoObject.owner,
        repo: repoObject.name,
        path: ACCESS_FILE_LOCATION
    })
        .then(res => res.data)
        .catch(err => {
            // TODO throw permission error
            if (err.status === 404) return undefined
            throw err
        })

    if (repoAccessFile) {
        return YAML.load(Buffer.from(repoAccessFile.content, 'base64'))
        // TODO Validate Config
    }
}

// ---------------------------------------------------------------------------------------------------------------------

function verifyIdToken(req, res, next) {
    const authorizationHeader = req.headers['authorization']
    if (!authorizationHeader) {
        return res.status(401).json(
            errorResponse({code: 'Unauthorized', message: 'Missing authorization header'})
        )
    }

    const authorization = authorizationHeader.split(' ')
    const authorizationScheme = authorization[0]
    if (authorizationScheme !== 'Bearer') {
        return res.status(401).json(
            errorResponse({code: 'Unauthorized', message: `Unexpected authorization scheme ${authorizationScheme}`})
        )
    }

    const bearerToken = authorization[1]

    const verifyOptions = {
        issuer: GITHUB_ACTIONS_ISSUER,
        ignoreExpiration: IS_DEVELOPMENT_ENV
    }

    const key = (header, callback) => {
        jwksClient({jwksUri: `${verifyOptions.issuer}/.well-known/jwks`})
            .getSigningKey(header.kid, (err, key) => {
                callback(err, err ? null : key.getPublicKey())
            })
    }

    jwt.verify(bearerToken, key, verifyOptions, (err, decoded) => {
        if (err) {
            return res.status(401).json(
                errorResponse({code: 'Unauthorized', message: 'Invalid token - ' + err.message})
            )
        }

        const hostname = req.headers['x-forwarded-host'].split(':')[0] || req.hostname
        if (decoded.aud !== hostname && !IS_DEVELOPMENT_ENV) {
            return res.status(401).json(
                errorResponse({code: 'Unauthorized', message: 'Invalid token - ' + `Unexpected aud: ${decoded.aud}`})
            )
        }

        // set token
        req.token = decoded
        next()
    })
}

function errorHandler(err, req, res, _next) {
    if (err.name === HttpClientError.name) {
        console.debug('[DEBUG]', err)
        return res.status(err.status).json(errorResponse(err))
    }

    console.error('[ERROR]', err)
    return res.status(500).json(
        errorResponse({code: "InternalServerError", message: "Unexpected error"})
    )
}

function errorResponse(err) {
    return {
        error: {
            code: err.code,
            message: err.message,
        }
    }
}

class HttpClientError {
    constructor(status, code, message, cause) {
        if (status < 400 || status >= 500) throw Error(`invalid client error status ${status}`)

        this.name = this.constructor.name
        this.code = code
        this.message = message
        this.status = status
        this.cause = cause
    }
}

// ---------------------------------------------------------------------------------------------------------------------

function escapeStringRegexp(string) {
    // source: https://www.npmjs.com/package/escape-string-regexp
    return string
        .replace(/[|\\{}()[\]^$+*?.]/g, '\\$&')
        .replace(/-/g, '\\x2d')
}
