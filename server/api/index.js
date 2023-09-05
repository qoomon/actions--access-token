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

    // TODO handle app is not installed
    const appInstallation = await appClient.apps.getUserInstallation({
        username: parseRepo(requestedRepositories[0]).owner
    }).then(res => res.data)

    // verify if app installation has all requested permissions
    for (const [scope, permission] of Object.entries(requestedPermissions)) {
        if (!verifyPermission(permission, appInstallation.permissions[scope])) {
            throw new HttpClientError(403, 'Forbidden', `App installation does not have requested permission: ${scope}:${permission}`)
        }
    }

    // TODO handle missing permissions for specific repositories
    const accessFileAccessToken = await appClient.apps.createInstallationAccessToken({
        installation_id: appInstallation.id,
        // be aware that an empty array will result in requesting permissions for all repositories
        repositories: ensureNotEmpty(requestedRepositories.map(repo => parseRepo(repo).name)),
        permissions: {single_file: 'read'},
    }).then(res => res.data)

    const installationClient = new Octokit({auth: accessFileAccessToken.token});

    // ensure requested permissions are granted for all requested repositories
    await Promise.all(accessFileAccessToken.repositories.map(async repository => {
        const repositoryAccessPermissions = await getRepoAccessPermissions(installationClient, {
            repo: repository.full_name,
            sourceRepo: request.token.repository,
        })

        // verify if repository grant all requested permissions
        for (const [scope, permission] of Object.entries(requestedPermissions)) {
            if (!verifyPermission(permission, repositoryAccessPermissions[scope])) {
                throw new HttpClientError(403, 'Forbidden', `${repository.full_name} repository does not grant requested permissions: ${scope}:${permission}`)
            }
        }
    }))

    const accessToken = await appClient.apps.createInstallationAccessToken({
        installation_id: appInstallation.id,
        // be aware that an empty array will result in requesting permissions for all repositories
        repositories: ensureNotEmpty(requestedRepositories.map(repo => parseRepo(repo).name)),
        // be aware that an empty object will result in requesting all granted permissions
        permissions: ensureNotEmpty(requestedPermissions),
    }).then(res => res.data)


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
    return /^(?!-)([a-z\d-]{1,38})(?<!-)\/(?!-)[a-z\d-]{1,100}(?<!-)$/i.test(repository)
}

function verifySingleOwner(repositories) {
    return new Set(repositories.map(it => parseRepo(it).owner)).size <= 1
}

function verifyPermission(requested, granted) {
    const permissionRanking  = ['read','write']
    let requestedRank = permissionRanking.indexOf(requested);
    let grantedRank = permissionRanking.indexOf(granted);
    return requestedRank <= grantedRank
}

async function getRepoAccessPermissions(octokit, params) {
    const repoAccessConfig = await getRepoAccessConfig(octokit, {
        repo: params.repo,
    })

    if (!repoAccessConfig || repoAccessConfig.self !== params.repo) {
        return {}
    }

    const repoAccessPolicy = repoAccessConfig.policies.find(policy => {
        if (policy.repository === 'self') {
            return params.repo === params.sourceRepo;
        }
        const policyRepoPattern = escapeStringRegexp(policy.repository)
            .replaceAll('\\*', '.*')
            .replaceAll('\\?', '.')
        const policyRepoRegExp = new RegExp(`^${policyRepoPattern}$`)
        return policyRepoRegExp.test(params.sourceRepo)
    })

    return repoAccessPolicy ? repoAccessPolicy.permissions : []
}

async function getRepoAccessConfig(octokit, params) {
    const repoObject = parseRepo(params.repo)
    const repoAccessFile = await octokit.repos.getContent({
        owner: repoObject.owner,
        repo: repoObject.name,
        path: ACCESS_FILE_LOCATION
    })
        .then(res => res.data)
        .catch(err => {
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
