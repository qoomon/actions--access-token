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

const appOctokit = new Octokit({
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

app.post('/access_tokens', async (request, response) => {
    const sourceRepo = request.token.repository
    const targetRepo = (request.query.repository === undefined || request.query.repository === 'self') ? sourceRepo : request.query.repository
    console.info('[INFO]', `Get access token to ${targetRepo} for ${sourceRepo}`)

    const appRepoInstallation = await getAppRepoInstallation({repo: targetRepo}).catch(err => {
        throw new HttpClientError(403, 'Forbidden', 'No permission granted', err)
    })

    const targetRepoPermissions = await getRepoAccessPermissions({
        appInstallation: appRepoInstallation,
        repo: targetRepo,
        sourceRepo: sourceRepo,
    })

    if (Object.entries(targetRepoPermissions).length === 0) {
        throw new HttpClientError(403, 'Forbidden', 'No permission granted')
    }

    const repoAccessToken = await getRepoAccessToken({
        appInstallation: appRepoInstallation,
        repo: targetRepo,
        permissions: targetRepoPermissions,
    })

    response.json({
        token: repoAccessToken.token,
        expires_at: repoAccessToken.expires_at,
        permissions: repoAccessToken.permissions,
        repository: repoAccessToken.repository,
    })
})

app.use(errorHandler)

export default app

// ---------------------------------------------------------------------------------------------------------------------

async function getRepoAccessToken(params) {
    const [_repoOwner, repoName] = params.repo.split('/')

    if (Object.entries(params.permissions).length === 0) {
        throw new Error('No permission requested')
    }

    const tokenResponse = await appOctokit.rest.apps.createInstallationAccessToken({
        installation_id: params.appInstallation.id,
        repositories: [repoName],
        permissions: params.permissions,
    })
    const token = tokenResponse.data
    token.repository = params.repo
    return token

}

async function getAppRepoInstallation(params) {
    const [repoOwner, repoName] = params.repo.split('/')
    const installationResponse = await appOctokit.rest.apps.getRepoInstallation({
        owner: repoOwner,
        repo: repoName || " ",
    })
    return installationResponse.data
}

function filterValidPermissions(permissions, eligiblePermissions) {
    const validPermissions = {}
    for (const [scope, permission] of Object.entries(permissions)) {
        if (isValidPermission(permission, eligiblePermissions[scope])) {
            validPermissions[scope] = permission
        }
    }
    return validPermissions
}

function isValidPermission(permission, grantedPermission) {
    const validPermissions = ['write', 'read']
    if (!validPermissions.includes(permission)) return false
    if (!validPermissions.includes(grantedPermission)) return false
    if (permission === grantedPermission) return true
    return grantedPermission === 'write'
}

async function getRepoAccessPermissions(params) {
    const repoAccessConfig = await getRepoAccessConfig({
        appInstallation: params.appInstallation,
        repo: params.repo,
    })
    if (!repoAccessConfig || repoAccessConfig.self !== params.repo) {
        return []
    }

    const repoAccessPolicy = repoAccessConfig.policies.find(policy => {
        if (policy.repository === 'self' && params.sourceRepo === params.repo) return true

        const policyRepoPattern = escapeStringRegexp(policy.repository)
            .replaceAll('\\*', '.*')
            .replaceAll('\\?', '.')
        const policyRepoRegExp = new RegExp(`^${policyRepoPattern}$`)
        return policyRepoRegExp.test(params.sourceRepo)
    })
    if (!repoAccessPolicy) {
        return []
    }

    return filterValidPermissions(repoAccessPolicy.permissions, params.appInstallation.permissions)
}

async function getRepoAccessConfig(params) {
    // create access token to read .github/access.yaml file
    const appRepoAccessToken = await getRepoAccessToken({
        appInstallation: params.appInstallation,
        repo: params.repo,
        permissions: {single_file: "read"},
    })

    const appRepoOctokit = new Octokit({auth: appRepoAccessToken.token})
    const [repoOwner, repoName] = params.repo.split('/')
    let repoAccessFileResponse
    try {
        repoAccessFileResponse = await appRepoOctokit.repos.getContent({
            owner: repoOwner, repo: repoName, path: ACCESS_FILE_LOCATION
        })
    } catch (err) {
        return
    }
    return YAML.load(Buffer.from(repoAccessFileResponse.data.content, 'base64'))
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
