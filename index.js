const core = require('@actions/core')
const {HttpClient, HttpClientError} = require('@actions/http-client')
const httpClient = new HttpClient()

// ---------------------------------------------------------------------------------------------------------------------

const IS_DEVELOPMENT_ENV = process.env.NODE_ENV === 'development'

// ---------------------------------------------------------------------------------------------------------------------
if (IS_DEVELOPMENT_ENV) {
    core.getIDToken = async (aud) => process.env.ACTIONS_ID_TOKEN
}

const ACCESS_MANAGER_ENDPOINT = (IS_DEVELOPMENT_ENV ? process.env.ACTIONS_ACCESS_MANAGER_ENDPOINT : undefined)
    || 'https://github-actions-access-manager.vercel.app/v2/access_token'

async function run() {
    const repositories = core.getMultilineInput('repositories')
    const permissions = core.getMultilineInput('permissions').reduce((result, scopePermission) => {
        const [scope, permission] = scopePermission.split(':').map(it => it.trim())
        result[scope] = permission
        return result
    }, {})

    const accessToken = await getAccessToken({
        repositories,
        permissions,
    })

    core.setSecret(accessToken.token)
    core.exportVariable('GITHUB_ACCESS_MANAGER_TOKEN', accessToken.token)
    core.setOutput('GITHUB_ACCESS_MANAGER_TOKEN', accessToken.token)
    console.info(accessToken)
}

run().catch(error => {
    if (IS_DEVELOPMENT_ENV) {
        console.error(error)
    }
    core.setFailed(error)
})

// ---------------------------------------------------------------------------------------------------------------------

async function getAccessToken(params) {
    const idTokenAudience = new URL(ACCESS_MANAGER_ENDPOINT).host
    const idToken = await core.getIDToken(idTokenAudience)
    return await httpClient.postJson(
        ACCESS_MANAGER_ENDPOINT,
        {
            repositories: params.repositories,
            permissions: params.permissions,
        },
        {'Authorization': 'Bearer ' + idToken},
    ).then(res => {
        if (res.statusCode > 399) {
            throw new Error(`endpoint: ${params.endpoint} statusCode: ${res.statusCode}`)
        }
        return res.result
    }).catch(err => {
        if (err instanceof HttpClientError) {
            if (err.result && err.result.error)
                throw new Error(err.result.error.message)
        }
        throw err
    })
}

