const core = require('@actions/core')
const {HttpClient} = require('@actions/http-client')
const httpClient = new HttpClient()

// ---------------------------------------------------------------------------------------------------------------------

const IS_DEVELOPMENT_ENV = process.env.NODE_ENV === 'development'

// ---------------------------------------------------------------------------------------------------------------------

if (IS_DEVELOPMENT_ENV) {
    core.getIDToken = async (_) => process.env.ACTIONS_ID_TOKEN
}

async function run() {
    const repository = core.getInput('repository', {required: true})
    const accessTokenEndpoint = core.getInput('endpoint', {required: true})

    const idTokenAudience = new URL(accessTokenEndpoint).host
    const idToken = await core.getIDToken(idTokenAudience)

    const accessToken = await getAccessToken({
        endpoint: accessTokenEndpoint,
        idToken: idToken,
        repository: repository,
    })

    core.setSecret(accessToken.token)
    core.exportVariable('GITHUB_ACCESS_MANAGER_TOKEN', accessToken.token)
    core.setOutput('token', accessToken.token)
    console.info(accessToken)
}

run().catch(error => {
    core.setFailed(error.message);
})

// ---------------------------------------------------------------------------------------------------------------------

async function getAccessToken(params) {
    return await httpClient.postJson(
        params.endpoint + '?' + `repository=${params.repository}`,
        {},
        {'Authorization': 'Bearer ' + params.idToken},
    ).then(res => {
        if (res.statusCode !== 200) throw new Error(res.result.error.message)
        return res.result
    });
}

