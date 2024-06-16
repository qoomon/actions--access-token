import * as core from '@actions/core'
import {HttpClient, HttpClientError, HttpClientResponse} from '@actions/http-client'
import {SignatureV4} from '@smithy/signature-v4'
import {Sha256} from '@aws-crypto/sha256-js'
import {fromWebToken} from '@aws-sdk/credential-providers'
import {getInput, getYamlInput, runAction} from './github-actions-utils'
import {z} from 'zod'
import {signHttpRequest} from './signature4'

import {config} from './config'
import {OutgoingHttpHeaders} from 'http'

// --- Main ------------------------------------------------------------------------------------------------------------

runAction(async () => {
  const input = {
    scope: z.enum(['repos', 'owner'])
        .parse(getInput('scope')),
    permissions: z.record(z.string())
        .parse(getYamlInput('permissions', {required: true})),
    repository: getInput('repository'),
    repositories: z.array(z.string()).default([])
        .parse(getYamlInput('repositories')),
    owner: getInput('owner'),
  }

  const tokenRequest = {
    scope: input.scope,
    permissions: input.permissions,
    repositories: input.repositories,
    owner: input.owner,
  }
  if (input.repository) {
    tokenRequest.repositories.unshift(input.repository)
  }

  const accessToken = await getAccessToken(tokenRequest)

  core.setSecret(accessToken.token)
  core.setOutput('token', accessToken.token)
})

// ---------------------------------------------------------------------------------------------------------------------

/**
 * Get access token from access manager endpoint
 * @param tokenRequest - token request
 * @param tokenRequest.organization - target organization
 * @param tokenRequest.repositories - target repositories
 * @param tokenRequest.permissions - target permissions
 * @returns token
 */
async function getAccessToken(tokenRequest: {
  scope: 'repos' | 'owner' | undefined
  permissions: GitHubAppPermissions
  repositories: string[] | undefined
  owner: string | undefined
}): Promise<GitHubAccessTokenResponse> {
  const idTokenForAccessManager = await core.getIDToken(config.api.url.hostname)

  let requestSigner
  if (config.api.auth?.aws) {
    requestSigner = new SignatureV4({
      sha256: Sha256,
      service: config.api.auth.aws.service,
      region: config.api.auth.aws.region,
      credentials: fromWebToken({
        webIdentityToken: idTokenForAccessManager,
        roleArn: config.api.auth.aws.roleArn,
        durationSeconds: 900, // 15 minutes are the minimum allowed by AWS
      }),
    })
  }

  return await httpRequest({
    method: 'POST', requestUrl: new URL('/access_tokens', config.api.url).href,
    data: JSON.stringify(tokenRequest),
    additionalHeaders: {
      'authorization': 'Bearer ' + idTokenForAccessManager,
      'content-type': 'application/json',
    },
  }, {
    signer: requestSigner,
  })
      .then(async (response) => response.readBody())
      .then(async (body) => JSON.parse(body))
}

/**
 * Make http request
 * @param request - request to send
 * @param options - options
 * @returns response - with parsed body if possible
 */
async function httpRequest(request: HttpRequest, options?: {
  signer?: SignatureV4
}): Promise<HttpClientResponse> {
  const httpClient = new HttpClient()
  if (options?.signer) {
    request = await signHttpRequest(request, options.signer)
  }

  return await httpClient.request(request.method, request.requestUrl, request.data, request.additionalHeaders)
      .then(async (response) => {
        if (!response.message.statusCode || response.message.statusCode < 200 || response.message.statusCode >= 300) {
          const body = await response.readBody()
          let bodyJson
          try {
            bodyJson = JSON.parse(body)
          } catch {
            // ignore
          }

          const msg = bodyJson?.message || body || 'Failed request'

          const httpError = new HttpClientError(msg, response.message.statusCode!)
          httpError.result = bodyJson || body
          throw httpError
        }
        return response
      })
}

// --- Types -----------------------------------------------------------------------------------------------------------

type GitHubAccessTokenResponse = {
  token: string
  expires_at: string
  owner: string
  repositories: string[]
  permissions: GitHubAppPermissions
}

type GitHubAppPermissions = Record<string, string>


type HttpRequest = {
  method: string,
  requestUrl: string,
  data: string | NodeJS.ReadableStream | null,
  additionalHeaders?: OutgoingHttpHeaders
}


