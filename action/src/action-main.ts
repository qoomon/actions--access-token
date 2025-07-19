import * as core from '@actions/core';
import {HttpClient, HttpClientError, HttpClientResponse} from '@actions/http-client';
import {SignatureV4} from '@smithy/signature-v4';
import {Sha256} from '@aws-crypto/sha256-js';
import {fromWebToken} from '@aws-sdk/credential-providers';
import {getInput, getYamlInput, runAction} from './github-actions-utils.js';
import {z} from 'zod';
import {signHttpRequest} from './signature4.js';

import {config} from './config.js';
import {OutgoingHttpHeaders} from 'http';

// --- Main ------------------------------------------------------------------------------------------------------------

runAction(async () => {
  const input = {
    permissions: z.record(z.string(), z.string())
        .parse(getYamlInput('permissions', {required: true})),
    repository: getInput('repository'),
    repositories: z.union([
      z.array(z.string()),
      z.literal('ALL'),
    ])
        .default(() => [])
        .parse(getYamlInput('repositories')),
    owner: getInput('owner'),
    // --- legacy support
    scope: getInput('scope'),
  };

  // --- legacy support
  {
    // legacy support for owner input
    if (input.scope === 'owner') {
      if (Array.isArray(input.repositories) && input.repositories.length === 0) {
        input.repositories = 'ALL';
      }
    }

    // Legacy support for snake_case permissions
    input.permissions = mapObjectEntries(input.permissions,
        ([key, value]) => [key.replace('_', '-'), value]);
  }

  if (Array.isArray(input.repositories) && input.repository) {
    input.repositories.unshift(input.repository);
  }

  core.info('Get access token...');
  const accessToken = await getAccessToken({
    permissions: input.permissions,
    repositories: input.repositories,
    owner: input.owner,
  });
  core.info('Access token hash: ' + accessToken.token_hash);

  core.setSecret(accessToken.token);
  core.setOutput('token', accessToken.token);

  // save token to state to be able to revoke it in post-action
  core.saveState('token', accessToken.token);
});

// ---------------------------------------------------------------------------------------------------------------------

/**
 * Get access token from access manager endpoint
 * @param tokenRequest - token request
 * @param tokenRequest.organization - target organization
 * @param tokenRequest.repositories - target repositories
 * @param tokenRequest.permissions - target permissions
 * @return token
 */
async function getAccessToken(tokenRequest: {
  permissions: GitHubAppPermissions
  repositories: string[] | 'ALL' | undefined
  owner: string | undefined
}): Promise<GitHubAccessTokenResponse> {
  const idTokenForAccessManager = await core.getIDToken(config.appServer.url.hostname)
      .catch((error) => {
        if (error.message === 'Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable') {
          throw new Error(error.message + ' Probably job permission `id-token: write` is missing');
        }
        throw error;
      });

  let requestSigner;
  if (config.appServer.auth) {
    if (config.appServer.auth.type === 'aws') {
      requestSigner = new SignatureV4({
        sha256: Sha256,
        service: config.appServer.auth.service,
        region: config.appServer.auth.region,
        credentials: fromWebToken({
          webIdentityToken: await core.getIDToken('sts.amazonaws.com'),
          roleArn: config.appServer.auth.roleArn,
          durationSeconds: 900, // 15 minutes are the minimum allowed by AWS
        }),
      });
    } else {
      throw new Error(`Unsupported app server auth type: ${config.appServer.auth?.type}`);
    }
  }

  return await httpRequest({
    method: 'POST', requestUrl: new URL('/access_tokens', config.appServer.url).href,
    data: JSON.stringify(tokenRequest),
    additionalHeaders: {
      'authorization': 'Bearer ' + idTokenForAccessManager,
      'content-type': 'application/json',
    },
  }, {
    signer: requestSigner,
  })
      .then(async (response) => response.readBody())
      .then(async (body) => JSON.parse(body));
}

/**
 * Make http request
 * @param request - request to send
 * @param options - options
 * @return response - with parsed body if possible
 */
async function httpRequest(request: HttpRequest, options?: {
  signer?: SignatureV4
}): Promise<HttpClientResponse> {
  const httpClient = new HttpClient();
  if (options?.signer) {
    request = await signHttpRequest(request, options.signer);
  }

  return await httpClient.request(request.method, request.requestUrl, request.data, request.additionalHeaders)
      .then(async (response) => {
        if (!response.message.statusCode || response.message.statusCode < 200 || response.message.statusCode >= 300) {
          const body = await response.readBody();
          let bodyJson;
          try {
            bodyJson = JSON.parse(body);
          } catch {
            // ignore
          }

          const msg = bodyJson?.message || body || 'Failed request';

          const httpError = new HttpClientError(msg, response.message.statusCode ?? 0);
          httpError.result = bodyJson || body;
          throw httpError;
        }
        return response;
      });
}

// --- Types -----------------------------------------------------------------------------------------------------------

interface GitHubAccessTokenResponse {
  token: string
  token_hash: string
  expires_at: string
  permissions: GitHubAppPermissions
  repositories: string[]
  owner: string
}

type GitHubAppPermissions = Record<string, string>


interface HttpRequest {
  method: string,
  requestUrl: string,
  data: string | NodeJS.ReadableStream | null,
  additionalHeaders?: OutgoingHttpHeaders
}

// --- Utils -----------------------------------------------------------------------------------------------------------

export function mapObjectEntries<V, U>(
    object: Record<string, V>,
    fn: (entry: [string, V]) => [string, U],
): Record<string, U> {
  return Object.fromEntries(Object.entries(object).map(fn)) as Record<string, U>;
}
