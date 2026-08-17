import * as core from '@actions/core';
import {HttpClient, HttpClientError, HttpClientResponse} from '@actions/http-client';
import {SignatureV4} from '@smithy/signature-v4';
import {Sha256} from '@aws-crypto/sha256-js';
import {fromWebToken} from '@aws-sdk/credential-providers';
import {getAction, getInput, getYamlInput, runAction} from './github-actions-utils.js';
import {z} from 'zod';
import {signHttpRequest} from './signature4.js';
import {retry} from './retry.js';

import {config} from './config.js';
import {OutgoingHttpHeaders} from 'http';

// --- Main ------------------------------------------------------------------------------------------------------------

runAction(async () => {
  const input = {
    owner: getInput('owner'),

    repositories: z.union([
      z.string().toUpperCase().pipe(z.literal('ALL')),
      z.array(z.string()),
      // comma separated repository names
      z.string().transform((value) => value
          .split(',').map((s) => s.trim()).filter((s) => s.length > 0)
      ),
    ]).optional().parse(getYamlInput('repositories')),

    permissions: z.union([
      z.record(z.string(), z.string()),
      // comma separated permissions
      z.string().transform((value) => Object.fromEntries(value
          .split(',')
          .map(s => s.trim()).filter(s => s.length > 0)
          .map((s) => {
            const [scope, permission] = s.split(':', 2).map((s) => s.trim());
            const scopeNormalized = scope.replaceAll(' ', '_').toLowerCase();
            return [scopeNormalized, permission];
          }))
      ).pipe(z.record(z.string(), z.string())),
    ]).parse(getYamlInput('permissions', {required: true})),
  };

  core.info('Get access token...');
  const accessToken = await getAccessToken({
    owner: input.owner,
    repositories: input.repositories,
    permissions: input.permissions,
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
 * @param tokenRequest.owner - target owner
 * @param tokenRequest.repositories - target repositories
 * @param tokenRequest.permissions - target permissions
 * @return token
 */
async function getAccessToken(tokenRequest: {
  owner?: string
  repositories?: string[] | 'ALL'
  permissions: GitHubAppPermissions
}): Promise<GitHubAccessTokenResponse> {
  const idTokenForAccessManager = await core.getIDToken(config.appServer.url.hostname)
      .catch((error) => {
        if (error.message === 'Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable') {
          throw new Error(error.message + ' Probably job permission `id-token: write` is missing');
        }
        throw error;
      });

  let requestSigner: SignatureV4 | undefined;
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

  return await retry(() => httpRequest({
    method: 'POST', requestUrl: new URL('/access_tokens', config.appServer.url).href,
    data: JSON.stringify(tokenRequest),
    additionalHeaders: {
      'authorization': 'Bearer ' + idTokenForAccessManager,
      'content-type': 'application/json',
    },
  }, {
    signer: requestSigner,
  }), {
    retryable: (error) => error instanceof HttpClientError && [429, 503].includes(error.statusCode),
    onRetry: (error, attempt, delay) => {
      core.info(`Retrying request (attempt ${attempt}) in ${delay}ms due to: ${error}`);
    },
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
  const httpClient = new HttpClient(getAction());
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
