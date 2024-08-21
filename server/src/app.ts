import {Hono} from 'hono';
import type {RequestIdVariables} from 'hono/request-id'
import {requestId} from 'hono/request-id'
import {prettyJSON} from 'hono/pretty-json';
import {HTTPException} from 'hono/http-exception';
import {bodyLimit} from 'hono/body-limit';
import {sha256} from 'hono/utils/crypto';
import {z} from 'zod';
import process from 'process';
import {hasEntries, toBase64} from './common/common-utils.js';
import {buildJwksKeyFetcher} from './common/jwt-utils.js';
import {
  buildWorkflowRunUrl,
  GitHubActionsJwtPayload,
  GitHubAppPermissions,
  GitHubAppPermissionsSchema,
  GitHubAppRepositoryPermissions,
  GitHubRepositoryNameSchema,
  GitHubRepositoryOwnerSchema,
  GitHubRepositorySchema,
  normalizePermissionScopes,
  parseRepository,
  verifyRepositoryPermissions,
} from './common/github-utils.js';
import {
  debugLogger,
  errorHandler,
  notFoundHandler,
  parseJsonBody,
  RequestLoggerVariables,
  setRequestLogger,
  tokenAuthenticator,
} from './common/hono-utils.js';
import {Status} from './common/http-utils.js';
import {accessTokenManager, GitHubAccessTokenError} from './access-token-manager.js';
import {logger as log} from './logger.js';
import {config} from './config.js';

// --- Initialization ------------------------------------------------------------------------------------------------
const GITHUB_ACTIONS_ACCESS_MANAGER = await accessTokenManager(config);

export function appInit(prepare?: (app: Hono<{
  Variables: RequestIdVariables & RequestLoggerVariables
}>) => void) {
  const app = new Hono<{
    Variables: RequestIdVariables & RequestLoggerVariables
  }>();
  if (prepare) {
    prepare(app);
  }
  app.use(requestId({headerName: process.env.REQUEST_ID_HEADER ?? 'X-Request-Id'}));
  app.use(setRequestLogger(log));
  app.use(debugLogger());
  app.onError(errorHandler());
  app.notFound(notFoundHandler());

  app.use(bodyLimit({maxSize: 100 * 1024})); // 100kb
  app.use(prettyJSON());

  const githubOidcAuthenticator = tokenAuthenticator<GitHubActionsJwtPayload>({
    allowedIss: 'https://token.actions.githubusercontent.com',
    allowedAud: config.githubActionsTokenVerifier.allowedAud,
    allowedSub: config.githubActionsTokenVerifier.allowedSub,
    key: buildJwksKeyFetcher({providerDiscovery: true}),
  });

  // --- handle access token request -----------------------------------------------------------------------------------
  app.post('/access_tokens',
      githubOidcAuthenticator,
      async (context) => {
        const requestLog = context.get('logger');

        const callerIdentity = context.get('token');
        requestLog.info({
          callerIdentity: {
            workflow_ref: callerIdentity.workflow_ref,
            job_workflow_ref: callerIdentity.job_workflow_ref,
            run_id: callerIdentity.run_id,
            attempts: callerIdentity.attempts,
          },
          workflowRunUrl: buildWorkflowRunUrl(callerIdentity),
        }, 'Caller Identity');

        const accessTokenRequest = await parseJsonBody(context.req, AccessTokenRequestBodySchema)
            .then((it) => normalizeAccessTokenRequestBody(it, callerIdentity));
        requestLog.info({accessTokenRequest}, 'Access Token Request');

        const githubActionsAccessToken = await GITHUB_ACTIONS_ACCESS_MANAGER
            .createAccessToken(callerIdentity, accessTokenRequest)
            .catch((error) => {
              if (error instanceof GitHubAccessTokenError) {
                requestLog.info('Access Token - Denied');
                throw new HTTPException(Status.FORBIDDEN, {message: error.message});
              }
              throw error;
            });

        // --- response with requested access token --------------------------------------------------------------------
        const tokenResponseBody = {
          token: githubActionsAccessToken.token,
          token_hash: await sha256(githubActionsAccessToken.token).then(toBase64),
          expires_at: githubActionsAccessToken.expires_at,
          permissions: githubActionsAccessToken.permissions ?
              normalizePermissionScopes(githubActionsAccessToken.permissions) : undefined,
          repositories: githubActionsAccessToken.repositories?.map((it) => it.name),
          owner: githubActionsAccessToken.owner,
        };

        // BE AWARE: do not log the access token
        requestLog.info({accessToken: {...tokenResponseBody, token: undefined}}, 'Access Token');

        return context.json(tokenResponseBody);
      },
  );

  return app;
}

/**
 * Normalize access token request body
 * @param tokenRequest - access token request body
 * @param callerIdentity - caller identity
 * @return normalized access token request body
 */
function normalizeAccessTokenRequestBody(
    tokenRequest: AccessTokenRequestBody,
    callerIdentity: GitHubActionsJwtPayload,
) {
  if (Object.entries(tokenRequest.permissions).length === 0) {
    throw new HTTPException(Status.BAD_REQUEST, {message: 'Token permissions must not be empty.'});
  }

  // determine default owner
  if (!tokenRequest.owner) {
    if (tokenRequest.repositories.length === 1 && tokenRequest.repositories[0].includes('/')) {
      // use the repository owner as the default target owner
      tokenRequest.owner = parseRepository(tokenRequest.repositories[0]).owner;
    } else {
      // use the caller repository owner as the default target owner
      tokenRequest.owner = callerIdentity.repository_owner;
    }
  }

  // remove owner prefixes and ensure all token repositories belong to the same owner
  tokenRequest.repositories = tokenRequest.repositories.map((repository) => {
    if (repository.includes('/')) {
      const {owner, repo} = parseRepository(repository);
      if (owner !== tokenRequest.owner) {
        throw new HTTPException(Status.BAD_REQUEST, {
          message: `All target repositories must belong to same owner.`,
        });
      }
      return repo;
    }

    return repository;
  });

  switch (tokenRequest.scope) {
    case 'owner': {
      return tokenRequest as typeof tokenRequest & { scope: 'owner', owner: string, permissions: GitHubAppPermissions };
    }
    case 'repos': {
      if (!hasEntries(tokenRequest.repositories)) {
        if (tokenRequest.owner !== callerIdentity.repository_owner) {
          throw new HTTPException(Status.BAD_REQUEST, {message: 'Token repositories must not be empty.'});
        }

        // use caller repository as default repository
        tokenRequest.repositories = [parseRepository(callerIdentity.repository).repo];
      }

      // ensure only repository permissions are requested
      const invalidRepositoryPermissionScopes = verifyRepositoryPermissions(tokenRequest.permissions).invalid;
      if (hasEntries(invalidRepositoryPermissionScopes)) {
        throw new HTTPException(Status.BAD_REQUEST, {
          message: `Invalid permissions scopes for token scope 'repos'.\n` +
              Object.keys(invalidRepositoryPermissionScopes).map((scope) => `- ${scope}`).join('\n'),
        });
      }

      return tokenRequest as typeof tokenRequest & {
        scope: 'repos',
        owner: string,
        permissions: GitHubAppRepositoryPermissions
      };
    }
    default:
      throw new HTTPException(Status.BAD_REQUEST, {message: `Invalid token scope '${tokenRequest.scope}'.`});
  }
}

// --- Schemas & Types -----------------------------------------------------------------------------------------------------------

const AccessTokenRequestBodySchema = z.strictObject({
  owner: GitHubRepositoryOwnerSchema.optional(),
  scope: z.enum(['repos', 'owner']).default('repos'),
  permissions: GitHubAppPermissionsSchema,
  repositories: z.array(z.union([GitHubRepositoryNameSchema, GitHubRepositorySchema])).default([]),
});
type AccessTokenRequestBody = z.infer<typeof AccessTokenRequestBodySchema>;
