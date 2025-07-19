import {Hono} from 'hono';
import {requestId} from 'hono/request-id'
import {prettyJSON} from 'hono/pretty-json';
import {HTTPException} from 'hono/http-exception';
import {bodyLimit} from 'hono/body-limit';
import {sha256} from 'hono/utils/crypto';
import {z} from 'zod';
import process from 'process';
import {toBase64} from './common/common-utils.js';
import {
  buildWorkflowRunUrl,
  GitHubActionsJwtPayload,
  GitHubAppPermissionsSchema,
  GitHubRepositoryNameSchema,
  GitHubRepositoryOwnerSchema,
  GitHubRepositorySchema,
  normalizePermissionScopes,
  parseRepository,
} from './common/github-utils.js';
import {debugLogger, errorHandler, notFoundHandler, parseJsonBody, tokenAuthenticator,} from './common/hono-utils.js';
import {Status} from './common/http-utils.js';
import {accessTokenManager, GitHubAccessTokenError} from './access-token-manager.js';
import {logger} from './logger.js';
import {config} from './config.js';

// --- Initialization ------------------------------------------------------------------------------------------------
const GITHUB_ACTIONS_ACCESS_MANAGER = await accessTokenManager(config);

export function appInit(prepare?: (app: Hono) => void) {
  const app = new Hono();
  prepare?.(app);

  app.use(requestId({headerName: process.env.REQUEST_ID_HEADER}));
  app.use((context, next) => logger.withAsyncBindings({
    requestId: context.var.requestId,
  }, next));
  app.use(debugLogger(logger));
  app.onError(errorHandler(logger));
  app.notFound(notFoundHandler());

  app.use(bodyLimit({maxSize: 100 * 1024})); // 100kb
  app.use(prettyJSON());

  // --- handle access token request -----------------------------------------------------------------------------------
  app.post('/access_tokens',
      tokenAuthenticator<GitHubActionsJwtPayload>({
        allowedIss: 'https://token.actions.githubusercontent.com',
        allowedAud: config.githubActionsTokenVerifier.allowedAud,
        allowedSub: config.githubActionsTokenVerifier.allowedSub,
      }),
      async (context) => {
        const callerIdentity = context.var.token;
        logger.info({
          identity: {
            workflow_ref: callerIdentity.workflow_ref,
            job_workflow_ref: callerIdentity.job_workflow_ref,
            run_id: callerIdentity.run_id,
            attempts: callerIdentity.attempts,
          },
          workflow_run_url: buildWorkflowRunUrl(callerIdentity),
        }, 'Caller Identity');

        // console.log("###### X ", JSON.stringify(AccessTokenRequestBodySchema));
        const accessTokenRequest = await parseJsonBody(context.req, AccessTokenRequestBodySchema)
            .then(async (it) => normalizeAccessTokenRequestBody(it, callerIdentity));
        console.log(`###### B ${context.get('requestId')}`, accessTokenRequest)
        logger.info({
          request: accessTokenRequest
        }, 'Access Token Request');

        const githubActionsAccessToken = await GITHUB_ACTIONS_ACCESS_MANAGER
            .createAccessToken(callerIdentity, accessTokenRequest)
            .catch((error) => {
              if (error instanceof GitHubAccessTokenError) {
                logger.info({
                  reason: error.message,
                }, 'Access Token Denied');
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
        logger.info({
          response: {
            ...tokenResponseBody,
            // retract token
            token: undefined,
          }
        }, 'Access Token Response');

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
// TODO move to access token manager
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
      tokenRequest.owner = callerIdentity.repository_owner
    }
  }

  if (Array.isArray(tokenRequest.repositories)) {
    if (tokenRequest.repositories.length === 0) {
      tokenRequest.repositories.push(callerIdentity.repository);
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
  }

  return {
    ...tokenRequest,
    owner: tokenRequest.owner as string,
  };
}

// --- Schemas & Types -----------------------------------------------------------------------------------------------------------

const AccessTokenRequestBodySchema = z.any().transform(val => {
  // legacy support for owner input
  if(val !== null && typeof val === 'object') {
    if(val.scope === 'owner') {
      delete val.scope;
      if(val.repositories?.length === 0) {
        val.repositories = 'ALL';
      }
    }
  }
  return val;
}).pipe(
    z.strictObject({
      owner: GitHubRepositoryOwnerSchema.optional(),
      permissions: GitHubAppPermissionsSchema,
      repositories: z.union([
            z.array(z.union([GitHubRepositoryNameSchema, GitHubRepositorySchema])),
            z.literal('ALL'),
          ], {
            error: `Invalid repository: Must be a valid repository name, match <owner>/<repository> or 'ALL'`
          },
      ).default(() => []),
    })
);
type AccessTokenRequestBody = z.infer<typeof AccessTokenRequestBodySchema>;
