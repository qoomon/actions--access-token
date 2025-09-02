import {Hono} from 'hono';
import {requestId} from 'hono/request-id'
import {prettyJSON} from 'hono/pretty-json';
import {HTTPException} from 'hono/http-exception';
import {bodyLimit} from 'hono/body-limit';
import {sha256} from 'hono/utils/crypto';
import {z} from 'zod';
import process from 'process';
import {hasEntries, toBase64} from './common/common-utils.js';
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
import * as zUtils from './common/zod-utils.js';
import {rateLimiter} from './common/rate-limiter.js';
import {SecurityLogger} from './common/security-logger.js';
import {requestTimeout} from './common/timeout.js';

// --- Initialization ------------------------------------------------------------------------------------------------
const GITHUB_ACTIONS_ACCESS_MANAGER = await accessTokenManager(config);
const securityLogger = new SecurityLogger(logger);

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

  // Request timeout middleware
  app.use(requestTimeout({timeout: 30000})); // 30 second timeout

  // Rate limiting for access token endpoint
  app.use('/access_tokens', rateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each client to 100 requests per window
    message: 'Too many token requests, please try again later.',
  }));

  // --- handle access token request -----------------------------------------------------------------------------------
  app.post('/access_tokens',
      tokenAuthenticator<GitHubActionsJwtPayload>({
        allowedIss: 'https://token.actions.githubusercontent.com',
        allowedAud: config.githubActionsTokenVerifier.allowedAud,
        allowedSub: config.githubActionsTokenVerifier.allowedSub,
      }),
      async (context) => {
        const callerIdentity = context.var.token;
        const clientIp = context.req.header('x-forwarded-for') || context.req.header('x-real-ip') || 'unknown';
        const userAgent = context.req.header('user-agent') || 'unknown';
        
        // Log successful authentication
        securityLogger.logAuthSuccess({
          requestId: context.var.requestId,
          clientIp,
          userAgent,
          subject: callerIdentity.sub,
          repository: callerIdentity.repository,
          metadata: {
            workflow_ref: callerIdentity.workflow_ref,
            job_workflow_ref: callerIdentity.job_workflow_ref,
            run_id: callerIdentity.run_id,
            attempts: callerIdentity.attempts,
          },
        });
        
        logger.info({
          identity: {
            workflow_ref: callerIdentity.workflow_ref,
            job_workflow_ref: callerIdentity.job_workflow_ref,
            run_id: callerIdentity.run_id,
            attempts: callerIdentity.attempts,
          },
          workflow_run_url: buildWorkflowRunUrl(callerIdentity),
        }, 'Caller Identity');

        const accessTokenRequest = await parseJsonBody(context.req, AccessTokenRequestBodySchema.check(
            z.superRefine((tokenRequest, ctx) => {
              if (Array.isArray(tokenRequest.repositories)) {
                if (tokenRequest.owner && !hasEntries(tokenRequest.repositories)) {
                  ctx.issues.push({
                    code: "custom",
                    message: "Must have at least one entry if owner is specified",
                    input: tokenRequest.repositories,
                    path: ['repositories'],
                  });
                }

                const repositories = tokenRequest.repositories
                    .map((repository) => parseRepository(
                        repository,
                        tokenRequest.owner ?? callerIdentity.repository_owner,
                    ));
                const repositoriesOwnerSet = new Set<string>();
                if (tokenRequest.owner) {
                  repositoriesOwnerSet.add(tokenRequest.owner);
                }
                const repositoriesNameSet = new Set<string>();
                for (const repository of repositories) {
                  repositoriesOwnerSet.add(repository.owner);
                  repositoriesNameSet.add(repository.repo);
                }

                if (repositoriesOwnerSet.size > 1) {
                  if (tokenRequest.owner) {
                    repositories.forEach((repository, index) => {
                      if (repository.owner !== tokenRequest.owner) {
                        ctx.issues.push({
                          code: "custom",
                          message: `Owner must match the specified owner '${tokenRequest.owner}'`,
                          input: tokenRequest.repositories,
                          path: ['repositories', index],
                        });
                      }
                    })
                  } else {
                    ctx.issues.push({
                      code: "custom",
                      message: "Must have one common owner",
                      input: tokenRequest.repositories,
                      path: ['repositories'],
                    });
                  }
                }
              }
            }),
        ))

        logger.info({
          request: accessTokenRequest
        }, 'Access Token Request');

        // TODO check if all repositories belong to the same owner

        const githubActionsAccessToken = await GITHUB_ACTIONS_ACCESS_MANAGER
            .createAccessToken(callerIdentity, accessTokenRequest)
            .catch((error) => {
              if (error instanceof GitHubAccessTokenError) {
                // Log authorization failure
                securityLogger.logAuthzFailure({
                  requestId: context.var.requestId,
                  clientIp,
                  userAgent,
                  subject: callerIdentity.sub,
                  repository: callerIdentity.repository,
                  permissions: accessTokenRequest.permissions,
                  reason: error.message,
                });
                
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

// --- Schemas & Types -----------------------------------------------------------------------------------------------------------

const LegacyAccessTokenRequestBodyTransformer = z.any().transform(val => {
  // legacy support for owner input
  if (val !== null && typeof val === 'object') {
    if (val.scope === 'owner') {
      delete val.scope;
      if (val.repositories?.length === 0) {
        val.repositories = 'ALL';
      }
    }
  }
  return val;
});

const AccessTokenRequestBodySchema = LegacyAccessTokenRequestBodyTransformer.pipe(z.strictObject({
  owner: GitHubRepositoryOwnerSchema.optional(),
  permissions: GitHubAppPermissionsSchema.check(zUtils.hasEntries),
  repositories: z.array(GitHubRepositoryNameSchema.or(GitHubRepositorySchema)).max(10)
      .or(z.literal('ALL'))
      .default(() => []),
}));
