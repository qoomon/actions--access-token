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

// --- Token Replay Protection -----------------------------------------------------------------------------------------
// Security: Track used JTI claims to prevent token replay attacks
// Using a Map with timestamp-based expiry to prevent memory leaks
const usedTokens = new Map<string, number>();
const TOKEN_REUSE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Check if a token has been used before (replay attack detection)
 * @param jti - JWT ID claim
 * @param iat - Issued at timestamp (as string)
 * @return true if token was already used
 */
function isTokenReplayed(jti: string | undefined, iat: string): boolean {
  if (!jti) {
    // If no JTI is provided, we cannot track replay - log warning
    logger.warn('OIDC token missing jti claim - replay protection disabled for this token');
    return false;
  }

  const now = Date.now();
  
  // Clean up expired entries (older than token reuse window)
  for (const [key, timestamp] of usedTokens.entries()) {
    if (now - timestamp > TOKEN_REUSE_WINDOW_MS) {
      usedTokens.delete(key);
    }
  }

  const tokenKey = `${jti}:${iat}`;
  if (usedTokens.has(tokenKey)) {
    return true;
  }

  usedTokens.set(tokenKey, now);
  return false;
}

// --- Rate Limiting ---------------------------------------------------------------------------------------------------
// Security: Rate limit requests by repository to prevent abuse
const rateLimitMap = new Map<string, { count: number, resetTime: number }>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 20; // Max requests per window per repository

/**
 * Check if a request should be rate limited
 * @param repository - repository identifier
 * @return true if rate limit exceeded
 */
function isRateLimited(repository: string): boolean {
  const now = Date.now();
  const rateLimit = rateLimitMap.get(repository);
  
  // Clean up expired entries
  for (const [key, value] of rateLimitMap.entries()) {
    if (now > value.resetTime) {
      rateLimitMap.delete(key);
    }
  }
  
  if (!rateLimit || now > rateLimit.resetTime) {
    rateLimitMap.set(repository, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  
  if (rateLimit.count >= RATE_LIMIT_MAX_REQUESTS) {
    return true;
  }
  
  rateLimit.count++;
  return false;
}

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
        
        // Security: Rate limiting by repository
        if (isRateLimited(callerIdentity.repository)) {
          logger.warn({
            repository: callerIdentity.repository,
            workflow_run_url: buildWorkflowRunUrl(callerIdentity),
          }, 'Rate limit exceeded');
          throw new HTTPException(Status.TOO_MANY_REQUESTS, {
            message: 'Rate limit exceeded. Please try again later.',
          });
        }
        
        // Security: Check for token replay attacks
        if (isTokenReplayed(callerIdentity.jti, callerIdentity.iat)) {
          logger.warn({
            workflow_run_url: buildWorkflowRunUrl(callerIdentity),
            jti: callerIdentity.jti,
          }, 'Token replay attack detected');
          throw new HTTPException(Status.FORBIDDEN, {
            message: 'Token has already been used',
          });
        }
        
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
  repositories: z.array(GitHubRepositoryNameSchema.or(GitHubRepositorySchema))
      .max(config.maxTargetRepositoriesPerRequest)
      .or(z.literal('ALL'))
      .default(() => []),
}));
