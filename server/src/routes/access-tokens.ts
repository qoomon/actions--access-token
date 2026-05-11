import {Hono} from 'hono';
import {HTTPException} from 'hono/http-exception';
import {sha256} from 'hono/utils/crypto';
import {z} from 'zod';
import {hasEntries, toBase64} from '../common/common-utils.js';
import {
  GitHubActionsJwtPayload,
  GitHubAppPermissionsSchema,
  GitHubRepositoryNameSchema,
  GitHubRepositoryOwnerSchema,
  GitHubRepositorySchema,
  normalizePermissionScopes,
  parseRepository,
} from '../common/github-utils.js';
import {parseJsonBody, tokenAuthenticator} from '../common/hono-utils.js';
import {Status} from '../common/http-utils.js';
import * as zUtils from '../common/zod-utils.js';
import {accessTokenManager, GitHubAccessTokenError, GitHubAccessTokenRequest} from '../access-token-manager.js';
import {logger} from '../logger.js';

type AccessManager = Awaited<ReturnType<typeof accessTokenManager>>;

/**
 * Creates and returns a Hono router that handles the /access_tokens endpoint.
 * Mount it with `app.route('/access_tokens', createAccessTokensRoute({...}))`.
 */
export function createAccessTokensRoute({
  manager,
  allowedAud,
  allowedSub,
  maxRepositories,
}: {
  manager: AccessManager,
  allowedAud: string[],
  allowedSub?: RegExp[],
  maxRepositories: number,
}) {
  const AccessTokenRequestBodySchema = LegacyAccessTokenRequestBodyTransformer.pipe(z.strictObject({
    owner: GitHubRepositoryOwnerSchema.optional(),
    permissions: GitHubAppPermissionsSchema.check(zUtils.hasEntries),
    repositories: z.array(GitHubRepositoryNameSchema.or(GitHubRepositorySchema))
        .max(maxRepositories)
        .or(z.literal('ALL'))
        .default(() => []),
  }));

  const route = new Hono();

  route.post('/',
      tokenAuthenticator<GitHubActionsJwtPayload>(
          new URL('https://token.actions.githubusercontent.com/.well-known/jwks'),
          {
            issuer: 'https://token.actions.githubusercontent.com',
            audience: allowedAud,
            subjects: allowedSub,
          },
      ),
      async (context) => {
        const callerIdentity = context.var.token;
        logger.info({
          identity: {
            repository_owner: callerIdentity.repository_owner,
            repository: callerIdentity.repository,
            job_workflow_ref: callerIdentity.job_workflow_ref,
            run_id: callerIdentity.run_id,
            run_attempt: callerIdentity.run_attempt,
          },
          // for debugging only:
          // workflow_run_url: buildWorkflowRunUrl(callerIdentity),
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
                    .map((repository: string) => parseRepository(
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
                    repositories.forEach((repository: { owner: string }, index: number) => {
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

        const githubActionsAccessToken = await manager
            .createAccessToken(callerIdentity, accessTokenRequest as GitHubAccessTokenRequest)
            .catch((error) => {
              if (error instanceof GitHubAccessTokenError) {
                logger.info({
                  reason: error.message,
                }, 'Access Token Denied');
                throw new HTTPException(Status.FORBIDDEN, {message: error.message});
              }
              throw error;
            });

        // --- response with requested access token ------------------------------------------------------------------
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

  return route;
}

// --- Schemas --------------------------------------------------------------------------------------------------------

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
