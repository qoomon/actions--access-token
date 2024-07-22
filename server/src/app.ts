import {Hono} from 'hono';
import {prettyJSON} from 'hono/pretty-json';
import {HTTPException} from 'hono/http-exception';
import {bodyLimit} from 'hono/body-limit';
import {sha256} from 'hono/utils/crypto';
import {Logger} from 'pino';
import {z} from 'zod';
import process from 'process';
import {hasEntries, toBase64} from './common/common-utils.js';
import {buildJwksKeyFetcher} from './common/jwt-utils.js';
import {
  GitHubActionsJwtPayload,
  GitHubAppPermissions,
  GitHubAppPermissionsSchema,
  GitHubAppRepositoryPermissions,
  GitHubRepositoryNameSchema,
  GitHubRepositoryOwnerSchema,
  normalizePermissionScopes,
  parseRepository,
  verifyRepositoryPermissions,
} from './common/github-utils.js';
import {
  debugLogger,
  errorHandler,
  notFoundHandler,
  parseJsonBody,
  setRequestId,
  setRequestLogger,
  tokenAuthenticator,
} from './common/hono-utils.js';
import {Status} from './common/http-utils.js';
import {accessTokenManager, GithubAccessTokenError} from './github-actions-access-manager.js';
import {logger as log} from './logger.js';
import {config} from './config.js';

// --- Initialization ------------------------------------------------------------------------------------------------

const GITHUB_ACTIONS_ACCESS_MANAGER = await accessTokenManager(config);

// --- Server Setup --------------------------------------------------------------------------------------------------
export const app = new Hono<{ Variables: { log: Logger, id: string } }>();
app.use(setRequestId(process.env.REQUEST_ID_HEADER));
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

// --- handle access token request ---------------------------------------------------------------------------------
app.post(
    '/access_tokens',
    githubOidcAuthenticator,
    async (context) => {
      const requestLog = context.get('log');

      const callerIdentity = context.get('token');
      requestLog.info({
        callerIdentity: {
          workflow_ref: callerIdentity.workflow_ref,
          run_id: callerIdentity.run_id,
          attempts: callerIdentity.attempts,
        },
        // workflowRunUrl example: https://github.com/qoomon/actions--access-token/actions/runs/9192965843/attempts/2
        workflowRunUrl: `https://github.com/${callerIdentity.repository}/actions/runs/${callerIdentity.run_id}` +
            `${callerIdentity.attempts ? `/attempts/${callerIdentity.attempts}` : ''}`,
      }, 'Caller Identity');

      const tokenRequest = await parseJsonBody(context.req, AccessTokenRequestBodySchema).then((it) => {
        if (Object.entries(it.permissions).length === 0) {
          throw new HTTPException(Status.BAD_REQUEST, {message: 'Token permissions must not be empty.'});
        }

        // use caller repository owner as default target owner
        it.owner = it.owner || callerIdentity.repository_owner;

        switch (it.scope) {
          case 'owner': {
            return it as typeof it & { scope: 'owner', owner: string, permissions: GitHubAppPermissions };
          }
          case 'repos': {
            if (!hasEntries(it.repositories)) {
              if (it.owner !== callerIdentity.repository_owner) {
                throw new HTTPException(Status.BAD_REQUEST, {message: 'Token repositories must not be empty.'});
              }

              // use caller repository as default repository
              it.repositories = [parseRepository(callerIdentity.repository).repo];
            }

            // ensure only repository permissions are requested
            const invalidRepositoryPermissionScopes = verifyRepositoryPermissions(it.permissions).invalid;
            if (hasEntries(invalidRepositoryPermissionScopes)) {
              throw new HTTPException(Status.BAD_REQUEST, {
                message: `Invalid permissions scopes for token scope 'repos'.\n` +
                    Object.keys(invalidRepositoryPermissionScopes).map((scope) => `- ${scope}`).join('\n'),
              });
            }

            return it as typeof it & { scope: 'repos', owner: string, permissions: GitHubAppRepositoryPermissions };
          }
          default:
            throw new HTTPException(Status.BAD_REQUEST, {message: `Invalid token scope '${it.scope}'.`});
        }
      });

      requestLog.info({tokenRequest}, 'Token Request');

      const githubActionsAccessToken = await GITHUB_ACTIONS_ACCESS_MANAGER
          .createAccessToken(callerIdentity, tokenRequest)
          .catch((error) => {
            if (error instanceof GithubAccessTokenError) {
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

      requestLog.info({
        ...tokenResponseBody,
        token: undefined,
      }, 'Access Token');

      return context.json(tokenResponseBody);
    },
);

// --- Schemas & Types -----------------------------------------------------------------------------------------------------------

export const AccessTokenRequestBodySchema = z.strictObject({
  owner: GitHubRepositoryOwnerSchema.optional(),
  scope: z.enum(['repos', 'owner']).default('repos'),
  permissions: GitHubAppPermissionsSchema,
  repositories: z.array(GitHubRepositoryNameSchema).default([]),
});
