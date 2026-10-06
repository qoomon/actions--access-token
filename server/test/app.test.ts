/* eslint-disable max-len */
/* eslint-disable @typescript-eslint/no-explicit-any */
// noinspection DuplicatedCode

import process from 'process';
import YAML from 'yaml';
import {expect} from 'expect';
import {after, beforeEach, describe, it, mock} from 'node:test';
import {createRemoteJWKSet, jwtVerify,} from 'jose';
import {RequestError} from '@octokit/request-error';
import {GitHubAppRepositoryPermissions, parseRepository, verifyPermission} from '../src/common/github-utils.js';
import * as Fixtures from './fixtures.js';
import {
  AppInstallation,
  DEFAULT_OWNER,
  DEFAULT_OWNER_ID,
  DEFAULT_REPO,
  GITHUB_ACTIONS_TOKEN_SIGNING,
  Repository
} from './fixtures.js';
import {joinRegExp, Optional} from '../src/common/common-utils.js';
import {Status} from '../src/common/http-utils.js';
import {
  GitHubOwnerAccessPolicy,
  GitHubRepositoryAccessPolicy,
  GitHubRepositoryAccessStatement,
} from '../src/access-policy.js';
import {RemoteJWKSetOptions} from 'jose/jwks/remote';

process.env.LOG_LEVEL = process.env.LOG_LEVEL || 'warn';
process.env.GITHUB_APP_ID = Fixtures.GITHUB_APP_AUTH.appId;
process.env.GITHUB_APP_PRIVATE_KEY = Fixtures.GITHUB_APP_AUTH.privateKey;
process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE = Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.aud;

const GITHUB_ACTIONS_JWKS_URL = 'https://token.actions.githubusercontent.com/.well-known/jwks';

mockJwks();
const githubMockEnvironment = mockGithub();

const {config} = await import('../src/config.js');
const {appInit} = await import('../src/app.js');

const app = appInit();

beforeEach(() => githubMockEnvironment.reset());
after(() => mock.restoreAll());

describe('App path /', () => {

  describe('GET request', () => {
    it('should respond with the GitHub project URL', async () => {
      // --- When ---
      const response = await app.request('/', {method: 'GET'});

      // --- Then ---
      expect(response.status).toBe(Status.OK);
      expect(await response.text()).toMatch(/https:\/\/github\.com\/qoomon\/actions--access-token/);
    });
  });
});

describe('App path /unknown', () => {

  const path = '/unknown';

  describe('GET request', () => {
    it('should respond with status NOT_FOUND', async () => {
      // --- When ---
      const response = await app.request(path, {method: 'GET'});

      // --- Then ---
      await assertResponse(response, {
        status: Status.NOT_FOUND,
        body: expect.any(Object),
      });
    });
  });
});

describe('App path /access_tokens', () => {

  const path = '/access_tokens';

  describe('GET request', () => {
    it('should respond with status NOT_FOUND', async () => {
      // --- When ---
      const response = await app.request(path, {method: 'GET'});

      // --- Then ---
      await assertResponse(response, {
        status: Status.NOT_FOUND,
        body: expect.any(Object),
      });
    });
  });

  describe('POST request', () => {

    describe('authentication', () => {
      it('should respond with UNAUTHORIZED if authorization header is missing', async () => {
        // --- When ---
        const response = await app.request(path, {method: 'POST'});

        // --- Then ---
        await assertResponse(response, {
          status: Status.UNAUTHORIZED,
          body: {
            requestId: expect.any(String),
            error: 'Unauthorized',
            message: 'Missing authorization header',
          },
        });
      });

      it('should respond with UNAUTHORIZED if authorization scheme is invalid', async () => {
        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: 'Invalid ___'},
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.UNAUTHORIZED,
          body: {
            requestId: expect.any(String),
            error: 'Unauthorized',
            message: 'Unexpected authorization scheme Invalid',
          },
        });
      });

      it('should respond with UNAUTHORIZED if authorization token value is malformed', async () => {
        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: 'Bearer malformed'},
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.UNAUTHORIZED,
          body: {
            requestId: expect.any(String),
            error: 'Unauthorized',
            message: 'Invalid token: Invalid Compact JWS',
          },
        });
      });

      it('should respond with UNAUTHORIZED if authorization token signature is invalid', async () => {
        // --- Given ---
        const githubToken = await Fixtures.createGitHubActionsToken({
          signing: {
            key: Fixtures.UNKNOWN_SIGNING_KEY.privateKey,
          },
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.UNAUTHORIZED,
          body: {
            requestId: expect.any(String),
            error: 'Unauthorized',
            message: 'Invalid token: signature verification failed',
          },
        });
      });

      it('should respond with UNAUTHORIZED if authorization token has expired', async () => {
        // --- Given ---
        const githubToken = await Fixtures.createGitHubActionsToken({
          expirationTime: 0,
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.UNAUTHORIZED,
          body: {
            requestId: expect.any(String),
            error: 'Unauthorized',
            message: 'Invalid token: "exp" claim timestamp check failed',
          },
        });
      });

      it('should respond with UNAUTHORIZED if authorization token is signed with an unexpected algorithm', async () => {
        // --- Given ---
        const githubToken = await Fixtures.createGitHubActionsToken({
          signing: {
            key: GITHUB_ACTIONS_TOKEN_SIGNING.key.privateKey,
            alg: 'PS256',
          },
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.UNAUTHORIZED,
          body: {
            requestId: expect.any(String),
            error: 'Unauthorized',
            message: 'Invalid token: "alg" (Algorithm) Header Parameter value not allowed',
          },
        });
      });

      for (const claim of ['exp', 'sub', 'repository', 'repository_owner', 'repository_id', 'repository_owner_id']) {
        it(`should respond with UNAUTHORIZED if authorization token does not contain the ${claim} claim`, async () => {
          // --- Given ---
          const githubToken = await Fixtures.createGitHubActionsToken({
            omitClaims: [claim],
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.UNAUTHORIZED,
            body: {
              requestId: expect.any(String),
              error: 'Unauthorized',
              message: `Invalid token: missing required "${claim}" claim`,
            },
          });
        });
      }
    });

    describe('request body validation', () => {
      // --- Given ---
      const githubTokenPromise = Fixtures.createGitHubActionsToken({});

      describe('body format', () => {
        it('should respond with REQUEST_TOO_LONG if request body exceeds the size limit', async () => {
          // --- Given ---
          const largeBody = 'x'.repeat(101 * 1024); // > 100 KB

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {'Content-Length': String(largeBody.length)},
            body: largeBody,
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.REQUEST_TOO_LONG,
            body: expect.any(Object),
          });
        });

        it('should respond with BAD_REQUEST if request body is invalid json', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: 'invalid json',
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body:\n/,
                / {2}- Unexpected token 'i', "invalid json" is not valid JSON\n$/,
              ])),
            },
          });
        });
      });

      describe('permissions', () => {
        it('should respond with BAD_REQUEST if token request does not contain any permission', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              permissions: {},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body:\n/,
                / {2}- permissions: Invalid object: must have at least one entry\n$/,
              ])),
            },
          });
        });

        it('should respond with BAD_REQUEST if token request permission scope is unexpected', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              permissions: {unexpected: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body:\n/,
                / {2}- permissions: Unrecognized key: "unexpected"\n$/,
              ])),
            },
          });
        });

        it('should respond with BAD_REQUEST if token request permission value is invalid', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              permissions: {secrets: 'invalid'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body:\n/,
                / {2}- permissions.secrets: Invalid option: expected one of .*\n$/,
              ])),
            },
          });
        });
      });

      describe('repositories', () => {
        it('should respond with BAD_REQUEST if token request repositories are invalid', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              repositories: ['invalid/invalid/invalid'],
              permissions: {actions: 'read'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body:\n/,
                / {2}- repositories: Union errors:/,
              ])),
            },
          });
        });

        it('should respond with BAD_REQUEST if repositories count exceeds the maximum allowed', async () => {
          // --- Given ---
          const tooManyRepos = Array.from({length: config.tokenRequest.targetRepositoriesMaxCount + 1}, (_, i) => `repo-${i}`);

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              repositories: tooManyRepos,
              permissions: {actions: 'read'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body:\n/,
                / {2}- repositories: Too big: /,
              ])),
            },
          });
        });

        it('should respond with BAD_REQUEST if token request repositories owners differ from request owner', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              owner: 'octocat',
              repositories: ['spongebob/sandbox'],
              permissions: {actions: 'read'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body.\n/,
                / {2}- repositories.0: Owner must match the specified owner 'octocat'\n$/,
              ])),
            },
          });
        });

        it('should respond with BAD_REQUEST if token request repositories have different owners', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              repositories: ['spongebob/sandbox', 'patrick/sandbox'],
              permissions: {actions: 'read'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body.\n/,
                / {2}- repositories: Must have one common owner\n$/,
              ])),
            },
          });
        });
      });

      describe('owner', () => {
        it('should respond with BAD_REQUEST if token request owner is invalid', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              owner: 'invalid/invalid',
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body.\n/,
                / {2}- owner: Invalid string: must match pattern .*\n$/,
              ])),
            },
          });
        });

        it('should respond with BAD_REQUEST if owner is specified but repositories is empty', async () => {
          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${await githubTokenPromise}`},
            body: JSON.stringify({
              owner: DEFAULT_OWNER,
              repositories: [],
              permissions: {actions: 'read'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.BAD_REQUEST,
            body: {
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(joinRegExp([
                /^Invalid request body.\n/,
                / {2}- repositories: Must have at least one entry if owner is specified\n$/,
              ])),
            },
          });
        });
      });

      it('should respond with BAD_REQUEST if request body has an unknown field', async () => {
        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${await githubTokenPromise}`},
          body: JSON.stringify({
            permissions: {actions: 'read'},
            unknownField: 'value',
          }),
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.BAD_REQUEST,
          body: {
            requestId: expect.any(String),
            error: 'Bad Request',
            message: expect.stringMatching(joinRegExp([
              /^Invalid request body:\n/,
              / {2}- Unrecognized key: "unknownField"\n$/,
            ])),
          },
        });
      });
    });

    describe('access control', () => {

      it('should respond with FORBIDDEN if GitHub app has not been installed for target owner', async () => {
        // --- Given ---
        const actionRepo = githubMockEnvironment.addRepository({});
        const githubToken = await Fixtures.createGitHubActionsToken({
          claims: {repository: actionRepo.name},
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {secrets: 'write'},
          }),
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.FORBIDDEN,
          body: {
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.owner}:\n`,
              / {2}- 'GitHub Actions Access Manager' has not been installed\./,
            ])),
          },
        });
      });

      it('should respond with FORBIDDEN if GitHub app is missing requested permission', async () => {
        // --- Given ---
        githubMockEnvironment.addAppInstallation({
          permissions: {single_file: 'read', contents: 'write'},
        });

        const actionRepo = githubMockEnvironment.addRepository({});
        const githubToken = await Fixtures.createGitHubActionsToken({
          claims: {repository: actionRepo.name},
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {secrets: 'write'},
          }),
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.FORBIDDEN,
          body: {
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.owner}:\n`,
              / {2}- secrets: write - '[^']+' installation not authorized\n/,
            ])),
          },
        });
      });

      it('should respond with FORBIDDEN if requested target owner has no access policy', async () => {
        // --- Given ---
        githubMockEnvironment.addAppInstallation({
          permissions: {single_file: 'read', contents: 'write'},
        });

        const actionRepo = githubMockEnvironment.addRepository({});
        const githubToken = await Fixtures.createGitHubActionsToken({
          claims: {repository: actionRepo.name},
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {contents: 'read'},
          }),
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.FORBIDDEN,
          body: {
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.owner}:\n`,
              / {2}- Access policy not found\n/,
            ])),
          },
        });
      });

      it('should respond with FORBIDDEN if requested target owner has an invalid access policy', async () => {
        // --- Given ---
        githubMockEnvironment.addAppInstallation({
          permissions: {single_file: 'read', contents: 'write'},
        });

        githubMockEnvironment.addOwnerRepository({
          ownerAccessPolicy: {
            origin: 'invalid',
            statements: [{
              subjects: ['ref:refs/heads/*'],
              permissions: {contents: 'write'},
            }],
          },
        });

        const actionRepo = githubMockEnvironment.addRepository({});
        const githubToken = await Fixtures.createGitHubActionsToken({
          claims: {repository: actionRepo.name},
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {contents: 'write'},
          }),
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.FORBIDDEN,
          body: {
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.owner}:\n`,
              / {2}- Invalid access policy\n/,
            ])),
          },
        });
      });

      it('should respond with FORBIDDEN if identity subject is not allowed by owner access policy', async () => {
        // --- Given ---
        githubMockEnvironment.addAppInstallation({
          permissions: {single_file: 'read', contents: 'write'},
        });

        githubMockEnvironment.addOwnerRepository({
          ownerAccessPolicy: {
            'allowed-subjects': ['repo:nobody/*:**'],
          },
        });

        const actionRepo = githubMockEnvironment.addRepository({});
        const githubToken = await Fixtures.createGitHubActionsToken({
          claims: {repository: actionRepo.name},
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {contents: 'read'},
          }),
        });

        // --- Then ---
        await assertResponse(response, {
          status: Status.FORBIDDEN,
          body: {
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.owner}:\n`,
              / {2}- OIDC token subject is not allowed by owner access policy\n/,
            ])),
          },
        });
      });

      describe('selected repositories', () => {
        beforeEach(() => {
          githubMockEnvironment.addAppInstallation({
            permissions: {single_file: 'read', contents: 'write'},
          });

          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'allowed-repository-permissions': {contents: 'write'},
            },
          });
        });

        it('should respond with FORBIDDEN if requested target repo permission is not allowed by owner policy', async () => {
          // --- Given ---
          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'allowed-repository-permissions': {contents: 'read'},
            },
          });

          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.owner}:\n`,
                / {2}- contents: write - Not allowed by owner access policy\n/,
              ])),
            },
          });
        });

        it('should respond with FORBIDDEN if requested target repo has no access policy', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'read'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.name}:\n`,
                / {2}- Access policy not found\n/,
              ])),
            },
          });
        });

        it('should respond with FORBIDDEN if requested target repo has an invalid access policy', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              origin: 'invalid',
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {contents: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.name}:\n`,
                / {2}- Invalid access policy\n/,
              ])),
            },
          });
        });

        it('should respond with FORBIDDEN if requested target repo scope permission are not granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {contents: 'read'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.name}:\n`,
                / {2}- contents: write - Not authorized/,
              ])),
            },
          });
        });

        it('should respond with FORBIDDEN if requested target repo grants access with a subject claim that contains a wildcard', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['*:refs/heads/*'],
                permissions: {contents: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.name}:\n`,
                / {2}- Not authorized/,
              ])),
            },
          });
        });

        it('should respond with FORBIDDEN if requested target repo grants access with a subject pattern that is not complete', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:octocat/*'],
                permissions: {contents: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.name}:\n`,
                / {2}- Not authorized\n/,
              ])),
            },
          });
        });

        it('should respond with FORBIDDEN if the caller repository customized the OIDC sub claim to impersonate a subject of the target repo policy', async () => {
          // --- Given ---
          const callerRepo = githubMockEnvironment.addRepository({});
          const targetRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                // legacy pattern without repo claim, which is completed to 'repo:${origin}:ref:refs/heads/main'
                subjects: ['ref:refs/heads/main'],
                permissions: {contents: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            // the sub claim template of the caller repository is customized to only contain the ref claim
            claims: {repository: callerRepo.name, ref: 'refs/heads/main', sub: 'ref:refs/heads/main'},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              repositories: [targetRepo.repo],
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${targetRepo.name}:\n`,
                / {2}- Not authorized\n/,
              ])),
            },
          });
        });

        it('should respond with FORBIDDEN if the caller ref differs in case from the ref granted by the target repo policy', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:ref:refs/heads/main'],
                permissions: {contents: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name, ref: 'refs/heads/Main'},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.name}:\n`,
                / {2}- Not authorized\n/,
              ])),
            },
          });
        });

        it('should respond with FORBIDDEN for a pull request ref even if the workflow file name contains a colon', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:**'],
                permissions: {contents: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name, ref: 'refs/pull/1/merge', workflow: 'build:pr.yml'},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.any(String),
            },
          });
        });

        it('should respond with FORBIDDEN if requested target repo permission scope was not granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {
                  issues: 'read',
                },
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'read'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.name}:\n`,
                / {2}- contents: read - Not authorized\n/,
              ])),
            },
          });
        });
      });

      describe('ALL repositories', () => {
        beforeEach(() => {
          githubMockEnvironment.addAppInstallation({
            permissions: {'single_file': 'read', 'contents': 'write', 'organization-secrets': 'write'},
          });
        });

        it('should respond with FORBIDDEN if requested target repo permissions not granted by owner', async () => {
          // --- Given ---
          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'allowed-repository-permissions': {contents: 'write'},
            },
          });

          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {contents: 'write'},
              repositories: 'ALL',
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.FORBIDDEN,
            body: {
              requestId: expect.any(String),
              error: 'Forbidden',
              message: expect.stringMatching(joinRegExp([/^Issues:\n/,
                `- ${actionRepo.owner}:\n`,
                / {2}- contents: write - Not allowed by owner access policy\n/,
              ])),
            },
          });
        });
      });
    });

    describe('successful token creation', () => {

      beforeEach(() => {
        githubMockEnvironment.addAppInstallation({
          permissions: {
            single_file: 'read',
            contents: 'write',
            secrets: 'write',
            pull_requests: 'write',
            organization_secrets: 'write',
          },
        });
      });

      describe('selected repositories', () => {
        beforeEach(() => {
          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'allowed-repository-permissions': {
                secrets: 'write',
                pull_requests: 'write'
              } satisfies GitHubAppRepositoryPermissions
                  & { pull_requests: 'write' } as GitHubAppRepositoryPermissions,
            },
          });
        });

        it('should respond with OK if requested repo permissions are granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:ref:refs/heads/*'],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [parseRepository(actionRepo.name).repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK if requested repo permissions are granted by repo with * wildcard', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: [`repo:${DEFAULT_OWNER}/*:ref:refs/heads/main`],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [parseRepository(actionRepo.name).repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK if requested repo permissions are granted by repo with ** wildcard', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:**'],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [parseRepository(actionRepo.name).repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK if the caller repository customized the OIDC sub claim and the target repo policy grants access to the caller repository', async () => {
          // --- Given ---
          const callerRepo = githubMockEnvironment.addRepository({});
          const targetRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: [`repo:${callerRepo.name}:ref:refs/heads/main`],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            // the sub claim template of the caller repository is customized to only contain the ref claim
            claims: {repository: callerRepo.name, ref: 'refs/heads/main', sub: 'ref:refs/heads/main'},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              repositories: [targetRepo.repo],
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: targetRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [targetRepo.repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK if requested repo permissions are granted by owner', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              statements: [{
                subjects: [`repo:${actionRepo.name}:ref:refs/heads/*`],
                permissions: {secrets: 'write'},
              }],
            },
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [actionRepo.repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK when explicit owner field matches requested repositories', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:ref:refs/heads/*'],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              owner: actionRepo.owner,
              repositories: [actionRepo.repo],
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [actionRepo.repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK for multiple repositories from the same owner', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:ref:refs/heads/*'],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const targetRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: [`repo:${actionRepo.name}:ref:refs/heads/*`],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              repositories: [actionRepo.repo, targetRepo.repo],
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: expect.arrayContaining([actionRepo.repo, targetRepo.repo]),
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK and include a token_hash in the response', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:ref:refs/heads/*'],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: expect.objectContaining({
              // sha256 returns a 64-char hex string; base64-encoding that hex text yields exactly 88 chars ending with ==
              token_hash: expect.stringMatching(/^[A-Za-z0-9+/]{86}==$/),
            }),
          });
        });

        it('should respond with OK even if target access policy has invalid permissions', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:ref:refs/heads/*'],
                permissions: {secrets: 'write', invalid_permission: 'write'} as GitHubAppRepositoryPermissions,
              }],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [actionRepo.repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK even if target access policy has invalid statements', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [
                {
                  subjects: ['repo:${origin}:ref:refs/heads/*'],
                  permissions: {secrets: 'write'},
                }, {
                  permissions: 'invalid',
                } as unknown as GitHubRepositoryAccessStatement,
              ],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {secrets: 'write'},
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [actionRepo.repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK even if requested repositories contains owner prefix', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [
                {
                  subjects: ['repo:${origin}:ref:refs/heads/*'],
                  permissions: {secrets: 'write'},
                }, {
                  permissions: 'invalid',
                } as unknown as GitHubRepositoryAccessStatement,
              ],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              repositories: [`${actionRepo.owner}/${actionRepo.repo}`],
              permissions: {secrets: 'write'},
            }),
          });
          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {secrets: 'write'},
              repositories: [actionRepo.repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK even if requested repository policy uses underscore permissions scopes', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [
                {
                  subjects: ['repo:${origin}:ref:refs/heads/*'],
                  permissions: {pull_requests: 'write'} as GitHubAppRepositoryPermissions,
                },
              ],
            },
          });
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              repositories: [`${actionRepo.owner}/${actionRepo.repo}`],
              permissions: {'pull-requests': 'write'},
            }),
          });
          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {'pull-requests': 'write'},
              repositories: [actionRepo.repo],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });
      });

      describe('ALL repositories', () => {

        it('should respond with OK if requested org permissions are granted', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'statements': [{
                subjects: [`repo:${actionRepo.name}:ref:refs/heads/*`],
                permissions: {'organization-secrets': 'write'},
              }],
            },
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'organization-secrets': 'write'},
              repositories: 'ALL',
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {'organization-secrets': 'write'},
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });

        it('should respond with OK even if requested org policy uses underscore permissions scopes', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = await Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'statements': [{
                subjects: [`repo:${actionRepo.name}:ref:refs/heads/*`],
                permissions: {'pull_requests': 'write'} as GitHubAppRepositoryPermissions,
              }],
            },
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'pull-requests': 'write'},
              repositories: 'ALL',
            }),
          });

          // --- Then ---
          await assertResponse(response, {
            status: Status.OK,
            body: {
              owner: actionRepo.owner,
              permissions: {'pull-requests': 'write'},
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
              token_hash: expect.any(String),
              expires_at: expect.stringMatching(/Z$/),
            },
          });
        });
      });
    });
  });
});


// --- Assertion Helpers --------------------------------------------------

/**
 * Assert response status and body match expectations
 * @param response - Response to assert
 * @param expected - Expected status and body
 */
async function assertResponse(
    response: Response,
    expected: {
      status: number;
      body?: Record<string, unknown>;
    },
): Promise<void> {
  expect({
    status: response.status,
    body: await response.json().catch(() => null)
  }).toEqual(expected)
}

// --- Mocks ------------------------------------------------------------------

/**
 * Mock modules
 * @return void
 */

function mockJwks() {
  mock.module('jose', {
    namedExports: {
      createRemoteJWKSet: (
          url: URL,
          options?: RemoteJWKSetOptions,
      ) => {
        if (url.toString() === GITHUB_ACTIONS_JWKS_URL) {
          return GITHUB_ACTIONS_TOKEN_SIGNING.key.publicKey;
        }
        return createRemoteJWKSet(url, options);
      },
      jwtVerify,
    },
  });
}

/**
 * Mock GitHub
 * @return GitHub environment
 */
function mockGithub() {
  const githubMockState: {
    repositories: Record<string, Repository>,
    appInstallations: Record<string, AppInstallation>,
  } = {
    repositories: {},
    appInstallations: {},
  };

  const Octokit = Object.assign(
      mock.fn(function (this: unknown, paramsOctokit: any) {

        // GitHub app
        if (paramsOctokit.auth.appId) {
          return {
            rest: {
              apps: {
                getAuthenticated: mock.fn(async () => ({
                  data: {
                    name: 'GitHub Actions Access Manager',
                    html_url: 'https://example.org',
                  },
                })),
                getUserInstallation: mock.fn(async (params: any) => {
                  const installation = githubMockState.appInstallations[params.username];
                  if (installation) return {data: installation};
                  throw new RequestError('Not Found', Status.NOT_FOUND, {
                    request: {headers: {}, url: 'http://localhost/tests'} as any,
                  });
                }),
                createInstallationAccessToken: mock.fn(async (params: any) => {
                  const installation = Object.values(githubMockState.appInstallations)
                      .find((installation) => installation.id === params.installation_id);
                  if (installation) {
                    Object.entries(params.permissions).forEach(([scope, permission]) => {
                      if (!verifyPermission({
                        requested: permission as string,
                        granted: installation.permissions[scope],
                      })) {
                        console.error(`Invalid permission: ${scope}` +
                            ` requested=${permission}` +
                            ` granted=${installation.permissions[scope]}`);
                        throw new RequestError('Unprocessable Entity', Status.UNPROCESSABLE_ENTITY, {
                          request: {headers: {}, url: 'http://localhost/tests'} as any,
                        });
                      }
                    });

                    return {
                      data: {
                        token: `INSTALLATION_ACCESS_TOKEN@${installation.id}`,
                        expires_at: dateIn({hour: +1}).toISOString(),
                        permissions: params.permissions,
                        repositories: params.repositories?.map((it: string) => ({
                          name: it,
                          full_name: `${installation.owner}/${it}`,
                        })),
                      },
                    };
                  }

                  throw new Error('Not Implemented');
                }),
              },
              users: {
                getByUsername: mock.fn(async (params: any) => {
                  // Return mock user ID based on username
                  // IDs must match those used in test fixtures for consistency
                  const ownerIdMap: Record<string, number> = {
                    'octocat': 789012,
                    'qoomon': 789012,
                    'myorg': 789012,
                    'github': 789012,
                  };
                  const id = ownerIdMap[params.username.toLowerCase()] ?? 789012;
                  return {data: {id, login: params.username}};
                }),
              },
            },
          };
        }

        // GitHub app installation
        if (typeof paramsOctokit.auth === 'string') {
          const installation = Object.values(githubMockState.appInstallations)
              .find((installation) => installation.id === parseInt(paramsOctokit.auth.split('@')[1]));

          if (installation) {
            return {
              rest: {
                repos: {
                  getContent: mock.fn(async (params: any) => {
                    if (params.owner !== installation.owner) {
                      throw new Error('Access Denied');
                    }

                    const repository = githubMockState.repositories[`${params.owner}/${params.repo}`];

                    if (repository?.accessPolicy
                        && config.accessPolicy.location.repo.paths.includes(params.path)) {
                      const contentString = YAML.stringify(repository.accessPolicy);
                      return {data: {type: 'file', content: Buffer.from(contentString).toString('base64')}};
                    }

                    if (repository?.ownerAccessPolicy &&
                        config.accessPolicy.location.owner.paths.includes(params.path)) {
                      const contentString = YAML.stringify(repository.ownerAccessPolicy);
                      return {data: {type: 'file', content: Buffer.from(contentString).toString('base64')}};
                    }

                    throw new RequestError('Not Found', Status.NOT_FOUND, {
                      request: {headers: {}, url: 'http://localhost/tests'} as any,
                    });
                  }),
                },
                users: {
                  getByUsername: mock.fn(async (params: any) => {
                    // Return mock user ID based on username
                    // IDs must match those used in test fixtures for consistency

                    const id = DEFAULT_OWNER_ID;
                    return {data: {id, login: params.username}};
                  }),
                },
              },
            };
          }
        }

        throw new Error('Not Implemented');
      }),
      {
        plugin: () => Octokit,
      }
  );

  mock.module('@octokit/core', {
    namedExports: {
      Octokit,
    },
  });

  return {
    reset() {
      githubMockState.repositories = {};
      githubMockState.appInstallations = {};
    },
    addOwnerRepository({owner, accessPolicy, ownerAccessPolicy}: {
      owner?: string,
      ownerAccessPolicy?: Optional<GitHubOwnerAccessPolicy,
          'origin' | 'statements' | 'allowed-repository-permissions'> | null,
      accessPolicy?: Optional<GitHubRepositoryAccessPolicy,
          'origin' | 'statements'> | null,
    }): Repository {
      owner = owner || DEFAULT_OWNER;
      const name = `${owner}/${config.accessPolicy.location.owner.repo}`;

      const repository: Repository = {
        name,
        ...parseRepository(name),
      };

      if (ownerAccessPolicy) {
        repository.ownerAccessPolicy = {
          'origin': name,
          'statements': [],
          'allowed-repository-permissions': {},
          ...ownerAccessPolicy,
        };
      }

      if (accessPolicy) {
        repository.accessPolicy = {
          origin: name,
          statements: [],
          ...accessPolicy,
        };
      }

      githubMockState.repositories[repository.name] = repository;

      return repository;
    },
    addRepository({name, accessPolicy}: {
      name?: string,
      accessPolicy?: Optional<GitHubRepositoryAccessPolicy,
          'origin' | 'statements'> | null,
    }): Repository {
      name = name || `${DEFAULT_OWNER}/${DEFAULT_REPO}-${Object.keys(githubMockState.repositories).length}`;

      const repository: Repository = {
        name,
        ...parseRepository(name),
      };

      if (accessPolicy) {
        repository.accessPolicy = {
          origin: name,
          statements: [],
          ...accessPolicy,
        };
      }

      githubMockState.repositories[repository.name] = repository;

      return repository;
    },

    addAppInstallation({targetType, owner, permissions}: {
      targetType?: 'User' | 'Organization',
      owner?: string,
      permissions?: Record<string, string>,
    }): AppInstallation {
      targetType = targetType || 'User';
      owner = owner || DEFAULT_OWNER;
      permissions = permissions || {};
      const id = 1000 + Object.keys(githubMockState.appInstallations).length;

      const installation = {
        id,
        target_type: targetType,
        owner,
        permissions,
        single_file_paths: permissions['single_file'] ? [
          ...config.accessPolicy.location.owner.paths,
          ...config.accessPolicy.location.repo.paths,
        ] : undefined,
      };
      githubMockState.appInstallations[installation.owner] = installation;
      return installation;
    },
  };
}

// --- Utils ------------------------------------------------------------------

/**
 * Create and modify date relative to now
 * @param hour - hours in future
 * @return relative date
 */
function dateIn({hour}: { hour: number }) {
  return new Date(new Date().setHours(new Date().getHours() + hour));
}
