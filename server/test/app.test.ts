/* eslint-disable @typescript-eslint/no-explicit-any */
// noinspection DuplicatedCode

import process from 'process';
import YAML from 'yaml';
import {describe, expect, it, jest} from '@jest/globals';
import {RequestError} from '@octokit/request-error';
import {GitHubAppRepositoryPermissions, parseRepository, verifyPermission} from '../src/common/github-utils.js';
import * as Fixtures from './fixtures.js';
import {AppInstallation, DEFAULT_OWNER, DEFAULT_REPO, Repository} from './fixtures.js';
import {joinRegExp, Optional, sleep} from '../src/common/common-utils.js';
import {withHint} from './jest-utils.js';
import {Status} from '../src/common/http-utils.js';
import {
  GitHubOwnerAccessPolicy,
  GitHubRepositoryAccessPolicy,
  GitHubRepositoryAccessStatement,
} from '../src/access-token-manager.js';

process.env.LOG_LEVEL = process.env.LOG_LEVEL || 'warn';
process.env.GITHUB_APP_ID = Fixtures.GITHUB_APP_AUTH.appId;
process.env.GITHUB_APP_PRIVATE_KEY = Fixtures.GITHUB_APP_AUTH.privateKey;
process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE = Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.aud;

mockJwks();
const githubMockEnvironment = mockGithub();

const {config} = await import('../src/config');
const {appInit} = await import('../src/app');

const app = appInit();

beforeEach(() => githubMockEnvironment.reset());

describe('App path /unknown', () => {

  const path = '/unknown';

  describe('GET request', () => {
    it('should response with status FORBIDDEN', async () => {
      // --- Given ---

      // --- When ---
      const response = await app.request(path, {method: 'GET'});

      // --- Then ---
      expect(response.status).toEqual(Status.NOT_FOUND);
    });
  });
});

describe('App path /access_tokens', () => {

  const path = '/access_tokens';

  describe('GET request', () => {
    it('should response with status NOT_FOUND', async () => {
      // --- When ---
      const response = await app.request(path, {method: 'GET'});

      // --- Then ---
      expect(response.status).toEqual(Status.NOT_FOUND);
    });
  });

  describe('POST request', () => {

    describe('should response with status UNAUTHORIZED', () => {
      it('if authorization header is missing', async () => {
        // --- When ---
        const response = await app.request(path, {method: 'POST'});

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED);
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: 'Missing authorization header',
        });
      });

      it('if authorization scheme is invalid', async () => {
        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: 'Invalid ___'},
        });

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED);
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: 'Unexpected authorization scheme Invalid',
        });
      });

      it('if authorization token value is malformed', async () => {
        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: 'Bearer malformed'},
        });

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED);
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: 'The token is malformed.',
        });
      });

      it('if authorization token signature is invalid', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken({
          signing: {
            key: Fixtures.UNKNOWN_SIGNING_KEY,
          },
        });

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
        });

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED);
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: 'The token signature is invalid.',
        });
      });

      it('if authorization token has expired', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken({
          signing: {expiresIn: 1},
        });
        await sleep(2); // ensure token is expired

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
        });

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED);
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: expect.stringMatching(/^The token has expired at /),
        });
      });
    });

    describe('should response with status BAD REQUEST', () => {
      // --- Given ---
      const githubToken = Fixtures.createGitHubActionsToken({});

      it('if request body is invalid json', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: 'invalid json',
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp([
            /^Invalid request body:\n/,
            /- Unexpected token 'i', "invalid json" is not valid JSON$/,
          ])),
        });
      });

      it('if token request scope is invalid', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            scope: 'invalid',
            permissions: {secrets: 'write'},
          }),
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp([
            /^Invalid request body.\n/,
            /- scope: Invalid enum value\..*$/,
          ])),
        });
      });

      it('if token request does not contain any permission', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {},
          }),
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(/^Token permissions must not be empty\.$/),
        });
      });

      it('if token request permission scope is unexpected', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {unexpected: 'write'},
          }),
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp([
            /^Invalid request body:\n/,
            /- permissions: Unrecognized key\(s\) in object: 'unexpected'$/,
          ])),
        });
      });

      it('if token request permission value is invalid', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {secrets: 'invalid'},
          }),
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp([
            /^Invalid request body.\n/,
            /- permissions.secrets: Invalid enum value\..*$/,
          ])),
        });
      });

      it('if token request repositories are invalid', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            repositories: ['invalid/invalid/invalid'],
            permissions: {actions: 'read'},
          }),
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp([
            /^Invalid request body.\n/,
            /- repositories.0: String must match regex pattern.*$/,
          ])),
        });
      });

      it('if token request owner is invalid', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            owner: 'invalid/invalid',
            permissions: {secrets: 'write'},
          }),
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp([
            /^Invalid request body.\n/,
            /- owner: String must match regex pattern.*$/,
          ])),
        });
      });

      it('if token request repositories owners differ from request owner', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            owner: 'octocat',
            repositories: ['spongebob/sandbox'],
            permissions: {actions: 'read'},
          }),
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(/^All target repositories must belong to same owner\.$/),
        });
      });

      it('if token request repositories have different owners', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            repositories: ['spongebob/sandbox', 'patrick/sandbox'],
            permissions: {actions: 'read'},
          }),
        });

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(/^All target repositories must belong to same owner\.$/),
        });
      });
    });

    describe('should response with status FORBIDDEN', () => {

      it('if GitHub app has not been installed for target repo', async () => {
        // --- Given ---
        const actionRepo = githubMockEnvironment.addRepository({});
        const githubToken = Fixtures.createGitHubActionsToken({
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
        await withHint(() => {
          expect(response.status).toEqual(Status.FORBIDDEN);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Forbidden',
          message: expect.stringMatching(joinRegExp([/^Issues:\n/,
            `- ${actionRepo.owner}:\n`,
            / {2}- 'GitHub Actions Access Manager' has not been installed\./,
          ])),
        });
      });

      it('if GitHub app is missing requested permission', async () => {
        // --- Given ---
        githubMockEnvironment.addAppInstallation({
          permissions: {single_file: 'read', contents: 'write'},
        });

        const actionRepo = githubMockEnvironment.addRepository({});
        const githubToken = Fixtures.createGitHubActionsToken({
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
        await withHint(() => {
          expect(response.status).toEqual(Status.FORBIDDEN);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Forbidden',
          message: expect.stringMatching(joinRegExp([/^Issues:\n/,
            `- ${actionRepo.owner}:\n`,
            / {2}- secrets: write - '[^']+' installation not authorized\n/,
          ])),
        });
      });

      it('if requested target owner has no access policy', async () => {
        // --- Given ---
        githubMockEnvironment.addAppInstallation({
          permissions: {single_file: 'read', contents: 'write'},
        });

        const actionRepo = githubMockEnvironment.addRepository({});
        const githubToken = Fixtures.createGitHubActionsToken({
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
        await withHint(() => {
          expect(response.status).toEqual(Status.FORBIDDEN);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Forbidden',
          message: expect.stringMatching(joinRegExp([/^Issues:\n/,
            `- ${actionRepo.owner}:\n`,
            / {2}- Access policy not found\n/,
          ])),
        });
      });

      it('if requested target owner has an invalid access policy', async () => {
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
        const githubToken = Fixtures.createGitHubActionsToken({
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
        await withHint(() => {
          expect(response.status).toEqual(Status.FORBIDDEN);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Forbidden',
          message: expect.stringMatching(joinRegExp([/^Issues:\n/,
            `- ${actionRepo.owner}:\n`,
            / {2}- Invalid access policy\n/,
          ])),
        });
      });

      it('if identity subject is not allowed by owner access policy', async () => {
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
        const githubToken = Fixtures.createGitHubActionsToken({
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
        await withHint(() => {
          expect(response.status).toEqual(Status.FORBIDDEN);
        }, async () => ({'response.json()': await response.json()}));
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Forbidden',
          message: expect.stringMatching(joinRegExp([/^Issues:\n/,
            `- ${actionRepo.owner}:\n`,
            / {2}- OIDC token subject is not allowed by owner access policy\n/,
          ])),
        });
      });

      describe('repos scope', () => {
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

        it('if requested permission is an owner permission', async () => {
          // --- Given ---
          const githubToken = Fixtures.createGitHubActionsToken({});

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'organization-secrets': 'read'},
            }),
          });

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.BAD_REQUEST);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Bad Request',
            message: expect.stringMatching(joinRegExp([
              /^Invalid permissions scopes for token scope 'repos'\.\n/,
              /- organization-secrets/,
            ])),
          });
        });

        it('if requested target repo permission is not allowed by owner policy', async () => {
          // --- Given ---
          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'allowed-repository-permissions': {contents: 'read'},
            },
          });

          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.owner}:\n`,
              / {2}- contents: write - Not allowed by owner access policy\n/,
            ])),
          });
        });

        it('if requested target repo has no access policy', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              scope: 'repos',
              permissions: {contents: 'read'},
            }),
          });

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.name}:\n`,
              / {2}- Access policy not found\n/,
            ])),
          });
        });

        it('if requested target repo has an invalid access policy', async () => {
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
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.name}:\n`,
              / {2}- Invalid access policy\n/,
            ])),
          });
        });

        it('if requested target repo scope permission are not granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {contents: 'read'},
              }],
            },
          });
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.name}:\n`,
              / {2}- contents: write - Not authorized/,
            ])),
          });
        });

        it('if requested target repo grants access with a subject claim contains a wildcard', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['*:refs/heads/*'],
                permissions: {contents: 'write'},
              }],
            },
          });
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.name}:\n`,
              / {2}- Not authorized/,
            ])),
          });
        });

        it('if requested target repo grants access with a subject pattern is not complete', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:octocat/*'],
                permissions: {contents: 'write'},
              }],
            },
          });
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.name}:\n`,
              / {2}- Not authorized\n/,
            ])),
          });
        });

        it('if requested target repo permission scope was not granted by repo', async () => {
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
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.name}:\n`,
              / {2}- contents: read - Not authorized\n/,
            ])),
          });
        });
      });

      describe('owner scope', () => {
        beforeEach(() => {
          githubMockEnvironment.addAppInstallation({
            permissions: {'single_file': 'read', 'contents': 'write', 'organization-secrets': 'write'},
          });
        });

        it('if requested target repo permissions not granted by owner', async () => {
          // --- Given ---
          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'allowed-repository-permissions': {contents: 'write'},
            },
          });

          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          });

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              scope: 'owner',
              permissions: {contents: 'write'},
            }),
          });

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp([/^Issues:\n/,
              `- ${actionRepo.owner}:\n`,
              / {2}- Not authorized\n/,
            ])),
          });
        });
      });
    });

    describe('should response with status OK', () => {

      beforeEach(() => {
        githubMockEnvironment.addAppInstallation({
          permissions: {
            single_file: 'read', contents: 'write', secrets: 'write', organization_secrets: 'write',
          },
        });
      });

      describe('repository scope', () => {
        beforeEach(() => {
          githubMockEnvironment.addOwnerRepository({
            ownerAccessPolicy: {
              'allowed-repository-permissions': {secrets: 'write'},
            },
          });
        });

        it('if requested repo permissions are granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:ref:refs/heads/*'],
                permissions: {secrets: 'write'},
              }],
            },
          });
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.OK);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {secrets: 'write'},
            repositories: [parseRepository(actionRepo.name).repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          });
        });

        it('if requested repo permissions are granted by owner', async () => {
          // --- Given ---

          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.OK);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {secrets: 'write'},
            repositories: [actionRepo.repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          });
        });

        it('even if target access policy has invalid permissions', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['repo:${origin}:ref:refs/heads/*'],
                permissions: {secrets: 'write', invalid_permission: 'write'} as GitHubAppRepositoryPermissions,
              }],
            },
          });
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.OK);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {secrets: 'write'},
            repositories: [actionRepo.repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          });
        });

        it('even if target access policy has invalid statements', async () => {
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
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.OK);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {secrets: 'write'},
            repositories: [actionRepo.repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          });
        });

        it('even if requested repositories contains owner prefix', async () => {
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
          const githubToken = Fixtures.createGitHubActionsToken({
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
          await withHint(() => {
            expect(response.status).toEqual(Status.OK);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {secrets: 'write'},
            repositories: [actionRepo.repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          });
        });
      });

      describe('owner scope', () => {

        it('if requested org permissions are granted', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({});
          const githubToken = Fixtures.createGitHubActionsToken({
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
              scope: 'owner',
              permissions: {'organization-secrets': 'write'},
            }),
          });

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.OK);
          }, async () => ({'response.json()': await response.json()}));
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {'organization-secrets': 'write'},
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          });
        });
      });
    });
  });
});

// --- Mocks ------------------------------------------------------------------

/**
 * Mock modules
 * @return void
 */
function mockJwks() {
  jest.unstable_mockModule('get-jwks', () => {
    const actual = jest.requireActual<any>('get-jwks');
    return {
      default: jest.fn().mockImplementation((params) => ({
        ...actual(params),
        getPublicKey: async (params: any) => {
          // intercept getPublicKey for GitHub Actions Token Signing and return fixture public key
          if (params.domain === Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.iss &&
              params.kid === Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.kid &&
              params.alg === Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.alg) {
            return Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.publicKey;
          }
          return actual.getPublicKey(params);
        },
      })),
    };
  });
}

/**
 * Mock GitHub
 * @return GitHub environment
 */
function mockGithub() {
  const mock: {
    repositories: Record<string, Repository>,
    appInstallations: Record<string, AppInstallation>,
  } = {
    repositories: {},
    appInstallations: {},
  };

  jest.unstable_mockModule('@octokit/rest', () => ({
    Octokit: jest.fn().mockImplementation((paramsOctokit: any) => {
      // GitHub app
      if (paramsOctokit.auth.appId) {
        return {
          apps: {
            getAuthenticated: jest.fn().mockReturnValue(Promise.resolve({
              data: {
                name: 'GitHub Actions Access Manager',
                html_url: 'https://example.org',
              },
            })),
            getUserInstallation: jest.fn().mockImplementation(async (params: any) => {
              const installation = mock.appInstallations[params.username];
              if (installation) return {data: installation};
              throw new RequestError('Not Found', Status.NOT_FOUND, {
                request: {headers: {}, url: 'http://localhost/tests'} as any,
              });
            }),
            createInstallationAccessToken: jest.fn().mockImplementation(async (params: any) => {
              const installation = Object.values(mock.appInstallations)
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
        };
      }

      // GitHub app installation
      if (typeof paramsOctokit.auth === 'string') {
        const installation = Object.values(mock.appInstallations)
            .find((installation) => installation.id === parseInt(paramsOctokit.auth.split('@')[1]));
        if (installation) {
          return {
            repos: {
              getContent: jest.fn().mockImplementation(async (params: any) => {
                if (params.owner !== installation.owner) {
                  throw new Error('Access Denied');
                }

                const repository = mock.repositories[`${params.owner}/${params.repo}`];

                if (repository?.accessPolicy && config.accessPolicyLocation.repo.paths.includes(params.path)) {
                  const contentString = YAML.stringify(repository.accessPolicy);
                  return {data: {type: 'file', content: Buffer.from(contentString).toString('base64')}};
                }

                if (repository?.ownerAccessPolicy && config.accessPolicyLocation.owner.paths.includes(params.path)) {
                  const contentString = YAML.stringify(repository.ownerAccessPolicy);
                  return {data: {type: 'file', content: Buffer.from(contentString).toString('base64')}};
                }

                throw new RequestError('Not Found', Status.NOT_FOUND, {
                  request: {headers: {}, url: 'http://localhost/tests'} as any,
                });
              }),
            },
          };
        }
      }

      throw new Error('Not Implemented');
    }),
  }));

  return {
    reset() {
      mock.repositories = {};
      mock.appInstallations = {};
    },
    addOwnerRepository({owner, accessPolicy, ownerAccessPolicy}: {
      owner?: string,
      ownerAccessPolicy?: Optional<GitHubOwnerAccessPolicy,
          'origin' | 'statements' | 'allowed-repository-permissions'> | null,
      accessPolicy?: Optional<GitHubRepositoryAccessPolicy,
          'origin' | 'statements'> | null,
    }): Repository {
      owner = owner || DEFAULT_OWNER;
      const name = `${owner}/${config.accessPolicyLocation.owner.repo}`;

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

      mock.repositories[repository.name] = repository;

      return repository;
    },
    addRepository({name, accessPolicy}: {
      name?: string,
      accessPolicy?: Optional<GitHubRepositoryAccessPolicy,
          'origin' | 'statements'> | null,
    }): Repository {
      name = name || `${DEFAULT_OWNER}/${DEFAULT_REPO}-${Object.keys(mock.appInstallations).length}`;

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

      mock.repositories[repository.name] = repository;

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
      const id = 1000 + Object.keys(mock.appInstallations).length;

      const installation = {
        id,
        target_type: targetType,
        owner,
        permissions,
        single_file_paths: permissions['single_file'] ? [
          ...config.accessPolicyLocation.owner.paths,
          ...config.accessPolicyLocation.repo.paths,
        ] : undefined,
      };
      mock.appInstallations[installation.owner] = installation;
      return installation;
    },
  };
}

// --- Utils ------------------------------------------------------------------

/**
 * Normalize permissions by replacing all '-' with '_'
 * @param permissions - permissions object
 * @return normalized permissions
 */
// function normalizePermissions(permissions: Record<string, string>) {
//   return mapObject(permissions, ([key, value]) => [
//     key.replaceAll('-', '_'),
//     value,
//   ])
// }

/**
 * Create and modify date relative to now
 * @param hour - hours in future
 * @return relative date
 */
function dateIn({hour}: { hour: number }) {
  return new Date(new Date().setHours(new Date().getHours() + hour));
}
