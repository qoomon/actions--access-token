import * as Fixtures from './fixtures.js'
import {AppInstallation, DEFAULT_OWNER, DEFAULT_REPO, Repository} from './fixtures.js'
import process from 'process'
import YAML from 'yaml'
import {GitHubAccessPolicy, GitHubAppPermissions} from '../lib/types.js'
import {parseRepository, verifyPermission} from '../lib/github-utils.js'
import {describe, expect, it, jest} from '@jest/globals'
import {RequestError} from '@octokit/request-error'
import {joinRegExp, sleep} from '../lib/common-utils.js'
import {withHint} from './lib/jest-utils.js'
import {Status} from '../lib/http-utils.js'

// WORKAROUND for https://github.com/honojs/hono/issues/2627
const GlobalRequest = globalThis.Request
globalThis.Request = class Request extends GlobalRequest {
  // eslint-disable-next-line require-jsdoc
  constructor(input: Request | string, init: RequestInit) {
    if (init) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (init as any).duplex ??= 'half'
    }
    super(input, init)
  }
} as typeof GlobalRequest

mockJwks()
const githubMockEnvironment = mockGithub()

beforeEach(() => githubMockEnvironment.reset())

const {appInit} = await import('../app')

process.env['LOG_LEVEL'] = process.env['LOG_LEVEL'] || 'warn'
process.env['GITHUB_APP_ID'] = Fixtures.GITHUB_APP_AUTH.appId
process.env['GITHUB_APP_PRIVATE_KEY'] = Fixtures.GITHUB_APP_AUTH.privateKey
process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE'] = Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.aud

const app = await appInit()

describe('App path /unknown', () => {
  const path = '/unknown'

  describe('GET request', () => {
    it('should response with status FORBIDDEN', async () => {
      // --- Given ---

      // --- When ---
      const response = await app.request(path, {method: 'GET'})

      // --- Then ---
      expect(response.status).toEqual(Status.NOT_FOUND)
    })
  })
})

describe('App path /access_tokens', () => {
  const path = '/access_tokens'

  describe('GET request', () => {
    it('should response with status NOT_FOUND', async () => {
      // --- When ---
      const response = await app.request(path, {method: 'GET'})

      // --- Then ---
      expect(response.status).toEqual(Status.NOT_FOUND)
    })
  })

  describe('POST request', () => {

    describe('should response with status UNAUTHORIZED', () => {

      it('if authorization header is missing', async () => {

        // --- When ---
        const response = await app.request(path, {method: 'POST'})

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED)
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: 'Missing authorization header',
        })
      })

      it('if authorization scheme is invalid', async () => {

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: 'Invalid ___'},
        })

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED)
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: 'Unexpected authorization scheme Invalid',
        })
      })

      it('if authorization token value is malformed', async () => {

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: 'Bearer malformed'},
        })

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED)
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: 'The token is malformed.',
        })
      })

      it('if authorization token signature is invalid', async () => {

        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken({
          signing: {
            key: Fixtures.UNKNOWN_SIGNING_KEY,
          },
        })

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
        })


        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED)
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: 'The token signature is invalid.',
        })
      })

      it('if authorization token is expired', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken({
          signing: {expiresIn: 1},
        })
        await sleep(2) // ensure token is expired

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
        })

        // --- Then ---
        expect(response.status).toEqual(Status.UNAUTHORIZED)
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Unauthorized',
          message: expect.stringMatching(/^The token has expired at /),
        })
      })
    })

    describe('should response with status BAD REQUEST', () => {
      // --- Given ---
      const githubToken = Fixtures.createGitHubActionsToken({})

      it('if request body is invalid json', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: 'invalid json',
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp(
              /^Invalid request body\.\n/,
              /.* is not valid JSON/,
          )),
        })
      })

      it('if token request does not contain any permission scopes', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {},
          }),
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(/^Token permissions must not be empty\.$/),
        })
      })

      it('if token request permission scope is unexpected', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {unexpected: 'write'},
          }),
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp(
              /^Invalid request body\.\n/,
              /- permissions: Unrecognized key\(s\) in object: 'unexpected'$/,
          )),
        })
      })

      it('if token request permission value is invalid', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {secrets: 'invalid' as any},
          }),
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp(
              /^Invalid request body.\n/,
              /- permissions.secrets: Invalid enum value\..*$/,
          )),
        })
      })

      it('if token request permission is a owner permission', async () => {
        // --- Given ---
        const actionRepo = githubMockEnvironment.addRepository({})
        const githubToken = Fixtures.createGitHubActionsToken({
          claims: {repository: actionRepo.name},
        })

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {'organization-secrets': 'read'},
          }),
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp(
              /^Invalid permissions scopes for token scope 'repos'\.\n/,
              /- organization-secrets/,
          )),
        })
      })

      it('if token request repository is invalid', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            repositories: ['invalid/invalid'],
            permissions: {actions: 'read'},
          }),
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp(
              /^Invalid request body.\n/,
              /- repositories.0: Invalid format\..*$/,
          )),
        })
      })

      it('if token request owner is invalid', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            owner: 'invalid/invalid',
            permissions: {'secrets': 'write'},
          }),
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp(
              /^Invalid request body.\n/,
              /- owner: Invalid format\..*$/,
          )),
        })
      })

      it('if token request scope is invalid', async () => {
        // --- Given ---

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            scope: 'invalid',
            permissions: {'secrets': 'write'},
          }),
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.BAD_REQUEST)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Bad Request',
          message: expect.stringMatching(joinRegExp(
              /^Invalid request body.\n/,
              /- scope: Invalid enum value\..*$/,
          )),
        })
      })
    })

    describe('should response with status FORBIDDEN', () => {

      it('if GitHub app has not been installed for target repo', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken({})

        // --- When ---
        const response = await app.request(path, {
          method: 'POST',
          headers: {Authorization: `Bearer ${githubToken}`},
          body: JSON.stringify({
            permissions: {'secrets': 'write'},
          }),
        })

        // --- Then ---
        await withHint(() => {
          expect(response.status).toEqual(Status.FORBIDDEN)
        }, async () => ({'response.json()': await response.json()}))
        expect(await response.json()).toMatchObject({
          requestId: expect.any(String),
          error: 'Forbidden',
          message: expect.stringMatching(joinRegExp(
              / has not been installed for .*\.\n/,
              /.*/,
          )),
        })
      })

      describe('repos scope', () => {
        beforeEach(() => {
          githubMockEnvironment.addAppInstallation({
            permissions: {'single_file': 'read', 'contents': 'write', 'organization-secrets': 'write'},
          })
        })

        it('if GitHub app is missing requested permission', async () => {
          // --- Given ---
          const githubToken = Fixtures.createGitHubActionsToken({})

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'secrets': 'write'},
            }),
          })

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN)
          }, async () => ({'response.json()': await response.json()}))
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp(
                /Some requested permissions got rejected\.\n/,
                /- secrets: write/,
            )),
          })
        })

        it('if requested repo permission scope are not granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({})
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'secrets': 'read'},
            }),
          })

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN)
          }, async () => ({'response.json()': await response.json()}))
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp(
                /^Some requested permissions got rejected\.\n/,
                /- secrets: read\n/,
                / {2}Permission has not been granted to .* installation/,
            )),
          })
        })

        it('if requested repo scope permission are not granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {'contents': 'read'},
              }],
            },
          })
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'contents': 'write'},
            }),
          })

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN)
          }, async () => ({'response.json()': await response.json()}))
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp(
                /^Some requested permissions got rejected\.\n/,
                /- contents: write\n {2}Permission has not been granted by.*/,
            )),
          })
        })

        it('if requested target repo has an invalid access policy', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              origin: 'wrong',
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {'contents': 'write'},
              }],
            },
          })
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'contents': 'write'},
            }),
          })

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN)
          }, async () => ({'response.json()': await response.json()}))
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp(
                /^Some requested permissions got rejected\.\n/,
                /- contents: write\n {2}Permission has not been granted by.*/,
            )),
          })
        })
      })

      describe('owner scope', () => {
        beforeEach(() => {
          githubMockEnvironment.addAppInstallation({
            permissions: {'single_file': 'read', 'contents': 'write', 'organization-secrets': 'write'},
          })
        })

        it('if requesting repo permissions not granted by owner', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {'contents': 'write'},
              }],
            },
          })
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              scope: 'owner',
              permissions: {'contents': 'read'},
            }),
          })

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN)
          }, async () => ({'response.json()': await response.json()}))
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp(
                /^Some requested permissions got rejected\.\n/,
                /- contents: read\n {2}Permission has not been granted by.*/,
            )),
          })
        })

        it('if requested repo permissions are not granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({})
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              scope: 'owner',
              permissions: {'contents': 'read'},
            }),
          })

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.FORBIDDEN)
          }, async () => ({'response.json()': await response.json()}))
          expect(await response.json()).toMatchObject({
            requestId: expect.any(String),
            error: 'Forbidden',
            message: expect.stringMatching(joinRegExp(
                /^Some requested permissions got rejected\.\n/,
                /- contents: read\n {2}Permission has not been granted by.*/,
            )),
          })
        })
      })
    })

    describe('should response with status OK', () => {
      beforeEach(() => {
        githubMockEnvironment.addAppInstallation({
          permissions: {single_file: 'read', contents: 'write', secrets: 'write', organization_secrets: 'write'},
        })
      })

      describe('repository scope', () => {
        it('if requested repo permissions are granted by repo', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {'secrets': 'write'},
              }],
            },
          })
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'secrets': 'write'},
            }),
          })

          // --- Then ---
          expect(response.status).toEqual(Status.OK)
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {'secrets': 'write'},
            repositories: [parseRepository(actionRepo.name).repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          })
        })

        it('if requested repo permissions are granted by org', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({})
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })
          githubMockEnvironment.addRepository({
            name: `${DEFAULT_OWNER}/.github-access-tokens`,
            ownerAccessPolicy: {
              statements: [{
                subjects: [`repo:${actionRepo.name}:ref:refs/heads/*`],
                permissions: {'secrets': 'write'},
              }],
            },
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${githubToken}`,
            },
            body: JSON.stringify({
              permissions: {'secrets': 'write'},
            }),
          })

          // --- Then ---
          expect(response.status).toEqual(Status.OK)
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {'secrets': 'write'},
            repositories: [actionRepo.repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          })
        })

        it('even if target access policy has invalid permissions', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {'secrets': 'write', 'invalid_permission': 'write'} as any,
              }],
            },
          })
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'secrets': 'write'},
            }),
          })

          // --- Then ---
          expect(response.status).toEqual(Status.OK)
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {'secrets': 'write'},
            repositories: [actionRepo.repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          })
        })

        it('even if target access policy has invalid statements', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({
            accessPolicy: {
              statements: [{
                subjects: ['ref:refs/heads/*'],
                permissions: {'secrets': 'write'} as any,
              }, {
                permissions: 'invalid',
              } as any],
            },
          })
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              permissions: {'secrets': 'write'},
            }),
          })

          // --- Then ---
          expect(response.status).toEqual(Status.OK)
          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {'secrets': 'write'},
            repositories: [actionRepo.repo],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          })
        })
      })

      describe('owner scope', () => {
        it('if requested org permissions are granted', async () => {
          // --- Given ---
          const actionRepo = githubMockEnvironment.addRepository({})
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {repository: actionRepo.name},
          })
          githubMockEnvironment.addRepository({
            name: `${DEFAULT_OWNER}/.github-access-tokens`,
            ownerAccessPolicy: {
              statements: [{
                subjects: [`repo:${actionRepo.name}:ref:refs/heads/*`],
                permissions: {'organization-secrets': 'write'},
              }],
            },
          })

          // --- When ---
          const response = await app.request(path, {
            method: 'POST',
            headers: {Authorization: `Bearer ${githubToken}`},
            body: JSON.stringify({
              scope: 'owner',
              permissions: {'organization-secrets': 'write'},
            }),
          })

          // --- Then ---
          await withHint(() => {
            expect(response.status).toEqual(Status.OK)
          }, async () => ({'response.json()': await response.json()}))

          expect(await response.json()).toMatchObject({
            owner: actionRepo.owner,
            permissions: {'organization-secrets': 'write'},
            repositories: [],
            token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@/),
            expires_at: expect.stringMatching(/Z$/),
          })
        })
      })
    })
  })
})

// --- Mocks ------------------------------------------------------------------

/**
 * Mock modules
 * @returns void
 */
function mockJwks() {
  jest.unstable_mockModule('get-jwks', () => {
    const actual = jest.requireActual('get-jwks') as any
    return {
      default: jest.fn().mockImplementation((params) => ({
        ...actual(params),
        getPublicKey: async (params: any) => {
          // intercept getPublicKey for GitHub Actions Token Signing and return fixture public key
          if (params.domain === Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.iss &&
              params.kid === Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.kid &&
              params.alg === Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.alg) {
            return Fixtures.GITHUB_ACTIONS_TOKEN_SIGNING.publicKey
          }
          return actual.getPublicKey(params)
        },
      })),
    }
  })
}

/**
 * Mock github
 * @returns github environment
 */
function mockGithub() {
  const mock: {
    repositories: Repository[],
    appInstallations: AppInstallation[],
  } = {
    repositories: [],
    appInstallations: [],
  }

  jest.unstable_mockModule('@octokit/rest', () => ({
    Octokit: jest.fn().mockImplementation((Octokit_params: any) => {
      // github app
      if (Octokit_params.auth.appId) {
        return {
          apps: {
            getAuthenticated: jest.fn().mockReturnValue(Promise.resolve({
              data: {
                name: 'GitHub Actions Access Manager',
                html_url: 'https://example.org',
              },
            })),
            getUserInstallation: jest.fn().mockImplementation(async (params: any) => {
              const installation = mock.appInstallations
                  .find((it) => it.owner === params.username)
              if (installation) return {data: installation}
              throw new RequestError('Not Found', Status.NOT_FOUND, {
                request: {headers: {}, url: 'http://localhost/tests'} as any,
              })
            }),
            createInstallationAccessToken: jest.fn().mockImplementation(async (params: any) => {
              const installation = mock.appInstallations
                  .find((it) => it.id === params.installation_id)
              if (installation) {
                Object.entries(params.permissions).forEach(([scope, permission]) => {
                  if (!verifyPermission({
                    requested: permission as string,
                    granted: installation.permissions[scope as keyof GitHubAppPermissions],
                  })) {
                    console.error(`Invalid permission: ${scope} requested=${permission} granted=${installation.permissions[scope as keyof GitHubAppPermissions]}`)
                    throw new RequestError('Unprocessable Entity', Status.UNPROCESSABLE_ENTITY, {
                      request: {headers: {}, url: 'http://localhost/tests'} as any,
                    })
                  }
                })

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
                }
              }

              throw new Error('Not Implemented')
            }),
          },
        }
      }

      // github app installation
      if (typeof Octokit_params.auth === 'string') {
        const installation = mock.appInstallations
            .find((it) => it.id === parseInt(Octokit_params.auth.split('@')[1]))
        if (installation) {
          return {
            repos: {
              getContent: jest.fn().mockImplementation(async (params: any) => {
                if (params.owner !== installation.owner) {
                  throw new Error('Access Denied')
                }

                const repository = mock.repositories
                    .find((it) => it.name === `${params.owner}/${params.repo}`)
                if (!repository) {
                  throw new RequestError('Not Found', Status.NOT_FOUND, {
                    request: {headers: {}, url: 'http://localhost/tests'} as any,
                  })
                }

                if (params.path === '.github/access-policy.yml' && repository?.accessPolicy) {
                  const contentString = YAML.stringify(repository.accessPolicy)
                  return {data: {content: Buffer.from(contentString).toString('base64')}}
                }

                if (params.path === 'access-policy.yml' && repository?.ownerAccessPolicy) {
                  const contentString = YAML.stringify(repository.ownerAccessPolicy)
                  return {data: {content: Buffer.from(contentString).toString('base64')}}
                }

                throw new RequestError('Not Found', Status.NOT_FOUND, {
                  request: {headers: {}, url: 'http://localhost/tests'} as any,
                })
              }),
            },
          }
        }
      }

      throw new Error('Not Implemented')
    }),
  }))

  return {
    reset() {
      mock.repositories = []
      mock.appInstallations = []
    },
    addRepository({name, accessPolicy, ownerAccessPolicy}: {
      name?: string,
      accessPolicy?: Omit<GitHubAccessPolicy, 'origin'> & { origin?: string },
      ownerAccessPolicy?: Omit<GitHubAccessPolicy, 'origin'> & { origin?: string },
    }): Repository {
      name = name || `${DEFAULT_OWNER}/${DEFAULT_REPO}-${mock.appInstallations.length}`
      accessPolicy = accessPolicy || {statements: []}
      ownerAccessPolicy = ownerAccessPolicy || {statements: []}

      const repository = {
        name,
        ...parseRepository(name),
        accessPolicy: {
          origin: name,
          ...accessPolicy,
        },
        ownerAccessPolicy: {
          origin: name,
          ...ownerAccessPolicy,
        },
      }
      mock.repositories.push(repository)

      return repository
    },

    addAppInstallation({target_type, owner, permissions}: {
      target_type?: 'User' | 'Organization',
      owner?: string,
      permissions?: Record<string, string>,
    }): AppInstallation {
      target_type = target_type || 'User'
      owner = owner || DEFAULT_OWNER
      permissions = permissions || {}
      const id = 1000 + mock.appInstallations.length

      const installation = {
        id,
        target_type, owner,
        permissions,
      }
      mock.appInstallations.push(installation)
      return installation
    },
  }
}

// --- Utils ------------------------------------------------------------------

/**
 * Normalize permissions by replacing all '-' with '_'
 * @param permissions - permissions object
 * @returns normalized permissions
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
 * @returns relative date
 */
function dateIn({hour}: { hour: number }) {
  return new Date(new Date().setHours(new Date().getHours() + hour))
}
