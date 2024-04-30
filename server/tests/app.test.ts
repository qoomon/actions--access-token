import {sleep} from '../lib/common-utils.js'
import * as Fixtures from './fixtures.js'
import process from 'process'
import StatusCodes from 'http-status-codes'
import YAML from 'yaml'
import {
  GitHubAccessPolicy,
  GitHubAppPermissions,
} from '../lib/types.js'
import {verifyPermission} from '../lib/github-utils.js'
import {describe, expect, it, jest} from '@jest/globals'
import request from 'supertest'
import {RequestError} from '@octokit/request-error'
import {withHint} from './lib/jest-utils.js'
import {components} from '@octokit/openapi-types'

// TODO move setup to test itself
const octokitEnvironment = {
  appInstallations: [
    // === User Installation ===
    {
      id: 1000,
      owner: 'john-doe',
      target_type: 'User',
      permissions: {
        single_file: 'read',
        contents: 'write',
        pull_requests: 'write',
        actions: 'write',
        actions_variables: 'write',
        secrets: 'write',
      },
    },
    // === Organization Installation ===
    {
      id: 9000,
      owner: 'sesame-street',
      target_type: 'Organization',
      permissions: {
        members: 'read',
        single_file: 'read',
        organization_secrets: 'write',
        organization_actions_variables: 'write',
        organization_projects: 'read',
        organization_self_hosted_runners: 'read',
        contents: 'write',
        actions: 'write',
      },
    },
    {
      id: 9001,
      owner: 'sesame-street-invalid-policy',
      target_type: 'Organization',
      permissions: {
        single_file: 'read',
        organization_secrets: 'write',
        organization_actions_variables: 'write',
      },
    },
    {
      id: 9002,
      owner: 'sesame-street-invalid-policy-yaml',
      target_type: 'Organization',
      permissions: {
        single_file: 'read',
        organization_secrets: 'write',
        organization_actions_variables: 'write',
      },
    },
    {
      id: 9003,
      owner: 'sesame-street-no-policy',
      target_type: 'Organization',
      permissions: {
        single_file: 'read',
        organization_secrets: 'write',
        organization_actions_variables: 'write',
      },
    },
  ] satisfies AppInstallation[],
  repositories: [
    // === Repository Access Policies ===
    {
      name: 'john-doe/action-repo',
      accessPolicy: {
        origin: `john-doe/action-repo`,
        statements: [{
          subjects: [
            `ref:refs/heads/*`,
          ],
          permissions: {
            'contents': 'write',
            'secrets': 'write',
            'actions': 'write',
            'actions-variables': 'write',
            'invalid_permission': 'write',
          },
        }],
      },
    },
    {
      name: 'john-doe/action-repo-relative-workflow_ref-subject',
      accessPolicy: {
        origin: `john-doe/action-repo-relative-workflow_ref-subject`,
        statements: [{
          subjects: [
            `workflow_ref:/.github/workflows/build.yml@refs/heads/main`,
          ],
          permissions: {
            contents: 'write',
          },
        }],
      },
    },
    {
      name: 'john-doe/sandbox-read-access',
      accessPolicy: {
        origin: `john-doe/sandbox-read-access`,
        statements: [{
          subjects: [
            `repo:john-doe/action-repo:ref:refs/heads/*`,
          ],
          permissions: {
            contents: 'read',
          },
        }],
      },
    },
    {
      name: 'john-doe/sandbox-write-access',
      accessPolicy: {
        origin: `john-doe/sandbox-write-access`,
        statements: [{
          subjects: [
            `repo:john-doe/action-repo:ref:refs/heads/*`,
          ],
          permissions: {
            contents: 'write',
          },
        }],
      },
    },
    {
      name: 'john-doe/sandbox-no-access-policy',
      accessPolicy: undefined,
    },
    {
      name: 'john-doe/sandbox-wrong-access-policy',
      accessPolicy: {
        origin: `john-doe/wrong-repo`,
        statements: [{
          subjects: [
            `repo:john-doe/action-repo:ref:refs/heads/*`,
          ],
          permissions: {
            contents: 'write',
            secrets: 'write',
          },
        }],
      },
    },
    {
      name: 'john-doe/sandbox-invalid-access-policy-yaml',
      accessPolicy: 'invalid' as any,
    },
    {
      name: 'john-doe/sandbox-unexpected-permissions',
      accessPolicy: {
        origin: `john-doe/sandbox-unexpected-permissions`,
        statements: [{
          subjects: [
            `repo:john-doe/action-repo:ref:refs/heads/*`,
          ],
          permissions: {
            'organization-secrets': 'write',
          },
        }],
      },
    },
    {
      name: 'john-doe/sandbox-invalid-access-policy-origin',
      accessPolicy: {
        origin: `john-doe/wrong`,
        statements: [],
      },
    },
    // === Organization Access Policies ===
    {
      name: 'sesame-street/.github',
      ownerAccessPolicy: {
        origin: `sesame-street/.github`,
        statements: [{
          subjects: [
            `repo:sesame-street/org:ref:refs/heads/*`,
          ],
          permissions: {
            'organization-secrets': 'write',
            'organization-actions-variables': 'write',
            'contents': 'read',
          },
        }],
      },
    },
    {
      name: 'sesame-street-invalid-policy/.github',
      ownerAccessPolicy: {
        origin: `sesame-street-invalid-policy/.github`,
        statements: [{
          subjects: [],
          permissions: 'invalid' as any,
        }],
      },
    },
    {
      name: 'sesame-street-invalid-policy/.github',
      ownerAccessPolicy: {
        origin: 'sesame-street-invalid-policy/.github',
        statements: [{
          subjects: [],
          permissions: 'invalid' as any,
        }],
      },
    },
    {
      name: 'sesame-street-invalid-policy-yaml/.github',
      ownerAccessPolicy: 'invalid' as any,
    },
    {
      name: 'sesame-street-no-policy/.github',
    },
  ] satisfies Repository[],
}

mockModules({octokitEnvironment})

const {appInit} = await import('../app')

process.env['LOG_LEVEL'] = 'info'
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
      const response = await request(app.callback()).get(path)

      // --- Then ---
      expect(response).toMatchObject({
        statusCode: StatusCodes.FORBIDDEN,
      })
    })
  })
})

describe('App path /access_tokens', () => {
  const path = '/access_tokens'

  describe('GET request', () => {
    it('should response with status METHOD_NOT_ALLOWED', async () => {
      // --- When ---
      const response = await request(app.callback()).get(path)

      // --- Then ---
      expect(response).toMatchObject({
        statusCode: StatusCodes.METHOD_NOT_ALLOWED,
      })
    })
  })

  describe('POST request', () => {

    describe('should response with status UNAUTHORIZED', () => {

      it('if authorization header is missing', async () => {
        // --- When ---
        const response = await request(app.callback()).post(path)

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.UNAUTHORIZED,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Unauthorized',
              message: 'Missing authorization header',
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      it('if authorization scheme is invalid', async () => {
        // --- When ---
        const response = await request(app.callback()).post(path)
            .set('Authorization', 'Boom xxx')

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.UNAUTHORIZED,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Unauthorized',
              message: 'Unexpected authorization scheme Boom',
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      it('if authorization token value is malformed', async () => {
        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth('malformed', {type: 'bearer'})

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.UNAUTHORIZED,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Unauthorized',
              message: 'The token is malformed.',
            }),
          })
        }, {
          'response.text': response.text,
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
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.UNAUTHORIZED,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Unauthorized',
              message: 'The token signature is invalid.',
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      it('if authorization token is expired', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken({
          signing: {
            expiresIn: 1,
          },
        })
        await sleep(2) // ensure token is expired

        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.UNAUTHORIZED,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Unauthorized',
              message: expect.stringMatching(/^The token has expired at /),
            }),
          })
        }, {
          'response.text': response.text,
        })
      })
    })

    describe('should response with status BAD REQUEST', () => {

      it('if request body is invalid json', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken()

        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})
            .type('text')
            .set('Content-type', 'application/json')
            .send('{invalid_json}')

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.BAD_REQUEST,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(/^Invalid request body\.\n.* JSON .*/),
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      it('if token request does not contain any permission scopes', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken()

        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})
            .send({
              permissions: {},
            })

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.BAD_REQUEST,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(/^Token permissions must not be empty\.$/),
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      it('if token request permission scope is unexpected', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken()

        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})
            .send({
              permissions: {
                unexpected: 'write',
              },
            })

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.BAD_REQUEST,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(/^Invalid request body\.\n- permissions: Unrecognized key\(s\) in object: 'unexpected'$/),
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      it('if token request permission is invalid', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken()

        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})
            .send({
              permissions: {
                actions: 'invalid' as any,
              } satisfies GitHubAppPermissions,
            })

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.BAD_REQUEST,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(/^Invalid request body.\n- permissions.actions: Invalid enum value\..*$/),
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      it('if token request repository is invalid', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken()

        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})
            .send({
              repositories: ['invalid/invalid'],
              permissions: {
                actions: 'read',
              } satisfies GitHubAppPermissions,
            })

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.BAD_REQUEST,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(/^Invalid request body.\n- repositories.0: Invalid format\..*$/),
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      it('if token request owner is invalid', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken()

        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})
            .send({
              owner: 'invalid/invalid',
              permissions: {
                'organization-actions-variables': 'read',
              } satisfies GitHubAppPermissions,
            })

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.BAD_REQUEST,
            _body: expect.objectContaining({
              requestId: expect.any(String),
              error: 'Bad Request',
              message: expect.stringMatching(/^Invalid request body.\n- owner: Invalid format\..*$/),
            }),
          })
        }, {
          'response.text': response.text,
        })
      })
    })

    describe('should response with status OK', () => {

      it('if token request for self', async () => {
        // --- Given ---
        const githubToken = Fixtures.createGitHubActionsToken({
          claims: {
            repository: 'john-doe/action-repo',
          },
        })

        // --- When ---
        const response = await request(app.callback()).post(path)
            .auth(githubToken, {type: 'bearer'})
            .send({
              permissions: {
                'actions': 'read',
                'actions-variables': 'read',
              },
            })

        // --- Then ---
        withHint(() => {
          expect(response).toMatchObject({
            headers: expect.any(Object),
            statusCode: StatusCodes.OK,
            _body: expect.objectContaining({
              owner: 'john-doe',
              permissions: {
                'actions': 'read',
                'actions-variables': 'read',
              },
              repositories: ['action-repo'],
              token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@1000$/),
              expires_at: expect.stringMatching(/Z$/),
            }),
          })
        }, {
          'response.text': response.text,
        })
      })

      describe('if token request for self, even', () => {
        it('if target access policy has invalid permissions', async () => {
          // TODO
          // --- Given ---
          const githubToken = Fixtures.createGitHubActionsToken({
            claims: {
              repository: 'john-doe/action-repo',
            },
          })

          // --- When ---
          const response = await request(app.callback()).post(path)
              .auth(githubToken, {type: 'bearer'})
              .send({
                permissions: {
                  'actions': 'read',
                  'actions-variables': 'read',
                },
              })

          // --- Then ---
          withHint(() => {
            expect(response).toMatchObject({
              headers: expect.any(Object),
              statusCode: StatusCodes.OK,
              _body: expect.objectContaining({
                owner: 'john-doe',
                permissions: {
                  'actions': 'read',
                  'actions-variables': 'read',
                },
                repositories: ['action-repo'],
                token: expect.stringMatching(/^INSTALLATION_ACCESS_TOKEN@1000$/),
                expires_at: expect.stringMatching(/Z$/),
              }),
            })
          }, {
            'response.text': response.text,
          })
        })
      })
    })
  })
})

/**
 * Mock modules
 * @param octokitEnvironment - octokit environment
 * @returns void
 */
function mockModules({octokitEnvironment}: {
  octokitEnvironment: {
    appInstallations: AppInstallation[],
    repositories: Repository[],
  }
}) {
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
              const installation = octokitEnvironment.appInstallations
                  .find((it) => it.owner === params.username)
              if (installation) return {data: installation}
              throw new RequestError('Not Found', StatusCodes.NOT_FOUND, {
                request: {headers: {}, url: 'http://localhost/tests'} as any,
              })
            }),
            createInstallationAccessToken: jest.fn().mockImplementation(async (params: any) => {
              const installation = octokitEnvironment.appInstallations
                  .find((it) => it.id === params.installation_id)
              if (installation) {
                Object.entries(params.permissions).forEach(([scope, permission]) => {
                  if (!verifyPermission({
                    requested: permission as string,
                    granted: installation.permissions[scope as keyof GitHubAppPermissions],
                  })) {
                    console.error(`Invalid permission: ${scope} requested=${permission} granted=${installation.permissions[scope as keyof GitHubAppPermissions]}`)
                    throw new RequestError('Unprocessable Entity', StatusCodes.UNPROCESSABLE_ENTITY, {
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
        const installation = octokitEnvironment.appInstallations
            .find((it) => it.id === parseInt(Octokit_params.auth.split('@')[1]))
        if (installation) {
          return {
            repos: {
              getContent: jest.fn().mockImplementation(async (params: any) => {
                if (params.owner !== installation.owner) {
                  throw new Error('Access Denied')
                }

                const repository = octokitEnvironment.repositories
                    .find((it) => it.name === `${params.owner}/${params.repo}`)
                if (!repository) {
                  throw new RequestError('Not Found', StatusCodes.NOT_FOUND, {
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

                throw new RequestError('Not Found', StatusCodes.NOT_FOUND, {
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

// --- Types ------------------------------------------------------------------

type AppInstallation = {
  id: number,
  permissions: components['schemas']['app-permissions'] & Record<string, string | undefined>,
  target_type?: string,
  owner: string,
}

type Repository = {
  name: string,
  accessPolicy?: GitHubAccessPolicy
  ownerAccessPolicy?: GitHubAccessPolicy,
}


