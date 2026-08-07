import {env, regexpOfWildcardPattern} from './common/common-utils.js';
import {formatPEMKey} from './common/rsa-key-utils.js';
import {z} from 'zod';
import {GitHubRepositoryNameSchema} from './common/github-utils.js';

const configSchema = z.strictObject({
  githubAppAuth: z.strictObject({
    appId: z.string()
        .regex(/^[1-9][0-9]*$/),
    privateKey: z.string()
        .regex(/^\s*-----BEGIN [\w\s]+ KEY-----/, 'Invalid key format')
        .regex(/-----END [\w\s]+ KEY-----\s*$/, 'Invalid key format')
        .transform(formatPEMKey),
  }),
  githubActionsTokenVerifier: z.strictObject({
    allowedAud: z.array(
        z.string().nonempty()
    ).nonempty(),
    allowedSub: z.array(
        z.instanceof(RegExp)
    ).optional(),
  }),

  tokenRequest: z.strictObject({
    targetRepositoriesMaxCount: z.number().int().positive(),
    maxSize: z.number().int().positive(),
  }),

  accessPolicy: z.strictObject({
    location: z.strictObject({
      owner: z.strictObject({
        repo: GitHubRepositoryNameSchema,
        paths: z.array(
            z.string().regex(/(\.yaml|\.yml)$/)
        ).nonempty(),
      }),
      repo: z.strictObject({
        paths: z.array(
            z.string().nonempty()
        ).nonempty(),
      }),
    }),
    maxSize: z.number().int().positive(),
  }),
});

export const config = configSchema.parse({
  githubAppAuth: {
    appId: env('GITHUB_APP_ID', true),
    // Some environments do not support multiline env vars; the schema's
    // .transform(formatPEMKey) normalizes single-line keys to the standard
    // multi-line PEM format before the value is used.
    privateKey: env('GITHUB_APP_PRIVATE_KEY', true),
  },
  githubActionsTokenVerifier: {
    allowedAud: env('GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE', true)
        .split(',')
        .map(aud => aud.trim()),
    allowedSub: env('GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS')
        ?.split(/\s*,\s*/)
        ?.map((subjectPattern) => regexpOfWildcardPattern(subjectPattern, 'i')),
  },

  tokenRequest: {
    /** Maximum number of target repositories allowed per access token request */
    targetRepositoriesMaxCount: 32,
    /** HTTP request body size limit in bytes */
    maxSize: 100 * 1024,
  },

  accessPolicy: {
    location: {
      owner: {
        repo: '.github-access-token',
        paths: ['access-token.yaml', 'access-token.yml'],
      },
      repo: {
        paths: ['.github/access-token.yaml', '.github/access-token.yml'],
      },
    },
    /** Maximum policy file size in bytes */
    maxSize: 100 * 1024,
  },
});
