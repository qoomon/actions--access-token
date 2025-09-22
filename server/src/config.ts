import {env, regexpOfWildcardPattern} from './common/common-utils.js';
import {formatPEMKey} from './common/ras-key-utils.js';
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
    allowedAud: z.string().nonempty(),
    allowedSub: z.array(
        z.instanceof(RegExp)
    ).optional(),
  }),
  accessPolicyLocation: z.strictObject({
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
});

export const config = validate({
  githubAppAuth: {
    appId: env('GITHUB_APP_ID', true),
    // depending on the environment multiline environment variables are not supported,
    // due to this limitation formatPEMKey ensure the right format, even if the key formatted as a single line
    privateKey: formatPEMKey(env('GITHUB_APP_PRIVATE_KEY', true)),
  },
  githubActionsTokenVerifier: {
    allowedAud: env('GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE', true),
    allowedSub: env('GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS')
        ?.split(/\s*,\s*/)
        ?.map((subjectPattern) => regexpOfWildcardPattern(subjectPattern, 'i')),
  },
  accessPolicyLocation: {
    owner: {
      repo: '.github-access-token',
      paths: ['access-token.yaml', 'access-token.yml'],
    },
    repo: {
      paths: ['.github/access-token.yaml', '.github/access-token.yml'],
    },
  },
});

function validate(config: z.infer<typeof configSchema>): z.infer<typeof configSchema> {
  return configSchema.parse(config);
}
