import process from 'process';
import {_throw, regexpOfWildcardPattern} from './common/common-utils.js';
import {formatPEMKey} from './common/ras-key-utils.js';

export const config: Readonly<Config> = {
  githubAppAuth: {
    appId: process.env.GITHUB_APP_ID ??
        _throw(new Error('Environment variable GITHUB_APP_ID is required')),
    // depending on the environment multiline environment variables are not supported,
    // due to this limitation formatPEMKey ensure the right format, even if the key formatted as a single line
    privateKey: formatPEMKey(process.env.GITHUB_APP_PRIVATE_KEY ??
        _throw(new Error('Environment variable GITHUB_APP_ID is required'))),
  },
  githubActionsTokenVerifier: {
    allowedAud: process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE ??
        _throw(new Error('Environment variable GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE is required')),
    allowedSub: process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS
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
};

// --- Types -----------------------------------------------------------------------------------------------------------

interface Config {
  githubAppAuth: {
    appId: string
    privateKey: string
  },
  githubActionsTokenVerifier: {
    allowedAud: string
    allowedSub?: RegExp[]
  }
  accessPolicyLocation: {
    owner: {
      paths: string[]
      repo: string
    },
    repo: {
      paths: string[]
    }
  }
}
