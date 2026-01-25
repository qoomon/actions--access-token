import {components} from '@octokit/openapi-types';
import {GitHubActionsJwtPayload, parseRepository} from '../src/common/github-utils.js';
import {GitHubOwnerAccessPolicy, GitHubRepositoryAccessPolicy} from '../src/access-token-manager.js';
import {JWTPayload, SignJWT} from 'jose';
import * as crypto from 'node:crypto';

export const DEFAULT_OWNER = 'octocat';
export const DEFAULT_REPO = 'playground';

export const GITHUB_APP_AUTH = {
  appId: '1234567890',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
      'MIIEowIBAAKCAQEApgH2MYIDYbfSFiLJWI5+qhslsWJSx/PI1RTzkNwBZT/FTJV4\n' +
      '8s+bjwzBsfWYNRegT2bWzDzeNMtRqZpLkaHF00eET3GU88twsO2gy8iDfWqqgre+\n' +
      '6D4tZ88hNGoKdm1pyp/FEJ8GhNyW2lIhoNmiVMy31JJFciyAf1lLERi35zw0XHD7\n' +
      'uTqN9S7QivrgHwlGNiSlqML2W9f4PbHvdHEyphRFHSyGMLQyKRX7dk7ndtAUTrxe\n' +
      'txDMZqDNB7hoQzVxTR41eDoglWN4Enb1NU7UF4C9j0EIOL/HjhKhfCiGnTXaTiMd\n' +
      'U4agocoArztK/k3HKlwHH4msw2bZT9m5bb4OfwIDAQABAoIBAQCUvCE2jkQ1YxsJ\n' +
      '1jUL8O+vvQ7ydSOyHswLjfAEE/n0G0TMrwdklXnMmyNYLLEosHhja8J7zvVP2/LY\n' +
      'wHOAka7K88Kp4xwPqnDXNLDipE6bKdyHrdWQA1VvMvePHIsvPCyS7L8Fe1W96F4I\n' +
      'UZnrodJ9o8X44OzztMeUUg6dzMXImIPvoVe9ctFBT3UCohXXCTj6jimiRXkvhahh\n' +
      'pq1jj1aJTCAsYRrd8Zl0o7hyqDTC/xzi7/TplV3a4Z4sqgj6f0GU2FU0+PcAlXj8\n' +
      'UAP+oCnVD1Rm7eaWMxLVD/4H4NvHFb2tNvDkwH5eRsQXCuHUHzcl/NjXRiopfAe+\n' +
      'tBrLEDSxAoGBAPL/Pbct4dGpt5KxT78dsuMPpYCFTBns61a8NdBUCM9t1DhWpfMz\n' +
      'VwiVNlFUiMYONi43ef8IUIo/fx8DwVp2CbEtdj1j8vC7+gAvTHcGI7SrOqutOooJ\n' +
      'omKsmcUkj3N9MX6i6j9ajnnAcQpxg8lLjccYQ8thpFdon9gJOcaFweQVAoGBAK7k\n' +
      'D7hzeoDuT4xjQD3RmftewnFEkWW2BUgfrkODO6fHjf0GjqJpAYEPjoPMeb2AnZiv\n' +
      'tbfFPN1TmGbcqipohN+lDLK56C2Draqgvn11LYKK4iCt1AjRNKvHkjisz6cHJFjd\n' +
      'nDoYzrPY7Zhmr6nz1DB+jLKx0s5/hWbZCXeqmClDAoGAMV9zJrkH3RXi2sd0MJzU\n' +
      'MBaJxidPYyUkXCc5t+6bK6phKGFSrquLz46hzryiXbudfp5/BzalRrHIHoEg1ESP\n' +
      'i5R1JdwdDJTlIwx5OOXic18nOKKl9k4m1G3FgK0BCLIzUEvB1MWNlWdokHqoEEpt\n' +
      'sDpZ7AUW4zu63qZhOtkKoFECgYBdUVFWEUAHdaE6fmbz1Vg9OVW1DGoshFATKNxa\n' +
      'J7b4ElGf9hS7ch4cWEmp57v5spvksbTbhsGwMv+5uvqNQFHN54p7/xh02LMcvUKH\n' +
      'PLP42NRJrZba0Y4yLn3GAeeW7wek5zKKCVyZuCEm1Xvbyj+pVI0MeDfMeVycASi9\n' +
      'Emi4cwKBgGlyApKOOxPGpaXSfjkeIpkPnDk9sQNpMr0zXQqZpg/OgPZmZNHdAOBg\n' +
      'RZycinkxOLbCl8JLVqqRWdkMaDBQScMGBQce7FEFwKCOyts9uakZcRCkF5F5E0H8\n' +
      'eZB2qW17Y/X/+rA0veFlI6Ms2D/aS5q/tknlhd2BMA2gGCHbasCH\n' +
      '-----END RSA PRIVATE KEY-----\n',
};

export const GITHUB_ACTIONS_TOKEN_SIGNING = {
  aud: 'github-actions-access-token.qoomon.workers.dev',
  iss: 'https://token.actions.githubusercontent.com',
  kid: 'DA6DD449E0E809599CECDFB3BDB6A2D7D0C2503A',
  key: crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  }),
};

export async function createGitHubActionsToken({claims, expirationTime, signing}: {
  claims?: {
    repository?: string,
    ref?: string,
    workflow_ref?: string,
  },
  expirationTime?: string | number,
  signing?: { key: crypto.KeyObject },
}) {
  const payload = createGitHubActionsTokenPayload(claims);

  return await new SignJWT(payload as unknown as JWTPayload)
      .setProtectedHeader({
        alg: 'RS256',
        kid: GITHUB_ACTIONS_TOKEN_SIGNING.kid,
      })
      .setExpirationTime(expirationTime ?? '1h')
      .sign(signing?.key ?? GITHUB_ACTIONS_TOKEN_SIGNING.key.privateKey)
}

function createGitHubActionsTokenPayload(claims?: {
  repository?: string,
  ref?: string,
  workflow?: string,
}) {
  const repository = claims?.repository ?? `${DEFAULT_OWNER}/${DEFAULT_REPO}`;
  const ref = claims?.ref ?? 'refs/heads/main';
  const workflow = claims?.workflow ?? 'build.yml';
  return {
    iss: GITHUB_ACTIONS_TOKEN_SIGNING.iss,
    aud: GITHUB_ACTIONS_TOKEN_SIGNING.aud,
    repository,
    repository_owner: parseRepository(repository).owner,
    ref,
    sub: `repo:${repository}:ref:${ref}`,
    workflow_ref: `${repository}/.github/workflows/${workflow}@${ref}`,
    job_workflow_ref: `${repository}/.github/workflows/${workflow}@${ref}`,
  } as GitHubActionsJwtPayload;
}

export const UNKNOWN_SIGNING_KEY = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

// ---- Types ----------------------------------------------------------------------------------------------------------

export interface AppInstallation {
  id: number,
  permissions: components['schemas']['app-permissions'] & Record<string, string | undefined>,
  target_type?: string,
  owner: string,
  single_file_paths?: string[],
}

export interface Repository {
  name: string,
  owner: string,
  repo: string,
  accessPolicy?: GitHubRepositoryAccessPolicy
  ownerAccessPolicy?: GitHubOwnerAccessPolicy,
}
