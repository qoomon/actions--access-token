/* eslint-disable require-jsdoc */
import jwt, {PrivateKey, SignerOptions} from 'fast-jwt';
import {components} from '@octokit/openapi-types';
import {GitHubActionsJwtPayload, parseRepository} from '../src/common/github-utils.js';
import {GitHubOwnerAccessPolicy, GitHubRepositoryAccessPolicy} from '../src/access-token-manager.js';

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
  aud: 'example.org',
  iss: 'https://token.actions.githubusercontent.com',
  kid: 'DA6DD449E0E809599CECDFB3BDB6A2D7D0C2503A',
  alg: 'RS256',
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
      '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\n' +
      '-----END RSA PRIVATE KEY-----\n',
  publicKey: '-----BEGIN PUBLIC KEY-----\n' +
      'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnwhc5IBZ4fFN5mVzEBbF\n' +
      'YA8AaqVbRpr82uML3gPvAZYOxdMiobelDRn313g7NpRICkBPzCUCZ8ppPOqzc/vN\n' +
      'dl5WbKF543Hes1gdhykaIKFE8tjCBqIpFkSzxDkNJ5a+YWq0rKwIu+PncFVqteq7\n' +
      'CNR/2T39S8eMs7APRSa6qsG4TiOzOGmouPvVegA/ywC0/hTOUCS8nEA0PeFf/Wgc\n' +
      'b9DQDKxpLjY3CJe3EfrMNDU23bH4MkRlSgoqi14Em1Ceu7Z5lD2gQcSkPuZ0BuUr\n' +
      'tDq0pLd2qVn6vFDh4F+CCpJCGst4gyDbEeXIG9B3M7EfE18xf+4kh8nMqBpYRR11\n' +
      'xW2Xpf/st0WDLx+BcUPLsrV7gtiC17GZ7H++QvWACva/QX7t8V/8Ss8HtNImjAl6\n' +
      'D5TsV91vAowTOmeYx1HCfD7HwggXuB4bbi5AJwCBmH2BHN/B4IMHIaRApkBwYG8Q\n' +
      'uJ1Ihht8Yop2eAV7vQGgYIb8j+Wysu9t9jAx6lMjgUNUJwU1M3nslLc3cthpGtO1\n' +
      '9tKURVjuCLcRB8TwVNK96US8ftU2aRnOwEd8j/aFoFMM+MK5EyWYvfy7g0M2FR1Z\n' +
      'a0TgLdIZMKtdzROHRqm/wJ6cm76NECUhyRL8vZkrZSBN+0UU1Xl9HskJSa+SLWVj\n' +
      'YnjhwKFXZlbaouifj9gwHBECAwEAAQ==\n' +
      '-----END PUBLIC KEY-----\n',
};

export function createGitHubActionsToken({expiresIn, claims, signing}: {
  expiresIn?: string | number,
  claims?: {
    repository?: string,
    ref?: string,
    workflow_ref?: string,
  },
  signing?: Partial<SignerOptions & { key: string | Buffer | PrivateKey }>,
}) {
  const signer = jwt.createSigner({
    iss: GITHUB_ACTIONS_TOKEN_SIGNING.iss,
    kid: GITHUB_ACTIONS_TOKEN_SIGNING.kid,
    key: GITHUB_ACTIONS_TOKEN_SIGNING.privateKey,
    aud: GITHUB_ACTIONS_TOKEN_SIGNING.aud,
    expiresIn: expiresIn || '1h',
    ...signing,
  });

  const payload = createGitHubActionsTokenPayload(claims);

  return signer(payload);
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
    repository,
    repository_owner: parseRepository(repository).owner,
    ref,
    sub: `repo:${repository}:ref:${ref}`,
    workflow_ref: `${repository}/.github/workflows/${workflow}@${ref}`,
  } as GitHubActionsJwtPayload;
}

export const UNKNOWN_SIGNING_KEY = '-----BEGIN PRIVATE KEY-----\n' +
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE8IW1jsqnWiYw\n' +
    'QG8ASQIhNjFyHt/N4zxKPmqSIBocN3kIJe0WBrOmqrDDZPzMsxwmB7ZAVtj31lfm\n' +
    '/OfkjA3k6fYvygF/GRBS4ysfCilH/2f9xwPRRESLly6CeI/NP1m7bKiLyz9yPRmI\n' +
    'w/9BIK4FE8YolXB+B3AZxTbcTYoAotFqbptx6ZGdDUasbQBuLMPWKKazzpYBSbk7\n' +
    'R4flYWGsHbZfHOyWHzr/tZPHA00x0AaV+JhYEelVM3Owj7j4YVY7z4jrPiubESND\n' +
    'yGHsrmmeDAVol8Faw/zXDOhKFjEIMFaaL007DeSREiwfhM+MzegMKYMRR20vo92s\n' +
    '6a4hxotDAgMBAAECggEAA2I2ieYIKVPtMAsLXS/j73ok41cQdVMgKA5melg+2plB\n' +
    'ZRhxuF0pHQX1v4Wuqj2xkB21zekwFSIDpJ5XxZ96ZaJ3bl7EI9DkbOgmR4Q/LVOA\n' +
    'D+YpdKD9pIBWdjtoDRi3i/bT9oLpdicCl0z2x8Gt+7xZPT1ED4ZFMMwooyRZ6KTb\n' +
    'vmK6MejjPKtthQdKvdtwQfu2TAJT/bbaFsU6jcDXq9NVfnnicz96nwkojHGgQIzW\n' +
    'c/VFfVfx1Kciar23p7pDE1Lf+/KZAe4IrUzrPxTzW81pJxRixGljPAtq7sbiTKt8\n' +
    'ENBegV9H04Y/gXm3Rzy+oEjnqQ5cA0j8sxnkJm48UQKBgQD5FYAew8j83sDWL8++\n' +
    '7jD19P7KuKIra2SZipRrvTJQcqF1xdxvVDPJvF9A0ZmbvAgnlijJexa9NYm436Fz\n' +
    'VQUs2jG7XqKgvyRLTLfTht5SDTq/V4jc+roNq9XlFcwtKD21nVm0uCEymhdrVmyK\n' +
    'rOxc7ykIKB/jFOd1up+PUIEE9wKBgQDKaGB8iQzElpaDexDNvjzNGgI8cUFVNGVl\n' +
    'WKRCIQu7IhEYoKsig2nhdWeyiZuNf4lZIm6gV+FxGnEaVThMlbzU5mbw1FGpqMLf\n' +
    'ZElFMJE+C2nWjUxP9ZooIuHCl3T3svsZ3y32sc7d42kDPFAG0VNATqvqxwwDl42T\n' +
    'H6A676Y1FQKBgBhpYggh2hXmYvHa97pXr9a7LymBFOu6d76QlWFFxqOZyHc5cBQ9\n' +
    'JWI1IwTARhS8RfRTRCYS+TSMBbZnvHQINhyiOdOKP9gPQ6hZmX6SrkFOaJ6OHqzB\n' +
    'qfBjEfCExWD7m6isBjmu/hnufjMX4kVpEzU8f0H8ZLultdWU98Rc+HgbAoGBAKt2\n' +
    'Ig49FtjN7DDzJnfzqJPibXSASGUCXsasgXEXh1V99VeUe4RgKGh6SV7f3SrPmC0u\n' +
    '0uH3sB1c1eUFvgx6aB0+FIP8iDUdpf8ReFQpYVBa4MyEo9m0Z2OKsQ5juQ0/zCDN\n' +
    'g6VQWLp0s3evNuefmVOHkXDwLwg38RFpoBVs/7JFAoGADkb1n19Dy0u14wRl1BCH\n' +
    '6j0rYmzQlHS+dQIPzuuOME856M7Ct4zXYWbO3GKwBCPlNZ00B8jwSccI3U4g0oie\n' +
    'aZfIPJWf5ZXMMKajnGEYBHz2HilRiwWoBId2+1JlGHJqs17zfFFItq8ga1Ev6KFa\n' +
    'gSUTt6QxSBWBgi3oYNRL7bk=\n' +
    '-----END PRIVATE KEY-----';

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
