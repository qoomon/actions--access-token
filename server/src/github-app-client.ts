import {Octokit as OctokitCore} from '@octokit/core';
import {paginateRest} from "@octokit/plugin-paginate-rest";
import {restEndpointMethods} from "@octokit/plugin-rest-endpoint-methods";
import {retry as retryPlugin} from '@octokit/plugin-retry';
import type {components} from '@octokit/openapi-types';
import {RestEndpointMethodTypes} from '@octokit/rest';
import {_throw, ensureHasEntries, mapObjectEntries} from './common/common-utils.js';
import {GitHubAppPermissions} from './common/github-utils.js';
import {Status} from './common/http-utils.js';

export const Octokit = OctokitCore
    .plugin(restEndpointMethods, paginateRest, retryPlugin);

export type Octokit = InstanceType<typeof Octokit>;

export type GitHubAppInstallation =
    RestEndpointMethodTypes['apps']['getUserInstallation']['response']['data'];
export type GitHubAppInstallationAccessToken =
    RestEndpointMethodTypes['apps']['createInstallationAccessToken']['response']['data'];

/**
 * Get GitHub app installation for an owner
 * @param client - GitHub app client
 * @param owner - app installation owner
 * @return installation or null if app is not installed for target
 */
export async function getAppInstallation(client: Octokit, {owner}: {
  owner: string
}): Promise<GitHubAppInstallation | null> {
  return client.rest.apps.getUserInstallation({username: owner})
      .then((res) => res.data)
      .catch(async (error) => (error.status === Status.NOT_FOUND ? null : _throw(error)));
}

/**
 * Create installation access token
 * @param client - GitHub app client
 * @param installation - target installation
 * @param repositories - target repositories
 * @param permissions - requested permissions
 * @return access token
 */
export async function createInstallationAccessToken(client: Octokit, installation: GitHubAppInstallation, {
  repositories, permissions,
}: {
  repositories?: string[],
  permissions: GitHubAppPermissions
}): Promise<GitHubAppInstallationAccessToken> {
  // noinspection TypeScriptValidateJSTypes
  return client.rest.apps.createInstallationAccessToken({
    installation_id: installation.id,
    // BE AWARE that an empty object will result in a token with all app installation permissions
    permissions: ensureHasEntries(mapObjectEntries(permissions, ([scope, permission]) => [
      scope.replaceAll('-', '_'), permission,
    ])),
    repositories,
  }).then((res) => res.data);
}

/**
 * Create Octokit instance authenticated as an app installation
 * @param client - GitHub app client
 * @param installation - app installation
 * @param permissions - requested permissions
 * @param repositories - requested repositories
 * @return octokit instance
 */
export async function createOctokit(client: Octokit, installation: GitHubAppInstallation, {
  permissions, repositories,
}: {
  permissions: components['schemas']['app-permissions'],
  repositories?: string[]
}): Promise<Octokit> {
  const token = await createInstallationAccessToken(client, installation, {permissions, repositories});
  return new Octokit({auth: token.token});
}

/**
 * Get repository file content as a string
 * @param client - GitHub client for target repository
 * @param owner - repository owner
 * @param repo - repository name
 * @param path - file path
 * @param maxSize - max allowed file size in bytes
 * @return file content or null if the file does not exist
 */
export async function getRepositoryFileContent(client: Octokit, {
  owner, repo, path, maxSize,
}: {
  owner: string,
  repo: string,
  path: string,
  maxSize?: number
}): Promise<string | null> {
  return client.rest.repos.getContent({owner, repo, path})
      .then((res) => {
        if ('type' in res.data && res.data.type === 'file') {
          if (maxSize !== undefined && res.data.size > maxSize) {
            throw new Error(`Expect file size to be less than ${maxSize}b, but was ${res.data.size}b` +
                ` for file ${owner}/${repo}/${path}`);
          }
          return Buffer.from(res.data.content, 'base64').toString();
        }
        throw new Error('Unexpected file content');
      })
      .catch((error) => {
        if (error.status === Status.NOT_FOUND) return null;
        throw error;
      });
}
