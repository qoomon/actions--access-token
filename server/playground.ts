import {z} from 'zod';
const GitHubRepositoryOwnerRegex = /^[a-z\d](-?[a-z\d])+$/i;
export const GitHubRepositoryOwnerSchema = z.string().regex(GitHubRepositoryOwnerRegex);
const GitHubRepositoryNameRegex = /^[a-z\d-._]+$/i;
export const GitHubRepositoryNameSchema = z.string().regex(GitHubRepositoryNameRegex);

export const GitHubRepositorySchema = z.string().regex(
    new RegExp(`^${GitHubRepositoryOwnerRegex.source.replace(/^\^|\$$/g, '')}` +
        `/${GitHubRepositoryNameRegex.source.replace(/^\^|\$$/g, '')}$`, 'i'),
);
const schema = z.strictObject({
  permissions: z.any(),
  repositories: z.union([
        z.array(z.union([GitHubRepositoryNameSchema, GitHubRepositorySchema])),
        z.literal('ALL'),
      ], {
        error: `Invalid repository: Must be a valid repository name, match <owner>/<repository> or 'ALL'`
      },
  ).default([]),
});

