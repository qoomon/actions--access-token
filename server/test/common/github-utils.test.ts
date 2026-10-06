import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {
  GitHubRepositoryNameSchema,
  GitHubRepositorySchema,
  parseRepository,
} from '../../src/common/github-utils';

describe('parseRepository', () => {
  it('should throw an Error for an invalid repository format', () => {
    // --- Given ---
    const invalidRepository = 'invalid';

    // --- When ---
    const call = () => {
      parseRepository(invalidRepository);
    };

    // --- Then ---
    assert.throws(call, Error);
  });
});

describe('GitHubRepositoryNameSchema', () => {
  for (const name of ['sandbox', '.github', 'my-repo_1.0', 'a.b', '...', '.-', '_']) {
    it(`accepts the repository name '${name}'`, () => {
      assert.equal(GitHubRepositoryNameSchema.safeParse(name).success, true);
    });
  }

  // '.' and '..' would be treated as path segments of the GitHub API url
  for (const name of ['.', '..', '', 'a/b', '../a', 'a b', 'a:b', 'a%2Fb']) {
    it(`rejects the repository name '${name}'`, () => {
      assert.equal(GitHubRepositoryNameSchema.safeParse(name).success, false);
    });
  }
});

describe('GitHubRepositorySchema', () => {
  for (const repository of ['octocat/sandbox', 'octocat/.github', 'octocat/...', 'octocat/a.b']) {
    it(`accepts the repository '${repository}'`, () => {
      assert.equal(GitHubRepositorySchema.safeParse(repository).success, true);
    });
  }

  for (const repository of [
    'octocat/.', 'octocat/..', 'octocat/', '/sandbox', 'octocat/a/b', '../sandbox', './sandbox',
  ]) {
    it(`rejects the repository '${repository}'`, () => {
      assert.equal(GitHubRepositorySchema.safeParse(repository).success, false);
    });
  }
});
