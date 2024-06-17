import * as core from '@actions/core'
import * as github from '@actions/github'
import {runAction} from './github-actions-utils'

runAction(async () => {
  const token = core.getState('token')

  core.info('Revoke access token.')
  // revoke access token
  // https://docs.github.com/en/rest/apps/installations?apiVersion=2022-11-28#revoke-an-installation-access-token
  await github.getOctokit(token)
      .request('DELETE /installation/token', {
        headers: {'X-GitHub-Api-Version': '2022-11-28'},
      })
})
