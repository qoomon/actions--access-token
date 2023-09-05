import {appInit} from '../../../app.js'
import * as process from 'process'

if (!process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE']) {
  const vercelUrl = process.env['VERCEL_URL'] ||
      Object.entries(process.env).find(([key]) => key.endsWith('_VERCEL_URL'))![1]!

  // --- guess audience from VERCEL_UR
  process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE'] = vercelUrl
      // remove deployment id and account name from hostname (e.g.github-actions-token-manager-1234567890-qoomon.vercel.app)
      .replace(/-[^-]+-[^-]+(?=\.vercel\.app$)/, '')
}

const app = await appInit()
export default app.callback()
