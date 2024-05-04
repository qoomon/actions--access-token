import {appInit} from '../../app.js'

import * as process from 'process'

if (!process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE']) {
  // --- guess audience from VERCEL_UR
  process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE'] = 'TODO' // TODO
}

const app = await appInit()

export default app
