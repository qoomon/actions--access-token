import {handle} from 'hono/vercel'
import * as process from 'process'
import 'pino-pretty'

if (!process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE']) {
  // --- guess audience from VERCEL_UR
  process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE'] = process.env['VERCEL_URL']!
      .replace(/-[^-]+(?=\.vercel\.app$)/, '')
}

process.env['LOG_PRETTY'] = process.env['LOG_PRETTY'] || 'true'
const {app} = await import('../../../src/app')

export const GET = handle(app)
export const POST = handle(app)
