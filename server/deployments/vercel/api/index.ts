import {handle} from 'hono/vercel'
import * as process from 'process'
import 'pino-pretty'

if (!process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE']) {
  // --- guess audience from VERCEL_URL
  process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE'] = process.env['VERCEL_URL']!
      .replace(/-[^-]+(?=\.vercel\.app$)/, '')
}

process.env['REQUEST_ID_HEADER'] = 'x-vercel-id'

const {app} = await import('../../../src/app.js')

export const GET = handle(app)
export const POST = handle(app)
