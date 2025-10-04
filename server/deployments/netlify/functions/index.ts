import {handle} from 'hono/netlify';
import * as process from 'process';

if (!process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE) {
  process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE = new URL(process.env.URL ?? '').hostname
}

process.env.REQUEST_ID_HEADER = 'x-nf-request-id';

const {appInit} = await import('../../../src/app.js');
const app = appInit();

export default handle(app)
