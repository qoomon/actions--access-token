import {serve} from '@hono/node-server';
import process from 'process';

const {appInit} = await import('./app');
const app = appInit();

const port = parseInt(process.env.PORT ?? '') || 3000;
console.log(`Server is listening on port ${port}`);
serve({fetch: app.fetch, port});
