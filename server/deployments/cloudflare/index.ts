import {Hono} from 'hono';
import process from 'process';

process.env.REQUEST_ID_HEADER = 'cf-request-id';

let app: Hono | null = null;
export default {
  fetch: async (...args: Parameters<Hono['fetch']>): Promise<Response> => {
    if (!app) {
      const {appInit} = await import('../../src/app.js');
      app = appInit();
    }

    return app.fetch(...args);
  },
};

