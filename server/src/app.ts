import {Hono} from 'hono';
import {requestId} from 'hono/request-id'
import {prettyJSON} from 'hono/pretty-json';
import {bodyLimit} from 'hono/body-limit';
import process from 'process';
import {debugLogger, errorHandler, notFoundHandler} from './common/hono-utils.js';
import {logger} from './logger.js';
import {createAccessTokensRoute} from './routes/access-tokens.js';

export function appInit(prepare?: (app: Hono) => void) {
  const app = new Hono();
  prepare?.(app);

  app.use(requestId({headerName: process.env.REQUEST_ID_HEADER}));
  app.use((context, next) => logger.withAsyncBindings({
    requestId: context.var.requestId,
  }, next));
  app.use(debugLogger(logger));
  app.onError(errorHandler(logger));
  app.notFound(notFoundHandler());

  app.use(bodyLimit({maxSize: 100 * 1024})); // 100kb
  app.use(prettyJSON());

  app.get('/', (context) => {
    return context.text('https://github.com/qoomon/actions--access-token');
  });

  // --- handle access token request ---------------------------------------------------------------------------------
  app.route('/access_tokens', createAccessTokensRoute());

  return app;
}
