import {ErrorHandler, HonoRequest, NotFoundHandler,} from 'hono';
import {Logger} from 'pino';
import {HTTPException} from 'hono/http-exception';
import type {StatusCode, UnofficialStatusCode} from 'hono/utils/http-status';
import {createMiddleware} from 'hono/factory';
import {ZodType} from 'zod';
import {createVerifier, KeyFetcher, TokenError, VerifierOptions,} from 'fast-jwt';
import {formatZodIssue, JsonTransformer} from './zod-utils.js';
import {Status, StatusPhrases} from './http-utils.js';
import {buildJwksKeyFetcher} from './jwt-utils.js';
import {indent} from './common-utils.js';

/**
 * Creates a NotFoundHandler that responses with JSON
 * @return NotFoundHandler
 */
export function notFoundHandler(): NotFoundHandler {
  return (context) => {
    context.status(Status.NOT_FOUND);
    return context.json({
      status: Status.NOT_FOUND,
      error: StatusPhrases[Status.NOT_FOUND],
    });
  };
}

/**
 * Creates an ErrorHandler that response with JSON
 * @return ErrorHandler
 */
export function errorHandler(logger: Logger): ErrorHandler {
  return (err, context) => {
    const requestId = context.var.requestId;

    if (err instanceof HTTPException && err.status < Status.INTERNAL_SERVER_ERROR) {
      logger.debug({err}, 'Http Request Client Error');
      context.status(err.status);
      return context.json({
        requestId,
        status: err.status,
        error: StatusPhrases[err.status as Exclude<StatusCode, UnofficialStatusCode>],
        message: err.message,
      });
    }
    logger.error({err}, 'Http Request Internal Server Error');
    context.status(Status.INTERNAL_SERVER_ERROR);
    return context.json({
      requestId,
      status: Status.INTERNAL_SERVER_ERROR,
      error: StatusPhrases[Status.INTERNAL_SERVER_ERROR],
    });
  };
}

/**
 * Creates a middleware to log http requests and responses
 * @return middleware
 */
export function debugLogger(logger: Logger) {
  return createMiddleware(async (context, next) => {
    logger.debug({
      path: context.req.path,
      method: context.req.method,
      query: context.req.query,
    }, 'Http Request');

    await next();

    logger.debug({
      status: context.res.status,
    }, 'Http Response');
  });
}

/**
 * Creates a middleware that parses the request body as json
 * @param req - request
 * @param schema - zod schema
 * @return middleware
 */
export async function parseJsonBody<T extends ZodType>(req: HonoRequest, schema: T) {
  const body = await req.text();
  const bodyParseResult = JsonTransformer.pipe(schema).safeParse(body);

  if (!bodyParseResult.success) {
    throw new HTTPException(Status.BAD_REQUEST, {
      message: `Invalid request body:\n${
          bodyParseResult.error.issues.map(formatZodIssue)
              .map((it) => indent(it, '  ')).join('\n')}`,
    });
  }
  return bodyParseResult.data;
}

/**
 * Creates a middleware that verifies a token and sets the token payload as 'token' context variable
 * @param options - fast-jwt createVerifier options
 * @return middleware
 */
export function tokenAuthenticator<T extends object>(
    options: Partial<VerifierOptions & { key?: KeyFetcher }>,
) {
  options.key ??= buildJwksKeyFetcher({providerDiscovery: true});
  const verifier = createVerifier(options);

  return createMiddleware<{ Variables: { token: T } }>(async (context, next) => {
    const authorizationHeaderValue = context.req.header().authorization;
    if (!authorizationHeaderValue) {
      throw new HTTPException(Status.UNAUTHORIZED, {
        message: 'Missing authorization header',
      });
    }

    const [authorizationScheme, tokenValue] = authorizationHeaderValue.split(' ');
    if (authorizationScheme !== 'Bearer') {
      throw new HTTPException(Status.UNAUTHORIZED, {
        message: `Unexpected authorization scheme ${authorizationScheme}`,
      });
    }

    const tokenPayload = await verifier(tokenValue)
        .catch((error) => {
          console.log(`FUCK verifier error`, {
            error: error.message,
            code: error.code,
            originalError: error.originalError?.message,
            stack: JSON.stringify(error.originalError?.stack),
          }); // TODO remove debug log
          if (error instanceof TokenError) {
            throw new HTTPException(Status.UNAUTHORIZED, {
              message: error.message,
            });
          }
          throw error;
        });

    context.set('token', tokenPayload as T);

    await next();
  });
}
