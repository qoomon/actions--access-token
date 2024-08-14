import {
  ErrorHandler, Handler, HonoRequest, NotFoundHandler,
} from 'hono';
import pino, {Logger} from 'pino';
import {HTTPException} from 'hono/http-exception';
import type {StatusCode, UnofficialStatusCode} from 'hono/utils/http-status';
import {createMiddleware} from 'hono/factory';
import {ZodType} from 'zod';
import {
  createVerifier, KeyFetcher, TokenError, VerifierOptions,
} from 'fast-jwt';
import {formatZodIssue, JsonTransformer} from './zod-utils.js';
import {Status, StatusPhrases} from './http-utils.js';
import {buildJwksKeyFetcher} from './jwt-utils.js';
import {indent} from './common-utils.js';

/**
 * Creates a MethodNotAllowedHandler
 * @return NotFoundHandler
 */
export function methodNotAllowedHandler(): Handler {
  return (context) => context.text('Method not allowed', 405);
}

/**
 * Creates a NotFoundHandler that responses with json
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
 * Creates an ErrorHandler that response with json
 * @return ErrorHandler
 */
export function errorHandler<ENV extends { Variables: { log: Logger, id?: string } }>(): ErrorHandler<ENV> {
  return (err, context) => {
    const requestId = context.get('id');
    let requestLogger = context.get('log');

    if (!requestLogger.bindings().requestId) {
      requestLogger = requestLogger.child({requestId});
    }

    if (err instanceof HTTPException && err.status < Status.INTERNAL_SERVER_ERROR) {
      requestLogger.debug({err}, 'Http Request Client Error');
      context.status(err.status);
      return context.json({
        requestId,
        status: err.status,
        error: StatusPhrases[err.status as Exclude<StatusCode, UnofficialStatusCode>],
        message: err.message,
      });
    }
    requestLogger.error({err}, 'Http Request Internal Server Error');
    context.status(Status.INTERNAL_SERVER_ERROR);
    return context.json({
      requestId,
      status: Status.INTERNAL_SERVER_ERROR,
      error: StatusPhrases[Status.INTERNAL_SERVER_ERROR],
    });
  };
}

/**
 * Creates a middleware that generates and sets a request id
 * @param header - header name
 * @return middleware
 */
export function setRequestId(header: string | undefined = 'x-request-id') {
  return createMiddleware<{ Variables: { id: string } }>(async (context, next) => {
    const id = context.req.header()[header ?? ''] || crypto.randomUUID();
    context.set('id', id);
    await next();
  });
}

/**
 * Creates a middleware that generates and sets a request logger
 * @param logger - logger
 * @return middleware
 */
export function setRequestLogger(logger: Logger = pino()) {
  return createMiddleware<{ Variables: { log: Logger, id?: string } }>(async (context, next) => {
    const requestId = context.get('id');
    const requestLogger = logger.child({requestId});
    context.set('log', requestLogger);
    await next();
  });
}

/**
 * Creates a middleware to log http requests and responses
 * @return middleware
 */
export function debugLogger() {
  return createMiddleware<{ Variables: { log: Logger, id?: string } }>(async (context, next) => {
    const debugLogger = context.get('log');
    debugLogger.debug({
      path: context.req.path,
      method: context.req.method,
      query: context.req.query,
    }, 'Http Request');

    await next();

    debugLogger.debug({
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
  const bodyParseResult = await JsonTransformer.pipe(schema).safeParseAsync(body);

  if (!bodyParseResult.success) {
    throw new HTTPException(Status.BAD_REQUEST, {
      message: `Invalid request body:\n${
        bodyParseResult.error.issues.map(formatZodIssue)
            .map((it) => indent(it, '- ')).join('\n')}`,
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
  options.key = options.key ?? buildJwksKeyFetcher({providerDiscovery: true});
  const verifier = createVerifier(options);

  return createMiddleware<{ Variables: { token: T } }>(async (context, next) => {
    // In addition to Authorization header the X-Authorization header can be used for situations,
    // where the Authorization header cannot be used
    // (e.g. when using an AWS IAM authorizer (SignatureV4) in front of this endpoint)
    const authorizationHeaderValue = context.req.header()['x-authorization'] || context.req.header().authorization;
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
