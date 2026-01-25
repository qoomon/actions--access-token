import {ErrorHandler, HonoRequest, NotFoundHandler,} from 'hono';
import {Logger} from 'pino';
import {HTTPException} from 'hono/http-exception';
import type {StatusCode, UnofficialStatusCode} from 'hono/utils/http-status';
import {createMiddleware} from 'hono/factory';
import {ZodType} from 'zod';
import {formatZodIssue, JsonTransformer} from './zod-utils.js';
import {Status, StatusPhrases} from './http-utils.js';
import {indent} from './common-utils.js';
import {createRemoteJWKSet, jwtVerify, JWTVerifyOptions} from 'jose';
import {JOSEError} from 'jose/errors';

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
 * @param jwksUrl - URL of the JWKS
 * @param options - fast-jwt createVerifier options
 * @return middleware
 */
export function tokenAuthenticator<T extends object>(
    jwksUrl: URL,
    options: JWTVerifyOptions & { subjects?: RegExp[] },
) {
  const jwkSet = createRemoteJWKSet(jwksUrl);

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

    const token = await jwtVerify(tokenValue,
        jwkSet, options,
    ).catch((error) => {
      if (error instanceof JOSEError) {
        throw new HTTPException(Status.UNAUTHORIZED, {
          message: 'Invalid token: ' + error.message,
        });
      }
      throw error;
    });

    if (options.subjects && !options.subjects
        .some((subject) => subject.test(token.payload.sub ?? ''))) {
      throw new HTTPException(Status.UNAUTHORIZED, {
        message: `Invalid Token: unexpected "sub" claim value`,
      });
    }

    context.set('token', token.payload as T);

    await next();
  });
}
