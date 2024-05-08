import {ErrorHandler, Handler, HonoRequest, NotFoundHandler} from 'hono'
import {HTTPException} from 'hono/http-exception'
import {Status, StatusPhrases} from './http-utils.js'
import type {StatusCode, UnOfficalStatusCode} from 'hono/utils/http-status'
import {createMiddleware} from 'hono/factory'
import {ZodType} from 'zod'
import {formatZodIssue, JsonTransformer} from './zod-utils.js'
import {TokenError} from 'fast-jwt'

/**
 * Creates a MethodNotAllowedHandler
 * @returns NotFoundHandler
 */
export function methodNotAllowedHandler(): Handler {
  return (context) => context.text('Method not allowed', 405)
}

/**
 * Creates a NotFoundHandler that responses with json
 * @returns NotFoundHandler
 */
export function notFoundHandler(): NotFoundHandler {
  return (context) => {
    context.status(Status.NOT_FOUND)
    return context.json({
      status: Status.NOT_FOUND,
      error: StatusPhrases[Status.NOT_FOUND],
    })
  }
}

/**
 * Creates an ErrorHandler that response with json
 * @param logger - logger
 * @returns ErrorHandler
 */
export function errorHandler(logger: {
  warn: (log: string) => void,
  error: (log: string) => void,
} = console): ErrorHandler {
  return (err, context) => {
    const requestId = context.get('id')

    if (err instanceof HTTPException && err.status < Status.INTERNAL_SERVER_ERROR) {
      context.status(err.status)
      return context.json({
        requestId, status: err.status,
        error: StatusPhrases[err.status as Exclude<StatusCode, UnOfficalStatusCode>],
        message: err.message,
      })
    } else {
      logger.error(requestId + ' -' +
          ' Internal Server Error: ' + err.message + '\n' +
          err.stack
      )

      context.status(Status.INTERNAL_SERVER_ERROR)
      return context.json({
        requestId, status: Status.INTERNAL_SERVER_ERROR,
        error: StatusPhrases[Status.INTERNAL_SERVER_ERROR],
      })
    }
  }
}

/**
 * Creates a middleware that generates and sets a request id
 * @param header - header name
 * @returns middleware
 */
export function requestId(header: string = 'x-request-id') {
  return createMiddleware<{ Variables: { id: string } }>(async (context, next) => {
    const id = context.req.header()[header] || crypto.randomUUID()
    context.set('id', id)
    await next()
  })
}

/**
 * Creates a middleware to log http requests and responses
 * @param logger - logger
 * @returns middleware
 */
export function debugLogger(logger: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  debug: (...log: any[]) => void,
} = console) {
  return createMiddleware(async (context, next) => {
    const requestId = context.get('id')

    const prefix = requestId ? `${requestId} - ` : ''

    logger.debug(prefix + 'Http Request ',
        JSON.stringify({
          path: context.req.path,
          method: context.req.method,
          query: context.req.query,
        }))

    await next()

    logger.debug(prefix + 'Http Response ',
        JSON.stringify({
          status: context.res.status,
        }))
  })
}

/**
 * Creates a middleware that parses the request body as json
 * @param req - request
 * @param schema - zod schema
 * @returns middleware
 */
export async function parseJsonBody<T extends ZodType>(req: HonoRequest, schema: T) {
  const body = await req.text()
  const bodyParseResult = await JsonTransformer.pipe(schema).safeParseAsync(body)

  if (!bodyParseResult.success) {
    throw new HTTPException(Status.BAD_REQUEST, {
      message: 'Invalid request body.\n' +
          bodyParseResult.error.issues.map(formatZodIssue)
              .map((it) => '- ' + it).join('\n'),
    })
  }
  return bodyParseResult.data
}

/**
 * Creates a middleware that verifies a token
 * @param verifier - fast-jwt verifier function
 * @returns middleware
 */
export function tokenVerifier<T extends object>(
    verifier: (token: string) => Promise<T>,
) {
  return createMiddleware<{ Variables: { token: T } }>(async (context, next) => {
    // In addition to Authorization header the X-Authorization header can be used for situations,
    // where the Authorization header cannot be used
    // (e.g. when using an AWS IAM authorizer (SignatureV4) in front of this endpoint)
    const authorizationHeaderValue = context.req.header()['x-authorization'] || context.req.header()['authorization']
    if (!authorizationHeaderValue) {
      throw new HTTPException(Status.UNAUTHORIZED, {
        message: 'Missing authorization header',
      })
    }

    const [authorizationScheme, tokenValue] = authorizationHeaderValue.split(' ')
    if (authorizationScheme !== 'Bearer') {
      throw new HTTPException(Status.UNAUTHORIZED, {
        message: `Unexpected authorization scheme ${authorizationScheme}`,
      })
    }

    const tokenPayload = await verifier(tokenValue)
        .catch((error) => {
          if (error instanceof TokenError) {
            throw new HTTPException(Status.UNAUTHORIZED, {
              message: error.message,
            })
          }
          throw error
        })

    context.set('token', tokenPayload)

    await next()
  })
}
