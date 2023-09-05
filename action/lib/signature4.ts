import {HttpClientRequest} from './types'
import {SignatureV4} from '@smithy/signature-v4'
import {OutgoingHttpHeaders} from 'http'

/**
 * Sign request to authenticate with AWS_IAM authentication
 * @param request - request to sign
 * @param signer - aws signer
 * @returns signed request
 */
export async function signHttpRequest(request: HttpClientRequest, signer: SignatureV4): Promise<HttpClientRequest> {
  const canonicalRequestUrl = new URL(request.requestUrl)
  const canonicalRequest = {
    protocol: canonicalRequestUrl.protocol,
    hostname: canonicalRequestUrl.hostname,
    port: canonicalRequestUrl.port ? parseInt(canonicalRequestUrl.port) : undefined,
    path: canonicalRequestUrl.pathname,
    query: Object.fromEntries(canonicalRequestUrl.searchParams.entries()),
    method: request.verb,
    body: request.data,
    headers: {
      ...canonicalHeadersOf(request.additionalHeaders || {}),
      // authorization header is used for signing, so we need to move it to a custom authorization header
      ...(request.additionalHeaders?.authorization && {
        'x-authorization': request.additionalHeaders?.authorization,
      }),
      host: canonicalRequestUrl.hostname, // set mandatory host header for signing
    },
  }
  const canonicalSignedRequest = await signer.sign(canonicalRequest)

  return {
    ...request,
    data: canonicalSignedRequest.body,
    additionalHeaders: canonicalSignedRequest.headers,
  }
}

/**
 * Convert http headers to canonical headers
 * @param headers - http headers
 * @returns canonical headers
 */
function canonicalHeadersOf(headers: OutgoingHttpHeaders): Record<string, string> {
  return Object.entries(headers).reduce((result, [key, value]) => {
    if (typeof value === 'string') {
      result[key] = value
    } else if (typeof value === 'number') {
      result[key] = String(value)
    } else if (Array.isArray(value)) {
      result[key] = value.join(', ')
    }
    return result
  }, <Record<string, string>>{})
}
