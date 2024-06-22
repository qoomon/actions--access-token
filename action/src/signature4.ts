import {SignatureV4} from '@smithy/signature-v4';
import {OutgoingHttpHeaders} from 'http';

/**
 * Sign request to authenticate with AWS_IAM authentication
 * @param request - request to sign
 * @param signer - aws signer
 * @return signed request
 */
export async function signHttpRequest(request: HttpRequest, signer: SignatureV4): Promise<HttpRequest> {
  const canonicalRequestUrl = new URL(request.requestUrl);
  const canonicalRequest = {
    protocol: canonicalRequestUrl.protocol,
    hostname: canonicalRequestUrl.hostname,
    port: canonicalRequestUrl.port ? parseInt(canonicalRequestUrl.port) : undefined,
    path: canonicalRequestUrl.pathname,
    query: Object.fromEntries(canonicalRequestUrl.searchParams.entries()),
    method: request.method,
    body: request.data,
    headers: {
      ...canonicalHeadersOf(request.additionalHeaders || {}),
      // authorization header is used for signing, so we need to move it to a custom authorization header
      ...(request.additionalHeaders?.authorization && {
        'x-authorization': request.additionalHeaders?.authorization,
      }),
      host: canonicalRequestUrl.hostname, // set mandatory host header for signing
    },
  };
  const canonicalSignedRequest = await signer.sign(canonicalRequest);

  return {
    ...request,
    data: canonicalSignedRequest.body,
    additionalHeaders: canonicalSignedRequest.headers,
  };
}

/**
 * Convert http headers to canonical headers
 * @param headers http headers
 * @return canonical headers
 */
function canonicalHeadersOf(headers: OutgoingHttpHeaders): Record<string, string> {
  return Object.entries(headers).reduce((result, [key, value]) => {
    if (typeof value === 'string') {
      result[key] = value;
    } else if (typeof value === 'number') {
      result[key] = String(value);
    } else if (Array.isArray(value)) {
      result[key] = value.join(', ');
    }
    return result;
  }, {} as Record<string, string>);
}

export interface HttpRequest {
  method: string,
  requestUrl: string,
  data: string | NodeJS.ReadableStream | null,
  additionalHeaders?: OutgoingHttpHeaders
}

