import { createRequire } from 'module';
import { NodeHttpHandler } from './chunk-E5WDDCGV.mjs';
import { setCredentialFeature } from './chunk-CNVAVDG2.mjs';
import './chunk-TTV4QKES.mjs';
import './chunk-CKKARQCR.mjs';
import { sdkStreamMixin, parseRfc3339DateTime } from './chunk-2D7RHDR7.mjs';
import { CredentialsProviderError } from './chunk-HAYTZHRA.mjs';
import { HttpRequest } from './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';
import fs from 'fs/promises';

createRequire(import.meta.url);

// node_modules/@aws-sdk/credential-provider-http/dist-es/index.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/fromHttp.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/checkUrl.js
init_esm_shims();
var ECS_CONTAINER_HOST = "169.254.170.2";
var EKS_CONTAINER_HOST_IPv4 = "169.254.170.23";
var EKS_CONTAINER_HOST_IPv6 = "[fd00:ec2::23]";
var checkUrl = (url, logger) => {
  if (url.protocol === "https:") {
    return;
  }
  if (url.hostname === ECS_CONTAINER_HOST || url.hostname === EKS_CONTAINER_HOST_IPv4 || url.hostname === EKS_CONTAINER_HOST_IPv6) {
    return;
  }
  if (url.hostname.includes("[")) {
    if (url.hostname === "[::1]" || url.hostname === "[0000:0000:0000:0000:0000:0000:0000:0001]") {
      return;
    }
  } else {
    if (url.hostname === "localhost") {
      return;
    }
    const ipComponents = url.hostname.split(".");
    const inRange = (component) => {
      const num = parseInt(component, 10);
      return 0 <= num && num <= 255;
    };
    if (ipComponents[0] === "127" && inRange(ipComponents[1]) && inRange(ipComponents[2]) && inRange(ipComponents[3]) && ipComponents.length === 4) {
      return;
    }
  }
  throw new CredentialsProviderError(`URL not accepted. It must either be HTTPS or match one of the following:
  - loopback CIDR 127.0.0.0/8 or [::1/128]
  - ECS container host 169.254.170.2
  - EKS container host 169.254.170.23 or [fd00:ec2::23]`, { logger });
};

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/requestHelpers.js
init_esm_shims();
function createGetRequest(url) {
  return new HttpRequest({
    protocol: url.protocol,
    hostname: url.hostname,
    port: Number(url.port),
    path: url.pathname,
    query: Array.from(url.searchParams.entries()).reduce((acc, [k, v]) => {
      acc[k] = v;
      return acc;
    }, {}),
    fragment: url.hash
  });
}
async function getCredentials(response, logger) {
  const stream = sdkStreamMixin(response.body);
  const str = await stream.transformToString();
  if (response.statusCode === 200) {
    const parsed = JSON.parse(str);
    if (typeof parsed.AccessKeyId !== "string" || typeof parsed.SecretAccessKey !== "string" || typeof parsed.Token !== "string" || typeof parsed.Expiration !== "string") {
      throw new CredentialsProviderError("HTTP credential provider response not of the required format, an object matching: { AccessKeyId: string, SecretAccessKey: string, Token: string, Expiration: string(rfc3339) }", { logger });
    }
    return {
      accessKeyId: parsed.AccessKeyId,
      secretAccessKey: parsed.SecretAccessKey,
      sessionToken: parsed.Token,
      expiration: parseRfc3339DateTime(parsed.Expiration)
    };
  }
  if (response.statusCode >= 400 && response.statusCode < 500) {
    let parsedBody = {};
    try {
      parsedBody = JSON.parse(str);
    } catch (e) {
    }
    throw Object.assign(new CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger }), {
      Code: parsedBody.Code,
      Message: parsedBody.Message
    });
  }
  throw new CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger });
}

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/retry-wrapper.js
init_esm_shims();
var retryWrapper = (toRetry, maxRetries, delayMs) => {
  return async () => {
    for (let i = 0; i < maxRetries; ++i) {
      try {
        return await toRetry();
      } catch (e) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
    return await toRetry();
  };
};

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/fromHttp.js
var AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
var DEFAULT_LINK_LOCAL_HOST = "http://169.254.170.2";
var AWS_CONTAINER_CREDENTIALS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
var AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";
var AWS_CONTAINER_AUTHORIZATION_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
var fromHttp = (options = {}) => {
  options.logger?.debug("@aws-sdk/credential-provider-http - fromHttp");
  let host;
  const relative = options.awsContainerCredentialsRelativeUri ?? process.env[AWS_CONTAINER_CREDENTIALS_RELATIVE_URI];
  const full = options.awsContainerCredentialsFullUri ?? process.env[AWS_CONTAINER_CREDENTIALS_FULL_URI];
  const token = options.awsContainerAuthorizationToken ?? process.env[AWS_CONTAINER_AUTHORIZATION_TOKEN];
  const tokenFile = options.awsContainerAuthorizationTokenFile ?? process.env[AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE];
  const warn = options.logger?.constructor?.name === "NoOpLogger" || !options.logger?.warn ? console.warn : options.logger.warn.bind(options.logger);
  if (relative && full) {
    warn("@aws-sdk/credential-provider-http: you have set both awsContainerCredentialsRelativeUri and awsContainerCredentialsFullUri.");
    warn("awsContainerCredentialsRelativeUri will take precedence.");
  }
  if (token && tokenFile) {
    warn("@aws-sdk/credential-provider-http: you have set both awsContainerAuthorizationToken and awsContainerAuthorizationTokenFile.");
    warn("awsContainerAuthorizationTokenFile will take precedence.");
  }
  if (relative) {
    host = `${DEFAULT_LINK_LOCAL_HOST}${relative}`;
  } else if (full) {
    host = full;
  } else {
    throw new CredentialsProviderError(`No HTTP credential provider host provided.
Set AWS_CONTAINER_CREDENTIALS_FULL_URI or AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.`, { logger: options.logger });
  }
  const url = new URL(host);
  checkUrl(url, options.logger);
  const requestHandler = NodeHttpHandler.create({ connectionTimeout: options.timeout ?? 1e3 });
  const requestTimeout = options.timeout ?? 1e3;
  const provider = retryWrapper(async () => {
    const request = createGetRequest(url);
    if (tokenFile) {
      request.headers.Authorization = validateToken((await fs.readFile(tokenFile)).toString());
    } else if (token) {
      request.headers.Authorization = validateToken(token);
    }
    try {
      const result = await requestHandler.handle(request, { requestTimeout });
      return getCredentials(result.response).then((creds) => setCredentialFeature(creds, "CREDENTIALS_HTTP", "z"));
    } catch (e) {
      throw new CredentialsProviderError(String(e), { logger: options.logger });
    }
  }, options.maxRetries ?? 3, options.timeout ?? 1e3);
  return async () => {
    try {
      return await provider();
    } finally {
      requestHandler.destroy?.();
    }
  };
};
var validateToken = (token) => {
  if (token.includes("\r\n")) {
    throw new CredentialsProviderError("Authorization token contains invalid \\r\\n sequence.");
  }
  return token;
};

export { fromHttp };
