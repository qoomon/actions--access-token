import { createRequire } from 'module';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';

createRequire(import.meta.url);

// node_modules/@smithy/types/dist-es/extensions/checksum.js
init_esm_shims();
var AlgorithmId;
(function(AlgorithmId2) {
  AlgorithmId2["MD5"] = "md5";
  AlgorithmId2["CRC32"] = "crc32";
  AlgorithmId2["CRC32C"] = "crc32c";
  AlgorithmId2["SHA1"] = "sha1";
  AlgorithmId2["SHA256"] = "sha256";
})(AlgorithmId || (AlgorithmId = {}));

// node_modules/@smithy/types/dist-es/extensions/index.js
init_esm_shims();

// node_modules/@smithy/types/dist-es/middleware.js
init_esm_shims();
var SMITHY_CONTEXT_KEY = "__smithy_context";

// node_modules/@smithy/types/dist-es/index.js
init_esm_shims();

// node_modules/@smithy/types/dist-es/endpoint.js
init_esm_shims();
var EndpointURLScheme;
(function(EndpointURLScheme2) {
  EndpointURLScheme2["HTTP"] = "http";
  EndpointURLScheme2["HTTPS"] = "https";
})(EndpointURLScheme || (EndpointURLScheme = {}));

// node_modules/@smithy/types/dist-es/profile.js
init_esm_shims();
var IniSectionType;
(function(IniSectionType2) {
  IniSectionType2["PROFILE"] = "profile";
  IniSectionType2["SSO_SESSION"] = "sso-session";
  IniSectionType2["SERVICES"] = "services";
})(IniSectionType || (IniSectionType = {}));

// node_modules/@smithy/core/dist-es/submodules/transport/getSmithyContext.js
init_esm_shims();
var getSmithyContext = (context) => context[SMITHY_CONTEXT_KEY] || (context[SMITHY_CONTEXT_KEY] = {});

// node_modules/@smithy/core/dist-es/submodules/transport/hasOwn.js
init_esm_shims();
function hasOwn(o, k) {
  return Object.prototype.hasOwnProperty.call(o, k);
}

// node_modules/@smithy/core/dist-es/submodules/transport/httpRequest.js
init_esm_shims();
var HttpRequest = class _HttpRequest {
  method;
  protocol;
  hostname;
  port;
  path;
  query;
  headers;
  username;
  password;
  fragment;
  body;
  constructor(options) {
    this.method = options.method || "GET";
    this.hostname = options.hostname || "localhost";
    this.port = options.port;
    this.query = options.query || {};
    this.headers = options.headers || {};
    this.body = options.body;
    this.protocol = options.protocol ? options.protocol.slice(-1) !== ":" ? `${options.protocol}:` : options.protocol : "https:";
    this.path = options.path ? options.path.charAt(0) !== "/" ? `/${options.path}` : options.path : "/";
    this.username = options.username;
    this.password = options.password;
    this.fragment = options.fragment;
  }
  static clone(request) {
    const cloned = new _HttpRequest({
      ...request,
      headers: { ...request.headers }
    });
    if (cloned.query) {
      cloned.query = cloneQuery(cloned.query);
    }
    return cloned;
  }
  static isInstance(request) {
    if (!request) {
      return false;
    }
    const req = request;
    return "method" in req && "protocol" in req && "hostname" in req && "path" in req && typeof req["query"] === "object" && typeof req["headers"] === "object";
  }
  clone() {
    return _HttpRequest.clone(this);
  }
};
function cloneQuery(query) {
  return Object.keys(query).reduce((carry, paramName) => {
    const param = query[paramName];
    return {
      ...carry,
      [paramName]: Array.isArray(param) ? [...param] : param
    };
  }, {});
}

// node_modules/@smithy/core/dist-es/submodules/transport/isValidHostLabel.js
init_esm_shims();
var VALID_HOST_LABEL_REGEX = new RegExp(`^(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63}$`);
var isValidHostLabel = (value, allowSubDomains = false) => {
  if (!allowSubDomains) {
    return VALID_HOST_LABEL_REGEX.test(value);
  }
  const labels = value.split(".");
  for (const label of labels) {
    if (!isValidHostLabel(label)) {
      return false;
    }
  }
  return true;
};

// node_modules/@smithy/core/dist-es/submodules/transport/normalizeProvider.js
init_esm_shims();
var normalizeProvider = (input) => {
  if (typeof input === "function")
    return input;
  const promisified = Promise.resolve(input);
  return () => promisified;
};

// node_modules/@smithy/core/dist-es/submodules/transport/parseUrl.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/transport/parseQueryString.js
init_esm_shims();
function parseQueryString(querystring) {
  const query = {};
  querystring = querystring.replace(/^\?/, "");
  if (querystring) {
    for (const pair of querystring.split("&")) {
      let [key, value = null] = pair.split("=");
      key = decodeURIComponent(key);
      if (value) {
        value = decodeURIComponent(value);
      }
      if (!(key in query)) {
        query[key] = value;
      } else if (Array.isArray(query[key])) {
        query[key].push(value);
      } else {
        query[key] = [query[key], value];
      }
    }
  }
  return query;
}

// node_modules/@smithy/core/dist-es/submodules/transport/parseUrl.js
var parseUrl = (url) => {
  if (typeof url === "string") {
    return parseUrl(new URL(url));
  }
  const { hostname, pathname, port, protocol, search } = url;
  let query;
  if (search) {
    query = parseQueryString(search);
  }
  return {
    hostname,
    port: port ? parseInt(port) : void 0,
    protocol,
    path: pathname,
    query
  };
};

// node_modules/@smithy/core/dist-es/submodules/transport/toEndpointV1.js
init_esm_shims();
var toEndpointV1 = (endpoint) => {
  if (typeof endpoint === "object") {
    if ("url" in endpoint) {
      const v1Endpoint = parseUrl(endpoint.url);
      if (endpoint.headers) {
        v1Endpoint.headers = {};
        for (const name in endpoint.headers) {
          if (!hasOwn(endpoint.headers, name))
            continue;
          v1Endpoint.headers[name.toLowerCase()] = endpoint.headers[name].join(", ");
        }
      }
      return v1Endpoint;
    }
    return endpoint;
  }
  return parseUrl(endpoint);
};

// node_modules/@smithy/core/dist-es/submodules/transport/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/transport/httpResponse.js
init_esm_shims();
var HttpResponse = class {
  statusCode;
  reason;
  headers;
  body;
  constructor(options) {
    this.statusCode = options.statusCode;
    this.reason = options.reason;
    this.headers = options.headers || {};
    this.body = options.body;
  }
  static isInstance(response) {
    if (!response)
      return false;
    const resp = response;
    return typeof resp.statusCode === "number" && typeof resp.headers === "object";
  }
};

// node_modules/@smithy/core/dist-es/submodules/transport/isValidHostname.js
init_esm_shims();
function isValidHostname(hostname) {
  const hostPattern = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/;
  return hostPattern.test(hostname);
}

export { AlgorithmId, EndpointURLScheme, HttpRequest, HttpResponse, IniSectionType, SMITHY_CONTEXT_KEY, getSmithyContext, hasOwn, isValidHostLabel, isValidHostname, normalizeProvider, parseUrl, toEndpointV1 };
