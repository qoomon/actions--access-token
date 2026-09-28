import { createRequire } from 'module';
import { NoOpLogger } from './chunk-TTV4QKES.mjs';
import { v4, parseRfc7231DateTime } from './chunk-2D7RHDR7.mjs';
import { loadConfig, NODE_REGION_CONFIG_OPTIONS, NODE_REGION_CONFIG_FILE_OPTIONS, booleanSelector, SelectorType, CONFIG_PREFIX_SEPARATOR } from './chunk-HAYTZHRA.mjs';
import { EndpointURLScheme, hasOwn, normalizeProvider, HttpRequest, isValidHostLabel, parseUrl, getSmithyContext, toEndpointV1, HttpResponse } from './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';
import { Readable } from 'stream';
import { platform, release } from 'os';
import { env, versions } from 'process';

createRequire(import.meta.url);

// node_modules/@aws-sdk/core/dist-es/submodules/client/index.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/emitWarningIfUnsupportedVersion.js
init_esm_shims();
var state = {
  warningEmitted: false
};
var emitWarningIfUnsupportedVersion = (version) => {
  if (version && !state.warningEmitted) {
    if (process.env.AWS_SDK_JS_NODE_VERSION_SUPPORT_WARNING_DISABLED === "true") {
      state.warningEmitted = true;
      return;
    }
    const userMajorVersion = parseInt(version.substring(1, version.indexOf(".")));
    const vv = 22;
    if (userMajorVersion < vv) {
      state.warningEmitted = true;
      process.emitWarning(`NodeVersionSupportWarning: The AWS SDK for JavaScript (v3)
versions published after the first week of January 2027
will require node >=${vv}. You are running node ${version}.

To continue receiving updates to AWS services, bug fixes,
and security updates please upgrade to node >=${vv}.

More information can be found at: https://a.co/c895JFp`);
    }
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/longPollMiddleware.js
init_esm_shims();
var longPollMiddleware = () => (next, context) => async (args) => {
  context.__retryLongPoll = true;
  return next(args);
};
var longPollMiddlewareOptions = {
  name: "longPollMiddleware",
  tags: ["RETRY"],
  step: "initialize",
  override: true
};
var getLongPollPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(longPollMiddleware(), longPollMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js
init_esm_shims();
function setCredentialFeature(credentials, feature, value) {
  if (!credentials.$source) {
    credentials.$source = {};
  }
  credentials.$source[feature] = value;
  return credentials;
}

// node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/retry/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/retry/middleware-retry/isStreamingPayload/isStreamingPayload.js
init_esm_shims();
var isStreamingPayload = (request) => request?.body instanceof Readable || typeof ReadableStream !== "undefined" && request?.body instanceof ReadableStream;

// node_modules/@smithy/core/dist-es/submodules/retry/middleware-retry/retryMiddleware.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/adaptors/getEndpointFromConfig.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/adaptors/getEndpointUrlConfig.js
init_esm_shims();
var ENV_ENDPOINT_URL = "AWS_ENDPOINT_URL";
var CONFIG_ENDPOINT_URL = "endpoint_url";
var getEndpointUrlConfig = (serviceId) => ({
  environmentVariableSelector: (env2) => {
    const serviceSuffixParts = serviceId.split(" ").map((w) => w.toUpperCase());
    const serviceEndpointUrl = env2[[ENV_ENDPOINT_URL, ...serviceSuffixParts].join("_")];
    if (serviceEndpointUrl)
      return serviceEndpointUrl;
    const endpointUrl = env2[ENV_ENDPOINT_URL];
    if (endpointUrl)
      return endpointUrl;
    return void 0;
  },
  configFileSelector: (profile, config) => {
    if (profile.services) {
      const servicesSectionKey = ["services", profile.services].join(CONFIG_PREFIX_SEPARATOR);
      if (!config || !config[servicesSectionKey]) {
        throw new Error(`The services section "${profile.services}" specified in the profile is not present in the shared configuration file.`);
      }
      const servicesSection = config[servicesSectionKey];
      const servicePrefixParts = serviceId.split(" ").map((w) => w.toLowerCase());
      const endpointUrl2 = servicesSection[[servicePrefixParts.join("_"), CONFIG_ENDPOINT_URL].join(CONFIG_PREFIX_SEPARATOR)];
      if (endpointUrl2)
        return endpointUrl2;
    }
    const endpointUrl = profile[CONFIG_ENDPOINT_URL];
    if (endpointUrl)
      return endpointUrl;
    return void 0;
  },
  default: void 0
});

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/adaptors/getIgnoreConfiguredEndpointUrls.js
init_esm_shims();
var ENV_IGNORE_CONFIGURED_ENDPOINT_URLS = "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS";
var CONFIG_IGNORE_CONFIGURED_ENDPOINT_URLS = "ignore_configured_endpoint_urls";
var ignoreConfiguredEndpointUrlsConfigSelectors = {
  environmentVariableSelector: (env2) => booleanSelector(env2, ENV_IGNORE_CONFIGURED_ENDPOINT_URLS, SelectorType.ENV),
  configFileSelector: (profile) => booleanSelector(profile, CONFIG_IGNORE_CONFIGURED_ENDPOINT_URLS, SelectorType.CONFIG),
  default: false
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/adaptors/getEndpointFromConfig.js
var getEndpointFromConfig = async (serviceId) => {
  const ignore = await loadConfig(ignoreConfiguredEndpointUrlsConfigSelectors)();
  if (ignore) {
    return void 0;
  }
  return loadConfig(getEndpointUrlConfig(serviceId ?? ""))();
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/adaptors/getEndpointFromInstructions.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/service-customizations/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/service-customizations/s3.js
init_esm_shims();
var resolveParamsForS3 = async (endpointParams) => {
  const bucket = endpointParams?.Bucket || "";
  if (typeof endpointParams.Bucket === "string") {
    endpointParams.Bucket = bucket.replace(/#/g, encodeURIComponent("#")).replace(/\?/g, encodeURIComponent("?"));
  }
  if (isArnBucketName(bucket)) {
    if (endpointParams.ForcePathStyle === true) {
      throw new Error("Path-style addressing cannot be used with ARN buckets");
    }
  } else if (!isDnsCompatibleBucketName(bucket) || bucket.indexOf(".") !== -1 && !String(endpointParams.Endpoint).startsWith("http:") || bucket.toLowerCase() !== bucket || bucket.length < 3) {
    endpointParams.ForcePathStyle = true;
  }
  if (endpointParams.DisableMultiRegionAccessPoints) {
    endpointParams.disableMultiRegionAccessPoints = true;
    endpointParams.DisableMRAP = true;
  }
  return endpointParams;
};
var DOMAIN_PATTERN = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
var IP_ADDRESS_PATTERN = /(\d+\.){3}\d+/;
var DOTS_PATTERN = /\.\./;
var isDnsCompatibleBucketName = (bucketName) => DOMAIN_PATTERN.test(bucketName) && !IP_ADDRESS_PATTERN.test(bucketName) && !DOTS_PATTERN.test(bucketName);
var isArnBucketName = (bucketName) => {
  const [arn, partition2, service, , , bucket] = bucketName.split(":");
  const isArn = arn === "arn" && bucketName.split(":").length >= 6;
  const isValidArn = Boolean(isArn && partition2 && service && bucket);
  if (isArn && !isValidArn) {
    throw new Error(`Invalid ARN: ${bucketName} was an invalid ARN.`);
  }
  return isValidArn;
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/adaptors/createConfigValueProvider.js
init_esm_shims();
var createConfigValueProvider = (configKey, canonicalEndpointParamKey, config, isClientContextParam = false) => {
  const configProvider = async () => {
    let configValue;
    if (isClientContextParam) {
      const clientContextParams = config.clientContextParams;
      const nestedValue = clientContextParams?.[configKey];
      configValue = nestedValue ?? config[configKey] ?? config[canonicalEndpointParamKey];
    } else {
      configValue = config[configKey] ?? config[canonicalEndpointParamKey];
    }
    if (typeof configValue === "function") {
      return configValue();
    }
    return configValue;
  };
  if (configKey === "credentialScope" || canonicalEndpointParamKey === "CredentialScope") {
    return async () => {
      const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
      const configValue = credentials?.credentialScope ?? credentials?.CredentialScope;
      return configValue;
    };
  }
  if (configKey === "accountId" || canonicalEndpointParamKey === "AccountId") {
    return async () => {
      const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
      const configValue = credentials?.accountId ?? credentials?.AccountId;
      return configValue;
    };
  }
  if (configKey === "endpoint" || canonicalEndpointParamKey === "endpoint") {
    return async () => {
      if (config.isCustomEndpoint === false) {
        return void 0;
      }
      const endpoint = await configProvider();
      if (endpoint && typeof endpoint === "object") {
        if ("url" in endpoint) {
          return endpoint.url.href;
        }
        if ("hostname" in endpoint) {
          const { protocol, hostname, port, path } = endpoint;
          return `${protocol}//${hostname}${port ? ":" + port : ""}${path}`;
        }
      }
      return endpoint;
    };
  }
  return configProvider;
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/adaptors/toEndpointV1.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/adaptors/getEndpointFromInstructions.js
function bindGetEndpointFromInstructions(getEndpointFromConfig2) {
  return async (commandInput, instructionsSupplier, clientConfig, context) => {
    if (!clientConfig.isCustomEndpoint && !clientConfig.ignoreConfiguredEndpointUrls) {
      let endpointFromConfig;
      if (clientConfig.serviceConfiguredEndpoint) {
        endpointFromConfig = await clientConfig.serviceConfiguredEndpoint();
      } else {
        endpointFromConfig = await getEndpointFromConfig2(clientConfig.serviceId);
      }
      if (endpointFromConfig) {
        clientConfig.endpoint = () => Promise.resolve(toEndpointV1(endpointFromConfig));
        clientConfig.isCustomEndpoint = true;
        context?.logger?.debug?.(`@smithy/core/endpoints - resolved endpoint from config: ${endpointFromConfig}`);
      }
    }
    const endpointParams = await resolveParams(commandInput, instructionsSupplier, clientConfig);
    if (typeof clientConfig.endpointProvider !== "function") {
      throw new Error("config.endpointProvider is not set.");
    }
    const endpoint = clientConfig.endpointProvider(endpointParams, context);
    if (clientConfig.isCustomEndpoint && clientConfig.endpoint) {
      const customEndpoint = await clientConfig.endpoint();
      if (customEndpoint?.headers) {
        endpoint.headers ??= {};
        for (const [name, value] of Object.entries(customEndpoint.headers)) {
          endpoint.headers[name] = Array.isArray(value) ? value : [value];
        }
      }
    }
    return endpoint;
  };
}
var resolveParams = async (commandInput, instructionsSupplier, clientConfig) => {
  const endpointParams = {};
  const instructions = instructionsSupplier?.getEndpointParameterInstructions?.() || {};
  for (const [name, instruction] of Object.entries(instructions)) {
    switch (instruction.type) {
      case "staticContextParams":
        endpointParams[name] = instruction.value;
        break;
      case "contextParams":
        endpointParams[name] = commandInput[instruction.name];
        break;
      case "clientContextParams":
      case "builtInParams":
        endpointParams[name] = await createConfigValueProvider(instruction.name, name, clientConfig, instruction.type !== "builtInParams")();
        break;
      case "operationContextParams":
        endpointParams[name] = instruction.get(commandInput);
        break;
      default:
        throw new Error("Unrecognized endpoint parameter instruction: " + JSON.stringify(instruction));
    }
  }
  if (Object.keys(instructions).length === 0) {
    Object.assign(endpointParams, clientConfig);
  }
  if (String(clientConfig.serviceId).toLowerCase() === "s3") {
    await resolveParamsForS3(endpointParams);
  }
  return endpointParams;
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/endpointMiddleware.js
init_esm_shims();
function setFeature(context, feature, value) {
  if (!context.__smithy_context) {
    context.__smithy_context = { features: {} };
  } else if (!context.__smithy_context.features) {
    context.__smithy_context.features = {};
  }
  context.__smithy_context.features[feature] = value;
}
function bindEndpointMiddleware(getEndpointFromConfig2) {
  const getEndpointFromInstructions2 = bindGetEndpointFromInstructions(getEndpointFromConfig2);
  return ({ config, instructions }) => {
    return (next, context) => async (args) => {
      if (config.isCustomEndpoint) {
        setFeature(context, "ENDPOINT_OVERRIDE", "N");
      }
      const endpoint = await getEndpointFromInstructions2(args.input, {
        getEndpointParameterInstructions() {
          return instructions;
        }
      }, { ...config }, context);
      context.endpointV2 = endpoint;
      context.authSchemes = endpoint.properties?.authSchemes;
      const authScheme = context.authSchemes?.[0];
      if (authScheme) {
        context["signing_region"] = authScheme.signingRegion;
        context["signing_service"] = authScheme.signingName;
        const smithyContext = getSmithyContext(context);
        const httpAuthOption = smithyContext?.selectedHttpAuthScheme?.httpAuthOption;
        if (httpAuthOption) {
          httpAuthOption.signingProperties = Object.assign(httpAuthOption.signingProperties || {}, {
            signing_region: authScheme.signingRegion,
            signingRegion: authScheme.signingRegion,
            signing_service: authScheme.signingName,
            signingName: authScheme.signingName,
            signingRegionSet: authScheme.signingRegionSet
          }, authScheme.properties);
        }
      }
      return next({
        ...args
      });
    };
  };
}

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/getEndpointPlugin.js
init_esm_shims();
var serializerMiddlewareOption = {
  name: "serializerMiddleware"};
var endpointMiddlewareOptions = {
  step: "serialize",
  tags: ["ENDPOINT_PARAMETERS", "ENDPOINT_V2", "ENDPOINT"],
  name: "endpointV2Middleware",
  override: true,
  relation: "before",
  toMiddleware: serializerMiddlewareOption.name
};
function bindGetEndpointPlugin(getEndpointFromConfig2) {
  const endpointMiddleware2 = bindEndpointMiddleware(getEndpointFromConfig2);
  return (config, instructions) => ({
    applyToStack: (clientStack) => {
      clientStack.addRelativeTo(endpointMiddleware2({
        config,
        instructions
      }), endpointMiddlewareOptions);
    }
  });
}

// node_modules/@smithy/core/dist-es/submodules/endpoints/middleware-endpoint/resolveEndpointConfig.js
init_esm_shims();
function bindResolveEndpointConfig(getEndpointFromConfig2) {
  return (input) => {
    const tls = input.tls ?? true;
    const { endpoint, useDualstackEndpoint, useFipsEndpoint } = input;
    const customEndpointProvider = endpoint != null ? async () => toEndpointV1(await normalizeProvider(endpoint)()) : void 0;
    const isCustomEndpoint = !!endpoint;
    const resolvedConfig = Object.assign(input, {
      endpoint: customEndpointProvider,
      tls,
      isCustomEndpoint,
      useDualstackEndpoint: normalizeProvider(useDualstackEndpoint ?? false),
      useFipsEndpoint: normalizeProvider(useFipsEndpoint ?? false),
      ignoreConfiguredEndpointUrls: !!input.ignoreConfiguredEndpointUrls
    });
    let configuredEndpointPromise = void 0;
    resolvedConfig.serviceConfiguredEndpoint = async () => {
      if (input.serviceId && !configuredEndpointPromise) {
        configuredEndpointPromise = getEndpointFromConfig2(input.serviceId);
      }
      return configuredEndpointPromise;
    };
    return resolvedConfig;
  };
}

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/bdd/BinaryDecisionDiagram.js
init_esm_shims();
var BinaryDecisionDiagram = class _BinaryDecisionDiagram {
  nodes;
  root;
  conditions;
  results;
  constructor(bdd, root, conditions, results) {
    this.nodes = bdd;
    this.root = root;
    this.conditions = conditions;
    this.results = results;
  }
  static from(bdd, root, conditions, results) {
    return new _BinaryDecisionDiagram(bdd, root, conditions, results);
  }
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/cache/EndpointCache.js
init_esm_shims();
var EndpointCache = class {
  capacity;
  data = /* @__PURE__ */ new Map();
  parameters = [];
  constructor({ size, params }) {
    this.capacity = size ?? 50;
    if (params) {
      this.parameters = params;
    }
  }
  get(endpointParams, resolver) {
    const key = this.hash(endpointParams);
    if (key === false) {
      return resolver();
    }
    if (!this.data.has(key)) {
      if (this.data.size > this.capacity + 10) {
        const keys = this.data.keys();
        let i = 0;
        while (true) {
          const { value, done } = keys.next();
          this.data.delete(value);
          if (done || ++i > 10) {
            break;
          }
        }
      }
      this.data.set(key, resolver());
    }
    return this.data.get(key);
  }
  size() {
    return this.data.size;
  }
  hash(endpointParams) {
    let buffer = "";
    const { parameters } = this;
    if (parameters.length === 0) {
      return false;
    }
    for (const param of parameters) {
      const val = String(endpointParams[param] ?? "");
      if (val.includes("|;")) {
        return false;
      }
      buffer += val + "|;";
    }
    return buffer;
  }
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/decideEndpoint.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/types/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/types/EndpointError.js
init_esm_shims();
var EndpointError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "EndpointError";
  }
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateCondition.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/debug/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/debug/debugId.js
init_esm_shims();
var debugId = "endpoints";

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/debug/toDebugString.js
init_esm_shims();
function toDebugString(input) {
  if (typeof input !== "object" || input == null) {
    return input;
  }
  if ("ref" in input) {
    return `$${toDebugString(input.ref)}`;
  }
  if ("fn" in input) {
    return `${input.fn}(${(input.argv || []).map(toDebugString).join(", ")})`;
  }
  return JSON.stringify(input, null, 2);
}

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/callFunction.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateExpression.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/customEndpointFunctions.js
init_esm_shims();
var customEndpointFunctions = {};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/endpointFunctions.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/booleanEquals.js
init_esm_shims();
var booleanEquals = (value1, value2) => value1 === value2;

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/coalesce.js
init_esm_shims();
function coalesce(...args) {
  for (const arg of args) {
    if (arg != null) {
      return arg;
    }
  }
  return void 0;
}

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/getAttr.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/getAttrPathList.js
init_esm_shims();
var getAttrPathList = (path) => {
  const parts = path.split(".");
  const pathList = [];
  for (const part of parts) {
    const squareBracketIndex = part.indexOf("[");
    if (squareBracketIndex !== -1) {
      if (part.indexOf("]") !== part.length - 1) {
        throw new EndpointError(`Path: '${path}' does not end with ']'`);
      }
      const arrayIndex = part.slice(squareBracketIndex + 1, -1);
      if (Number.isNaN(parseInt(arrayIndex))) {
        throw new EndpointError(`Invalid array index: '${arrayIndex}' in path: '${path}'`);
      }
      if (squareBracketIndex !== 0) {
        pathList.push(part.slice(0, squareBracketIndex));
      }
      pathList.push(arrayIndex);
    } else {
      pathList.push(part);
    }
  }
  return pathList;
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/getAttr.js
var getAttr = (value, path) => getAttrPathList(path).reduce((acc, index) => {
  if (typeof acc !== "object") {
    throw new EndpointError(`Index '${index}' in '${path}' not found in '${JSON.stringify(value)}'`);
  } else if (Array.isArray(acc)) {
    const i = parseInt(index);
    return acc[i < 0 ? acc.length + i : i];
  }
  return acc[index];
}, value);

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/isSet.js
init_esm_shims();
var isSet = (value) => value != null;

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/ite.js
init_esm_shims();
function ite(condition, trueValue, falseValue) {
  return condition ? trueValue : falseValue;
}

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/not.js
init_esm_shims();
var not = (value) => !value;

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/parseURL.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/isIpAddress.js
init_esm_shims();
var IP_V4_REGEX = new RegExp(`^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}$`);
var isIpAddress = (value) => IP_V4_REGEX.test(value) || value.startsWith("[") && value.endsWith("]");

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/parseURL.js
var DEFAULT_PORTS = {
  [EndpointURLScheme.HTTP]: 80,
  [EndpointURLScheme.HTTPS]: 443
};
var parseURL = (value) => {
  const whatwgURL = (() => {
    try {
      if (value instanceof URL) {
        return value;
      }
      if (typeof value === "object" && "hostname" in value) {
        const { hostname: hostname2, port, protocol: protocol2 = "", path = "", query = {} } = value;
        const url = new URL(`${protocol2}//${hostname2}${port ? `:${port}` : ""}${path}`);
        url.search = Object.entries(query).map(([k, v]) => `${k}=${v}`).join("&");
        return url;
      }
      return new URL(value);
    } catch (ignored) {
      return null;
    }
  })();
  if (!whatwgURL) {
    console.error(`Unable to parse ${JSON.stringify(value)} as a whatwg URL.`);
    return null;
  }
  const urlString = whatwgURL.href;
  const { host, hostname, pathname, protocol, search } = whatwgURL;
  if (search) {
    return null;
  }
  const scheme = protocol.slice(0, -1);
  if (!Object.values(EndpointURLScheme).includes(scheme)) {
    return null;
  }
  const isIp = isIpAddress(hostname);
  const inputContainsDefaultPort = urlString.includes(`${host}:${DEFAULT_PORTS[scheme]}`) || typeof value === "string" && value.includes(`${host}:${DEFAULT_PORTS[scheme]}`);
  const authority = `${host}${inputContainsDefaultPort ? `:${DEFAULT_PORTS[scheme]}` : ``}`;
  return {
    scheme,
    authority,
    path: pathname,
    normalizedPath: pathname.endsWith("/") ? pathname : `${pathname}/`,
    isIp
  };
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/split.js
init_esm_shims();
function split(value, delimiter, limit) {
  if (limit === 1) {
    return [value];
  }
  if (value === "") {
    return [""];
  }
  const parts = value.split(delimiter);
  if (limit === 0) {
    return parts;
  }
  return parts.slice(0, limit - 1).concat(parts.slice(1).join(delimiter));
}

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/stringEquals.js
init_esm_shims();
var stringEquals = (value1, value2) => value1 === value2;

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/substring.js
init_esm_shims();
var substring = (input, start, stop, reverse) => {
  if (input == null || start >= stop || input.length < stop || /[^\u0000-\u007f]/.test(input)) {
    return null;
  }
  if (!reverse) {
    return input.substring(start, stop);
  }
  return input.substring(input.length - stop, input.length - start);
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/lib/uriEncode.js
init_esm_shims();
var uriEncode = (value) => encodeURIComponent(value).replace(/[!*'()]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/endpointFunctions.js
var endpointFunctions = {
  booleanEquals,
  coalesce,
  getAttr,
  isSet,
  isValidHostLabel,
  ite,
  not,
  parseURL,
  split,
  stringEquals,
  substring,
  uriEncode
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateTemplate.js
init_esm_shims();
var evaluateTemplate = (template, options) => {
  const evaluatedTemplateArr = [];
  const { referenceRecord, endpointParams } = options;
  let currentIndex = 0;
  while (currentIndex < template.length) {
    const openingBraceIndex = template.indexOf("{", currentIndex);
    if (openingBraceIndex === -1) {
      evaluatedTemplateArr.push(template.slice(currentIndex));
      break;
    }
    evaluatedTemplateArr.push(template.slice(currentIndex, openingBraceIndex));
    const closingBraceIndex = template.indexOf("}", openingBraceIndex);
    if (closingBraceIndex === -1) {
      evaluatedTemplateArr.push(template.slice(openingBraceIndex));
      break;
    }
    if (template[openingBraceIndex + 1] === "{" && template[closingBraceIndex + 1] === "}") {
      evaluatedTemplateArr.push(template.slice(openingBraceIndex + 1, closingBraceIndex));
      currentIndex = closingBraceIndex + 2;
    }
    const parameterName = template.substring(openingBraceIndex + 1, closingBraceIndex);
    if (parameterName.includes("#")) {
      const [refName, attrName] = parameterName.split("#");
      evaluatedTemplateArr.push(getAttr(referenceRecord[refName] ?? endpointParams[refName], attrName));
    } else {
      evaluatedTemplateArr.push(referenceRecord[parameterName] ?? endpointParams[parameterName]);
    }
    currentIndex = closingBraceIndex + 1;
  }
  return evaluatedTemplateArr.join("");
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/getReferenceValue.js
init_esm_shims();
var getReferenceValue = ({ ref }, options) => {
  return options.referenceRecord[ref] ?? options.endpointParams[ref];
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateExpression.js
var evaluateExpression = (obj, keyName, options) => {
  if (typeof obj === "string") {
    return evaluateTemplate(obj, options);
  } else if (obj["fn"]) {
    return group.callFunction(obj, options);
  } else if (obj["ref"]) {
    return getReferenceValue(obj, options);
  }
  throw new EndpointError(`'${keyName}': ${String(obj)} is not a string, function or reference.`);
};
var callFunction = ({ fn, argv }, options) => {
  const evaluatedArgs = Array(argv.length);
  for (let i = 0; i < evaluatedArgs.length; ++i) {
    const arg = argv[i];
    if (typeof arg === "boolean" || typeof arg === "number") {
      evaluatedArgs[i] = arg;
    } else {
      evaluatedArgs[i] = group.evaluateExpression(arg, "arg", options);
    }
  }
  const namespaceSeparatorIndex = fn.indexOf(".");
  if (namespaceSeparatorIndex !== -1) {
    const namespaceFunctions = customEndpointFunctions[fn.slice(0, namespaceSeparatorIndex)];
    const customFunction = namespaceFunctions?.[fn.slice(namespaceSeparatorIndex + 1)];
    if (typeof customFunction === "function") {
      return customFunction(...evaluatedArgs);
    }
  }
  const callable = endpointFunctions[fn];
  if (typeof callable === "function") {
    return callable(...evaluatedArgs);
  }
  throw new Error(`function ${fn} not loaded in endpointFunctions.`);
};
var group = {
  evaluateExpression,
  callFunction
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateCondition.js
var evaluateCondition = (condition, options) => {
  const { assign } = condition;
  if (assign && assign in options.referenceRecord) {
    throw new EndpointError(`'${assign}' is already defined in Reference Record.`);
  }
  const value = callFunction(condition, options);
  options.logger?.debug?.(`${debugId} evaluateCondition: ${toDebugString(condition)} = ${toDebugString(value)}`);
  const result = value === "" ? true : !!value;
  if (assign != null) {
    return { result, toAssign: { name: assign, value } };
  }
  return { result };
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/getEndpointHeaders.js
init_esm_shims();
var getEndpointHeaders = (headers, options) => Object.entries(headers ?? {}).reduce((acc, [headerKey, headerVal]) => {
  acc[headerKey] = headerVal.map((headerValEntry) => {
    const processedExpr = evaluateExpression(headerValEntry, "Header value entry", options);
    if (typeof processedExpr !== "string") {
      throw new EndpointError(`Header '${headerKey}' value '${processedExpr}' is not a string`);
    }
    return processedExpr;
  });
  return acc;
}, {});

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/getEndpointProperties.js
init_esm_shims();
var getEndpointProperties = (properties, options) => Object.entries(properties).reduce((acc, [propertyKey, propertyVal]) => {
  acc[propertyKey] = group2.getEndpointProperty(propertyVal, options);
  return acc;
}, {});
var getEndpointProperty = (property, options) => {
  if (Array.isArray(property)) {
    return property.map((propertyEntry) => getEndpointProperty(propertyEntry, options));
  }
  switch (typeof property) {
    case "string":
      return evaluateTemplate(property, options);
    case "object":
      if (property === null) {
        throw new EndpointError(`Unexpected endpoint property: ${property}`);
      }
      return group2.getEndpointProperties(property, options);
    case "boolean":
      return property;
    default:
      throw new EndpointError(`Unexpected endpoint property type: ${typeof property}`);
  }
};
var group2 = {
  getEndpointProperty,
  getEndpointProperties
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/getEndpointUrl.js
init_esm_shims();
var getEndpointUrl = (endpointUrl, options) => {
  const expression = evaluateExpression(endpointUrl, "Endpoint URL", options);
  if (typeof expression === "string") {
    try {
      return new URL(expression);
    } catch (error) {
      console.error(`Failed to construct URL with ${expression}`, error);
      throw error;
    }
  }
  throw new EndpointError(`Endpoint URL must be a string, got ${typeof expression}`);
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/decideEndpoint.js
var RESULT = 1e8;
var decideEndpoint = (bdd, options) => {
  const { nodes, root, results, conditions } = bdd;
  let ref = root;
  const referenceRecord = {};
  const closure = {
    referenceRecord,
    endpointParams: options.endpointParams,
    logger: options.logger
  };
  while (ref !== 1 && ref !== -1 && ref < RESULT) {
    const node_i = 3 * (Math.abs(ref) - 1);
    const [condition_i, highRef, lowRef] = [nodes[node_i], nodes[node_i + 1], nodes[node_i + 2]];
    const [fn, argv, assign] = conditions[condition_i];
    const evaluation = evaluateCondition({ fn, assign, argv }, closure);
    if (evaluation.toAssign) {
      const { name, value } = evaluation.toAssign;
      referenceRecord[name] = value;
    }
    ref = ref >= 0 === evaluation.result ? highRef : lowRef;
  }
  if (ref >= RESULT) {
    const result = results[ref - RESULT];
    if (result[0] === -1) {
      const [, errorExpression] = result;
      throw new EndpointError(evaluateExpression(errorExpression, "Error", closure));
    }
    const [url, properties, headers] = result;
    return {
      url: getEndpointUrl(url, closure),
      properties: getEndpointProperties(properties, closure),
      headers: getEndpointHeaders(headers ?? {}, closure)
    };
  }
  throw new EndpointError(`No matching endpoint.`);
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/resolveEndpoint.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateRules.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateConditions.js
init_esm_shims();
var evaluateConditions = (conditions = [], options) => {
  const conditionsReferenceRecord = {};
  const conditionOptions = {
    ...options,
    referenceRecord: { ...options.referenceRecord }
  };
  let didAssign = false;
  for (const condition of conditions) {
    const { result, toAssign } = evaluateCondition(condition, conditionOptions);
    if (!result) {
      return { result };
    }
    if (toAssign) {
      didAssign = true;
      conditionsReferenceRecord[toAssign.name] = toAssign.value;
      conditionOptions.referenceRecord[toAssign.name] = toAssign.value;
      options.logger?.debug?.(`${debugId} assign: ${toAssign.name} := ${toDebugString(toAssign.value)}`);
    }
  }
  if (didAssign) {
    return { result: true, referenceRecord: conditionsReferenceRecord };
  }
  return { result: true };
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateEndpointRule.js
init_esm_shims();
var evaluateEndpointRule = (endpointRule, options) => {
  const { conditions, endpoint } = endpointRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  const endpointRuleOptions = referenceRecord ? {
    ...options,
    referenceRecord: { ...options.referenceRecord, ...referenceRecord }
  } : options;
  const { url, properties, headers } = endpoint;
  options.logger?.debug?.(`${debugId} Resolving endpoint from template: ${toDebugString(endpoint)}`);
  const endpointToReturn = { url: getEndpointUrl(url, endpointRuleOptions) };
  if (headers != null) {
    endpointToReturn.headers = getEndpointHeaders(headers, endpointRuleOptions);
  }
  if (properties != null) {
    endpointToReturn.properties = getEndpointProperties(properties, endpointRuleOptions);
  }
  return endpointToReturn;
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateErrorRule.js
init_esm_shims();
var evaluateErrorRule = (errorRule, options) => {
  const { conditions, error } = errorRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  const errorRuleOptions = referenceRecord ? {
    ...options,
    referenceRecord: { ...options.referenceRecord, ...referenceRecord }
  } : options;
  throw new EndpointError(evaluateExpression(error, "Error", errorRuleOptions));
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/utils/evaluateRules.js
var evaluateRules = (rules, options) => {
  for (const rule of rules) {
    if (rule.type === "endpoint") {
      const endpointOrUndefined = evaluateEndpointRule(rule, options);
      if (endpointOrUndefined) {
        return endpointOrUndefined;
      }
    } else if (rule.type === "error") {
      evaluateErrorRule(rule, options);
    } else if (rule.type === "tree") {
      const endpointOrUndefined = group3.evaluateTreeRule(rule, options);
      if (endpointOrUndefined) {
        return endpointOrUndefined;
      }
    } else {
      throw new EndpointError(`Unknown endpoint rule: ${rule}`);
    }
  }
  throw new EndpointError(`Rules evaluation failed`);
};
var evaluateTreeRule = (treeRule, options) => {
  const { conditions, rules } = treeRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  const treeRuleOptions = referenceRecord ? { ...options, referenceRecord: { ...options.referenceRecord, ...referenceRecord } } : options;
  return group3.evaluateRules(rules, treeRuleOptions);
};
var group3 = {
  evaluateRules,
  evaluateTreeRule
};

// node_modules/@smithy/core/dist-es/submodules/endpoints/util-endpoints/resolveEndpoint.js
var resolveEndpoint = (ruleSetObject, options) => {
  const { endpointParams, logger } = options;
  const { parameters, rules } = ruleSetObject;
  options.logger?.debug?.(`${debugId} Initial EndpointParams: ${toDebugString(endpointParams)}`);
  for (const paramKey in parameters) {
    if (!hasOwn(parameters, paramKey))
      continue;
    const parameter = parameters[paramKey];
    const endpointParam = endpointParams[paramKey];
    if (endpointParam == null && parameter.default != null) {
      endpointParams[paramKey] = parameter.default;
      continue;
    }
    if (parameter.required && endpointParam == null) {
      throw new EndpointError(`Missing required parameter: '${paramKey}'`);
    }
  }
  const endpoint = evaluateRules(rules, { endpointParams, logger, referenceRecord: {} });
  options.logger?.debug?.(`${debugId} Resolved endpoint: ${toDebugString(endpoint)}`);
  return endpoint;
};
var resolveEndpointConfig = bindResolveEndpointConfig(getEndpointFromConfig);
var getEndpointPlugin = bindGetEndpointPlugin(getEndpointFromConfig);

// node_modules/@smithy/core/dist-es/submodules/retry/service-error-classification/service-error-classification.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/retry/service-error-classification/constants.js
init_esm_shims();
var THROTTLING_ERROR_CODES = [
  "BandwidthLimitExceeded",
  "EC2ThrottledException",
  "LimitExceededException",
  "PriorRequestNotComplete",
  "ProvisionedThroughputExceededException",
  "RequestLimitExceeded",
  "RequestThrottled",
  "RequestThrottledException",
  "SlowDown",
  "ThrottledException",
  "Throttling",
  "ThrottlingException",
  "TooManyRequestsException",
  "TransactionInProgressException"
];
var TRANSIENT_ERROR_CODES = ["TimeoutError", "RequestTimeout", "RequestTimeoutException"];
var TRANSIENT_ERROR_STATUS_CODES = [500, 502, 503, 504];
var NODEJS_TIMEOUT_ERROR_CODES = ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"];
var NODEJS_NETWORK_ERROR_CODES = ["EHOSTUNREACH", "ENETUNREACH", "ENOTFOUND", "EAI_AGAIN"];

// node_modules/@smithy/core/dist-es/submodules/retry/service-error-classification/service-error-classification.js
var isRetryableByTrait = (error) => error?.$retryable !== void 0;
var isClockSkewCorrectedError = (error) => error.$metadata?.clockSkewCorrected;
var isBrowserNetworkError = (error) => {
  const errorMessages = /* @__PURE__ */ new Set([
    "Failed to fetch",
    "NetworkError when attempting to fetch resource",
    "The Internet connection appears to be offline",
    "Load failed",
    "Network request failed"
  ]);
  const isValid = error && error instanceof TypeError;
  if (!isValid) {
    return false;
  }
  return errorMessages.has(error.message);
};
var isThrottlingError = (error) => error.$metadata?.httpStatusCode === 429 || THROTTLING_ERROR_CODES.includes(error.name) || error.$retryable?.throttling == true;
var isTransientError = (error, depth = 0) => isRetryableByTrait(error) || isClockSkewCorrectedError(error) || error.name === "InvalidSignatureException" && error.message?.includes("Signature expired") || TRANSIENT_ERROR_CODES.includes(error.name) || NODEJS_TIMEOUT_ERROR_CODES.includes(error?.code || "") || NODEJS_NETWORK_ERROR_CODES.includes(error?.code || "") || TRANSIENT_ERROR_STATUS_CODES.includes(error.$metadata?.httpStatusCode || 0) || isBrowserNetworkError(error) || isNodeJsHttp2TransientError(error) || error.cause !== void 0 && depth <= 10 && isTransientError(error.cause, depth + 1);
var isServerError = (error) => {
  if (error.$metadata?.httpStatusCode !== void 0) {
    const statusCode = error.$metadata.httpStatusCode;
    if (500 <= statusCode && statusCode <= 599 && !isTransientError(error)) {
      return true;
    }
    return false;
  }
  return false;
};
function isNodeJsHttp2TransientError(error) {
  return error.code === "ERR_HTTP2_STREAM_ERROR" && error.message.includes("NGHTTP2_REFUSED_STREAM");
}

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/constants.js
init_esm_shims();
var MAXIMUM_RETRY_DELAY = 20 * 1e3;
var INITIAL_RETRY_TOKENS = 500;
var NO_RETRY_INCREMENT = 1;
var INVOCATION_ID_HEADER = "amz-sdk-invocation-id";
var REQUEST_HEADER = "amz-sdk-request";

// node_modules/@smithy/core/dist-es/submodules/retry/middleware-retry/parseRetryAfterHeader.js
init_esm_shims();
function parseRetryAfterHeader(response, logger) {
  if (!HttpResponse.isInstance(response)) {
    return;
  }
  for (const header in response.headers) {
    if (!hasOwn(response.headers, header))
      continue;
    const h = header.toLowerCase();
    if (h === "retry-after") {
      const retryAfter = response.headers[header];
      let retryAfterSeconds = NaN;
      if (retryAfter.endsWith("GMT")) {
        try {
          const date = parseRfc7231DateTime(retryAfter);
          retryAfterSeconds = (date.getTime() - Date.now()) / 1e3;
        } catch (e) {
          logger?.trace?.("Failed to parse retry-after header");
          logger?.trace?.(e);
        }
      } else if (retryAfter.match(/ GMT, ((\d+)|(\d+\.\d+))$/)) {
        retryAfterSeconds = Number(retryAfter.match(/ GMT, ([\d.]+)$/)?.[1]);
      } else if (retryAfter.match(/^((\d+)|(\d+\.\d+))$/)) {
        retryAfterSeconds = Number(retryAfter);
      } else if (Date.parse(retryAfter) >= Date.now()) {
        retryAfterSeconds = (Date.parse(retryAfter) - Date.now()) / 1e3;
      }
      if (isNaN(retryAfterSeconds)) {
        return;
      }
      return new Date(Date.now() + retryAfterSeconds * 1e3);
    } else if (h === "x-amz-retry-after") {
      const v = response.headers[header];
      const backoffMilliseconds = Number(v);
      if (isNaN(backoffMilliseconds)) {
        logger?.trace?.(`Failed to parse x-amz-retry-after=${v}`);
        return;
      }
      return new Date(Date.now() + backoffMilliseconds);
    }
  }
}

// node_modules/@smithy/core/dist-es/submodules/retry/middleware-retry/util.js
init_esm_shims();
var asSdkError = (error) => {
  if (error instanceof Error)
    return error;
  if (error instanceof Object)
    return Object.assign(new Error(), error);
  if (typeof error === "string")
    return new Error(error);
  return new Error(`AWS SDK error wrapper for ${error}`);
};

// node_modules/@smithy/core/dist-es/submodules/retry/middleware-retry/retryMiddleware.js
function bindRetryMiddleware(isStreamingPayload2) {
  return (options) => (next, context) => async (args) => {
    let retryStrategy = await options.retryStrategy();
    const maxAttempts = await options.maxAttempts();
    if (isRetryStrategyV2(retryStrategy)) {
      retryStrategy = retryStrategy;
      let retryToken = await retryStrategy.acquireInitialRetryToken((context["partition_id"] ?? "") + (context.__retryLongPoll ? ":longpoll" : ""));
      let lastError = new Error();
      let attempts = 0;
      let totalRetryDelay = 0;
      const { request } = args;
      const isRequest = HttpRequest.isInstance(request);
      if (isRequest) {
        request.headers[INVOCATION_ID_HEADER] = v4();
      }
      while (true) {
        try {
          if (isRequest) {
            request.headers[REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
          }
          const { response, output } = await next(args);
          retryStrategy.recordSuccess(retryToken);
          output.$metadata.attempts = attempts + 1;
          output.$metadata.totalRetryDelay = totalRetryDelay;
          return { response, output };
        } catch (e) {
          const retryErrorInfo = getRetryErrorInfo(e, options.logger);
          lastError = asSdkError(e);
          if (isRequest && isStreamingPayload2(request)) {
            (context.logger instanceof NoOpLogger ? console : context.logger)?.warn("An error was encountered in a non-retryable streaming request.");
            throw lastError;
          }
          try {
            retryToken = await retryStrategy.refreshRetryTokenForRetry(retryToken, retryErrorInfo);
          } catch (ignoredRefreshError) {
            if (!lastError.$metadata) {
              lastError.$metadata = {};
            }
            lastError.$metadata.attempts = attempts + 1;
            lastError.$metadata.totalRetryDelay = totalRetryDelay;
            throw lastError;
          }
          attempts = retryToken.getRetryCount();
          const delay = retryToken.getRetryDelay();
          totalRetryDelay += (retryToken?.$retryLog?.acquisitionDelay ?? 0) + delay;
          if (delay > 0) {
            await cooldown(delay);
          }
        }
      }
    } else {
      retryStrategy = retryStrategy;
      if (retryStrategy?.mode) {
        context.userAgent = [...context.userAgent || [], ["cfg/retry-mode", retryStrategy.mode]];
      }
      return retryStrategy.retry(next, args);
    }
  };
}
var cooldown = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
var isRetryStrategyV2 = (retryStrategy) => typeof retryStrategy.acquireInitialRetryToken !== "undefined" && typeof retryStrategy.refreshRetryTokenForRetry !== "undefined" && typeof retryStrategy.recordSuccess !== "undefined";
var getRetryErrorInfo = (error, logger) => {
  const errorInfo = {
    error,
    errorType: getRetryErrorType(error)
  };
  const retryAfterHint = parseRetryAfterHeader(error.$response, logger);
  if (retryAfterHint) {
    errorInfo.retryAfterHint = retryAfterHint;
  }
  return errorInfo;
};
var getRetryErrorType = (error) => {
  if (isThrottlingError(error))
    return "THROTTLING";
  if (isTransientError(error))
    return "TRANSIENT";
  if (isServerError(error))
    return "SERVER_ERROR";
  return "CLIENT_ERROR";
};
var retryMiddlewareOptions = {
  name: "retryMiddleware",
  tags: ["RETRY"],
  step: "finalizeRequest",
  priority: "high",
  override: true
};
function bindGetRetryPlugin(isStreamingPayload2) {
  const retryMiddleware2 = bindRetryMiddleware(isStreamingPayload2);
  return (options) => ({
    applyToStack: (clientStack) => {
      clientStack.add(retryMiddleware2(options), retryMiddlewareOptions);
    }
  });
}

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/AdaptiveRetryStrategy.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/DefaultRateLimiter.js
init_esm_shims();
var DefaultRateLimiter = class _DefaultRateLimiter {
  static setTimeoutFn = (fn, delay) => setTimeout(fn, delay);
  beta;
  minCapacity;
  minFillRate;
  scaleConstant;
  smooth;
  enabled = false;
  availableTokens = 0;
  lastMaxRate = 0;
  measuredTxRate = 0;
  requestCount = 0;
  fillRate;
  lastThrottleTime;
  lastTimestamp = 0;
  lastTxRateBucket;
  maxCapacity;
  timeWindow = 0;
  constructor(options) {
    this.beta = options?.beta ?? 0.7;
    this.minCapacity = options?.minCapacity ?? 1;
    this.minFillRate = options?.minFillRate ?? 0.5;
    this.scaleConstant = options?.scaleConstant ?? 0.4;
    this.smooth = options?.smooth ?? 0.8;
    this.lastThrottleTime = this.getCurrentTimeInSeconds();
    this.lastTxRateBucket = Math.floor(this.getCurrentTimeInSeconds());
    this.fillRate = this.minFillRate;
    this.maxCapacity = this.minCapacity;
  }
  async getSendToken() {
    return this.acquireTokenBucket(1);
  }
  updateClientSendingRate(response) {
    let calculatedRate;
    this.updateMeasuredRate();
    const retryErrorInfo = response;
    const isThrottling = retryErrorInfo?.errorType === "THROTTLING" || isThrottlingError(retryErrorInfo?.error ?? response);
    if (isThrottling) {
      const rateToUse = !this.enabled ? this.measuredTxRate : Math.min(this.measuredTxRate, this.fillRate);
      this.lastMaxRate = rateToUse;
      this.calculateTimeWindow();
      this.lastThrottleTime = this.getCurrentTimeInSeconds();
      calculatedRate = this.cubicThrottle(rateToUse);
      this.enableTokenBucket();
    } else {
      this.calculateTimeWindow();
      calculatedRate = this.cubicSuccess(this.getCurrentTimeInSeconds());
    }
    const newRate = Math.min(calculatedRate, 2 * this.measuredTxRate);
    this.updateTokenBucketRate(newRate);
  }
  getCurrentTimeInSeconds() {
    return Date.now() / 1e3;
  }
  async acquireTokenBucket(amount) {
    if (!this.enabled) {
      return;
    }
    this.refillTokenBucket();
    while (amount > this.availableTokens) {
      const delay = (amount - this.availableTokens) / this.fillRate * 1e3;
      await new Promise((resolve) => _DefaultRateLimiter.setTimeoutFn(resolve, delay));
      this.refillTokenBucket();
    }
    this.availableTokens = this.availableTokens - amount;
  }
  refillTokenBucket() {
    const timestamp = this.getCurrentTimeInSeconds();
    if (!this.lastTimestamp) {
      this.lastTimestamp = timestamp;
      return;
    }
    const fillAmount = (timestamp - this.lastTimestamp) * this.fillRate;
    this.availableTokens = Math.min(this.maxCapacity, this.availableTokens + fillAmount);
    this.lastTimestamp = timestamp;
  }
  calculateTimeWindow() {
    this.timeWindow = this.getPrecise(Math.pow(this.lastMaxRate * (1 - this.beta) / this.scaleConstant, 1 / 3));
  }
  cubicThrottle(rateToUse) {
    return this.getPrecise(rateToUse * this.beta);
  }
  cubicSuccess(timestamp) {
    return this.getPrecise(this.scaleConstant * Math.pow(timestamp - this.lastThrottleTime - this.timeWindow, 3) + this.lastMaxRate);
  }
  enableTokenBucket() {
    this.enabled = true;
  }
  updateTokenBucketRate(newRate) {
    this.refillTokenBucket();
    this.fillRate = Math.max(newRate, this.minFillRate);
    this.maxCapacity = Math.max(newRate, this.minCapacity);
    this.availableTokens = Math.min(this.availableTokens, this.maxCapacity);
  }
  updateMeasuredRate() {
    const t = this.getCurrentTimeInSeconds();
    const timeBucket = Math.floor(t * 2) / 2;
    this.requestCount++;
    if (timeBucket > this.lastTxRateBucket) {
      const currentRate = this.requestCount / (timeBucket - this.lastTxRateBucket);
      this.measuredTxRate = this.getPrecise(currentRate * this.smooth + this.measuredTxRate * (1 - this.smooth));
      this.requestCount = 0;
      this.lastTxRateBucket = timeBucket;
    }
  }
  getPrecise(num) {
    return parseFloat(num.toFixed(8));
  }
};

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/StandardRetryStrategy.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/DefaultRetryBackoffStrategy.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/retries-2026-config.js
init_esm_shims();
var Retry = class _Retry {
  static v2026 = typeof process !== "undefined" && process.env?.SMITHY_NEW_RETRIES_2026 === "true";
  static delay() {
    return _Retry.v2026 ? 50 : 100;
  }
  static throttlingDelay() {
    return _Retry.v2026 ? 1e3 : 500;
  }
  static cost() {
    return _Retry.v2026 ? 14 : 5;
  }
  static throttlingCost() {
    return _Retry.v2026 ? 5 : 10;
  }
  static modifiedCostType() {
    return _Retry.v2026 ? "THROTTLING" : "TRANSIENT";
  }
};

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/DefaultRetryBackoffStrategy.js
var DefaultRetryBackoffStrategy = class {
  x = Retry.delay();
  computeNextBackoffDelay(i) {
    const b = Math.random();
    const r = 2;
    const t_i = b * Math.min(this.x * r ** i, MAXIMUM_RETRY_DELAY);
    return Math.floor(t_i);
  }
  setDelayBase(delay) {
    this.x = delay;
  }
};

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/DefaultRetryToken.js
init_esm_shims();
var DefaultRetryToken = class {
  delay;
  count;
  cost;
  longPoll;
  $retryLog = {
    acquisitionDelay: 0
  };
  constructor(delay, count, cost, longPoll) {
    this.delay = delay;
    this.count = count;
    this.cost = cost;
    this.longPoll = longPoll;
  }
  getRetryCount() {
    return this.count;
  }
  getRetryDelay() {
    return Math.min(MAXIMUM_RETRY_DELAY, this.delay);
  }
  getRetryCost() {
    return this.cost;
  }
  isLongPoll() {
    return this.longPoll;
  }
};

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/config.js
init_esm_shims();
var RETRY_MODES;
(function(RETRY_MODES2) {
  RETRY_MODES2["STANDARD"] = "standard";
  RETRY_MODES2["ADAPTIVE"] = "adaptive";
})(RETRY_MODES || (RETRY_MODES = {}));
var DEFAULT_MAX_ATTEMPTS = 3;
var DEFAULT_RETRY_MODE = RETRY_MODES.STANDARD;

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/StandardRetryStrategy.js
var refusal = {
  incompatible: 1,
  attempts: 2,
  capacity: 3
};
var StandardRetryStrategy = class {
  mode = RETRY_MODES.STANDARD;
  retryBackoffStrategy;
  capacity = INITIAL_RETRY_TOKENS;
  maxAttemptsProvider;
  baseDelay;
  constructor(arg1) {
    if (typeof arg1 === "number") {
      this.maxAttemptsProvider = async () => arg1;
    } else if (typeof arg1 === "function") {
      this.maxAttemptsProvider = arg1;
    } else if (arg1 && typeof arg1 === "object") {
      this.maxAttemptsProvider = async () => arg1.maxAttempts;
      this.baseDelay = arg1.baseDelay;
      this.retryBackoffStrategy = arg1.backoff;
    }
    this.maxAttemptsProvider ??= async () => DEFAULT_MAX_ATTEMPTS;
    this.baseDelay ??= Retry.delay();
    this.retryBackoffStrategy ??= new DefaultRetryBackoffStrategy();
  }
  async acquireInitialRetryToken(retryTokenScope) {
    return new DefaultRetryToken(Retry.delay(), 0, void 0, Retry.v2026 && retryTokenScope.includes(":longpoll"));
  }
  async refreshRetryTokenForRetry(token, errorInfo) {
    const maxAttempts = await this.getMaxAttempts();
    const retryCode = this.retryCode(token, errorInfo, maxAttempts);
    const shouldRetry = retryCode === 0;
    const isLongPoll = token.isLongPoll?.();
    if (shouldRetry || isLongPoll) {
      const errorType = errorInfo.errorType;
      this.retryBackoffStrategy.setDelayBase(errorType === "THROTTLING" ? Retry.throttlingDelay() : this.baseDelay);
      const delayFromErrorType = this.retryBackoffStrategy.computeNextBackoffDelay(token.getRetryCount());
      let retryDelay = delayFromErrorType;
      if (errorInfo.retryAfterHint instanceof Date) {
        retryDelay = Math.max(delayFromErrorType, Math.min(errorInfo.retryAfterHint.getTime() - Date.now(), delayFromErrorType + 5e3));
      }
      if (!shouldRetry) {
        const longPollBackoff = Retry.v2026 && retryCode === refusal.capacity && isLongPoll ? retryDelay : 0;
        if (longPollBackoff > 0) {
          await new Promise((r) => setTimeout(r, longPollBackoff));
        }
      } else {
        const capacityCost = this.getCapacityCost(errorType);
        this.capacity -= capacityCost;
        const nextToken = new DefaultRetryToken(0, token.getRetryCount() + 1, capacityCost, token.isLongPoll?.() ?? false);
        await new Promise((r) => setTimeout(r, retryDelay));
        nextToken.$retryLog.acquisitionDelay = retryDelay;
        return nextToken;
      }
    }
    throw new Error("No retry token available");
  }
  recordSuccess(token) {
    this.capacity = Math.min(INITIAL_RETRY_TOKENS, this.capacity + (token.getRetryCost() ?? NO_RETRY_INCREMENT));
  }
  getCapacity() {
    return this.capacity;
  }
  async maxAttempts() {
    return this.maxAttemptsProvider();
  }
  async getMaxAttempts() {
    try {
      return await this.maxAttemptsProvider();
    } catch (ignored) {
      console.warn(`Max attempts provider could not resolve. Using default of ${DEFAULT_MAX_ATTEMPTS}`);
      return DEFAULT_MAX_ATTEMPTS;
    }
  }
  retryCode(tokenToRenew, errorInfo, maxAttempts) {
    const attempts = tokenToRenew.getRetryCount() + 1;
    const retryableStatus = this.isRetryableError(errorInfo.errorType) ? 0 : refusal.incompatible;
    const attemptStatus = attempts < maxAttempts ? 0 : refusal.attempts;
    const capacityStatus = this.capacity >= this.getCapacityCost(errorInfo.errorType) ? 0 : refusal.capacity;
    return retryableStatus || attemptStatus || capacityStatus;
  }
  getCapacityCost(errorType) {
    return errorType === Retry.modifiedCostType() ? Retry.throttlingCost() : Retry.cost();
  }
  isRetryableError(errorType) {
    return errorType === "THROTTLING" || errorType === "TRANSIENT";
  }
};

// node_modules/@smithy/core/dist-es/submodules/retry/util-retry/AdaptiveRetryStrategy.js
var AdaptiveRetryStrategy = class {
  mode = RETRY_MODES.ADAPTIVE;
  rateLimiter;
  standardRetryStrategy;
  constructor(maxAttemptsProvider, options) {
    const { rateLimiter } = options ?? {};
    this.rateLimiter = rateLimiter ?? new DefaultRateLimiter();
    this.standardRetryStrategy = options ? new StandardRetryStrategy({
      maxAttempts: typeof maxAttemptsProvider === "number" ? maxAttemptsProvider : 3,
      ...options
    }) : new StandardRetryStrategy(maxAttemptsProvider);
  }
  async acquireInitialRetryToken(retryTokenScope) {
    const token = await this.standardRetryStrategy.acquireInitialRetryToken(retryTokenScope);
    await this.rateLimiter.getSendToken();
    return token;
  }
  async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
    this.rateLimiter.updateClientSendingRate(errorInfo);
    const token = await this.standardRetryStrategy.refreshRetryTokenForRetry(tokenToRenew, errorInfo);
    await this.rateLimiter.getSendToken();
    return token;
  }
  recordSuccess(token) {
    this.rateLimiter.updateClientSendingRate({});
    this.standardRetryStrategy.recordSuccess(token);
  }
  async maxAttemptsProvider() {
    return this.standardRetryStrategy.maxAttempts();
  }
};

// node_modules/@smithy/core/dist-es/submodules/retry/middleware-retry/configurations.js
init_esm_shims();
var ENV_MAX_ATTEMPTS = "AWS_MAX_ATTEMPTS";
var CONFIG_MAX_ATTEMPTS = "max_attempts";
var NODE_MAX_ATTEMPT_CONFIG_OPTIONS = {
  environmentVariableSelector: (env2) => {
    const value = env2[ENV_MAX_ATTEMPTS];
    if (!value)
      return void 0;
    const maxAttempt = parseInt(value);
    if (Number.isNaN(maxAttempt)) {
      throw new Error(`Environment variable ${ENV_MAX_ATTEMPTS} mast be a number, got "${value}"`);
    }
    return maxAttempt;
  },
  configFileSelector: (profile) => {
    const value = profile[CONFIG_MAX_ATTEMPTS];
    if (!value)
      return void 0;
    const maxAttempt = parseInt(value);
    if (Number.isNaN(maxAttempt)) {
      throw new Error(`Shared config file entry ${CONFIG_MAX_ATTEMPTS} mast be a number, got "${value}"`);
    }
    return maxAttempt;
  },
  default: DEFAULT_MAX_ATTEMPTS
};
var resolveRetryConfig = (input, defaults) => {
  const { retryStrategy, retryMode } = input;
  const { defaultMaxAttempts = DEFAULT_MAX_ATTEMPTS, defaultBaseDelay = Retry.delay() } = defaults ?? {};
  const maxAttemptsProvider = normalizeProvider(input.maxAttempts ?? defaultMaxAttempts);
  let controller = retryStrategy ? Promise.resolve(retryStrategy) : void 0;
  const getDefault = async () => {
    const maxAttempts = await maxAttemptsProvider();
    const adaptive = await normalizeProvider(retryMode)() === RETRY_MODES.ADAPTIVE;
    if (adaptive) {
      return new AdaptiveRetryStrategy(maxAttemptsProvider, {
        maxAttempts,
        baseDelay: defaultBaseDelay
      });
    }
    return new StandardRetryStrategy({
      maxAttempts,
      baseDelay: defaultBaseDelay
    });
  };
  return Object.assign(input, {
    maxAttempts: maxAttemptsProvider,
    retryStrategy: () => controller ??= getDefault()
  });
};
var ENV_RETRY_MODE = "AWS_RETRY_MODE";
var CONFIG_RETRY_MODE = "retry_mode";
var NODE_RETRY_MODE_CONFIG_OPTIONS = {
  environmentVariableSelector: (env2) => env2[ENV_RETRY_MODE],
  configFileSelector: (profile) => profile[CONFIG_RETRY_MODE],
  default: DEFAULT_RETRY_MODE
};
var getRetryPlugin = bindGetRetryPlugin(isStreamingPayload);

// node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js
Retry.v2026 ||= typeof process === "object" && process.env?.AWS_NEW_RETRIES_2026 === "true";
function setFeature2(context, feature, value) {
  if (!context.__aws_sdk_context) {
    context.__aws_sdk_context = {
      features: {}
    };
  } else if (!context.__aws_sdk_context.features) {
    context.__aws_sdk_context.features = {};
  }
  context.__aws_sdk_context.features[feature] = value;
}

// node_modules/@aws-sdk/core/dist-es/submodules/client/setTokenFeature.js
init_esm_shims();
function setTokenFeature(token, feature, value) {
  if (!token.$source) {
    token.$source = {};
  }
  token.$source[feature] = value;
  return token;
}

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-host-header/hostHeaderMiddleware.js
init_esm_shims();
function resolveHostHeaderConfig(input) {
  return input;
}
var hostHeaderMiddleware = (options) => (next) => async (args) => {
  if (!HttpRequest.isInstance(args.request))
    return next(args);
  const { request } = args;
  const { handlerProtocol = "" } = options.requestHandler.metadata || {};
  if (handlerProtocol.indexOf("h2") >= 0 && !request.headers[":authority"]) {
    delete request.headers["host"];
    request.headers[":authority"] = request.hostname + (request.port ? ":" + request.port : "");
  } else if (!request.headers["host"]) {
    let host = request.hostname;
    if (request.port != null)
      host += `:${request.port}`;
    request.headers["host"] = host;
  }
  return next(args);
};
var hostHeaderMiddlewareOptions = {
  name: "hostHeaderMiddleware",
  step: "build",
  priority: "low",
  tags: ["HOST"],
  override: true
};
var getHostHeaderPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(hostHeaderMiddleware(options), hostHeaderMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-logger/loggerMiddleware.js
init_esm_shims();
var loggerMiddleware = () => (next, context) => async (args) => {
  try {
    const response = await next(args);
    const { clientName, commandName, logger, dynamoDbDocumentClientOptions = {} } = context;
    const { overrideInputFilterSensitiveLog, overrideOutputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
    const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
    const outputFilterSensitiveLog = overrideOutputFilterSensitiveLog ?? context.outputFilterSensitiveLog;
    const { $metadata, ...outputWithoutMetadata } = response.output;
    logger?.info?.({
      clientName,
      commandName,
      input: inputFilterSensitiveLog(args.input),
      output: outputFilterSensitiveLog(outputWithoutMetadata),
      metadata: $metadata
    });
    return response;
  } catch (error) {
    const { clientName, commandName, logger, dynamoDbDocumentClientOptions = {} } = context;
    const { overrideInputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
    const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
    logger?.error?.({
      clientName,
      commandName,
      input: inputFilterSensitiveLog(args.input),
      error,
      metadata: error.$metadata
    });
    throw error;
  }
};
var loggerMiddlewareOptions = {
  name: "loggerMiddleware",
  tags: ["LOGGER"],
  step: "initialize",
  override: true
};
var getLoggerPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(loggerMiddleware(), loggerMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-recursion-detection/configuration.js
init_esm_shims();
var recursionDetectionMiddlewareOptions = {
  step: "build",
  tags: ["RECURSION_DETECTION", "TRACE_CONTEXT_PROPAGATION"],
  name: "recursionDetectionMiddleware",
  override: true,
  priority: "low"
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-recursion-detection/getRecursionDetectionPlugin.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-recursion-detection/recursionDetectionMiddleware.js
init_esm_shims();

// node_modules/@aws/lambda-invoke-store/dist-es/invoke-store.js
init_esm_shims();
var PROTECTED_KEYS = {
  REQUEST_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_REQUEST_ID"),
  X_RAY_TRACE_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_X_RAY_TRACE_ID"),
  TENANT_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_TENANT_ID"),
  TRACEPARENT: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_TRACEPARENT"),
  TRACESTATE: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_TRACESTATE"),
  BAGGAGE: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_BAGGAGE")
};
var NO_GLOBAL_AWS_LAMBDA = ["true", "1"].includes(process.env?.AWS_LAMBDA_NODEJS_NO_GLOBAL_AWSLAMBDA ?? "");
if (!NO_GLOBAL_AWS_LAMBDA) {
  globalThis.awslambda = globalThis.awslambda || {};
}
var InvokeStoreBase = class {
  static PROTECTED_KEYS = PROTECTED_KEYS;
  isProtectedKey(key) {
    return Object.values(PROTECTED_KEYS).includes(key);
  }
  getRequestId() {
    return this.get(PROTECTED_KEYS.REQUEST_ID) ?? "-";
  }
  getXRayTraceId() {
    return this.get(PROTECTED_KEYS.X_RAY_TRACE_ID);
  }
  getTenantId() {
    return this.get(PROTECTED_KEYS.TENANT_ID);
  }
  getTraceparent() {
    return this.get(PROTECTED_KEYS.TRACEPARENT);
  }
  getTracestate() {
    return this.get(PROTECTED_KEYS.TRACESTATE);
  }
  getBaggage() {
    return this.get(PROTECTED_KEYS.BAGGAGE);
  }
};
var InvokeStoreSingle = class extends InvokeStoreBase {
  currentContext;
  getContext() {
    return this.currentContext;
  }
  hasContext() {
    return this.currentContext !== void 0;
  }
  get(key) {
    return this.currentContext?.[key];
  }
  set(key, value) {
    if (this.isProtectedKey(key)) {
      throw new Error(`Cannot modify protected Lambda context field: ${String(key)}`);
    }
    this.currentContext = this.currentContext || {};
    this.currentContext[key] = value;
  }
  run(context, fn) {
    this.currentContext = context;
    return fn();
  }
};
var InvokeStoreMulti = class _InvokeStoreMulti extends InvokeStoreBase {
  als;
  static async create() {
    const instance = new _InvokeStoreMulti();
    const asyncHooks = await import('async_hooks');
    instance.als = new asyncHooks.AsyncLocalStorage();
    return instance;
  }
  getContext() {
    return this.als.getStore();
  }
  hasContext() {
    return this.als.getStore() !== void 0;
  }
  get(key) {
    return this.als.getStore()?.[key];
  }
  set(key, value) {
    if (this.isProtectedKey(key)) {
      throw new Error(`Cannot modify protected Lambda context field: ${String(key)}`);
    }
    const store = this.als.getStore();
    if (!store) {
      throw new Error("No context available");
    }
    store[key] = value;
  }
  run(context, fn) {
    return this.als.run(context, fn);
  }
};
var InvokeStore;
(function(InvokeStore2) {
  let instance = null;
  async function getInstanceAsync(forceInvokeStoreMulti) {
    if (!instance) {
      instance = (async () => {
        const isMulti = forceInvokeStoreMulti === true || "AWS_LAMBDA_MAX_CONCURRENCY" in process.env;
        const newInstance = isMulti ? await InvokeStoreMulti.create() : new InvokeStoreSingle();
        if (!NO_GLOBAL_AWS_LAMBDA && globalThis.awslambda?.InvokeStore) {
          return globalThis.awslambda.InvokeStore;
        } else if (!NO_GLOBAL_AWS_LAMBDA && globalThis.awslambda) {
          globalThis.awslambda.InvokeStore = newInstance;
          return newInstance;
        } else {
          return newInstance;
        }
      })();
    }
    return instance;
  }
  InvokeStore2.getInstanceAsync = getInstanceAsync;
  InvokeStore2._testing = process.env.AWS_LAMBDA_BENCHMARK_MODE === "1" ? {
    reset: () => {
      instance = null;
      if (globalThis.awslambda?.InvokeStore) {
        delete globalThis.awslambda.InvokeStore;
      }
      globalThis.awslambda = { InvokeStore: void 0 };
    }
  } : void 0;
})(InvokeStore || (InvokeStore = {}));

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-recursion-detection/recursionDetectionMiddleware.js
var AWS_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME";
var _X_AMZN_TRACE_ID = "_X_AMZN_TRACE_ID";
var X_AMZN_TRACE_ID = "X-Amzn-Trace-Id";
var TRACEPARENT = "traceparent";
var TRACESTATE = "tracestate";
var BAGGAGE = "baggage";
var recursionDetectionMiddleware = () => (next) => async (args) => {
  const { request } = args;
  if (!HttpRequest.isInstance(request)) {
    return next(args);
  }
  let invokeStore;
  {
    const traceIdHeader = Object.keys(request.headers ?? {}).find((h) => h.toLowerCase() === X_AMZN_TRACE_ID.toLowerCase()) ?? X_AMZN_TRACE_ID;
    if (!request.headers.hasOwnProperty(traceIdHeader)) {
      const functionName = process.env[AWS_LAMBDA_FUNCTION_NAME];
      const traceIdFromEnv = process.env[_X_AMZN_TRACE_ID];
      invokeStore ??= await InvokeStore.getInstanceAsync();
      const traceIdFromInvokeStore = invokeStore?.getXRayTraceId();
      const traceId = traceIdFromInvokeStore ?? traceIdFromEnv;
      const nonEmptyString = (str) => typeof str === "string" && str.length > 0;
      if (nonEmptyString(functionName) && nonEmptyString(traceId)) {
        request.headers[X_AMZN_TRACE_ID] = traceId;
      }
    }
  }
  {
    sanitizeTraceHeaders(request.headers);
    const existingTraceparent = request.headers[TRACEPARENT];
    if (!existingTraceparent) {
      const traceparent = (invokeStore ??= await InvokeStore.getInstanceAsync())?.getTraceparent?.();
      if (traceparent) {
        request.headers[TRACEPARENT] = traceparent;
        const tracestate = invokeStore?.getTracestate?.();
        if (tracestate) {
          request.headers[TRACESTATE] = tracestate;
        }
        const baggage = invokeStore?.getBaggage?.();
        if (baggage) {
          request.headers[BAGGAGE] = baggage;
        }
      }
    }
  }
  return next(args);
};
function sanitizeTraceHeaders(headers) {
  for (const header of Object.keys(headers)) {
    const lower = header.toLowerCase();
    if (header !== lower && (lower === TRACEPARENT || lower === TRACESTATE || lower === BAGGAGE)) {
      headers[lower] = headers[header];
      delete headers[header];
    }
  }
}

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-recursion-detection/getRecursionDetectionPlugin.js
var getRecursionDetectionPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(recursionDetectionMiddleware(), recursionDetectionMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-user-agent/configurations.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/legacy-root-exports/middleware-http-auth-scheme/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/legacy-root-exports/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/legacy-root-exports/middleware-http-auth-scheme/resolveAuthOptions.js
init_esm_shims();
var resolveAuthOptions = (candidateAuthOptions, authSchemePreference) => {
  if (!authSchemePreference || authSchemePreference.length === 0) {
    return candidateAuthOptions;
  }
  const preferredAuthOptions = [];
  for (const preferredSchemeName of authSchemePreference) {
    for (const candidateAuthOption of candidateAuthOptions) {
      const candidateAuthSchemeName = candidateAuthOption.schemeId.split("#")[1];
      if (candidateAuthSchemeName === preferredSchemeName) {
        preferredAuthOptions.push(candidateAuthOption);
      }
    }
  }
  for (const candidateAuthOption of candidateAuthOptions) {
    if (!preferredAuthOptions.find(({ schemeId }) => schemeId === candidateAuthOption.schemeId)) {
      preferredAuthOptions.push(candidateAuthOption);
    }
  }
  return preferredAuthOptions;
};

// node_modules/@smithy/core/dist-es/legacy-root-exports/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js
function convertHttpAuthSchemesToMap(httpAuthSchemes) {
  const map = /* @__PURE__ */ new Map();
  for (const scheme of httpAuthSchemes) {
    map.set(scheme.schemeId, scheme);
  }
  return map;
}
var httpAuthSchemeMiddleware = (config, mwOptions) => (next, context) => async (args) => {
  const options = config.httpAuthSchemeProvider(await mwOptions.httpAuthSchemeParametersProvider(config, context, args.input));
  const authSchemePreference = config.authSchemePreference ? await config.authSchemePreference() : [];
  const resolvedOptions = resolveAuthOptions(options, authSchemePreference);
  const authSchemes = convertHttpAuthSchemesToMap(config.httpAuthSchemes);
  const smithyContext = getSmithyContext(context);
  const failureReasons = [];
  for (const option of resolvedOptions) {
    const scheme = authSchemes.get(option.schemeId);
    if (!scheme) {
      failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` was not enabled for this service.`);
      continue;
    }
    const identityProvider = scheme.identityProvider(await mwOptions.identityProviderConfigProvider(config));
    if (!identityProvider) {
      failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` did not have an IdentityProvider configured.`);
      continue;
    }
    const { identityProperties = {}, signingProperties = {} } = option.propertiesExtractor?.(config, context) || {};
    option.identityProperties = Object.assign(option.identityProperties || {}, identityProperties);
    option.signingProperties = Object.assign(option.signingProperties || {}, signingProperties);
    smithyContext.selectedHttpAuthScheme = {
      httpAuthOption: option,
      identity: await identityProvider(option.identityProperties),
      signer: scheme.signer
    };
    break;
  }
  if (!smithyContext.selectedHttpAuthScheme) {
    throw new Error(failureReasons.join("\n"));
  }
  return next(args);
};

// node_modules/@smithy/core/dist-es/legacy-root-exports/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.js
init_esm_shims();
var httpAuthSchemeEndpointRuleSetMiddlewareOptions = {
  step: "serialize",
  tags: ["HTTP_AUTH_SCHEME"],
  name: "httpAuthSchemeMiddleware",
  override: true,
  relation: "before",
  toMiddleware: "endpointV2Middleware"
};
var getHttpAuthSchemeEndpointRuleSetPlugin = (config, { httpAuthSchemeParametersProvider, identityProviderConfigProvider }) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(httpAuthSchemeMiddleware(config, {
      httpAuthSchemeParametersProvider,
      identityProviderConfigProvider
    }), httpAuthSchemeEndpointRuleSetMiddlewareOptions);
  }
});

// node_modules/@smithy/core/dist-es/legacy-root-exports/middleware-http-signing/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/legacy-root-exports/middleware-http-signing/httpSigningMiddleware.js
init_esm_shims();
var defaultErrorHandler = (signingProperties) => (error) => {
  throw error;
};
var defaultSuccessHandler = (httpResponse, signingProperties) => {
};
var httpSigningMiddleware = (config) => (next, context) => async (args) => {
  if (!HttpRequest.isInstance(args.request)) {
    return next(args);
  }
  const smithyContext = getSmithyContext(context);
  const scheme = smithyContext.selectedHttpAuthScheme;
  if (!scheme) {
    throw new Error(`No HttpAuthScheme was selected: unable to sign request`);
  }
  const { httpAuthOption: { signingProperties = {} }, identity, signer } = scheme;
  const output = await next({
    ...args,
    request: await signer.sign(args.request, identity, signingProperties)
  }).catch((signer.errorHandler || defaultErrorHandler)(signingProperties));
  (signer.successHandler || defaultSuccessHandler)(output.response, signingProperties);
  return output;
};

// node_modules/@smithy/core/dist-es/legacy-root-exports/middleware-http-signing/getHttpSigningMiddleware.js
init_esm_shims();
var httpSigningMiddlewareOptions = {
  step: "finalizeRequest",
  tags: ["HTTP_SIGNING"],
  name: "httpSigningMiddleware",
  aliases: ["apiKeyMiddleware", "tokenMiddleware", "awsAuthMiddleware"],
  override: true,
  relation: "after",
  toMiddleware: "retryMiddleware"
};
var getHttpSigningPlugin = (config) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(httpSigningMiddleware(), httpSigningMiddlewareOptions);
  }
});

// node_modules/@smithy/core/dist-es/normalizeProvider.js
init_esm_shims();
var normalizeProvider2 = (input) => {
  if (typeof input === "function")
    return input;
  const promisified = Promise.resolve(input);
  return () => promisified;
};

// node_modules/@smithy/core/dist-es/legacy-root-exports/util-identity-and-auth/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/legacy-root-exports/util-identity-and-auth/DefaultIdentityProviderConfig.js
init_esm_shims();
var DefaultIdentityProviderConfig = class {
  authSchemes = /* @__PURE__ */ new Map();
  constructor(config) {
    for (const key in config) {
      if (!hasOwn(config, key))
        continue;
      const value = config[key];
      if (value !== void 0) {
        this.authSchemes.set(key, value);
      }
    }
  }
  getIdentityProvider(schemeId) {
    return this.authSchemes.get(schemeId);
  }
};

// node_modules/@smithy/core/dist-es/legacy-root-exports/util-identity-and-auth/httpAuthSchemes/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/legacy-root-exports/util-identity-and-auth/httpAuthSchemes/noAuth.js
init_esm_shims();
var NoAuthSigner = class {
  async sign(httpRequest, identity, signingProperties) {
    return httpRequest;
  }
};

// node_modules/@smithy/core/dist-es/legacy-root-exports/util-identity-and-auth/memoizeIdentityProvider.js
init_esm_shims();
var createIsIdentityExpiredFunction = (expirationMs) => function isIdentityExpired2(identity) {
  return doesIdentityRequireRefresh(identity) && identity.expiration.getTime() - Date.now() < expirationMs;
};
var EXPIRATION_MS = 3e5;
var isIdentityExpired = createIsIdentityExpiredFunction(EXPIRATION_MS);
var doesIdentityRequireRefresh = (identity) => identity.expiration !== void 0;
var memoizeIdentityProvider = (provider, isExpired, requiresRefresh) => {
  if (provider === void 0) {
    return void 0;
  }
  const normalizedProvider = typeof provider !== "function" ? async () => Promise.resolve(provider) : provider;
  let resolved;
  let pending;
  let hasResult;
  let isConstant = false;
  const coalesceProvider = async (options) => {
    if (!pending) {
      pending = normalizedProvider(options);
    }
    try {
      resolved = await pending;
      hasResult = true;
      isConstant = false;
    } finally {
      pending = void 0;
    }
    return resolved;
  };
  if (isExpired === void 0) {
    return async (options) => {
      if (!hasResult || options?.forceRefresh) {
        resolved = await coalesceProvider(options);
      }
      return resolved;
    };
  }
  return async (options) => {
    if (!hasResult || options?.forceRefresh) {
      resolved = await coalesceProvider(options);
    }
    if (isConstant) {
      return resolved;
    }
    if (!requiresRefresh(resolved)) {
      isConstant = true;
      return resolved;
    }
    if (isExpired(resolved)) {
      await coalesceProvider(options);
      return resolved;
    }
    return resolved;
  };
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-user-agent/configurations.js
var DEFAULT_UA_APP_ID = void 0;
function isValidUserAgentAppId(appId) {
  if (appId === void 0) {
    return true;
  }
  return typeof appId === "string" && appId.length <= 50;
}
function resolveUserAgentConfig(input) {
  const normalizedAppIdProvider = normalizeProvider2(input.userAgentAppId ?? DEFAULT_UA_APP_ID);
  const { customUserAgent } = input;
  return Object.assign(input, {
    customUserAgent: typeof customUserAgent === "string" ? [[customUserAgent]] : customUserAgent,
    userAgentAppId: async () => {
      const appId = await normalizedAppIdProvider();
      if (!isValidUserAgentAppId(appId)) {
        const logger = input.logger?.constructor?.name === "NoOpLogger" || !input.logger ? console : input.logger;
        if (typeof appId !== "string") {
          logger?.warn("userAgentAppId must be a string or undefined.");
        } else if (appId.length > 50) {
          logger?.warn("The provided userAgentAppId exceeds the maximum length of 50 characters.");
        }
      }
      return appId;
    }
  });
}

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-user-agent/user-agent-middleware.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/lib/aws/partition.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/lib/aws/partitions.js
init_esm_shims();
var partitionsInfo = {
  "partitions": [
    {
      "id": "aws",
      "outputs": {
        "dnsSuffix": "amazonaws.com",
        "dualStackDnsSuffix": "api.aws",
        "implicitGlobalRegion": "us-east-1",
        "name": "aws",
        "supportsDualStack": true,
        "supportsFIPS": true
      },
      "regionRegex": "^(us|eu|ap|sa|ca|me|af|il|mx)\\-\\w+\\-\\d+$",
      "regions": {
        "af-south-1": {
          "description": "Africa (Cape Town)"
        },
        "ap-east-1": {
          "description": "Asia Pacific (Hong Kong)"
        },
        "ap-east-2": {
          "description": "Asia Pacific (Taipei)"
        },
        "ap-northeast-1": {
          "description": "Asia Pacific (Tokyo)"
        },
        "ap-northeast-2": {
          "description": "Asia Pacific (Seoul)"
        },
        "ap-northeast-3": {
          "description": "Asia Pacific (Osaka)"
        },
        "ap-south-1": {
          "description": "Asia Pacific (Mumbai)"
        },
        "ap-south-2": {
          "description": "Asia Pacific (Hyderabad)"
        },
        "ap-southeast-1": {
          "description": "Asia Pacific (Singapore)"
        },
        "ap-southeast-2": {
          "description": "Asia Pacific (Sydney)"
        },
        "ap-southeast-3": {
          "description": "Asia Pacific (Jakarta)"
        },
        "ap-southeast-4": {
          "description": "Asia Pacific (Melbourne)"
        },
        "ap-southeast-5": {
          "description": "Asia Pacific (Malaysia)"
        },
        "ap-southeast-6": {
          "description": "Asia Pacific (New Zealand)"
        },
        "ap-southeast-7": {
          "description": "Asia Pacific (Thailand)"
        },
        "aws-global": {
          "description": "aws global region"
        },
        "ca-central-1": {
          "description": "Canada (Central)"
        },
        "ca-west-1": {
          "description": "Canada West (Calgary)"
        },
        "eu-central-1": {
          "description": "Europe (Frankfurt)"
        },
        "eu-central-2": {
          "description": "Europe (Zurich)"
        },
        "eu-north-1": {
          "description": "Europe (Stockholm)"
        },
        "eu-south-1": {
          "description": "Europe (Milan)"
        },
        "eu-south-2": {
          "description": "Europe (Spain)"
        },
        "eu-west-1": {
          "description": "Europe (Ireland)"
        },
        "eu-west-2": {
          "description": "Europe (London)"
        },
        "eu-west-3": {
          "description": "Europe (Paris)"
        },
        "il-central-1": {
          "description": "Israel (Tel Aviv)"
        },
        "me-central-1": {
          "description": "Middle East (UAE)"
        },
        "me-south-1": {
          "description": "Middle East (Bahrain)"
        },
        "mx-central-1": {
          "description": "Mexico (Central)"
        },
        "sa-east-1": {
          "description": "South America (Sao Paulo)"
        },
        "us-east-1": {
          "description": "US East (N. Virginia)"
        },
        "us-east-2": {
          "description": "US East (Ohio)"
        },
        "us-west-1": {
          "description": "US West (N. California)"
        },
        "us-west-2": {
          "description": "US West (Oregon)"
        }
      }
    },
    {
      "id": "aws-cn",
      "outputs": {
        "dnsSuffix": "amazonaws.com.cn",
        "dualStackDnsSuffix": "api.amazonwebservices.com.cn",
        "implicitGlobalRegion": "cn-northwest-1",
        "name": "aws-cn",
        "supportsDualStack": true,
        "supportsFIPS": true
      },
      "regionRegex": "^cn\\-\\w+\\-\\d+$",
      "regions": {
        "aws-cn-global": {
          "description": "aws-cn global region"
        },
        "cn-north-1": {
          "description": "China (Beijing)"
        },
        "cn-northwest-1": {
          "description": "China (Ningxia)"
        }
      }
    },
    {
      "id": "aws-eusc",
      "outputs": {
        "dnsSuffix": "amazonaws.eu",
        "dualStackDnsSuffix": "api.amazonwebservices.eu",
        "implicitGlobalRegion": "eusc-de-east-1",
        "name": "aws-eusc",
        "supportsDualStack": true,
        "supportsFIPS": true
      },
      "regionRegex": "^eusc\\-(de)\\-\\w+\\-\\d+$",
      "regions": {
        "eusc-de-east-1": {
          "description": "AWS European Sovereign Cloud (Germany)"
        }
      }
    },
    {
      "id": "aws-iso",
      "outputs": {
        "dnsSuffix": "c2s.ic.gov",
        "dualStackDnsSuffix": "api.aws.ic.gov",
        "implicitGlobalRegion": "us-iso-east-1",
        "name": "aws-iso",
        "supportsDualStack": true,
        "supportsFIPS": true
      },
      "regionRegex": "^us\\-iso\\-\\w+\\-\\d+$",
      "regions": {
        "aws-iso-global": {
          "description": "aws-iso global region"
        },
        "us-iso-east-1": {
          "description": "US ISO East"
        },
        "us-iso-west-1": {
          "description": "US ISO WEST"
        }
      }
    },
    {
      "id": "aws-iso-b",
      "outputs": {
        "dnsSuffix": "sc2s.sgov.gov",
        "dualStackDnsSuffix": "api.aws.scloud",
        "implicitGlobalRegion": "us-isob-east-1",
        "name": "aws-iso-b",
        "supportsDualStack": true,
        "supportsFIPS": true
      },
      "regionRegex": "^us\\-isob\\-\\w+\\-\\d+$",
      "regions": {
        "aws-iso-b-global": {
          "description": "aws-iso-b global region"
        },
        "us-isob-east-1": {
          "description": "US ISOB East (Ohio)"
        },
        "us-isob-west-1": {
          "description": "US ISOB West"
        }
      }
    },
    {
      "id": "aws-iso-e",
      "outputs": {
        "dnsSuffix": "cloud.adc-e.uk",
        "dualStackDnsSuffix": "api.cloud-aws.adc-e.uk",
        "implicitGlobalRegion": "eu-isoe-west-1",
        "name": "aws-iso-e",
        "supportsDualStack": true,
        "supportsFIPS": true
      },
      "regionRegex": "^eu\\-isoe\\-\\w+\\-\\d+$",
      "regions": {
        "aws-iso-e-global": {
          "description": "aws-iso-e global region"
        },
        "eu-isoe-west-1": {
          "description": "EU ISOE West"
        }
      }
    },
    {
      "id": "aws-iso-f",
      "outputs": {
        "dnsSuffix": "csp.hci.ic.gov",
        "dualStackDnsSuffix": "api.aws.hci.ic.gov",
        "implicitGlobalRegion": "us-isof-south-1",
        "name": "aws-iso-f",
        "supportsDualStack": true,
        "supportsFIPS": true
      },
      "regionRegex": "^us\\-isof\\-\\w+\\-\\d+$",
      "regions": {
        "aws-iso-f-global": {
          "description": "aws-iso-f global region"
        },
        "us-isof-east-1": {
          "description": "US ISOF EAST"
        },
        "us-isof-south-1": {
          "description": "US ISOF SOUTH"
        }
      }
    },
    {
      "id": "aws-us-gov",
      "outputs": {
        "dnsSuffix": "amazonaws.com",
        "dualStackDnsSuffix": "api.aws",
        "implicitGlobalRegion": "us-gov-west-1",
        "name": "aws-us-gov",
        "supportsDualStack": true,
        "supportsFIPS": true
      },
      "regionRegex": "^us\\-gov\\-\\w+\\-\\d+$",
      "regions": {
        "aws-us-gov-global": {
          "description": "aws-us-gov global region"
        },
        "us-gov-east-1": {
          "description": "AWS GovCloud (US-East)"
        },
        "us-gov-west-1": {
          "description": "AWS GovCloud (US-West)"
        }
      }
    }
  ],
  "version": "1.1"
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/lib/aws/partition.js
var selectedPartitionsInfo = partitionsInfo;
var selectedUserAgentPrefix = "";
var partition = (value) => {
  const { partitions } = selectedPartitionsInfo;
  for (const partition2 of partitions) {
    const { regions, outputs } = partition2;
    for (const [region, regionData] of Object.entries(regions)) {
      if (region === value) {
        return {
          ...outputs,
          ...regionData
        };
      }
    }
  }
  for (const partition2 of partitions) {
    const { regionRegex, outputs } = partition2;
    if (new RegExp(regionRegex).test(value)) {
      return {
        ...outputs
      };
    }
  }
  const DEFAULT_PARTITION = partitions.find((partition2) => partition2.id === "aws");
  if (!DEFAULT_PARTITION) {
    throw new Error("Provided region was not found in the partition array or regex, and default partition with id 'aws' doesn't exist.");
  }
  return {
    ...DEFAULT_PARTITION.outputs
  };
};
var setPartitionInfo = (partitionsInfo2, userAgentPrefix = "") => {
  selectedPartitionsInfo = partitionsInfo2;
  selectedUserAgentPrefix = userAgentPrefix;
};
var useDefaultPartitionInfo = () => {
  setPartitionInfo(partitionsInfo, "");
};
var getUserAgentPrefix = () => selectedUserAgentPrefix;

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-user-agent/check-features.js
init_esm_shims();
var ACCOUNT_ID_ENDPOINT_REGEX = /\d{12}\.ddb/;
async function checkFeatures(context, config, args) {
  const request = args.request;
  if (request?.headers?.["smithy-protocol"] === "rpc-v2-cbor") {
    setFeature2(context, "PROTOCOL_RPC_V2_CBOR", "M");
  }
  if (typeof config.retryStrategy === "function") {
    const retryStrategy = await config.retryStrategy();
    if (typeof retryStrategy.mode === "string") {
      switch (retryStrategy.mode) {
        case RETRY_MODES.ADAPTIVE:
          setFeature2(context, "RETRY_MODE_ADAPTIVE", "F");
          break;
        case RETRY_MODES.STANDARD:
          setFeature2(context, "RETRY_MODE_STANDARD", "E");
          break;
      }
    }
  }
  if (typeof config.accountIdEndpointMode === "function") {
    const endpointV2 = context.endpointV2;
    if (String(endpointV2?.url?.hostname).match(ACCOUNT_ID_ENDPOINT_REGEX)) {
      setFeature2(context, "ACCOUNT_ID_ENDPOINT", "O");
    }
    switch (await config.accountIdEndpointMode?.()) {
      case "disabled":
        setFeature2(context, "ACCOUNT_ID_MODE_DISABLED", "Q");
        break;
      case "preferred":
        setFeature2(context, "ACCOUNT_ID_MODE_PREFERRED", "P");
        break;
      case "required":
        setFeature2(context, "ACCOUNT_ID_MODE_REQUIRED", "R");
        break;
    }
  }
  const identity = context.__smithy_context?.selectedHttpAuthScheme?.identity;
  if (identity?.$source) {
    const credentials = identity;
    if (credentials.accountId) {
      setFeature2(context, "RESOLVED_ACCOUNT_ID", "T");
    }
    for (const [key, value] of Object.entries(credentials.$source ?? {})) {
      setFeature2(context, key, value);
    }
  }
}

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-user-agent/constants.js
init_esm_shims();
var USER_AGENT = "user-agent";
var X_AMZ_USER_AGENT = "x-amz-user-agent";
var SPACE = " ";
var UA_NAME_SEPARATOR = "/";
var UA_NAME_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w]/g;
var UA_VALUE_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w#]/g;
var UA_ESCAPE_CHAR = "-";

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-user-agent/encode-features.js
init_esm_shims();
var BYTE_LIMIT = 1024;
function encodeFeatures(features) {
  let buffer = "";
  for (const key in features) {
    const val = features[key];
    if (buffer.length + val.length + 1 <= BYTE_LIMIT) {
      if (buffer.length) {
        buffer += "," + val;
      } else {
        buffer += val;
      }
      continue;
    }
    break;
  }
  return buffer;
}

// node_modules/@aws-sdk/core/dist-es/submodules/client/middleware-user-agent/user-agent-middleware.js
var userAgentMiddleware = (options) => (next, context) => async (args) => {
  const { request } = args;
  if (!HttpRequest.isInstance(request)) {
    return next(args);
  }
  const { headers } = request;
  const userAgent = context?.userAgent?.map(escapeUserAgent) || [];
  const defaultUserAgent2 = (await options.defaultUserAgentProvider()).map(escapeUserAgent);
  await checkFeatures(context, options, args);
  const awsContext = context;
  defaultUserAgent2.push(`m/${encodeFeatures(Object.assign({}, context.__smithy_context?.features, awsContext.__aws_sdk_context?.features))}`);
  const customUserAgent = options?.customUserAgent?.map(escapeUserAgent) || [];
  const appId = await options.userAgentAppId();
  if (appId) {
    defaultUserAgent2.push(escapeUserAgent([`app`, `${appId}`]));
  }
  const prefix = getUserAgentPrefix();
  const sdkUserAgentValue = (prefix ? [prefix] : []).concat([...defaultUserAgent2, ...userAgent, ...customUserAgent]).join(SPACE);
  const normalUAValue = [
    ...defaultUserAgent2.filter((section) => section.startsWith("aws-sdk-")),
    ...customUserAgent
  ].join(SPACE);
  if (options.runtime !== "browser") {
    if (normalUAValue) {
      headers[X_AMZ_USER_AGENT] = headers[X_AMZ_USER_AGENT] ? `${headers[USER_AGENT]} ${normalUAValue}` : normalUAValue;
    }
    headers[USER_AGENT] = sdkUserAgentValue;
  } else {
    headers[X_AMZ_USER_AGENT] = sdkUserAgentValue;
  }
  return next({
    ...args,
    request
  });
};
var escapeUserAgent = (userAgentPair) => {
  const name = userAgentPair[0].split(UA_NAME_SEPARATOR).map((part) => part.replace(UA_NAME_ESCAPE_REGEX, UA_ESCAPE_CHAR)).join(UA_NAME_SEPARATOR);
  const version = userAgentPair[1]?.replace(UA_VALUE_ESCAPE_REGEX, UA_ESCAPE_CHAR);
  const prefixSeparatorIndex = name.indexOf(UA_NAME_SEPARATOR);
  const prefix = name.substring(0, prefixSeparatorIndex);
  let uaName = name.substring(prefixSeparatorIndex + 1);
  if (prefix === "api") {
    uaName = uaName.toLowerCase();
  }
  return [prefix, uaName, version].filter((item) => item && item.length > 0).reduce((acc, item, index) => {
    switch (index) {
      case 0:
        return item;
      case 1:
        return `${acc}/${item}`;
      default:
        return `${acc}#${item}`;
    }
  }, "");
};
var getUserAgentMiddlewareOptions = {
  name: "getUserAgentMiddleware",
  step: "build",
  priority: "low",
  tags: ["SET_USER_AGENT", "USER_AGENT"],
  override: true
};
var getUserAgentPlugin = (config) => ({
  applyToStack: (clientStack) => {
    clientStack.add(userAgentMiddleware(config), getUserAgentMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-node/defaultUserAgent.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-node/getRuntimeUserAgentPair.js
init_esm_shims();
var getRuntimeUserAgentPair = () => {
  const runtimesToCheck = ["deno", "bun", "llrt"];
  for (const runtime of runtimesToCheck) {
    if (versions[runtime]) {
      return [`md/${runtime}`, versions[runtime]];
    }
  }
  return ["md/nodejs", versions.node];
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-node/is-crt-available.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-node/crt-availability.js
init_esm_shims();
var crtAvailability = {
  isCrtAvailable: false
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-node/is-crt-available.js
var isCrtAvailable = () => {
  if (crtAvailability.isCrtAvailable) {
    return ["md/crt-avail"];
  }
  return null;
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-node/defaultUserAgent.js
var createDefaultUserAgentProvider = ({ serviceId, clientVersion }) => {
  const runtimeUserAgentPair = getRuntimeUserAgentPair();
  return async (config) => {
    const sections = [
      ["aws-sdk-js", clientVersion],
      ["ua", "2.1"],
      [`os/${platform()}`, release()],
      ["lang/js"],
      runtimeUserAgentPair
    ];
    const crtAvailable = isCrtAvailable();
    if (crtAvailable) {
      sections.push(crtAvailable);
    }
    if (serviceId) {
      sections.push([`api/${serviceId}`, clientVersion]);
    }
    if (env.AWS_EXECUTION_ENV) {
      sections.push([`exec-env/${env.AWS_EXECUTION_ENV}`]);
    }
    const appId = await config?.userAgentAppId?.();
    const resolvedUserAgent = appId ? [...sections, [`app/${appId}`]] : [...sections];
    return resolvedUserAgent;
  };
};
var defaultUserAgent = createDefaultUserAgentProvider;

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-node/nodeAppIdConfigOptions.js
init_esm_shims();
var UA_APP_ID_ENV_NAME = "AWS_SDK_UA_APP_ID";
var UA_APP_ID_INI_NAME = "sdk_ua_app_id";
var UA_APP_ID_INI_NAME_DEPRECATED = "sdk-ua-app-id";
var NODE_APP_ID_CONFIG_OPTIONS = {
  environmentVariableSelector: (env2) => env2[UA_APP_ID_ENV_NAME],
  configFileSelector: (profile) => profile[UA_APP_ID_INI_NAME] ?? profile[UA_APP_ID_INI_NAME_DEPRECATED],
  default: DEFAULT_UA_APP_ID
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-browser/defaultUserAgent.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-browser/createUserAgentStringParsingProvider.js
init_esm_shims();
var createUserAgentStringParsingProvider = ({ serviceId, clientVersion }) => async (config) => {
  const module = await import('./bowser-ONRGOS7L.mjs');
  const parse = module.parse ?? module.default.parse ?? (() => "");
  const parsedUA = typeof window !== "undefined" && window?.navigator?.userAgent ? parse(window.navigator.userAgent) : void 0;
  const sections = [
    ["aws-sdk-js", clientVersion],
    ["ua", "2.1"],
    [`os/${parsedUA?.os?.name || "other"}`, parsedUA?.os?.version],
    ["lang/js"],
    ["md/browser", `${parsedUA?.browser?.name ?? "unknown"}_${parsedUA?.browser?.version ?? "unknown"}`]
  ];
  if (serviceId) {
    sections.push([`api/${serviceId}`, clientVersion]);
  }
  const appId = await config?.userAgentAppId?.();
  if (appId) {
    sections.push([`app/${appId}`]);
  }
  return sections;
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-user-agent-browser/defaultUserAgent.js
var fallback = {
  os(ua) {
    if (/iPhone|iPad|iPod/.test(ua))
      return "iOS";
    if (/Macintosh|Mac OS X/.test(ua))
      return "macOS";
    if (/Windows NT/.test(ua))
      return "Windows";
    if (/Android/.test(ua))
      return "Android";
    if (/Linux/.test(ua))
      return "Linux";
    return void 0;
  },
  browser(ua) {
    if (/EdgiOS|EdgA|Edg\//.test(ua))
      return "Microsoft Edge";
    if (/Firefox\//.test(ua))
      return "Firefox";
    if (/Chrome\//.test(ua))
      return "Chrome";
    if (/Safari\//.test(ua))
      return "Safari";
    return void 0;
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/aws.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/lib/aws/isVirtualHostableS3Bucket.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/lib/isIpAddress.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/lib/aws/isVirtualHostableS3Bucket.js
var isVirtualHostableS3Bucket = (value, allowSubDomains = false) => {
  if (allowSubDomains) {
    for (const label of value.split(".")) {
      if (!isVirtualHostableS3Bucket(label)) {
        return false;
      }
    }
    return true;
  }
  if (!isValidHostLabel(value)) {
    return false;
  }
  if (value.length < 3 || value.length > 63) {
    return false;
  }
  if (value !== value.toLowerCase()) {
    return false;
  }
  if (isIpAddress(value)) {
    return false;
  }
  return true;
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/lib/aws/parseArn.js
init_esm_shims();
var ARN_DELIMITER = ":";
var RESOURCE_DELIMITER = "/";
var parseArn = (value) => {
  const segments = value.split(ARN_DELIMITER);
  if (segments.length < 6)
    return null;
  const [arn, partition2, service, region, accountId, ...resourcePath] = segments;
  if (arn !== "arn" || partition2 === "" || service === "" || resourcePath.join(ARN_DELIMITER) === "")
    return null;
  const resourceId = resourcePath.map((resource) => resource.split(RESOURCE_DELIMITER)).flat();
  return {
    partition: partition2,
    service,
    region,
    accountId,
    resourceId
  };
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/aws.js
var awsEndpointFunctions = {
  isVirtualHostableS3Bucket,
  parseArn,
  partition
};
customEndpointFunctions.aws = awsEndpointFunctions;

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/resolveEndpoint.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/resolveDefaultAwsRegionalEndpointsConfig.js
init_esm_shims();
var resolveDefaultAwsRegionalEndpointsConfig = (input) => {
  if (typeof input.endpointProvider !== "function") {
    throw new Error("@aws-sdk/util-endpoint - endpointProvider and endpoint missing in config for this client.");
  }
  const { endpoint } = input;
  if (endpoint === void 0) {
    input.endpoint = async () => {
      return toEndpointV12(input.endpointProvider({
        Region: typeof input.region === "function" ? await input.region() : input.region,
        UseDualStack: typeof input.useDualstackEndpoint === "function" ? await input.useDualstackEndpoint() : input.useDualstackEndpoint,
        UseFIPS: typeof input.useFipsEndpoint === "function" ? await input.useFipsEndpoint() : input.useFipsEndpoint,
        Endpoint: void 0
      }, { logger: input.logger }));
    };
  }
  return input;
};
var toEndpointV12 = (endpoint) => parseUrl(endpoint.url);

// node_modules/@aws-sdk/core/dist-es/submodules/client/util-endpoints/types/EndpointError.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/region-config-resolver/awsRegionConfig.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/client/region-config-resolver/stsRegionDefaultResolver.js
init_esm_shims();
function stsRegionDefaultResolver(loaderConfig = {}) {
  return loadConfig({
    ...NODE_REGION_CONFIG_OPTIONS,
    async default() {
      if (!warning.silence) {
        console.warn("@aws-sdk - WARN - default STS region of us-east-1 used. See @aws-sdk/credential-providers README and set a region explicitly.");
      }
      return "us-east-1";
    }
  }, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig });
}
var warning = {
  silence: false
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/region-config-resolver/extensions.js
init_esm_shims();
var getAwsRegionExtensionConfiguration = (runtimeConfig) => {
  return {
    setRegion(region) {
      runtimeConfig.region = region;
    },
    region() {
      return runtimeConfig.region;
    }
  };
};
var resolveAwsRegionExtensionConfiguration = (awsRegionExtensionConfiguration) => {
  return {
    region: awsRegionExtensionConfiguration.region()
  };
};

export { BinaryDecisionDiagram, DEFAULT_RETRY_MODE, DEFAULT_UA_APP_ID, DefaultIdentityProviderConfig, EndpointCache, EndpointError, NODE_APP_ID_CONFIG_OPTIONS, NODE_MAX_ATTEMPT_CONFIG_OPTIONS, NODE_RETRY_MODE_CONFIG_OPTIONS, NoAuthSigner, UA_APP_ID_ENV_NAME, UA_APP_ID_INI_NAME, awsEndpointFunctions, createDefaultUserAgentProvider, createUserAgentStringParsingProvider, crtAvailability, customEndpointFunctions, decideEndpoint, defaultUserAgent, doesIdentityRequireRefresh, emitWarningIfUnsupportedVersion, fallback, getAwsRegionExtensionConfiguration, getEndpointPlugin, getHostHeaderPlugin, getHttpAuthSchemeEndpointRuleSetPlugin, getHttpSigningPlugin, getLoggerPlugin, getLongPollPlugin, getRecursionDetectionPlugin, getRetryPlugin, getUserAgentMiddlewareOptions, getUserAgentPlugin, getUserAgentPrefix, hostHeaderMiddleware, hostHeaderMiddlewareOptions, isIdentityExpired, isIpAddress, isVirtualHostableS3Bucket, loggerMiddleware, loggerMiddlewareOptions, memoizeIdentityProvider, normalizeProvider2 as normalizeProvider, parseArn, partition, recursionDetectionMiddleware, recursionDetectionMiddlewareOptions, resolveAwsRegionExtensionConfiguration, resolveDefaultAwsRegionalEndpointsConfig, resolveEndpoint, resolveEndpointConfig, resolveHostHeaderConfig, resolveParams, resolveRetryConfig, resolveUserAgentConfig, setCredentialFeature, setFeature2 as setFeature, setPartitionInfo, setTokenFeature, state, stsRegionDefaultResolver, toEndpointV12 as toEndpointV1, useDefaultPartitionInfo, userAgentMiddleware, warning };
