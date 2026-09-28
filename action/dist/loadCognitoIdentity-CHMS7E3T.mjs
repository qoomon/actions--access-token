import { createRequire } from 'module';
import { package_default, NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, resolveAwsSdkSigV4Config, AwsJson1_1Protocol, AwsSdkSigV4Signer } from './chunk-PLMJQQI7.mjs';
import { NodeHttpHandler } from './chunk-E5WDDCGV.mjs';
import './chunk-W3GIPFDL.mjs';
import { Sha256Node } from './chunk-BSGV3LZS.mjs';
import { BinaryDecisionDiagram, EndpointCache, awsEndpointFunctions, customEndpointFunctions, getEndpointPlugin, resolveUserAgentConfig, resolveRetryConfig, resolveHostHeaderConfig, resolveEndpointConfig, getUserAgentPlugin, getRetryPlugin, getHostHeaderPlugin, getLoggerPlugin, getRecursionDetectionPlugin, getHttpAuthSchemeEndpointRuleSetPlugin, DefaultIdentityProviderConfig, getHttpSigningPlugin, emitWarningIfUnsupportedVersion as emitWarningIfUnsupportedVersion$1, NODE_APP_ID_CONFIG_OPTIONS, DEFAULT_RETRY_MODE, NODE_RETRY_MODE_CONFIG_OPTIONS, NODE_MAX_ATTEMPT_CONFIG_OPTIONS, createDefaultUserAgentProvider, getAwsRegionExtensionConfiguration, resolveAwsRegionExtensionConfiguration, NoAuthSigner, decideEndpoint } from './chunk-CNVAVDG2.mjs';
import { makeBuilder, ServiceException, Client, emitWarningIfUnsupportedVersion, getDefaultExtensionConfiguration, resolveDefaultRuntimeConfig, NoOpLogger, loadConfigsForDefaultMode } from './chunk-TTV4QKES.mjs';
import { getContentLengthPlugin, getHttpHandlerExtensionConfiguration, resolveHttpHandlerRuntimeConfig } from './chunk-CKKARQCR.mjs';
import { TypeRegistry, getSchemaSerdePlugin, streamCollector, calculateBodyLength, toUtf8, fromUtf8, toBase64, fromBase64 } from './chunk-2D7RHDR7.mjs';
import { resolveRegionConfig, resolveDefaultsModeConfig, loadConfig, NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, NODE_REGION_CONFIG_OPTIONS, NODE_REGION_CONFIG_FILE_OPTIONS } from './chunk-HAYTZHRA.mjs';
import { normalizeProvider, getSmithyContext, parseUrl } from './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';

createRequire(import.meta.url);

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/loadCognitoIdentity.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/CognitoIdentityClient.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/auth/httpAuthSchemeProvider.js
init_esm_shims();
var defaultCognitoIdentityHttpAuthSchemeParametersProvider = async (config, context, input) => {
  return {
    operation: getSmithyContext(context).operation,
    region: await normalizeProvider(config.region)() || (() => {
      throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
    })()
  };
};
function createAwsAuthSigv4HttpAuthOption(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "cognito-identity",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var defaultCognitoIdentityHttpAuthSchemeProvider = (authParameters) => {
  const options = [];
  switch (authParameters.operation) {
    case "GetCredentialsForIdentity":
      {
        options.push(createSmithyApiNoAuthHttpAuthOption());
        break;
      }
    case "GetId":
      {
        options.push(createSmithyApiNoAuthHttpAuthOption());
        break;
      }
    default: {
      options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
    }
  }
  return options;
};
var resolveHttpAuthSchemeConfig = (config) => {
  const config_0 = resolveAwsSdkSigV4Config(config);
  return Object.assign(config_0, {
    authSchemePreference: normalizeProvider(config.authSchemePreference ?? [])
  });
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/endpoint/EndpointParameters.js
init_esm_shims();
var resolveClientEndpointParameters = (options) => {
  return Object.assign(options, {
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "cognito-identity"
  });
};
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/runtimeConfig.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/runtimeConfig.shared.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/endpoint/endpointResolver.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/endpoint/bdd.js
init_esm_shims();
var m = "ref";
var a = -1;
var b = true;
var c = "isSet";
var d = "PartitionResult";
var e = "booleanEquals";
var f = "getAttr";
var g = "stringEquals";
var h = { [m]: "Endpoint" };
var i = { [m]: d };
var j = { [m]: "Region" };
var k = {};
var l = [j];
var _data = {
  conditions: [
    [c, [h]],
    [c, l],
    ["aws.partition", l, d],
    [e, [{ [m]: "UseFIPS" }, b]],
    [e, [{ fn: f, argv: [i, "supportsFIPS"] }, b]],
    [e, [{ [m]: "UseDualStack" }, b]],
    [e, [{ fn: f, argv: [i, "supportsDualStack"] }, b]],
    [g, [{ fn: f, argv: [i, "name"] }, "aws"]],
    [g, [j, "us-east-1"]],
    [g, [j, "us-east-2"]],
    [g, [j, "us-west-1"]],
    [g, [j, "us-west-2"]]
  ],
  results: [
    [a],
    [a, "Invalid Configuration: FIPS and custom endpoint are not supported"],
    [a, "Invalid Configuration: Dualstack and custom endpoint are not supported"],
    [h, k],
    ["https://cognito-identity-fips.us-east-1.amazonaws.com", k],
    ["https://cognito-identity-fips.us-east-2.amazonaws.com", k],
    ["https://cognito-identity-fips.us-west-1.amazonaws.com", k],
    ["https://cognito-identity-fips.us-west-2.amazonaws.com", k],
    ["https://cognito-identity-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", k],
    [a, "FIPS and DualStack are enabled, but this partition does not support one or both"],
    ["https://cognito-identity-fips.{Region}.{PartitionResult#dnsSuffix}", k],
    [a, "FIPS is enabled but this partition does not support FIPS"],
    ["https://cognito-identity.{Region}.amazonaws.com", k],
    ["https://cognito-identity.{Region}.{PartitionResult#dualStackDnsSuffix}", k],
    [a, "DualStack is enabled but this partition does not support DualStack"],
    ["https://cognito-identity.{Region}.{PartitionResult#dnsSuffix}", k],
    [a, "Invalid Configuration: Missing Region"]
  ]
};
var root = 2;
var r = 1e8;
var nodes = new Int32Array([
  -1,
  1,
  -1,
  0,
  17,
  3,
  1,
  4,
  r + 16,
  2,
  5,
  r + 16,
  3,
  9,
  6,
  5,
  7,
  r + 15,
  6,
  8,
  r + 14,
  7,
  r + 12,
  r + 13,
  4,
  11,
  10,
  5,
  r + 9,
  r + 11,
  5,
  12,
  r + 10,
  6,
  13,
  r + 9,
  8,
  r + 4,
  14,
  9,
  r + 5,
  15,
  10,
  r + 6,
  16,
  11,
  r + 7,
  r + 8,
  3,
  r + 1,
  18,
  5,
  r + 2,
  r + 3
]);
var bdd = BinaryDecisionDiagram.from(nodes, root, _data.conditions, _data.results);

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/endpoint/endpointResolver.js
var cache = new EndpointCache({
  size: 50,
  params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
});
var defaultEndpointResolver = (endpointParams, context = {}) => {
  return cache.get(endpointParams, () => decideEndpoint(bdd, {
    endpointParams,
    logger: context.logger
  }));
};
customEndpointFunctions.aws = awsEndpointFunctions;

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/schemas/schemas_0.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/models/CognitoIdentityServiceException.js
init_esm_shims();
var CognitoIdentityServiceException = class _CognitoIdentityServiceException extends ServiceException {
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _CognitoIdentityServiceException.prototype);
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/models/errors.js
init_esm_shims();
var ExternalServiceException = class _ExternalServiceException extends CognitoIdentityServiceException {
  name = "ExternalServiceException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ExternalServiceException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ExternalServiceException.prototype);
  }
};
var InternalErrorException = class _InternalErrorException extends CognitoIdentityServiceException {
  name = "InternalErrorException";
  $fault = "server";
  constructor(opts) {
    super({
      name: "InternalErrorException",
      $fault: "server",
      ...opts
    });
    Object.setPrototypeOf(this, _InternalErrorException.prototype);
  }
};
var InvalidIdentityPoolConfigurationException = class _InvalidIdentityPoolConfigurationException extends CognitoIdentityServiceException {
  name = "InvalidIdentityPoolConfigurationException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidIdentityPoolConfigurationException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidIdentityPoolConfigurationException.prototype);
  }
};
var InvalidParameterException = class _InvalidParameterException extends CognitoIdentityServiceException {
  name = "InvalidParameterException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidParameterException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidParameterException.prototype);
  }
};
var NotAuthorizedException = class _NotAuthorizedException extends CognitoIdentityServiceException {
  name = "NotAuthorizedException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "NotAuthorizedException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _NotAuthorizedException.prototype);
  }
};
var ResourceConflictException = class _ResourceConflictException extends CognitoIdentityServiceException {
  name = "ResourceConflictException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ResourceConflictException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ResourceConflictException.prototype);
  }
};
var ResourceNotFoundException = class _ResourceNotFoundException extends CognitoIdentityServiceException {
  name = "ResourceNotFoundException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ResourceNotFoundException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ResourceNotFoundException.prototype);
  }
};
var TooManyRequestsException = class _TooManyRequestsException extends CognitoIdentityServiceException {
  name = "TooManyRequestsException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "TooManyRequestsException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _TooManyRequestsException.prototype);
  }
};
var LimitExceededException = class _LimitExceededException extends CognitoIdentityServiceException {
  name = "LimitExceededException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "LimitExceededException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _LimitExceededException.prototype);
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/schemas/schemas_0.js
var _AI = "AccountId";
var _AKI = "AccessKeyId";
var _C = "Credentials";
var _CRA = "CustomRoleArn";
var _E = "Expiration";
var _ESE = "ExternalServiceException";
var _GCFI = "GetCredentialsForIdentity";
var _GCFII = "GetCredentialsForIdentityInput";
var _GCFIR = "GetCredentialsForIdentityResponse";
var _GI = "GetId";
var _GII = "GetIdInput";
var _GIR = "GetIdResponse";
var _IEE = "InternalErrorException";
var _II = "IdentityId";
var _IIPCE = "InvalidIdentityPoolConfigurationException";
var _IPE = "InvalidParameterException";
var _IPI = "IdentityPoolId";
var _IPT = "IdentityProviderToken";
var _L = "Logins";
var _LEE = "LimitExceededException";
var _LM = "LoginsMap";
var _NAE = "NotAuthorizedException";
var _RCE = "ResourceConflictException";
var _RNFE = "ResourceNotFoundException";
var _SK = "SecretKey";
var _SKS = "SecretKeyString";
var _ST = "SessionToken";
var _TMRE = "TooManyRequestsException";
var _c = "client";
var _e = "error";
var _hE = "httpError";
var _m = "message";
var _s = "smithy.ts.sdk.synthetic.com.amazonaws.cognitoidentity";
var _se = "server";
var n0 = "com.amazonaws.cognitoidentity";
var _s_registry = TypeRegistry.for(_s);
var CognitoIdentityServiceException$ = [-3, _s, "CognitoIdentityServiceException", 0, [], []];
_s_registry.registerError(CognitoIdentityServiceException$, CognitoIdentityServiceException);
var n0_registry = TypeRegistry.for(n0);
var ExternalServiceException$ = [
  -3,
  n0,
  _ESE,
  { [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(ExternalServiceException$, ExternalServiceException);
var InternalErrorException$ = [
  -3,
  n0,
  _IEE,
  { [_e]: _se },
  [_m],
  [0]
];
n0_registry.registerError(InternalErrorException$, InternalErrorException);
var InvalidIdentityPoolConfigurationException$ = [
  -3,
  n0,
  _IIPCE,
  { [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(InvalidIdentityPoolConfigurationException$, InvalidIdentityPoolConfigurationException);
var InvalidParameterException$ = [
  -3,
  n0,
  _IPE,
  { [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(InvalidParameterException$, InvalidParameterException);
var LimitExceededException$ = [
  -3,
  n0,
  _LEE,
  { [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(LimitExceededException$, LimitExceededException);
var NotAuthorizedException$ = [
  -3,
  n0,
  _NAE,
  { [_e]: _c, [_hE]: 403 },
  [_m],
  [0]
];
n0_registry.registerError(NotAuthorizedException$, NotAuthorizedException);
var ResourceConflictException$ = [
  -3,
  n0,
  _RCE,
  { [_e]: _c, [_hE]: 409 },
  [_m],
  [0]
];
n0_registry.registerError(ResourceConflictException$, ResourceConflictException);
var ResourceNotFoundException$ = [
  -3,
  n0,
  _RNFE,
  { [_e]: _c, [_hE]: 404 },
  [_m],
  [0]
];
n0_registry.registerError(ResourceNotFoundException$, ResourceNotFoundException);
var TooManyRequestsException$ = [
  -3,
  n0,
  _TMRE,
  { [_e]: _c, [_hE]: 429 },
  [_m],
  [0]
];
n0_registry.registerError(TooManyRequestsException$, TooManyRequestsException);
var errorTypeRegistries = [
  _s_registry,
  n0_registry
];
var IdentityProviderToken = [0, n0, _IPT, 8, 0];
var SecretKeyString = [0, n0, _SKS, 8, 0];
var Credentials$ = [
  3,
  n0,
  _C,
  0,
  [_AKI, _SK, _ST, _E],
  [0, [() => SecretKeyString, 0], 0, 4]
];
var GetCredentialsForIdentityInput$ = [
  3,
  n0,
  _GCFII,
  0,
  [_II, _L, _CRA],
  [0, [() => LoginsMap, 0], 0],
  1
];
var GetCredentialsForIdentityResponse$ = [
  3,
  n0,
  _GCFIR,
  0,
  [_II, _C],
  [0, [() => Credentials$, 0]]
];
var GetIdInput$ = [
  3,
  n0,
  _GII,
  0,
  [_IPI, _AI, _L],
  [0, 0, [() => LoginsMap, 0]],
  1
];
var GetIdResponse$ = [
  3,
  n0,
  _GIR,
  0,
  [_II],
  [0]
];
var LoginsMap = [
  2,
  n0,
  _LM,
  0,
  [
    0,
    0
  ],
  [
    () => IdentityProviderToken,
    0
  ]
];
var GetCredentialsForIdentity$ = [
  9,
  n0,
  _GCFI,
  0,
  () => GetCredentialsForIdentityInput$,
  () => GetCredentialsForIdentityResponse$
];
var GetId$ = [
  9,
  n0,
  _GI,
  0,
  () => GetIdInput$,
  () => GetIdResponse$
];

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/runtimeConfig.shared.js
var getRuntimeConfig = (config) => {
  return {
    apiVersion: "2014-06-30",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
    extensions: config?.extensions ?? [],
    httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultCognitoIdentityHttpAuthSchemeProvider,
    httpAuthSchemes: config?.httpAuthSchemes ?? [
      {
        schemeId: "aws.auth#sigv4",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
        signer: new AwsSdkSigV4Signer()
      },
      {
        schemeId: "smithy.api#noAuth",
        identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
        signer: new NoAuthSigner()
      }
    ],
    logger: config?.logger ?? new NoOpLogger(),
    protocol: config?.protocol ?? AwsJson1_1Protocol,
    protocolSettings: config?.protocolSettings ?? {
      defaultNamespace: "com.amazonaws.cognitoidentity",
      errorTypeRegistries,
      xmlNamespace: "http://cognito-identity.amazonaws.com/doc/2014-06-30/",
      version: "2014-06-30",
      serviceTarget: "AWSCognitoIdentityService"
    },
    serviceId: config?.serviceId ?? "Cognito Identity",
    sha256: config?.sha256 ?? Sha256Node,
    urlParser: config?.urlParser ?? parseUrl,
    utf8Decoder: config?.utf8Decoder ?? fromUtf8,
    utf8Encoder: config?.utf8Encoder ?? toUtf8
  };
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/runtimeConfig.js
var getRuntimeConfig2 = (config) => {
  emitWarningIfUnsupportedVersion(process.version);
  const defaultsMode = resolveDefaultsModeConfig(config);
  const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
  const clientSharedValues = getRuntimeConfig(config);
  emitWarningIfUnsupportedVersion$1(process.version);
  const loaderConfig = {
    profile: config?.profile,
    logger: clientSharedValues.logger
  };
  return {
    ...clientSharedValues,
    ...config,
    runtime: "node",
    defaultsMode,
    authSchemePreference: config?.authSchemePreference ?? loadConfig(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
    bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
    defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({ serviceId: clientSharedValues.serviceId, clientVersion: package_default.version }),
    maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
    region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
    requestHandler: NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
    retryMode: config?.retryMode ?? loadConfig({
      ...NODE_RETRY_MODE_CONFIG_OPTIONS,
      default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE
    }, config),
    streamCollector: config?.streamCollector ?? streamCollector,
    useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
    useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
    userAgentAppId: config?.userAgentAppId ?? loadConfig(NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
  };
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/runtimeExtensions.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/auth/httpAuthExtensionConfiguration.js
init_esm_shims();
var getHttpAuthExtensionConfiguration = (runtimeConfig) => {
  const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
  let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
  let _credentials = runtimeConfig.credentials;
  return {
    setHttpAuthScheme(httpAuthScheme) {
      const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
      if (index === -1) {
        _httpAuthSchemes.push(httpAuthScheme);
      } else {
        _httpAuthSchemes.splice(index, 1, httpAuthScheme);
      }
    },
    httpAuthSchemes() {
      return _httpAuthSchemes;
    },
    setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
      _httpAuthSchemeProvider = httpAuthSchemeProvider;
    },
    httpAuthSchemeProvider() {
      return _httpAuthSchemeProvider;
    },
    setCredentials(credentials) {
      _credentials = credentials;
    },
    credentials() {
      return _credentials;
    }
  };
};
var resolveHttpAuthRuntimeConfig = (config) => {
  return {
    httpAuthSchemes: config.httpAuthSchemes(),
    httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
    credentials: config.credentials()
  };
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/runtimeExtensions.js
var resolveRuntimeExtensions = (runtimeConfig, extensions) => {
  const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/CognitoIdentityClient.js
var CognitoIdentityClient = class extends Client {
  config;
  constructor(...[configuration]) {
    const _config_0 = getRuntimeConfig2(configuration || {});
    super(_config_0);
    this.initConfig = _config_0;
    const _config_1 = resolveClientEndpointParameters(_config_0);
    const _config_2 = resolveUserAgentConfig(_config_1);
    const _config_3 = resolveRetryConfig(_config_2);
    const _config_4 = resolveRegionConfig(_config_3);
    const _config_5 = resolveHostHeaderConfig(_config_4);
    const _config_6 = resolveEndpointConfig(_config_5);
    const _config_7 = resolveHttpAuthSchemeConfig(_config_6);
    const _config_8 = resolveRuntimeExtensions(_config_7, configuration?.extensions || []);
    this.config = _config_8;
    this.middlewareStack.use(getSchemaSerdePlugin(this.config));
    this.middlewareStack.use(getUserAgentPlugin(this.config));
    this.middlewareStack.use(getRetryPlugin(this.config));
    this.middlewareStack.use(getContentLengthPlugin(this.config));
    this.middlewareStack.use(getHostHeaderPlugin(this.config));
    this.middlewareStack.use(getLoggerPlugin(this.config));
    this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
    this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
      httpAuthSchemeParametersProvider: defaultCognitoIdentityHttpAuthSchemeParametersProvider,
      identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
        "aws.auth#sigv4": config.credentials
      })
    }));
    this.middlewareStack.use(getHttpSigningPlugin(this.config));
  }
  destroy() {
    super.destroy();
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/commands/GetCredentialsForIdentityCommand.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/commandBuilder.js
init_esm_shims();
var command = makeBuilder(commonParams, "AWSCognitoIdentityService", "CognitoIdentityClient", getEndpointPlugin);
var _ep0 = {};
var _mw0 = (Command, cs, config, o) => [];

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/commands/GetCredentialsForIdentityCommand.js
var GetCredentialsForIdentityCommand = class extends command(_ep0, _mw0, "GetCredentialsForIdentity", GetCredentialsForIdentity$) {
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/cognito-identity/commands/GetIdCommand.js
init_esm_shims();
var GetIdCommand = class extends command(_ep0, _mw0, "GetId", GetId$) {
};

export { CognitoIdentityClient, GetCredentialsForIdentityCommand, GetIdCommand };
