import { createRequire } from 'module';
import { package_default, NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, resolveAwsSdkSigV4Config, AwsRestJsonProtocol, AwsSdkSigV4Signer } from './chunk-PLMJQQI7.mjs';
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

// node_modules/@aws-sdk/credential-provider-sso/dist-es/loadSso.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/SSOClient.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/auth/httpAuthSchemeProvider.js
init_esm_shims();
var defaultSSOHttpAuthSchemeParametersProvider = async (config, context, input) => {
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
      name: "awsssoportal",
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
var defaultSSOHttpAuthSchemeProvider = (authParameters) => {
  const options = [];
  switch (authParameters.operation) {
    case "GetRoleCredentials":
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/endpoint/EndpointParameters.js
init_esm_shims();
var resolveClientEndpointParameters = (options) => {
  return Object.assign(options, {
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "awsssoportal"
  });
};
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/runtimeConfig.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/runtimeConfig.shared.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/endpoint/endpointResolver.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/endpoint/bdd.js
init_esm_shims();
var k = "ref";
var a = -1;
var b = true;
var c = "isSet";
var d = "PartitionResult";
var e = "booleanEquals";
var f = "getAttr";
var g = { [k]: "Endpoint" };
var h = { [k]: d };
var i = {};
var j = [{ [k]: "Region" }];
var _data = {
  conditions: [
    [c, [g]],
    [c, j],
    ["aws.partition", j, d],
    [e, [{ [k]: "UseFIPS" }, b]],
    [e, [{ [k]: "UseDualStack" }, b]],
    [e, [{ fn: f, argv: [h, "supportsDualStack"] }, b]],
    [e, [{ fn: f, argv: [h, "supportsFIPS"] }, b]],
    ["stringEquals", [{ fn: f, argv: [h, "name"] }, "aws-us-gov"]]
  ],
  results: [
    [a],
    [a, "Invalid Configuration: FIPS and custom endpoint are not supported"],
    [a, "Invalid Configuration: Dualstack and custom endpoint are not supported"],
    [g, i],
    ["https://portal.sso-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", i],
    [a, "FIPS and DualStack are enabled, but this partition does not support one or both"],
    ["https://portal.sso.{Region}.amazonaws.com", i],
    ["https://portal.sso-fips.{Region}.{PartitionResult#dnsSuffix}", i],
    [a, "FIPS is enabled but this partition does not support FIPS"],
    ["https://portal.sso.{Region}.{PartitionResult#dualStackDnsSuffix}", i],
    [a, "DualStack is enabled but this partition does not support DualStack"],
    ["https://portal.sso.{Region}.{PartitionResult#dnsSuffix}", i],
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
  13,
  3,
  1,
  4,
  r + 12,
  2,
  5,
  r + 12,
  3,
  8,
  6,
  4,
  7,
  r + 11,
  5,
  r + 9,
  r + 10,
  4,
  11,
  9,
  6,
  10,
  r + 8,
  7,
  r + 6,
  r + 7,
  5,
  12,
  r + 5,
  6,
  r + 4,
  r + 5,
  3,
  r + 1,
  14,
  4,
  r + 2,
  r + 3
]);
var bdd = BinaryDecisionDiagram.from(nodes, root, _data.conditions, _data.results);

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/endpoint/endpointResolver.js
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/schemas/schemas_0.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/models/errors.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/models/SSOServiceException.js
init_esm_shims();
var SSOServiceException = class _SSOServiceException extends ServiceException {
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _SSOServiceException.prototype);
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/models/errors.js
var InvalidRequestException = class _InvalidRequestException extends SSOServiceException {
  name = "InvalidRequestException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidRequestException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidRequestException.prototype);
  }
};
var ResourceNotFoundException = class _ResourceNotFoundException extends SSOServiceException {
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
var TooManyRequestsException = class _TooManyRequestsException extends SSOServiceException {
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
var UnauthorizedException = class _UnauthorizedException extends SSOServiceException {
  name = "UnauthorizedException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "UnauthorizedException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _UnauthorizedException.prototype);
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/schemas/schemas_0.js
var _ATT = "AccessTokenType";
var _GRC = "GetRoleCredentials";
var _GRCR = "GetRoleCredentialsRequest";
var _GRCRe = "GetRoleCredentialsResponse";
var _IRE = "InvalidRequestException";
var _RC = "RoleCredentials";
var _RNFE = "ResourceNotFoundException";
var _SAKT = "SecretAccessKeyType";
var _STT = "SessionTokenType";
var _TMRE = "TooManyRequestsException";
var _UE = "UnauthorizedException";
var _aI = "accountId";
var _aKI = "accessKeyId";
var _aT = "accessToken";
var _ai = "account_id";
var _c = "client";
var _e = "error";
var _ex = "expiration";
var _h = "http";
var _hE = "httpError";
var _hH = "httpHeader";
var _hQ = "httpQuery";
var _m = "message";
var _rC = "roleCredentials";
var _rN = "roleName";
var _rn = "role_name";
var _s = "smithy.ts.sdk.synthetic.com.amazonaws.sso";
var _sAK = "secretAccessKey";
var _sT = "sessionToken";
var _xasbt = "x-amz-sso_bearer_token";
var n0 = "com.amazonaws.sso";
var _s_registry = TypeRegistry.for(_s);
var SSOServiceException$ = [-3, _s, "SSOServiceException", 0, [], []];
_s_registry.registerError(SSOServiceException$, SSOServiceException);
var n0_registry = TypeRegistry.for(n0);
var InvalidRequestException$ = [
  -3,
  n0,
  _IRE,
  { [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(InvalidRequestException$, InvalidRequestException);
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
var UnauthorizedException$ = [
  -3,
  n0,
  _UE,
  { [_e]: _c, [_hE]: 401 },
  [_m],
  [0]
];
n0_registry.registerError(UnauthorizedException$, UnauthorizedException);
var errorTypeRegistries = [
  _s_registry,
  n0_registry
];
var AccessTokenType = [0, n0, _ATT, 8, 0];
var SecretAccessKeyType = [0, n0, _SAKT, 8, 0];
var SessionTokenType = [0, n0, _STT, 8, 0];
var GetRoleCredentialsRequest$ = [
  3,
  n0,
  _GRCR,
  0,
  [_rN, _aI, _aT],
  [[0, { [_hQ]: _rn }], [0, { [_hQ]: _ai }], [() => AccessTokenType, { [_hH]: _xasbt }]],
  3
];
var GetRoleCredentialsResponse$ = [
  3,
  n0,
  _GRCRe,
  0,
  [_rC],
  [[() => RoleCredentials$, 0]]
];
var RoleCredentials$ = [
  3,
  n0,
  _RC,
  0,
  [_aKI, _sAK, _sT, _ex],
  [0, [() => SecretAccessKeyType, 0], [() => SessionTokenType, 0], 1]
];
var GetRoleCredentials$ = [
  9,
  n0,
  _GRC,
  { [_h]: ["GET", "/federation/credentials", 200] },
  () => GetRoleCredentialsRequest$,
  () => GetRoleCredentialsResponse$
];

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/runtimeConfig.shared.js
var getRuntimeConfig = (config) => {
  return {
    apiVersion: "2019-06-10",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
    extensions: config?.extensions ?? [],
    httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSSOHttpAuthSchemeProvider,
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
    protocol: config?.protocol ?? AwsRestJsonProtocol,
    protocolSettings: config?.protocolSettings ?? {
      defaultNamespace: "com.amazonaws.sso",
      errorTypeRegistries,
      version: "2019-06-10",
      serviceTarget: "SWBPortalService"
    },
    serviceId: config?.serviceId ?? "SSO",
    sha256: config?.sha256 ?? Sha256Node,
    urlParser: config?.urlParser ?? parseUrl,
    utf8Decoder: config?.utf8Decoder ?? fromUtf8,
    utf8Encoder: config?.utf8Encoder ?? toUtf8
  };
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/runtimeConfig.js
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/runtimeExtensions.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/auth/httpAuthExtensionConfiguration.js
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/runtimeExtensions.js
var resolveRuntimeExtensions = (runtimeConfig, extensions) => {
  const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/SSOClient.js
var SSOClient = class extends Client {
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
      httpAuthSchemeParametersProvider: defaultSSOHttpAuthSchemeParametersProvider,
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/commands/GetRoleCredentialsCommand.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/commandBuilder.js
init_esm_shims();
var command = makeBuilder(commonParams, "SWBPortalService", "SSOClient", getEndpointPlugin);
var _ep0 = {};
var _mw0 = (Command, cs, config, o) => [];

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso/commands/GetRoleCredentialsCommand.js
var GetRoleCredentialsCommand = class extends command(_ep0, _mw0, "GetRoleCredentials", GetRoleCredentials$) {
};

export { GetRoleCredentialsCommand, SSOClient };
