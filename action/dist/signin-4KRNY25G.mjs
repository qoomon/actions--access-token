import { createRequire } from 'module';
import { package_default, NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, resolveAwsSdkSigV4Config, AwsRestJsonProtocol, AwsSdkSigV4Signer } from './chunk-PLMJQQI7.mjs';
import { NodeHttpHandler } from './chunk-E5WDDCGV.mjs';
import './chunk-W3GIPFDL.mjs';
import { Sha256Node } from './chunk-BSGV3LZS.mjs';
import { BinaryDecisionDiagram, EndpointCache, awsEndpointFunctions, customEndpointFunctions, getEndpointPlugin, resolveUserAgentConfig, resolveRetryConfig, resolveHostHeaderConfig, resolveEndpointConfig, getUserAgentPlugin, getRetryPlugin, getHostHeaderPlugin, getLoggerPlugin, getRecursionDetectionPlugin, getHttpAuthSchemeEndpointRuleSetPlugin, DefaultIdentityProviderConfig, getHttpSigningPlugin, emitWarningIfUnsupportedVersion as emitWarningIfUnsupportedVersion$1, NODE_APP_ID_CONFIG_OPTIONS, DEFAULT_RETRY_MODE, NODE_RETRY_MODE_CONFIG_OPTIONS, NODE_MAX_ATTEMPT_CONFIG_OPTIONS, createDefaultUserAgentProvider, getAwsRegionExtensionConfiguration, resolveAwsRegionExtensionConfiguration, NoAuthSigner, decideEndpoint } from './chunk-CNVAVDG2.mjs';
import { makeBuilder, createAggregatedClient, ServiceException, Client, emitWarningIfUnsupportedVersion, getDefaultExtensionConfiguration, resolveDefaultRuntimeConfig, NoOpLogger, loadConfigsForDefaultMode } from './chunk-TTV4QKES.mjs';
export { Command as $Command, Client as __Client } from './chunk-TTV4QKES.mjs';
import { getContentLengthPlugin, getHttpHandlerExtensionConfiguration, resolveHttpHandlerRuntimeConfig } from './chunk-CKKARQCR.mjs';
import { TypeRegistry, getSchemaSerdePlugin, streamCollector, calculateBodyLength, toUtf8, fromUtf8, toBase64, fromBase64 } from './chunk-2D7RHDR7.mjs';
import { resolveRegionConfig, resolveDefaultsModeConfig, loadConfig, NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, NODE_REGION_CONFIG_OPTIONS, NODE_REGION_CONFIG_FILE_OPTIONS } from './chunk-HAYTZHRA.mjs';
import { normalizeProvider, getSmithyContext, parseUrl } from './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';

createRequire(import.meta.url);

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/index.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/SigninClient.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthSchemeProvider.js
init_esm_shims();
var defaultSigninHttpAuthSchemeParametersProvider = async (config, context, input) => {
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
      name: "signin",
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
var defaultSigninHttpAuthSchemeProvider = (authParameters) => {
  const options = [];
  switch (authParameters.operation) {
    case "CreateOAuth2Token":
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/EndpointParameters.js
init_esm_shims();
var resolveClientEndpointParameters = (options) => {
  return Object.assign(options, {
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "signin"
  });
};
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.shared.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/endpointResolver.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/bdd.js
init_esm_shims();
var s = "ref";
var a = -1;
var b = false;
var c = true;
var d = "isSet";
var e = "booleanEquals";
var f = "coalesce";
var g = "PartitionResult";
var h = "stringEquals";
var i = "getAttr";
var j = "https://signin.{Region}.{PartitionResult#dualStackDnsSuffix}";
var k = { [s]: "Endpoint" };
var l = { "fn": i, "argv": [{ [s]: g }, "name"] };
var m = { [s]: "Region" };
var n = { [s]: g };
var o = { "authSchemes": [{ "name": "sigv4", "signingName": "signin", "signingRegion": "{Region}" }] };
var p = {};
var q = [m];
var _data = {
  conditions: [
    [d, q],
    [e, [{ fn: f, argv: [{ [s]: "IsControlPlane" }, b] }, c]],
    [d, [k]],
    ["aws.partition", q, g],
    [e, [{ [s]: "UseFIPS" }, c]],
    [h, [l, "aws"]],
    [e, [{ fn: f, argv: [{ [s]: "IsOAuthEndpoint" }, b] }, c]],
    [e, [{ [s]: "UseDualStack" }, c]],
    [h, [l, "aws-cn"]],
    [h, [m, "us-gov-west-1"]],
    [h, [l, "aws-us-gov"]],
    [e, [{ fn: i, argv: [n, "supportsFIPS"] }, c]],
    [h, [l, "aws-iso"]],
    [h, [l, "aws-iso-b"]],
    [h, [l, "aws-iso-f"]],
    [h, [l, "aws-iso-e"]],
    [h, [l, "aws-eusc"]],
    [e, [{ fn: i, argv: [n, "supportsDualStack"] }, c]]
  ],
  results: [
    [a],
    ["https://signin.{Region}.api.aws", o],
    ["https://signin.{Region}.api.amazonwebservices.com.cn", o],
    [j, o],
    [a, "FIPS endpoints are not supported for OAuth operations. Disable FIPS or use a non-OAuth operation."],
    ["https://{Region}.oauth.signin.aws", o],
    ["https://{Region}.signin.aws.amazon.com", p],
    ["https://{Region}.signin.amazonaws.cn", p],
    ["https://{Region}.signin.amazonaws-us-gov.com", p],
    ["https://{Region}.signin.c2shome.ic.gov", p],
    ["https://{Region}.signin.sc2shome.sgov.gov", p],
    ["https://{Region}.signin.csphome.hci.ic.gov", p],
    ["https://{Region}.signin.csphome.adc-e.uk", p],
    ["https://{Region}.signin.amazonaws-eusc.eu", p],
    ["https://signin-fips.amazonaws-us-gov.com", p],
    ["https://{Region}.signin-fips.amazonaws-us-gov.com", p],
    ["https://{Region}.signin.{PartitionResult#dnsSuffix}", p],
    [a, "Invalid Configuration: FIPS and custom endpoint are not supported"],
    [a, "Invalid Configuration: Dualstack and custom endpoint are not supported"],
    [k, p],
    ["https://signin-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", p],
    [a, "FIPS and DualStack are enabled, but this partition does not support one or both"],
    ["https://signin-fips.{Region}.{PartitionResult#dnsSuffix}", p],
    [a, "FIPS is enabled but this partition does not support FIPS"],
    [j, p],
    [a, "DualStack is enabled but this partition does not support DualStack"],
    ["https://signin.{Region}.{PartitionResult#dnsSuffix}", p],
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
  6,
  3,
  2,
  36,
  4,
  4,
  5,
  r + 27,
  6,
  r + 4,
  r + 27,
  1,
  29,
  7,
  2,
  36,
  8,
  3,
  9,
  31,
  4,
  22,
  10,
  5,
  19,
  11,
  7,
  21,
  12,
  8,
  r + 7,
  13,
  10,
  r + 8,
  14,
  12,
  r + 9,
  15,
  13,
  r + 10,
  16,
  14,
  r + 11,
  17,
  15,
  r + 12,
  18,
  16,
  r + 13,
  r + 16,
  6,
  r + 5,
  20,
  7,
  21,
  r + 6,
  17,
  r + 24,
  r + 25,
  6,
  r + 4,
  23,
  7,
  27,
  24,
  9,
  r + 14,
  25,
  10,
  r + 15,
  26,
  11,
  r + 22,
  r + 23,
  11,
  28,
  r + 21,
  17,
  r + 20,
  r + 21,
  2,
  35,
  30,
  3,
  39,
  31,
  4,
  32,
  r + 27,
  6,
  r + 4,
  33,
  7,
  r + 27,
  34,
  9,
  r + 14,
  r + 27,
  3,
  39,
  36,
  4,
  38,
  37,
  7,
  r + 18,
  r + 19,
  6,
  r + 4,
  r + 17,
  5,
  r + 1,
  40,
  8,
  r + 2,
  r + 3
]);
var bdd = BinaryDecisionDiagram.from(nodes, root, _data.conditions, _data.results);

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/endpointResolver.js
var cache = new EndpointCache({
  size: 50,
  params: ["Endpoint", "IsControlPlane", "IsOAuthEndpoint", "Region", "UseDualStack", "UseFIPS"]
});
var defaultEndpointResolver = (endpointParams, context = {}) => {
  return cache.get(endpointParams, () => decideEndpoint(bdd, {
    endpointParams,
    logger: context.logger
  }));
};
customEndpointFunctions.aws = awsEndpointFunctions;

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/schemas/schemas_0.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/errors.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/SigninServiceException.js
init_esm_shims();
var SigninServiceException = class _SigninServiceException extends ServiceException {
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _SigninServiceException.prototype);
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/errors.js
var AccessDeniedException = class _AccessDeniedException extends SigninServiceException {
  name = "AccessDeniedException";
  $fault = "client";
  error;
  constructor(opts) {
    super({
      name: "AccessDeniedException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _AccessDeniedException.prototype);
    this.error = opts.error;
  }
};
var InternalServerException = class _InternalServerException extends SigninServiceException {
  name = "InternalServerException";
  $fault = "server";
  error;
  constructor(opts) {
    super({
      name: "InternalServerException",
      $fault: "server",
      ...opts
    });
    Object.setPrototypeOf(this, _InternalServerException.prototype);
    this.error = opts.error;
  }
};
var TooManyRequestsError = class _TooManyRequestsError extends SigninServiceException {
  name = "TooManyRequestsError";
  $fault = "client";
  error;
  constructor(opts) {
    super({
      name: "TooManyRequestsError",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _TooManyRequestsError.prototype);
    this.error = opts.error;
  }
};
var ValidationException = class _ValidationException extends SigninServiceException {
  name = "ValidationException";
  $fault = "client";
  error;
  constructor(opts) {
    super({
      name: "ValidationException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ValidationException.prototype);
    this.error = opts.error;
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/schemas/schemas_0.js
var _ADE = "AccessDeniedException";
var _AT = "AccessToken";
var _COAT = "CreateOAuth2Token";
var _COATR = "CreateOAuth2TokenRequest";
var _COATRB = "CreateOAuth2TokenRequestBody";
var _COATRBr = "CreateOAuth2TokenResponseBody";
var _COATRr = "CreateOAuth2TokenResponse";
var _COATWIAM = "CreateOAuth2TokenWithIAM";
var _COATWIAMR = "CreateOAuth2TokenWithIAMRequest";
var _COATWIAMRr = "CreateOAuth2TokenWithIAMResponse";
var _ISE = "InternalServerException";
var _OAAT = "OAuthAccessToken";
var _RT = "RefreshToken";
var _TMRE = "TooManyRequestsError";
var _VE = "ValidationException";
var _aKI = "accessKeyId";
var _aT = "accessToken";
var _at = "access_token";
var _c = "client";
var _cI = "clientId";
var _cV = "codeVerifier";
var _co = "code";
var _e = "error";
var _eI = "expiresIn";
var _ei = "expires_in";
var _gT = "grantType";
var _gt = "grant_type";
var _h = "http";
var _hE = "httpError";
var _iT = "idToken";
var _jN = "jsonName";
var _m = "message";
var _r = "resource";
var _rT = "refreshToken";
var _rU = "redirectUri";
var _s = "smithy.ts.sdk.synthetic.com.amazonaws.signin";
var _sAK = "secretAccessKey";
var _sT = "sessionToken";
var _se = "server";
var _tI = "tokenInput";
var _tO = "tokenOutput";
var _tT = "tokenType";
var _tt = "token_type";
var n0 = "com.amazonaws.signin";
var _s_registry = TypeRegistry.for(_s);
var SigninServiceException$ = [-3, _s, "SigninServiceException", 0, [], []];
_s_registry.registerError(SigninServiceException$, SigninServiceException);
var n0_registry = TypeRegistry.for(n0);
var AccessDeniedException$ = [
  -3,
  n0,
  _ADE,
  { [_e]: _c },
  [_e, _m],
  [0, 0],
  2
];
n0_registry.registerError(AccessDeniedException$, AccessDeniedException);
var InternalServerException$ = [
  -3,
  n0,
  _ISE,
  { [_e]: _se, [_hE]: 500 },
  [_e, _m],
  [0, 0],
  2
];
n0_registry.registerError(InternalServerException$, InternalServerException);
var TooManyRequestsError$ = [
  -3,
  n0,
  _TMRE,
  { [_e]: _c, [_hE]: 429 },
  [_e, _m],
  [0, 0],
  2
];
n0_registry.registerError(TooManyRequestsError$, TooManyRequestsError);
var ValidationException$ = [
  -3,
  n0,
  _VE,
  { [_e]: _c, [_hE]: 400 },
  [_e, _m],
  [0, 0],
  2
];
n0_registry.registerError(ValidationException$, ValidationException);
var errorTypeRegistries = [
  _s_registry,
  n0_registry
];
var OAuthAccessToken = [0, n0, _OAAT, 8, 0];
var RefreshToken = [0, n0, _RT, 8, 0];
var AccessToken$ = [
  3,
  n0,
  _AT,
  8,
  [_aKI, _sAK, _sT],
  [[0, { [_jN]: _aKI }], [0, { [_jN]: _sAK }], [0, { [_jN]: _sT }]],
  3
];
var CreateOAuth2TokenRequest$ = [
  3,
  n0,
  _COATR,
  0,
  [_tI],
  [[() => CreateOAuth2TokenRequestBody$, 16]],
  1
];
var CreateOAuth2TokenRequestBody$ = [
  3,
  n0,
  _COATRB,
  0,
  [_cI, _gT, _co, _rU, _cV, _rT],
  [[0, { [_jN]: _cI }], [0, { [_jN]: _gT }], 0, [0, { [_jN]: _rU }], [0, { [_jN]: _cV }], [() => RefreshToken, { [_jN]: _rT }]],
  2
];
var CreateOAuth2TokenResponse$ = [
  3,
  n0,
  _COATRr,
  0,
  [_tO],
  [[() => CreateOAuth2TokenResponseBody$, 16]],
  1
];
var CreateOAuth2TokenResponseBody$ = [
  3,
  n0,
  _COATRBr,
  0,
  [_aT, _tT, _eI, _rT, _iT],
  [[() => AccessToken$, { [_jN]: _aT }], [0, { [_jN]: _tT }], [1, { [_jN]: _eI }], [() => RefreshToken, { [_jN]: _rT }], [0, { [_jN]: _iT }]],
  4
];
var CreateOAuth2TokenWithIAMRequest$ = [
  3,
  n0,
  _COATWIAMR,
  0,
  [_gT, _r],
  [[0, { [_jN]: _gt }], 0],
  2
];
var CreateOAuth2TokenWithIAMResponse$ = [
  3,
  n0,
  _COATWIAMRr,
  0,
  [_aT, _tT, _eI],
  [[() => OAuthAccessToken, { [_jN]: _at }], [0, { [_jN]: _tt }], [1, { [_jN]: _ei }]],
  3
];
var CreateOAuth2Token$ = [
  9,
  n0,
  _COAT,
  { [_h]: ["POST", "/v1/token", 200] },
  () => CreateOAuth2TokenRequest$,
  () => CreateOAuth2TokenResponse$
];
var CreateOAuth2TokenWithIAM$ = [
  9,
  n0,
  _COATWIAM,
  { [_h]: ["POST", "/v1/token?x-amz-client-auth-method=iam", 200] },
  () => CreateOAuth2TokenWithIAMRequest$,
  () => CreateOAuth2TokenWithIAMResponse$
];

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.shared.js
var getRuntimeConfig = (config) => {
  return {
    apiVersion: "2023-01-01",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
    extensions: config?.extensions ?? [],
    httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSigninHttpAuthSchemeProvider,
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
      defaultNamespace: "com.amazonaws.signin",
      errorTypeRegistries,
      version: "2023-01-01",
      serviceTarget: "Signin"
    },
    serviceId: config?.serviceId ?? "Signin",
    sha256: config?.sha256 ?? Sha256Node,
    urlParser: config?.urlParser ?? parseUrl,
    utf8Decoder: config?.utf8Decoder ?? fromUtf8,
    utf8Encoder: config?.utf8Encoder ?? toUtf8
  };
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.js
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeExtensions.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthExtensionConfiguration.js
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeExtensions.js
var resolveRuntimeExtensions = (runtimeConfig, extensions) => {
  const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/SigninClient.js
var SigninClient = class extends Client {
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
      httpAuthSchemeParametersProvider: defaultSigninHttpAuthSchemeParametersProvider,
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/Signin.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/CreateOAuth2TokenCommand.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commandBuilder.js
init_esm_shims();
var command = makeBuilder(commonParams, "Signin", "SigninClient", getEndpointPlugin);
var _ep0 = {
  IsControlPlane: { type: "staticContextParams", value: false }
};
var _ep1 = {
  IsOAuthEndpoint: { type: "staticContextParams", value: true }
};
var _mw0 = (Command2, cs, config, o2) => [];

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/CreateOAuth2TokenCommand.js
var CreateOAuth2TokenCommand = class extends command(_ep0, _mw0, "CreateOAuth2Token", CreateOAuth2Token$) {
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/CreateOAuth2TokenWithIAMCommand.js
init_esm_shims();
var CreateOAuth2TokenWithIAMCommand = class extends command(_ep1, _mw0, "CreateOAuth2TokenWithIAM", CreateOAuth2TokenWithIAM$) {
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/Signin.js
var commands = {
  CreateOAuth2TokenCommand,
  CreateOAuth2TokenWithIAMCommand
};
var Signin = class extends SigninClient {
};
createAggregatedClient(commands, Signin);

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/enums.js
init_esm_shims();
var OAuth2ErrorCode = {
  AUTHCODE_EXPIRED: "AUTHCODE_EXPIRED",
  CONFLICT: "CONFLICT",
  INSUFFICIENT_PERMISSIONS: "INSUFFICIENT_PERMISSIONS",
  INVALID_REQUEST: "INVALID_REQUEST",
  RESOURCE_NOT_FOUND: "RESOURCE_NOT_FOUND",
  SERVER_ERROR: "server_error",
  SERVICE_QUOTA_EXCEEDED: "SERVICE_QUOTA_EXCEEDED",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  USER_CREDENTIALS_CHANGED: "USER_CREDENTIALS_CHANGED"
};

export { AccessDeniedException, AccessDeniedException$, AccessToken$, CreateOAuth2Token$, CreateOAuth2TokenCommand, CreateOAuth2TokenRequest$, CreateOAuth2TokenRequestBody$, CreateOAuth2TokenResponse$, CreateOAuth2TokenResponseBody$, CreateOAuth2TokenWithIAM$, CreateOAuth2TokenWithIAMCommand, CreateOAuth2TokenWithIAMRequest$, CreateOAuth2TokenWithIAMResponse$, InternalServerException, InternalServerException$, OAuth2ErrorCode, Signin, SigninClient, SigninServiceException, SigninServiceException$, TooManyRequestsError, TooManyRequestsError$, ValidationException, ValidationException$, errorTypeRegistries };
