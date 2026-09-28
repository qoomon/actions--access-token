import { createRequire } from 'module';
import { AwsSdkSigV4Signer, AwsSdkSigV4ASigner, NODE_SIGV4A_CONFIG_OPTIONS, package_default, NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, resolveAwsSdkSigV4Config, resolveAwsSdkSigV4AConfig, AwsQueryProtocol } from './chunk-PLMJQQI7.mjs';
import { NodeHttpHandler } from './chunk-E5WDDCGV.mjs';
import { signatureV4aContainer, SignatureV4 } from './chunk-W3GIPFDL.mjs';
import { Sha256Node } from './chunk-BSGV3LZS.mjs';
import { BinaryDecisionDiagram, EndpointCache, awsEndpointFunctions, customEndpointFunctions, getEndpointPlugin, resolveUserAgentConfig, resolveRetryConfig, resolveHostHeaderConfig, resolveEndpointConfig, getUserAgentPlugin, getRetryPlugin, getHostHeaderPlugin, getLoggerPlugin, getRecursionDetectionPlugin, getHttpAuthSchemeEndpointRuleSetPlugin, DefaultIdentityProviderConfig, getHttpSigningPlugin, emitWarningIfUnsupportedVersion as emitWarningIfUnsupportedVersion$1, NoAuthSigner, NODE_APP_ID_CONFIG_OPTIONS, DEFAULT_RETRY_MODE, NODE_RETRY_MODE_CONFIG_OPTIONS, NODE_MAX_ATTEMPT_CONFIG_OPTIONS, createDefaultUserAgentProvider, getAwsRegionExtensionConfiguration, resolveAwsRegionExtensionConfiguration, resolveParams, decideEndpoint, setCredentialFeature, stsRegionDefaultResolver } from './chunk-CNVAVDG2.mjs';
import { makeBuilder, createAggregatedClient, ServiceException, Client, emitWarningIfUnsupportedVersion, getDefaultExtensionConfiguration, resolveDefaultRuntimeConfig, NoOpLogger, loadConfigsForDefaultMode } from './chunk-TTV4QKES.mjs';
import { getContentLengthPlugin, getHttpHandlerExtensionConfiguration, resolveHttpHandlerRuntimeConfig } from './chunk-CKKARQCR.mjs';
import { TypeRegistry, getSchemaSerdePlugin, streamCollector, calculateBodyLength, toUtf8, fromUtf8, toBase64, fromBase64 } from './chunk-2D7RHDR7.mjs';
import { resolveRegionConfig, resolveDefaultsModeConfig, loadConfig, NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, NODE_REGION_CONFIG_OPTIONS, NODE_REGION_CONFIG_FILE_OPTIONS } from './chunk-HAYTZHRA.mjs';
import { normalizeProvider, parseUrl, getSmithyContext } from './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';

createRequire(import.meta.url);

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/index.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STSClient.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthSchemeProvider.js
init_esm_shims();

// node_modules/@aws-sdk/signature-v4-multi-region/dist-es/index.js
init_esm_shims();

// node_modules/@aws-sdk/signature-v4-multi-region/dist-es/SignatureV4MultiRegion.js
init_esm_shims();

// node_modules/@aws-sdk/signature-v4-multi-region/dist-es/signature-v4-crt-container.js
init_esm_shims();

// node_modules/@aws-sdk/signature-v4-multi-region/dist-es/SignatureV4SignWithCredentials.js
init_esm_shims();
var SESSION_TOKEN_QUERY_PARAM = "X-Amz-S3session-Token";
var SESSION_TOKEN_HEADER = SESSION_TOKEN_QUERY_PARAM.toLowerCase();
var SignatureV4SignWithCredentials = class extends SignatureV4 {
  async signWithCredentials(requestToSign, credentials, options) {
    const credentialsWithoutSessionToken = getCredentialsWithoutSessionToken(credentials);
    requestToSign.headers[SESSION_TOKEN_HEADER] = credentials.sessionToken;
    const privateAccess = this;
    setSingleOverride(privateAccess, credentialsWithoutSessionToken);
    return privateAccess.signRequest(requestToSign, options ?? {});
  }
  async presignWithCredentials(requestToSign, credentials, options) {
    const credentialsWithoutSessionToken = getCredentialsWithoutSessionToken(credentials);
    delete requestToSign.headers[SESSION_TOKEN_HEADER];
    requestToSign.headers[SESSION_TOKEN_QUERY_PARAM] = credentials.sessionToken;
    requestToSign.query = requestToSign.query ?? {};
    requestToSign.query[SESSION_TOKEN_QUERY_PARAM] = credentials.sessionToken;
    const privateAccess = this;
    setSingleOverride(privateAccess, credentialsWithoutSessionToken);
    return this.presign(requestToSign, options);
  }
};
function getCredentialsWithoutSessionToken(credentials) {
  return {
    accessKeyId: credentials.accessKeyId,
    secretAccessKey: credentials.secretAccessKey,
    expiration: credentials.expiration
  };
}
function setSingleOverride(privateAccess, credentialsWithoutSessionToken) {
  const currentCredentialProvider = privateAccess.credentialProvider;
  privateAccess.credentialProvider = () => {
    privateAccess.credentialProvider = currentCredentialProvider;
    return Promise.resolve(credentialsWithoutSessionToken);
  };
}

// node_modules/@aws-sdk/signature-v4-multi-region/dist-es/SignatureV4MultiRegion.js
var SignatureV4MultiRegion = class {
  sigv4aSigner;
  sigv4Signer;
  signerOptions;
  static sigv4aDependency() {
    if (typeof signatureV4aContainer.SignatureV4a === "function") {
      return "js";
    }
    return "none";
  }
  constructor(options) {
    this.sigv4Signer = new SignatureV4SignWithCredentials(options);
    this.signerOptions = options;
  }
  async sign(requestToSign, options = {}) {
    if (options.signingRegion === "*") {
      return this.getSigv4aSigner().sign(requestToSign, options);
    }
    return this.sigv4Signer.sign(requestToSign, options);
  }
  async signWithCredentials(requestToSign, credentials, options = {}) {
    if (options.signingRegion === "*") {
      this.getSigv4aSigner();
      {
        throw new Error(`signWithCredentials with signingRegion '*' is only supported when using the CRT dependency @aws-sdk/signature-v4-crt. Please check whether you have installed the "@aws-sdk/signature-v4-crt" package explicitly. You must also register the package by calling [require("@aws-sdk/signature-v4-crt");] or an ESM equivalent such as [import "@aws-sdk/signature-v4-crt";]. For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt`);
      }
    }
    return this.sigv4Signer.signWithCredentials(requestToSign, credentials, options);
  }
  async presign(originalRequest, options = {}) {
    if (options.signingRegion === "*") {
      this.getSigv4aSigner();
      {
        throw new Error(`presign with signingRegion '*' is only supported when using the CRT dependency @aws-sdk/signature-v4-crt. Please check whether you have installed the "@aws-sdk/signature-v4-crt" package explicitly. You must also register the package by calling [require("@aws-sdk/signature-v4-crt");] or an ESM equivalent such as [import "@aws-sdk/signature-v4-crt";]. For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt`);
      }
    }
    return this.sigv4Signer.presign(originalRequest, options);
  }
  async presignWithCredentials(originalRequest, credentials, options = {}) {
    if (options.signingRegion === "*") {
      throw new Error("Method presignWithCredentials is not supported for [signingRegion=*].");
    }
    return this.sigv4Signer.presignWithCredentials(originalRequest, credentials, options);
  }
  getSigv4aSigner() {
    if (!this.sigv4aSigner) {
      const JsSigV4aSigner = signatureV4aContainer.SignatureV4a;
      if (this.signerOptions.runtime === "node") {
        if (!JsSigV4aSigner) {
          throw new Error("Neither CRT nor JS SigV4a implementation is available. Please load either @aws-sdk/signature-v4-crt or @aws-sdk/signature-v4a. For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt");
        }
        if (JsSigV4aSigner && typeof JsSigV4aSigner === "function") {
          this.sigv4aSigner = new JsSigV4aSigner({
            ...this.signerOptions
          });
        } else {
          throw new Error("Available SigV4a implementation is not a valid constructor. Please ensure you've properly imported @aws-sdk/signature-v4-crt or @aws-sdk/signature-v4a.For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt");
        }
      } else {
        if (!JsSigV4aSigner || typeof JsSigV4aSigner !== "function") {
          throw new Error("JS SigV4a implementation is not available or not a valid constructor. Please check whether you have installed the @aws-sdk/signature-v4a package explicitly. The CRT implementation is not available for browsers. You must also register the package by calling [require('@aws-sdk/signature-v4a');] or an ESM equivalent such as [import '@aws-sdk/signature-v4a';]. For more information please go to https://github.com/aws/aws-sdk-js-v3#using-javascript-non-crt-implementation-of-sigv4a");
        }
        this.sigv4aSigner = new JsSigV4aSigner({
          ...this.signerOptions
        });
      }
    }
    return this.sigv4aSigner;
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/endpointResolver.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/bdd.js
init_esm_shims();
var q = "ref";
var a = -1;
var b = true;
var c = "isSet";
var d = "PartitionResult";
var e = "booleanEquals";
var f = "stringEquals";
var g = "getAttr";
var h = "us-east-1";
var i = "sigv4";
var j = "sts";
var k = "https://sts.{Region}.{PartitionResult#dnsSuffix}";
var l = { [q]: "Endpoint" };
var m = { [q]: "Region" };
var n = { [q]: d };
var o = {};
var p = [m];
var _data = {
  conditions: [
    [c, [l]],
    [c, p],
    ["aws.partition", p, d],
    [e, [{ [q]: "UseFIPS" }, b]],
    [e, [{ [q]: "UseDualStack" }, b]],
    [f, [m, "aws-global"]],
    [e, [{ [q]: "UseGlobalEndpoint" }, b]],
    [f, [m, "eu-central-1"]],
    [e, [{ fn: g, argv: [n, "supportsDualStack"] }, b]],
    [e, [{ fn: g, argv: [n, "supportsFIPS"] }, b]],
    [f, [m, "ap-south-1"]],
    [f, [m, "eu-north-1"]],
    [f, [m, "eu-west-1"]],
    [f, [m, "eu-west-2"]],
    [f, [m, "eu-west-3"]],
    [f, [m, "sa-east-1"]],
    [f, [m, h]],
    [f, [m, "us-east-2"]],
    [f, [m, "us-west-2"]],
    [f, [m, "us-west-1"]],
    [f, [m, "ca-central-1"]],
    [f, [m, "ap-southeast-1"]],
    [f, [m, "ap-northeast-1"]],
    [f, [m, "ap-southeast-2"]],
    [f, [{ fn: g, argv: [n, "name"] }, "aws-us-gov"]]
  ],
  results: [
    [a],
    ["https://sts.amazonaws.com", { authSchemes: [{ name: i, signingName: j, signingRegion: h }] }],
    [k, { authSchemes: [{ name: i, signingName: j, signingRegion: "{Region}" }] }],
    [a, "Invalid Configuration: FIPS and custom endpoint are not supported"],
    [a, "Invalid Configuration: Dualstack and custom endpoint are not supported"],
    [l, o],
    ["https://sts-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", o],
    [a, "FIPS and DualStack are enabled, but this partition does not support one or both"],
    ["https://sts.{Region}.amazonaws.com", o],
    ["https://sts-fips.{Region}.{PartitionResult#dnsSuffix}", o],
    [a, "FIPS is enabled but this partition does not support FIPS"],
    ["https://sts.{Region}.{PartitionResult#dualStackDnsSuffix}", o],
    [a, "DualStack is enabled but this partition does not support DualStack"],
    [k, o],
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
  30,
  3,
  1,
  4,
  r + 14,
  2,
  5,
  r + 14,
  3,
  25,
  6,
  4,
  24,
  7,
  5,
  r + 1,
  8,
  6,
  9,
  r + 13,
  7,
  r + 1,
  10,
  10,
  r + 1,
  11,
  11,
  r + 1,
  12,
  12,
  r + 1,
  13,
  13,
  r + 1,
  14,
  14,
  r + 1,
  15,
  15,
  r + 1,
  16,
  16,
  r + 1,
  17,
  17,
  r + 1,
  18,
  18,
  r + 1,
  19,
  19,
  r + 1,
  20,
  20,
  r + 1,
  21,
  21,
  r + 1,
  22,
  22,
  r + 1,
  23,
  23,
  r + 1,
  r + 2,
  8,
  r + 11,
  r + 12,
  4,
  28,
  26,
  9,
  27,
  r + 10,
  24,
  r + 8,
  r + 9,
  8,
  29,
  r + 7,
  9,
  r + 6,
  r + 7,
  3,
  r + 3,
  31,
  4,
  r + 4,
  r + 5
]);
var bdd = BinaryDecisionDiagram.from(nodes, root, _data.conditions, _data.results);

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/endpointResolver.js
var cache = new EndpointCache({
  size: 50,
  params: ["Endpoint", "Region", "UseDualStack", "UseFIPS", "UseGlobalEndpoint"]
});
var defaultEndpointResolver = (endpointParams, context = {}) => {
  return cache.get(endpointParams, () => decideEndpoint(bdd, {
    endpointParams,
    logger: context.logger
  }));
};
customEndpointFunctions.aws = awsEndpointFunctions;

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthSchemeProvider.js
var createEndpointRuleSetHttpAuthSchemeParametersProvider = (defaultHttpAuthSchemeParametersProvider) => async (config, context, input) => {
  if (!input) {
    throw new Error("Could not find `input` for `defaultEndpointRuleSetHttpAuthSchemeParametersProvider`");
  }
  const defaultParameters = await defaultHttpAuthSchemeParametersProvider(config, context, input);
  const instructionsFn = getSmithyContext(context)?.commandInstance?.constructor?.getEndpointParameterInstructions;
  if (!instructionsFn) {
    throw new Error(`getEndpointParameterInstructions() is not defined on '${context.commandName}'`);
  }
  const endpointParameters = await resolveParams(input, { getEndpointParameterInstructions: instructionsFn }, config);
  return Object.assign(defaultParameters, endpointParameters);
};
var _defaultSTSHttpAuthSchemeParametersProvider = async (config, context, input) => {
  return {
    operation: getSmithyContext(context).operation,
    region: await normalizeProvider(config.region)() || (() => {
      throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
    })()
  };
};
var defaultSTSHttpAuthSchemeParametersProvider = createEndpointRuleSetHttpAuthSchemeParametersProvider(_defaultSTSHttpAuthSchemeParametersProvider);
function createAwsAuthSigv4HttpAuthOption(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "sts",
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
function createAwsAuthSigv4aHttpAuthOption(authParameters) {
  return {
    schemeId: "aws.auth#sigv4a",
    signingProperties: {
      name: "sts",
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
var createEndpointRuleSetHttpAuthSchemeProvider = (defaultEndpointResolver2, defaultHttpAuthSchemeResolver, createHttpAuthOptionFunctions) => {
  const endpointRuleSetHttpAuthSchemeProvider = (authParameters) => {
    const endpoint = defaultEndpointResolver2(authParameters);
    const authSchemes = endpoint.properties?.authSchemes;
    if (!authSchemes) {
      return defaultHttpAuthSchemeResolver(authParameters);
    }
    const options = [];
    for (const scheme of authSchemes) {
      const { name: resolvedName, properties = {}, ...rest } = scheme;
      const name = resolvedName.toLowerCase();
      if (resolvedName !== name) {
        console.warn(`HttpAuthScheme has been normalized with lowercasing: '${resolvedName}' to '${name}'`);
      }
      let schemeId;
      if (name === "sigv4a") {
        schemeId = "aws.auth#sigv4a";
        const sigv4Present = authSchemes.find((s) => {
          const name2 = s.name.toLowerCase();
          return name2 !== "sigv4a" && name2.startsWith("sigv4");
        });
        if (SignatureV4MultiRegion.sigv4aDependency() === "none" && sigv4Present) {
          continue;
        }
      } else if (name.startsWith("sigv4")) {
        schemeId = "aws.auth#sigv4";
      } else {
        throw new Error(`Unknown HttpAuthScheme found in '@smithy.rules#endpointRuleSet': '${name}'`);
      }
      const createOption = createHttpAuthOptionFunctions[schemeId];
      if (!createOption) {
        throw new Error(`Could not find HttpAuthOption create function for '${schemeId}'`);
      }
      const option = createOption(authParameters);
      option.schemeId = schemeId;
      option.signingProperties = { ...option.signingProperties || {}, ...rest, ...properties };
      options.push(option);
    }
    return options;
  };
  return endpointRuleSetHttpAuthSchemeProvider;
};
var _defaultSTSHttpAuthSchemeProvider = (authParameters) => {
  const options = [];
  switch (authParameters.operation) {
    case "AssumeRoleWithWebIdentity": {
      options.push(createSmithyApiNoAuthHttpAuthOption());
      options.push(createAwsAuthSigv4aHttpAuthOption(authParameters));
      break;
    }
    default: {
      options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
      options.push(createAwsAuthSigv4aHttpAuthOption(authParameters));
    }
  }
  return options;
};
var defaultSTSHttpAuthSchemeProvider = createEndpointRuleSetHttpAuthSchemeProvider(defaultEndpointResolver, _defaultSTSHttpAuthSchemeProvider, {
  "aws.auth#sigv4": createAwsAuthSigv4HttpAuthOption,
  "aws.auth#sigv4a": createAwsAuthSigv4aHttpAuthOption,
  "smithy.api#noAuth": createSmithyApiNoAuthHttpAuthOption
});
var resolveHttpAuthSchemeConfig = (config) => {
  const config_0 = resolveAwsSdkSigV4Config(config);
  const config_1 = resolveAwsSdkSigV4AConfig(config_0);
  return Object.assign(config_1, {
    authSchemePreference: normalizeProvider(config.authSchemePreference ?? [])
  });
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/EndpointParameters.js
init_esm_shims();
var resolveClientEndpointParameters = (options) => {
  return Object.assign(options, {
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    useGlobalEndpoint: options.useGlobalEndpoint ?? false,
    defaultSigningName: "sts"
  });
};
var commonParams = {
  UseGlobalEndpoint: { type: "builtInParams", name: "useGlobalEndpoint" },
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.shared.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/schemas/schemas_0.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/errors.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/STSServiceException.js
init_esm_shims();
var STSServiceException = class _STSServiceException extends ServiceException {
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _STSServiceException.prototype);
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/errors.js
var ExpiredTokenException = class _ExpiredTokenException extends STSServiceException {
  name = "ExpiredTokenException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ExpiredTokenException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
  }
};
var MalformedPolicyDocumentException = class _MalformedPolicyDocumentException extends STSServiceException {
  name = "MalformedPolicyDocumentException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "MalformedPolicyDocumentException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _MalformedPolicyDocumentException.prototype);
  }
};
var PackedPolicyTooLargeException = class _PackedPolicyTooLargeException extends STSServiceException {
  name = "PackedPolicyTooLargeException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "PackedPolicyTooLargeException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _PackedPolicyTooLargeException.prototype);
  }
};
var RegionDisabledException = class _RegionDisabledException extends STSServiceException {
  name = "RegionDisabledException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "RegionDisabledException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _RegionDisabledException.prototype);
  }
};
var IDPRejectedClaimException = class _IDPRejectedClaimException extends STSServiceException {
  name = "IDPRejectedClaimException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "IDPRejectedClaimException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _IDPRejectedClaimException.prototype);
  }
};
var InvalidIdentityTokenException = class _InvalidIdentityTokenException extends STSServiceException {
  name = "InvalidIdentityTokenException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidIdentityTokenException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidIdentityTokenException.prototype);
  }
};
var IDPCommunicationErrorException = class _IDPCommunicationErrorException extends STSServiceException {
  name = "IDPCommunicationErrorException";
  $fault = "client";
  $retryable = {};
  constructor(opts) {
    super({
      name: "IDPCommunicationErrorException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _IDPCommunicationErrorException.prototype);
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/schemas/schemas_0.js
var _A = "Arn";
var _AKI = "AccessKeyId";
var _AR = "AssumeRole";
var _ARI = "AssumedRoleId";
var _ARR = "AssumeRoleRequest";
var _ARRs = "AssumeRoleResponse";
var _ARU = "AssumedRoleUser";
var _ARWWI = "AssumeRoleWithWebIdentity";
var _ARWWIR = "AssumeRoleWithWebIdentityRequest";
var _ARWWIRs = "AssumeRoleWithWebIdentityResponse";
var _Au = "Audience";
var _C = "Credentials";
var _CA = "ContextAssertion";
var _DS = "DurationSeconds";
var _E = "Expiration";
var _EI = "ExternalId";
var _ETE = "ExpiredTokenException";
var _IDPCEE = "IDPCommunicationErrorException";
var _IDPRCE = "IDPRejectedClaimException";
var _IITE = "InvalidIdentityTokenException";
var _K = "Key";
var _MPDE = "MalformedPolicyDocumentException";
var _P = "Policy";
var _PA = "PolicyArns";
var _PAr = "ProviderArn";
var _PC = "ProvidedContexts";
var _PCLT = "ProvidedContextsListType";
var _PCr = "ProvidedContext";
var _PDT = "PolicyDescriptorType";
var _PI = "ProviderId";
var _PPS = "PackedPolicySize";
var _PPTLE = "PackedPolicyTooLargeException";
var _Pr = "Provider";
var _RA = "RoleArn";
var _RDE = "RegionDisabledException";
var _RSN = "RoleSessionName";
var _SAK = "SecretAccessKey";
var _SFWIT = "SubjectFromWebIdentityToken";
var _SI = "SourceIdentity";
var _SN = "SerialNumber";
var _ST = "SessionToken";
var _T = "Tags";
var _TC = "TokenCode";
var _TTK = "TransitiveTagKeys";
var _Ta = "Tag";
var _V = "Value";
var _WIT = "WebIdentityToken";
var _a = "arn";
var _aKST = "accessKeySecretType";
var _aQE = "awsQueryError";
var _c = "client";
var _cTT = "clientTokenType";
var _e = "error";
var _hE = "httpError";
var _m = "message";
var _pDLT = "policyDescriptorListType";
var _s = "smithy.ts.sdk.synthetic.com.amazonaws.sts";
var _tLT = "tagListType";
var n0 = "com.amazonaws.sts";
var _s_registry = TypeRegistry.for(_s);
var STSServiceException$ = [-3, _s, "STSServiceException", 0, [], []];
_s_registry.registerError(STSServiceException$, STSServiceException);
var n0_registry = TypeRegistry.for(n0);
var ExpiredTokenException$ = [
  -3,
  n0,
  _ETE,
  { [_aQE]: [`ExpiredTokenException`, 400], [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(ExpiredTokenException$, ExpiredTokenException);
var IDPCommunicationErrorException$ = [
  -3,
  n0,
  _IDPCEE,
  { [_aQE]: [`IDPCommunicationError`, 400], [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(IDPCommunicationErrorException$, IDPCommunicationErrorException);
var IDPRejectedClaimException$ = [
  -3,
  n0,
  _IDPRCE,
  { [_aQE]: [`IDPRejectedClaim`, 403], [_e]: _c, [_hE]: 403 },
  [_m],
  [0]
];
n0_registry.registerError(IDPRejectedClaimException$, IDPRejectedClaimException);
var InvalidIdentityTokenException$ = [
  -3,
  n0,
  _IITE,
  { [_aQE]: [`InvalidIdentityToken`, 400], [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(InvalidIdentityTokenException$, InvalidIdentityTokenException);
var MalformedPolicyDocumentException$ = [
  -3,
  n0,
  _MPDE,
  { [_aQE]: [`MalformedPolicyDocument`, 400], [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(MalformedPolicyDocumentException$, MalformedPolicyDocumentException);
var PackedPolicyTooLargeException$ = [
  -3,
  n0,
  _PPTLE,
  { [_aQE]: [`PackedPolicyTooLarge`, 400], [_e]: _c, [_hE]: 400 },
  [_m],
  [0]
];
n0_registry.registerError(PackedPolicyTooLargeException$, PackedPolicyTooLargeException);
var RegionDisabledException$ = [
  -3,
  n0,
  _RDE,
  { [_aQE]: [`RegionDisabledException`, 403], [_e]: _c, [_hE]: 403 },
  [_m],
  [0]
];
n0_registry.registerError(RegionDisabledException$, RegionDisabledException);
var errorTypeRegistries = [
  _s_registry,
  n0_registry
];
var accessKeySecretType = [0, n0, _aKST, 8, 0];
var clientTokenType = [0, n0, _cTT, 8, 0];
var AssumedRoleUser$ = [
  3,
  n0,
  _ARU,
  0,
  [_ARI, _A],
  [0, 0],
  2
];
var AssumeRoleRequest$ = [
  3,
  n0,
  _ARR,
  0,
  [_RA, _RSN, _PA, _P, _DS, _T, _TTK, _EI, _SN, _TC, _SI, _PC],
  [0, 0, () => policyDescriptorListType, 0, 1, () => tagListType, 64 | 0, 0, 0, 0, 0, () => ProvidedContextsListType],
  2
];
var AssumeRoleResponse$ = [
  3,
  n0,
  _ARRs,
  0,
  [_C, _ARU, _PPS, _SI],
  [[() => Credentials$, 0], () => AssumedRoleUser$, 1, 0]
];
var AssumeRoleWithWebIdentityRequest$ = [
  3,
  n0,
  _ARWWIR,
  0,
  [_RA, _RSN, _WIT, _PI, _PA, _P, _DS],
  [0, 0, [() => clientTokenType, 0], 0, () => policyDescriptorListType, 0, 1],
  3
];
var AssumeRoleWithWebIdentityResponse$ = [
  3,
  n0,
  _ARWWIRs,
  0,
  [_C, _SFWIT, _ARU, _PPS, _Pr, _Au, _SI],
  [[() => Credentials$, 0], 0, () => AssumedRoleUser$, 1, 0, 0, 0]
];
var Credentials$ = [
  3,
  n0,
  _C,
  0,
  [_AKI, _SAK, _ST, _E],
  [0, [() => accessKeySecretType, 0], 0, 4],
  4
];
var PolicyDescriptorType$ = [
  3,
  n0,
  _PDT,
  0,
  [_a],
  [0]
];
var ProvidedContext$ = [
  3,
  n0,
  _PCr,
  0,
  [_PAr, _CA],
  [0, 0]
];
var Tag$ = [
  3,
  n0,
  _Ta,
  0,
  [_K, _V],
  [0, 0],
  2
];
var policyDescriptorListType = [
  1,
  n0,
  _pDLT,
  0,
  () => PolicyDescriptorType$
];
var ProvidedContextsListType = [
  1,
  n0,
  _PCLT,
  0,
  () => ProvidedContext$
];
var tagListType = [
  1,
  n0,
  _tLT,
  0,
  () => Tag$
];
var AssumeRole$ = [
  9,
  n0,
  _AR,
  0,
  () => AssumeRoleRequest$,
  () => AssumeRoleResponse$
];
var AssumeRoleWithWebIdentity$ = [
  9,
  n0,
  _ARWWI,
  0,
  () => AssumeRoleWithWebIdentityRequest$,
  () => AssumeRoleWithWebIdentityResponse$
];

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.shared.js
var getRuntimeConfig = (config) => {
  return {
    apiVersion: "2011-06-15",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
    extensions: config?.extensions ?? [],
    httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSTSHttpAuthSchemeProvider,
    httpAuthSchemes: config?.httpAuthSchemes ?? [
      {
        schemeId: "aws.auth#sigv4",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
        signer: new AwsSdkSigV4Signer()
      },
      {
        schemeId: "aws.auth#sigv4a",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4a"),
        signer: new AwsSdkSigV4ASigner()
      },
      {
        schemeId: "smithy.api#noAuth",
        identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
        signer: new NoAuthSigner()
      }
    ],
    logger: config?.logger ?? new NoOpLogger(),
    protocol: config?.protocol ?? AwsQueryProtocol,
    protocolSettings: config?.protocolSettings ?? {
      defaultNamespace: "com.amazonaws.sts",
      errorTypeRegistries,
      xmlNamespace: "https://sts.amazonaws.com/doc/2011-06-15/",
      version: "2011-06-15",
      serviceTarget: "AWSSecurityTokenServiceV20110615"
    },
    serviceId: config?.serviceId ?? "STS",
    sha256: config?.sha256 ?? Sha256Node,
    signerConstructor: config?.signerConstructor ?? SignatureV4MultiRegion,
    urlParser: config?.urlParser ?? parseUrl,
    utf8Decoder: config?.utf8Decoder ?? fromUtf8,
    utf8Encoder: config?.utf8Encoder ?? toUtf8
  };
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.js
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
    httpAuthSchemes: config?.httpAuthSchemes ?? [
      {
        schemeId: "aws.auth#sigv4",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4") || (async (idProps) => await config.credentialDefaultProvider(idProps?.__config || {})()),
        signer: new AwsSdkSigV4Signer()
      },
      {
        schemeId: "aws.auth#sigv4a",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4a"),
        signer: new AwsSdkSigV4ASigner()
      },
      {
        schemeId: "smithy.api#noAuth",
        identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
        signer: new NoAuthSigner()
      }
    ],
    maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
    region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
    requestHandler: NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
    retryMode: config?.retryMode ?? loadConfig({
      ...NODE_RETRY_MODE_CONFIG_OPTIONS,
      default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE
    }, config),
    sigv4aSigningRegionSet: config?.sigv4aSigningRegionSet ?? loadConfig(NODE_SIGV4A_CONFIG_OPTIONS, loaderConfig),
    streamCollector: config?.streamCollector ?? streamCollector,
    useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
    useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
    userAgentAppId: config?.userAgentAppId ?? loadConfig(NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
  };
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeExtensions.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthExtensionConfiguration.js
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

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeExtensions.js
var resolveRuntimeExtensions = (runtimeConfig, extensions) => {
  const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STSClient.js
var STSClient = class extends Client {
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
      httpAuthSchemeParametersProvider: defaultSTSHttpAuthSchemeParametersProvider,
      identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
        "aws.auth#sigv4": config.credentials,
        "aws.auth#sigv4a": config.credentials
      })
    }));
    this.middlewareStack.use(getHttpSigningPlugin(this.config));
  }
  destroy() {
    super.destroy();
  }
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STS.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleCommand.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commandBuilder.js
init_esm_shims();
var command = makeBuilder(commonParams, "AWSSecurityTokenServiceV20110615", "STSClient", getEndpointPlugin);
var _ep0 = {};
var _mw0 = (Command2, cs, config, o2) => [];

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleCommand.js
var AssumeRoleCommand = class extends command(_ep0, _mw0, "AssumeRole", AssumeRole$) {
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleWithWebIdentityCommand.js
init_esm_shims();
var AssumeRoleWithWebIdentityCommand = class extends command(_ep0, _mw0, "AssumeRoleWithWebIdentity", AssumeRoleWithWebIdentity$) {
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STS.js
var commands = {
  AssumeRoleCommand,
  AssumeRoleWithWebIdentityCommand
};
var STS = class extends STSClient {
};
createAggregatedClient(commands, STS);

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultRoleAssumers.js
init_esm_shims();

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultStsRoleAssumers.js
init_esm_shims();
var getAccountIdFromAssumedRoleUser = (assumedRoleUser) => {
  if (typeof assumedRoleUser?.Arn === "string") {
    const arnComponents = assumedRoleUser.Arn.split(":");
    if (arnComponents.length > 4 && arnComponents[4] !== "") {
      return arnComponents[4];
    }
  }
  return void 0;
};
var resolveRegion = async (_region, _parentRegion, credentialProviderLogger, loaderConfig = {}) => {
  const region = typeof _region === "function" ? await _region() : _region;
  const parentRegion = typeof _parentRegion === "function" ? await _parentRegion() : _parentRegion;
  let stsDefaultRegion = "";
  const resolvedRegion = region ?? parentRegion ?? (stsDefaultRegion = await stsRegionDefaultResolver(loaderConfig)());
  credentialProviderLogger?.debug?.("@aws-sdk/client-sts::resolveRegion", "accepting first of:", `${region} (credential provider clientConfig)`, `${parentRegion} (contextual client)`, `${stsDefaultRegion} (STS default: AWS_REGION, profile region, or us-east-1)`);
  return resolvedRegion;
};
var getDefaultRoleAssumer = (stsOptions, STSClient2) => {
  let stsClient;
  let closureSourceCreds;
  return async (sourceCreds, params) => {
    closureSourceCreds = sourceCreds;
    if (!stsClient) {
      const { logger = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
      const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
        logger,
        profile
      });
      const isCompatibleRequestHandler = !isH2(requestHandler);
      stsClient = new STSClient2({
        ...stsOptions,
        userAgentAppId,
        profile,
        credentialDefaultProvider: () => async () => closureSourceCreds,
        region: resolvedRegion,
        requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
        logger
      });
    }
    const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleCommand(params));
    if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) {
      throw new Error(`Invalid response from STS.assumeRole call with role ${params.RoleArn}`);
    }
    const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
    const credentials = {
      accessKeyId: Credentials.AccessKeyId,
      secretAccessKey: Credentials.SecretAccessKey,
      sessionToken: Credentials.SessionToken,
      expiration: Credentials.Expiration,
      ...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
      ...accountId && { accountId }
    };
    setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE", "i");
    return credentials;
  };
};
var getDefaultRoleAssumerWithWebIdentity = (stsOptions, STSClient2) => {
  let stsClient;
  return async (params) => {
    if (!stsClient) {
      const { logger = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
      const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
        logger,
        profile
      });
      const isCompatibleRequestHandler = !isH2(requestHandler);
      stsClient = new STSClient2({
        ...stsOptions,
        userAgentAppId,
        profile,
        region: resolvedRegion,
        requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
        logger
      });
    }
    const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleWithWebIdentityCommand(params));
    if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) {
      throw new Error(`Invalid response from STS.assumeRoleWithWebIdentity call with role ${params.RoleArn}`);
    }
    const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
    const credentials = {
      accessKeyId: Credentials.AccessKeyId,
      secretAccessKey: Credentials.SecretAccessKey,
      sessionToken: Credentials.SessionToken,
      expiration: Credentials.Expiration,
      ...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
      ...accountId && { accountId }
    };
    if (accountId) {
      setCredentialFeature(credentials, "RESOLVED_ACCOUNT_ID", "T");
    }
    setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE_WEB_ID", "k");
    return credentials;
  };
};
var isH2 = (requestHandler) => {
  return requestHandler?.metadata?.handlerProtocol === "h2";
};

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultRoleAssumers.js
var getCustomizableStsClientCtor = (baseCtor, customizations) => {
  if (!customizations)
    return baseCtor;
  else
    return class CustomizableSTSClient extends baseCtor {
      constructor(config) {
        super(config);
        for (const customization of customizations) {
          this.middlewareStack.use(customization);
        }
      }
    };
};
var getDefaultRoleAssumer2 = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumer(stsOptions, getCustomizableStsClientCtor(STSClient, stsPlugins));
var getDefaultRoleAssumerWithWebIdentity2 = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumerWithWebIdentity(stsOptions, getCustomizableStsClientCtor(STSClient, stsPlugins));
var decorateDefaultCredentialProvider = (provider) => (input) => provider({
  roleAssumer: getDefaultRoleAssumer2(input),
  roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity2(input),
  ...input
});

export { AssumeRole$, AssumeRoleCommand, AssumeRoleRequest$, AssumeRoleResponse$, AssumeRoleWithWebIdentity$, AssumeRoleWithWebIdentityCommand, AssumeRoleWithWebIdentityRequest$, AssumeRoleWithWebIdentityResponse$, AssumedRoleUser$, Credentials$, ExpiredTokenException, ExpiredTokenException$, IDPCommunicationErrorException, IDPCommunicationErrorException$, IDPRejectedClaimException, IDPRejectedClaimException$, InvalidIdentityTokenException, InvalidIdentityTokenException$, MalformedPolicyDocumentException, MalformedPolicyDocumentException$, PackedPolicyTooLargeException, PackedPolicyTooLargeException$, PolicyDescriptorType$, ProvidedContext$, RegionDisabledException, RegionDisabledException$, STS, STSClient, STSServiceException, STSServiceException$, Tag$, decorateDefaultCredentialProvider, errorTypeRegistries, getDefaultRoleAssumer2 as getDefaultRoleAssumer, getDefaultRoleAssumerWithWebIdentity2 as getDefaultRoleAssumerWithWebIdentity };
