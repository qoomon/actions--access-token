import { createRequire } from 'module';
import { SignatureV4 } from './chunk-2XSHXKPI.mjs';
import { normalizeProvider, setCredentialFeature, memoizeIdentityProvider, isIdentityExpired, doesIdentityRequireRefresh } from './chunk-5O5CB24P.mjs';
import { decorateServiceException, getValueFromTextNode } from './chunk-AY2K4GWE.mjs';
import { determineTimestampFormat, HttpBindingProtocol, HttpInterceptingShapeSerializer, HttpInterceptingShapeDeserializer, RpcProtocol, collectBody, extendedEncodeURIComponent, FromStringShapeDeserializer } from './chunk-BB2CEPRS.mjs';
import { NormalizedSchema, generateIdempotencyToken, LazyJsonString, NumericValue, toBase64, dateToUtcString, toUtf8, deref, TypeRegistry, fromBase64, parseEpochTimestamp, parseRfc7231DateTime, parseRfc3339DateTimeWithOffset } from './chunk-GXHTACOW.mjs';
import { loadConfig, booleanSelector, SelectorType, ProviderError } from './chunk-HAYTZHRA.mjs';
import { HttpRequest, HttpResponse } from './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';

createRequire(import.meta.url);

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/index.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getDateHeader.js
init_esm_shims();
var getDateHeader = (response) => HttpResponse.isInstance(response) ? response.headers?.date ?? response.headers?.Date : void 0;
var getAgeHeader = (response) => HttpResponse.isInstance(response) ? response.headers?.age ?? response.headers?.Age : void 0;

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.js
init_esm_shims();
var getSkewCorrectedDate = (systemClockOffset) => new Date(Date.now() + systemClockOffset);

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.js
init_esm_shims();
var getUpdatedSystemClockOffset = (clockTime, currentSystemClockOffset, timeRequestSent, ageHeader) => {
  if (ageHeader !== void 0) {
    return currentSystemClockOffset;
  }
  const serverTime = Date.parse(clockTime);
  const timeResponseReceived = Date.now();
  if (timeRequestSent !== void 0 && timeResponseReceived - timeRequestSent > 9e5) {
    return currentSystemClockOffset;
  }
  const candidateSkew = timeRequestSent !== void 0 ? serverTime - (timeRequestSent + timeResponseReceived) / 2 : serverTime - timeResponseReceived;
  return candidateSkew;
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js
var throwSigningPropertyError = (name, property) => {
  if (!property) {
    throw new Error(`Property \`${name}\` is not resolved for AWS SDK SigV4Auth`);
  }
  return property;
};
var validateSigningProperties = async (signingProperties) => {
  const context = throwSigningPropertyError("context", signingProperties.context);
  const config = throwSigningPropertyError("config", signingProperties.config);
  const authScheme = context.endpointV2?.properties?.authSchemes?.[0];
  const signerFunction = throwSigningPropertyError("signer", config.signer);
  const signer = await signerFunction(authScheme);
  const signingRegion = signingProperties?.signingRegion;
  const signingRegionSet = signingProperties?.signingRegionSet;
  const signingName = signingProperties?.signingName;
  return {
    config,
    signer,
    signingRegion,
    signingRegionSet,
    signingName
  };
};
var AwsSdkSigV4Signer = class {
  async sign(httpRequest, identity, signingProperties) {
    if (!HttpRequest.isInstance(httpRequest)) {
      throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
    }
    const validatedProps = await validateSigningProperties(signingProperties);
    const { config, signer } = validatedProps;
    let { signingRegion, signingName } = validatedProps;
    const handlerExecutionContext = signingProperties.context;
    if (handlerExecutionContext?.authSchemes?.length ?? 0 > 1) {
      const [first, second] = handlerExecutionContext.authSchemes;
      if (first?.name === "sigv4a" && second?.name === "sigv4") {
        signingRegion = second?.signingRegion ?? signingRegion;
        signingName = second?.signingName ?? signingName;
      }
    }
    const noSkewCorrection = await config.disableClockSkewCorrection?.() === true;
    signingProperties._disableClockSkewCorrection = noSkewCorrection;
    if (!noSkewCorrection) {
      signingProperties._preRequestSystemClockOffset = config.systemClockOffset;
      signingProperties._requestSentAt = Date.now();
    }
    const signedRequest = await signer.sign(httpRequest, {
      signingDate: noSkewCorrection ? /* @__PURE__ */ new Date() : getSkewCorrectedDate(config.systemClockOffset),
      signingRegion,
      signingService: signingName
    });
    return signedRequest;
  }
  errorHandler(signingProperties) {
    return (error) => {
      const errorException = error;
      if (!signingProperties._disableClockSkewCorrection) {
        const serverTime = errorException.ServerTime ?? getDateHeader(errorException.$response);
        if (serverTime) {
          const config = throwSigningPropertyError("config", signingProperties.config);
          const preRequestOffset = signingProperties._preRequestSystemClockOffset;
          const timeRequestSent = signingProperties._requestSentAt;
          const ageHeader = getAgeHeader(errorException.$response);
          const newOffset = getUpdatedSystemClockOffset(serverTime, config.systemClockOffset, timeRequestSent, ageHeader);
          config.systemClockOffset = newOffset;
          const skewExceedsThreshold = Math.abs(newOffset) >= 24e4;
          const isLocalCorrection = newOffset !== preRequestOffset;
          const isConcurrentCorrection = preRequestOffset !== void 0 && preRequestOffset !== newOffset;
          if (skewExceedsThreshold && (isLocalCorrection || isConcurrentCorrection) && errorException.$metadata) {
            errorException.$metadata.clockSkewCorrected = true;
          }
        }
      }
      throw error;
    };
  }
  successHandler(httpResponse, signingProperties) {
    if (signingProperties._disableClockSkewCorrection) {
      return;
    }
    const dateHeader = getDateHeader(httpResponse);
    if (dateHeader) {
      const config = throwSigningPropertyError("config", signingProperties.config);
      const timeRequestSent = signingProperties._requestSentAt;
      const ageHeader = getAgeHeader(httpResponse);
      config.systemClockOffset = getUpdatedSystemClockOffset(dateHeader, config.systemClockOffset, timeRequestSent, ageHeader);
    }
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4ASigner.js
init_esm_shims();
var AwsSdkSigV4ASigner = class extends AwsSdkSigV4Signer {
  async sign(httpRequest, identity, signingProperties) {
    if (!HttpRequest.isInstance(httpRequest)) {
      throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
    }
    const { config, signer, signingRegion, signingRegionSet, signingName } = await validateSigningProperties(signingProperties);
    const configResolvedSigningRegionSet = await config.sigv4aSigningRegionSet?.();
    const multiRegionOverride = (configResolvedSigningRegionSet ?? signingRegionSet ?? [signingRegion]).join(",");
    const noSkewCorrection = await config.disableClockSkewCorrection?.() === true;
    signingProperties._disableClockSkewCorrection = noSkewCorrection;
    if (!noSkewCorrection) {
      signingProperties._preRequestSystemClockOffset = config.systemClockOffset;
      signingProperties._requestSentAt = Date.now();
    }
    const signedRequest = await signer.sign(httpRequest, {
      signingDate: noSkewCorrection ? /* @__PURE__ */ new Date() : getSkewCorrectedDate(config.systemClockOffset),
      signingRegion: multiRegionOverride,
      signingService: signingName
    });
    return signedRequest;
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/NODE_AUTH_SCHEME_PREFERENCE_OPTIONS.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getArrayForCommaSeparatedString.js
init_esm_shims();
var getArrayForCommaSeparatedString = (str) => typeof str === "string" && str.length > 0 ? str.split(",").map((item) => item.trim()) : [];

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getBearerTokenEnvKey.js
init_esm_shims();
var getBearerTokenEnvKey = (signingName) => `AWS_BEARER_TOKEN_${signingName.replace(/[\s-]/g, "_").toUpperCase()}`;

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/NODE_AUTH_SCHEME_PREFERENCE_OPTIONS.js
var NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY = "AWS_AUTH_SCHEME_PREFERENCE";
var NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY = "auth_scheme_preference";
var NODE_AUTH_SCHEME_PREFERENCE_OPTIONS = {
  environmentVariableSelector: (env, options) => {
    if (options?.signingName) {
      const bearerTokenKey = getBearerTokenEnvKey(options.signingName);
      if (bearerTokenKey in env)
        return ["httpBearerAuth"];
    }
    if (!(NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY in env))
      return void 0;
    return getArrayForCommaSeparatedString(env[NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY]);
  },
  configFileSelector: (profile) => {
    if (!(NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY in profile))
      return void 0;
    return getArrayForCommaSeparatedString(profile[NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY]);
  },
  default: []
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4AConfig.js
init_esm_shims();
var resolveAwsSdkSigV4AConfig = (config) => {
  config.sigv4aSigningRegionSet = normalizeProvider(config.sigv4aSigningRegionSet);
  return config;
};
var NODE_SIGV4A_CONFIG_OPTIONS = {
  environmentVariableSelector(env) {
    if (env.AWS_SIGV4A_SIGNING_REGION_SET) {
      return env.AWS_SIGV4A_SIGNING_REGION_SET.split(",").map((_) => _.trim());
    }
    throw new ProviderError("AWS_SIGV4A_SIGNING_REGION_SET not set in env.", {
      tryNextLink: true
    });
  },
  configFileSelector(profile) {
    if (profile.sigv4a_signing_region_set) {
      return (profile.sigv4a_signing_region_set ?? "").split(",").map((_) => _.trim());
    }
    throw new ProviderError("sigv4a_signing_region_set not set in profile.", {
      tryNextLink: true
    });
  },
  default: void 0
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/index.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.js
init_esm_shims();
var bindResolveAwsSdkSigV4Config = (defaultDisableClockSkewCorrection) => (config) => {
  let inputCredentials = config.credentials;
  let isUserSupplied = !!config.credentials;
  let resolvedCredentials = void 0;
  Object.defineProperty(config, "credentials", {
    set(credentials) {
      if (credentials && credentials !== inputCredentials && credentials !== resolvedCredentials) {
        isUserSupplied = true;
      }
      inputCredentials = credentials;
      const memoizedProvider = normalizeCredentialProvider(config, {
        credentials: inputCredentials,
        credentialDefaultProvider: config.credentialDefaultProvider
      });
      const boundProvider = bindCallerConfig(config, memoizedProvider);
      if (isUserSupplied && !boundProvider.attributed) {
        const isCredentialObject = typeof inputCredentials === "object" && inputCredentials !== null;
        resolvedCredentials = async (options) => {
          const creds = await boundProvider(options);
          const attributedCreds = creds;
          if (isCredentialObject && (!attributedCreds.$source || Object.keys(attributedCreds.$source).length === 0)) {
            return setCredentialFeature(attributedCreds, "CREDENTIALS_CODE", "e");
          }
          return attributedCreds;
        };
        resolvedCredentials.memoized = boundProvider.memoized;
        resolvedCredentials.configBound = boundProvider.configBound;
        resolvedCredentials.attributed = true;
      } else {
        resolvedCredentials = boundProvider;
      }
    },
    get() {
      return resolvedCredentials;
    },
    enumerable: true,
    configurable: true
  });
  config.credentials = inputCredentials;
  const { signingEscapePath = true, systemClockOffset = config.systemClockOffset || 0, sha256 } = config;
  let signer;
  if (config.signer) {
    signer = normalizeProvider(config.signer);
  } else if (config.regionInfoProvider) {
    signer = () => normalizeProvider(config.region)().then(async (region) => [
      await config.regionInfoProvider(region, {
        useFipsEndpoint: await config.useFipsEndpoint(),
        useDualstackEndpoint: await config.useDualstackEndpoint()
      }) || {},
      region
    ]).then(([regionInfo, region]) => {
      const { signingRegion, signingService } = regionInfo;
      config.signingRegion = config.signingRegion || signingRegion || region;
      config.signingName = config.signingName || signingService || config.serviceId;
      const params = {
        ...config,
        credentials: config.credentials,
        region: config.signingRegion,
        service: config.signingName,
        sha256,
        uriEscapePath: signingEscapePath
      };
      const SignerCtor = config.signerConstructor || SignatureV4;
      return new SignerCtor(params);
    });
  } else {
    signer = async (authScheme) => {
      authScheme = Object.assign({}, {
        name: "sigv4",
        signingName: config.signingName || config.defaultSigningName,
        signingRegion: await normalizeProvider(config.region)(),
        properties: {}
      }, authScheme);
      const signingRegion = authScheme.signingRegion;
      const signingService = authScheme.signingName;
      config.signingRegion = config.signingRegion || signingRegion;
      config.signingName = config.signingName || signingService || config.serviceId;
      const params = {
        ...config,
        credentials: config.credentials,
        region: config.signingRegion,
        service: config.signingName,
        sha256,
        uriEscapePath: signingEscapePath
      };
      const SignerCtor = config.signerConstructor || SignatureV4;
      return new SignerCtor(params);
    };
  }
  const resolvedConfig = Object.assign(config, {
    systemClockOffset,
    signingEscapePath,
    signer,
    disableClockSkewCorrection: normalizeProvider(config.disableClockSkewCorrection ?? defaultDisableClockSkewCorrection)
  });
  return resolvedConfig;
};
function normalizeCredentialProvider(config, { credentials, credentialDefaultProvider }) {
  let credentialsProvider;
  if (credentials) {
    if (!credentials?.memoized) {
      credentialsProvider = memoizeIdentityProvider(credentials, isIdentityExpired, doesIdentityRequireRefresh);
    } else {
      credentialsProvider = credentials;
    }
  } else {
    if (credentialDefaultProvider) {
      credentialsProvider = normalizeProvider(credentialDefaultProvider(Object.assign({}, config, {
        parentClientConfig: config
      })));
    } else {
      credentialsProvider = async () => {
        throw new Error("@aws-sdk/core::resolveAwsSdkSigV4Config - `credentials` not provided and no credentialDefaultProvider was configured.");
      };
    }
  }
  credentialsProvider.memoized = true;
  return credentialsProvider;
}
function bindCallerConfig(config, credentialsProvider) {
  if (credentialsProvider.configBound) {
    return credentialsProvider;
  }
  const fn = async (options) => credentialsProvider({ ...options, callerClientConfig: config });
  fn.memoized = credentialsProvider.memoized;
  fn.configBound = true;
  return fn;
}

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/index.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/clock-skew-defaults.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/clock-skew-node-config.js
init_esm_shims();
var ENV_DISABLE_CLOCK_SKEW_CORRECTION = "AWS_DISABLE_CLOCK_SKEW_CORRECTION";
var CONFIG_DISABLE_CLOCK_SKEW_CORRECTION = "disable_clock_skew_correction";
var NODE_DISABLE_CLOCK_SKEW_CORRECTION_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => booleanSelector(env, ENV_DISABLE_CLOCK_SKEW_CORRECTION, SelectorType.ENV),
  configFileSelector: (profile) => booleanSelector(profile, CONFIG_DISABLE_CLOCK_SKEW_CORRECTION, SelectorType.CONFIG),
  default: false
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/clock-skew-defaults.js
var DEFAULT_DISABLE_CLOCK_SKEW_CORRECTION = loadConfig(NODE_DISABLE_CLOCK_SKEW_CORRECTION_CONFIG_OPTIONS);

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/index.js
var resolveAwsSdkSigV4Config = bindResolveAwsSdkSigV4Config(DEFAULT_DISABLE_CLOCK_SKEW_CORRECTION);

// node_modules/@aws-sdk/nested-clients/package.json
var package_default = {
  name: "@aws-sdk/nested-clients",
  version: "3.997.46",
  description: "Nested clients for AWS SDK packages.",
  homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/packages/nested-clients",
  license: "Apache-2.0",
  author: {
    name: "AWS SDK for JavaScript Team",
    url: "https://aws.amazon.com/sdk-for-javascript/"
  },
  repository: {
    type: "git",
    url: "https://github.com/aws/aws-sdk-js-v3.git",
    directory: "packages/nested-clients"
  },
  files: [
    "./cognito-identity.d.ts",
    "./cognito-identity.js",
    "./signin.d.ts",
    "./signin.js",
    "./sso-oidc.d.ts",
    "./sso-oidc.js",
    "./sso.d.ts",
    "./sso.js",
    "./sts.d.ts",
    "./sts.js",
    "dist-*/**"
  ],
  sideEffects: false,
  main: "./dist-cjs/index.js",
  module: "./dist-es/index.js",
  browser: {
    "./dist-es/submodules/cognito-identity/runtimeConfig": "./dist-es/submodules/cognito-identity/runtimeConfig.browser",
    "./dist-es/submodules/signin/runtimeConfig": "./dist-es/submodules/signin/runtimeConfig.browser",
    "./dist-es/submodules/sso-oidc/runtimeConfig": "./dist-es/submodules/sso-oidc/runtimeConfig.browser",
    "./dist-es/submodules/sso/runtimeConfig": "./dist-es/submodules/sso/runtimeConfig.browser",
    "./dist-es/submodules/sts/runtimeConfig": "./dist-es/submodules/sts/runtimeConfig.browser"
  },
  types: "./dist-types/index.d.ts",
  typesVersions: {
    "<4.5": {
      "dist-types/*": [
        "dist-types/ts3.4/*"
      ],
      "*": [
        "dist-types/ts3.4/submodules/*/index.d.ts"
      ]
    }
  },
  "react-native": {},
  exports: {
    "./package.json": "./package.json",
    "./sso-oidc": {
      types: "./dist-types/submodules/sso-oidc/index.d.ts",
      module: "./dist-es/submodules/sso-oidc/index.js",
      node: "./dist-cjs/submodules/sso-oidc/index.js",
      import: "./dist-es/submodules/sso-oidc/index.js",
      require: "./dist-cjs/submodules/sso-oidc/index.js"
    },
    "./sts": {
      types: "./dist-types/submodules/sts/index.d.ts",
      module: "./dist-es/submodules/sts/index.js",
      node: "./dist-cjs/submodules/sts/index.js",
      import: "./dist-es/submodules/sts/index.js",
      require: "./dist-cjs/submodules/sts/index.js"
    },
    "./signin": {
      types: "./dist-types/submodules/signin/index.d.ts",
      module: "./dist-es/submodules/signin/index.js",
      node: "./dist-cjs/submodules/signin/index.js",
      import: "./dist-es/submodules/signin/index.js",
      require: "./dist-cjs/submodules/signin/index.js"
    },
    "./cognito-identity": {
      types: "./dist-types/submodules/cognito-identity/index.d.ts",
      module: "./dist-es/submodules/cognito-identity/index.js",
      node: "./dist-cjs/submodules/cognito-identity/index.js",
      import: "./dist-es/submodules/cognito-identity/index.js",
      require: "./dist-cjs/submodules/cognito-identity/index.js"
    },
    "./sso": {
      types: "./dist-types/submodules/sso/index.d.ts",
      module: "./dist-es/submodules/sso/index.js",
      node: "./dist-cjs/submodules/sso/index.js",
      import: "./dist-es/submodules/sso/index.js",
      require: "./dist-cjs/submodules/sso/index.js"
    }
  },
  scripts: {
    build: "concurrently 'yarn:build:types' 'yarn:build:es' && yarn build:cjs",
    "build:cjs": "node ../../scripts/compilation/inline",
    "build:es": "premove dist-es && tsc -p tsconfig.es.json",
    "build:include:deps": 'yarn g:turbo run build -F="$npm_package_name"',
    "build:types": "premove dist-types && tsc -p tsconfig.types.json",
    "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
    clean: "premove dist-cjs dist-es dist-types",
    lint: "node ../../scripts/validation/submodules-linter.js",
    prebuild: "yarn lint",
    test: "yarn g:vitest run",
    "test:watch": "yarn g:vitest watch"
  },
  dependencies: {
    "@aws-sdk/core": "^3.978.1",
    "@aws-sdk/signature-v4-multi-region": "^3.996.47",
    "@aws-sdk/types": "^3.974.6",
    "@smithy/core": "^3.35.0",
    "@smithy/fetch-http-handler": "^5.8.0",
    "@smithy/node-http-handler": "^4.12.1",
    "@smithy/types": "^4.19.0",
    tslib: "^2.6.2"
  },
  devDependencies: {
    concurrently: "7.0.0",
    "downlevel-dts": "0.10.1",
    premove: "4.0.0",
    typescript: "~7.0.2"
  },
  engines: {
    node: ">=20.0.0"
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_1Protocol.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJsonRpcProtocol.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/ProtocolLib.js
init_esm_shims();
var ProtocolLib = class {
  queryCompat;
  errorRegistry;
  constructor(queryCompat = false) {
    this.queryCompat = queryCompat;
  }
  resolveRestContentType(defaultContentType, inputSchema) {
    const members = inputSchema.getMemberSchemas();
    const httpPayloadMember = Object.values(members).find((m) => {
      return !!m.getMergedTraits().httpPayload;
    });
    if (httpPayloadMember) {
      const mediaType = httpPayloadMember.getMergedTraits().mediaType;
      if (mediaType) {
        return mediaType;
      } else if (httpPayloadMember.isStringSchema()) {
        return "text/plain";
      } else if (httpPayloadMember.isBlobSchema()) {
        return "application/octet-stream";
      } else {
        return defaultContentType;
      }
    } else if (!inputSchema.isUnitSchema()) {
      const hasBody = Object.values(members).find((m) => {
        const { httpQuery, httpQueryParams, httpHeader, httpLabel, httpPrefixHeaders } = m.getMergedTraits();
        const noPrefixHeaders = httpPrefixHeaders === void 0;
        return !httpQuery && !httpQueryParams && !httpHeader && !httpLabel && noPrefixHeaders;
      });
      if (hasBody) {
        return defaultContentType;
      }
    }
  }
  async getErrorSchemaOrThrowBaseException(errorIdentifier, defaultNamespace, response, dataObject, metadata, getErrorSchema) {
    let errorName = errorIdentifier;
    if (errorIdentifier.includes("#")) {
      [, errorName] = errorIdentifier.split("#");
    }
    const errorMetadata = {
      $metadata: metadata,
      $fault: response.statusCode < 500 ? "client" : "server"
    };
    if (!this.errorRegistry) {
      throw new Error("@aws-sdk/core/protocols - error handler not initialized.");
    }
    try {
      const errorSchema = getErrorSchema?.(this.errorRegistry, errorName) ?? this.errorRegistry.getSchema(errorIdentifier);
      return { errorSchema, errorMetadata };
    } catch (e) {
      dataObject.message = dataObject.message ?? dataObject.Message ?? "UnknownError";
      const synthetic = this.errorRegistry;
      const baseExceptionSchema = synthetic.getBaseException();
      if (baseExceptionSchema) {
        const ErrorCtor = synthetic.getErrorCtor(baseExceptionSchema) ?? Error;
        throw this.decorateServiceException(Object.assign(new ErrorCtor({ name: errorName }), errorMetadata), dataObject);
      }
      const d = dataObject;
      const message = d?.message ?? d?.Message ?? d?.Error?.Message ?? d?.Error?.message;
      throw this.decorateServiceException(Object.assign(new Error(message), {
        name: errorName
      }, errorMetadata), dataObject);
    }
  }
  compose(composite, errorIdentifier, defaultNamespace) {
    let namespace = defaultNamespace;
    if (errorIdentifier.includes("#")) {
      [namespace] = errorIdentifier.split("#");
    }
    const staticRegistry = TypeRegistry.for(namespace);
    const defaultSyntheticRegistry = TypeRegistry.for("smithy.ts.sdk.synthetic." + defaultNamespace);
    composite.copyFrom(staticRegistry);
    composite.copyFrom(defaultSyntheticRegistry);
    this.errorRegistry = composite;
  }
  decorateServiceException(exception, additions = {}) {
    if (this.queryCompat) {
      const msg = exception.Message ?? additions.Message;
      const error = decorateServiceException(exception, additions);
      if (msg) {
        error.message = msg;
      }
      const errorObj = error.Error ?? {};
      errorObj.Type = error.Error?.Type;
      errorObj.Code = error.Error?.Code;
      errorObj.Message = error.Error?.message ?? error.Error?.Message ?? msg;
      error.Error = errorObj;
      const reqId = error.$metadata.requestId;
      if (reqId) {
        error.RequestId = reqId;
      }
      return error;
    }
    return decorateServiceException(exception, additions);
  }
  setQueryCompatError(output, response) {
    const queryErrorHeader = response.headers?.["x-amzn-query-error"];
    if (output !== void 0 && queryErrorHeader != null) {
      const [Code, Type] = queryErrorHeader.split(";");
      const keys = Object.keys(output);
      const Error2 = {
        Code,
        Type
      };
      output.Code = Code;
      output.Type = Type;
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        Error2[k === "message" ? "Message" : k] = output[k];
      }
      delete Error2.__type;
      output.Error = Error2;
    }
  }
  queryCompatOutput(queryCompatErrorData, errorData) {
    if (queryCompatErrorData.Error) {
      errorData.Error = queryCompatErrorData.Error;
    }
    if (queryCompatErrorData.Type) {
      errorData.Type = queryCompatErrorData.Type;
    }
    if (queryCompatErrorData.Code) {
      errorData.Code = queryCompatErrorData.Code;
    }
  }
  findQueryCompatibleError(registry, errorName) {
    try {
      return registry.getSchema(errorName);
    } catch (e) {
      return registry.find((schema) => NormalizedSchema.of(schema).getMergedTraits().awsQueryError?.[0] === errorName);
    }
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/codec-v2/JsonCodec2.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/ConfigurableSerdeContext.js
init_esm_shims();
var SerdeContextConfig = class {
  serdeContext;
  setSerdeContext(serdeContext) {
    this.serdeContext = serdeContext;
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/codec-v2/JsonShapeDeserializer2.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/UnionSerde.js
init_esm_shims();
var UnionSerde = class {
  from;
  to;
  keys;
  constructor(from, to) {
    this.from = from;
    this.to = to;
    const keys = Object.keys(this.from);
    const set = new Set(keys);
    set.delete("__type");
    this.keys = set;
  }
  mark(key) {
    this.keys.delete(key);
  }
  hasUnknown() {
    return this.keys.size === 1 && Object.keys(this.to).length === 0;
  }
  writeUnknown() {
    if (this.hasUnknown()) {
      const k = this.keys.values().next().value;
      const v = this.from[k];
      this.to.$unknown = [k, v];
    }
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/detectBufferParsing.js
init_esm_shims();
var canParseBuffer;
function detectBufferParsing() {
  if (canParseBuffer === void 0) {
    try {
      if (typeof Buffer !== "function") {
        canParseBuffer = false;
      } else {
        const result = JSON.parse(Buffer.from([123, 125]));
        canParseBuffer = result !== null && typeof result === "object";
      }
    } catch {
      canParseBuffer = false;
    }
  }
  return canParseBuffer;
}

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReviver.js
init_esm_shims();
function jsonReviver(key, value, context) {
  if (context?.source) {
    const numericString = context.source;
    if (typeof value === "number") {
      const inSafeRange = value <= Number.MAX_SAFE_INTEGER && value >= Number.MIN_SAFE_INTEGER;
      if (inSafeRange) {
        if (isRepresentable(numericString, value)) {
          return value;
        }
        return new NumericValue(numericString, "bigDecimal");
      } else {
        if (isFractionalBigNumeric(numericString)) {
          return new NumericValue(numericString, "bigDecimal");
        }
        if (/[eE]/.test(numericString)) {
          return expandExponentToBigInt(numericString);
        }
        return BigInt(numericString);
      }
    }
  }
  return value;
}
function isFractionalBigNumeric(s) {
  const dotIndex = s.indexOf(".");
  if (dotIndex === -1) {
    return false;
  }
  const eIndex = s.search(/[eE]/);
  if (eIndex === -1) {
    return true;
  }
  const fracDigits = eIndex - dotIndex - 1;
  const exp = parseInt(s.slice(eIndex + 1), 10);
  return exp < fracDigits;
}
function isRepresentable(numericString, value) {
  if (numericString === String(value)) {
    return true;
  }
  if (Object.is(value, -0)) {
    return true;
  }
  if (/[eE]/.test(numericString)) {
    return expandToDecimal(numericString) === expandToDecimal(String(value));
  }
  const normalized = numericString.replace(/(\.\d*?)0+$/, "$1").replace(/\.$/, "");
  const canonical = String(value);
  if (normalized === canonical) {
    return true;
  }
  if (/[eE]/.test(canonical)) {
    return normalized === expandToDecimal(canonical);
  }
  return false;
}
function expandToDecimal(s) {
  const negative = s.startsWith("-");
  const abs = negative ? s.slice(1) : s;
  const eIndex = abs.search(/[eE]/);
  let result;
  if (eIndex === -1) {
    result = abs;
  } else {
    const exp = parseInt(abs.slice(eIndex + 1), 10);
    const mantissa = abs.slice(0, eIndex);
    const dotIndex = mantissa.indexOf(".");
    let digits;
    let intLen;
    if (dotIndex === -1) {
      digits = mantissa;
      intLen = mantissa.length;
    } else {
      digits = mantissa.slice(0, dotIndex) + mantissa.slice(dotIndex + 1);
      intLen = dotIndex;
    }
    digits = digits.replace(/0+$/, "") || "0";
    const newDotPos = intLen + exp;
    if (digits === "0") {
      result = "0";
    } else if (newDotPos <= 0) {
      result = "0." + "0".repeat(-newDotPos) + digits;
    } else if (newDotPos >= digits.length) {
      result = digits + "0".repeat(newDotPos - digits.length);
    } else {
      result = digits.slice(0, newDotPos) + "." + digits.slice(newDotPos);
    }
  }
  if (result.includes(".")) {
    result = result.replace(/(\.\d*?)0+$/, "$1").replace(/\.$/, "");
  }
  return (negative ? "-" : "") + result;
}
function expandExponentToBigInt(s) {
  const eIndex = s.search(/[eE]/);
  const exp = parseInt(s.slice(eIndex + 1), 10);
  const negative = s.startsWith("-");
  const mantissa = s.slice(negative ? 1 : 0, eIndex);
  const dotIndex = mantissa.indexOf(".");
  let digits;
  let shift;
  if (dotIndex === -1) {
    digits = mantissa;
    shift = exp;
  } else {
    digits = mantissa.slice(0, dotIndex) + mantissa.slice(dotIndex + 1);
    const fracDigits = mantissa.length - dotIndex - 1;
    shift = exp - fracDigits;
  }
  digits = digits.replace(/0+$/, "") || "0";
  const result = BigInt(digits) * 10n ** BigInt(shift + (mantissa.replace(".", "").length - digits.length));
  return negative ? -result : result;
}

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/needsReviver.js
init_esm_shims();
var REVIVER_SYMBOL = /* @__PURE__ */ Symbol.for("@aws-sdk/reviver");
function needsReviver(schema) {
  const ns = NormalizedSchema.of(schema);
  const raw = ns.getSchema();
  if (Array.isArray(raw) && ns.isStructSchema()) {
    if (REVIVER_SYMBOL in raw) {
      return raw[REVIVER_SYMBOL];
    }
    const result = _check(ns, /* @__PURE__ */ new Set());
    raw[REVIVER_SYMBOL] = result;
    return result;
  }
  return _check(ns, /* @__PURE__ */ new Set());
}
function _check(ns, seen) {
  const raw = ns.getSchema();
  if (seen.has(raw)) {
    return false;
  }
  seen.add(raw);
  if (ns.isBigIntegerSchema() || ns.isBigDecimalSchema()) {
    return true;
  }
  if (ns.isStructSchema()) {
    for (const [, memberSchema] of ns.structIterator()) {
      if (_check(memberSchema, seen)) {
        return true;
      }
    }
  } else if (ns.isListSchema() || ns.isMapSchema()) {
    if (_check(ns.getValueSchema(), seen)) {
      return true;
    }
  } else if (ns.isDocumentSchema()) {
    return true;
  }
  return false;
}

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/parseJsonBody.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/common.js
init_esm_shims();
var collectBodyString = (streamBody, context) => collectBody(streamBody, context).then((body) => (context?.utf8Encoder ?? toUtf8)(body));

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/parseJsonBody.js
async function parseJsonBody(streamBody, context, schema) {
  let parsingInput;
  if (detectBufferParsing() && typeof streamBody?.[Symbol.asyncIterator] === "function") {
    const buffer = await collectBody(streamBody, context);
    if (typeof Buffer === "function") {
      if (Buffer.isBuffer(buffer)) {
        parsingInput = buffer;
      } else {
        parsingInput = Buffer.from(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      }
    }
  }
  if (!parsingInput) {
    parsingInput = await collectBodyString(streamBody, context);
  }
  if (parsingInput.length === 0) {
    return {};
  }
  const reviver = schema && needsReviver(schema) ? jsonReviver : void 0;
  try {
    return JSON.parse(parsingInput, reviver);
  } catch (e) {
    if (e?.name === "SyntaxError") {
      Object.defineProperty(e, "$responseBodyText", {
        value: typeof parsingInput === "string" ? parsingInput : parsingInput.toString("utf8")
      });
    }
    throw e;
  }
}
var findKey = (object, key) => Object.keys(object).find((k) => k.toLowerCase() === key.toLowerCase());
var sanitizeErrorCode = (rawValue) => {
  let cleanValue = rawValue;
  if (typeof cleanValue === "number") {
    cleanValue = cleanValue.toString();
  }
  if (cleanValue.indexOf(",") >= 0) {
    cleanValue = cleanValue.split(",")[0];
  }
  if (cleanValue.indexOf(":") >= 0) {
    cleanValue = cleanValue.split(":")[0];
  }
  if (cleanValue.indexOf("#") >= 0) {
    cleanValue = cleanValue.split("#")[1];
  }
  return cleanValue;
};
var loadRestJsonErrorCode = (output, data) => {
  return loadErrorCode(output, data, ["header", "code", "type"]);
};
var loadJsonRpcErrorCode = (output, data, queryCompat = false) => {
  return loadErrorCode(output, data, queryCompat ? ["code", "header", "type"] : ["type", "code", "header"]);
};
var loadErrorCode = ({ headers }, data, order) => {
  while (order.length > 0) {
    const location = order.shift();
    switch (location) {
      case "header":
        const headerKey = findKey(headers ?? {}, "x-amzn-errortype");
        if (headerKey !== void 0) {
          return sanitizeErrorCode(headers[headerKey]);
        }
        break;
      case "code":
        const codeKey = findKey(data ?? {}, "code");
        if (codeKey && data[codeKey] !== void 0) {
          return sanitizeErrorCode(data[codeKey]);
        }
        break;
      case "type":
        if (data?.__type !== void 0) {
          return sanitizeErrorCode(data.__type);
        }
        break;
    }
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/writeKey.js
init_esm_shims();
function writeKey(obj) {
  Object.defineProperty(obj, "__proto__", { value: void 0, writable: true, enumerable: true, configurable: true });
}

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/codec-v2/JsonShapeDeserializer2.js
var JsonShapeDeserializer2 = class extends SerdeContextConfig {
  settings;
  constructor(settings) {
    super();
    this.settings = settings;
  }
  async read(schema, data) {
    const reviver = needsReviver(schema) ? jsonReviver : void 0;
    let parsed;
    if (typeof data === "string") {
      if (data.length === 0) {
        return {};
      }
      parsed = JSON.parse(data, reviver);
    } else if (data instanceof Uint8Array && detectBufferParsing()) {
      if (data.byteLength === 0) {
        return {};
      }
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
      parsed = JSON.parse(buf, reviver);
    } else {
      parsed = await parseJsonBody(data, this.serdeContext, schema);
    }
    return this._read(schema, parsed);
  }
  readObject(schema, data) {
    return this._read(schema, data);
  }
  _read(schema, value) {
    const isObject = value !== null && typeof value === "object";
    const ns = NormalizedSchema.of(schema);
    if (isObject) {
      if (ns.isStructSchema()) {
        return this._readStruct(ns, value);
      }
      if (Array.isArray(value) && ns.isListSchema()) {
        const listMember = ns.getValueSchema();
        if (this.needsTransform(listMember)) {
          for (let i = 0; i < value.length; ++i) {
            value[i] = this._read(listMember, value[i]);
          }
        }
        return value;
      }
      if (ns.isMapSchema()) {
        const mapMember = ns.getValueSchema();
        const map = value;
        if (this.needsTransform(mapMember)) {
          for (const k in map) {
            if (k === "__proto__") {
              writeKey(map);
            }
            map[k] = this._read(mapMember, map[k]);
          }
        }
        return map;
      }
    }
    if (ns.isBlobSchema() && typeof value === "string") {
      return fromBase64(value);
    }
    const mediaType = ns.getMergedTraits().mediaType;
    if (ns.isStringSchema() && typeof value === "string" && mediaType) {
      const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
      if (isJson) {
        return LazyJsonString.from(value);
      }
      return value;
    }
    if (ns.isTimestampSchema() && value != null) {
      const format = determineTimestampFormat(ns, this.settings);
      switch (format) {
        case 5:
          return parseRfc3339DateTimeWithOffset(value);
        case 6:
          return parseRfc7231DateTime(value);
        case 7:
          return parseEpochTimestamp(value);
        default:
          console.warn("Missing timestamp format, parsing value with Date constructor:", value);
          return new Date(value);
      }
    }
    if (ns.isBigIntegerSchema() && (typeof value === "number" || typeof value === "string")) {
      return BigInt(value);
    }
    if (ns.isBigDecimalSchema() && value != void 0) {
      if (value instanceof NumericValue) {
        return value;
      }
      const untyped = value;
      if (untyped.type === "bigDecimal" && "string" in untyped) {
        return new NumericValue(untyped.string, untyped.type);
      }
      return new NumericValue(String(value), "bigDecimal");
    }
    if (ns.isNumericSchema() && typeof value === "string") {
      switch (value) {
        case "Infinity":
          return Infinity;
        case "-Infinity":
          return -Infinity;
        case "NaN":
          return NaN;
      }
      return value;
    }
    if (ns.isDocumentSchema()) {
      if (isObject) {
        if (Array.isArray(value)) {
          for (let i = 0; i < value.length; ++i) {
            const v = value[i];
            if (!(v instanceof NumericValue)) {
              value[i] = this._read(ns, v);
            }
          }
        } else {
          const doc = value;
          for (const k in doc) {
            if (k === "__proto__") {
              writeKey(doc);
            }
            const v = doc[k];
            if (!(v instanceof NumericValue)) {
              doc[k] = this._read(ns, v);
            }
          }
        }
      }
    }
    return value;
  }
  _readStruct(ns, record) {
    const union = ns.isUnionSchema();
    const out = {};
    let nameMap;
    const hasType = typeof record.__type === "string";
    const { jsonName } = this.settings;
    if (jsonName && hasType) {
      nameMap = {};
    }
    let unionSerde;
    if (union) {
      unionSerde = new UnionSerde(record, out);
    }
    for (const [memberName, memberSchema] of ns.structIterator()) {
      let fromKey = memberName;
      if (jsonName) {
        fromKey = memberSchema.getMergedTraits().jsonName ?? fromKey;
        if (hasType) {
          nameMap[fromKey] = memberName;
        }
      }
      if (union) {
        unionSerde.mark(fromKey);
      }
      if (record[fromKey] != null) {
        out[memberName] = this._read(memberSchema, record[fromKey]);
      }
    }
    if (union) {
      unionSerde.writeUnknown();
    } else if (hasType) {
      for (const k in record) {
        const v = record[k];
        const t = jsonName ? nameMap[k] ?? k : k;
        if (!(t in out)) {
          out[t] = v;
        }
      }
    }
    return out;
  }
  needsTransform(ns) {
    if (ns.isBlobSchema() || ns.isTimestampSchema() || ns.isBigIntegerSchema() || ns.isBigDecimalSchema()) {
      return true;
    }
    if (ns.isDocumentSchema() || ns.isStructSchema() || ns.isListSchema() || ns.isMapSchema()) {
      return true;
    }
    if (ns.isStringSchema() && ns.getMergedTraits().mediaType) {
      return true;
    }
    return false;
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/codec-v2/JsonShapeSerializer2.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/codec-v2/JsonBytesStringAdapter.js
init_esm_shims();
var JsonBytesStringAdapter = class _JsonBytesStringAdapter extends Uint8Array {
  string = null;
  static allocUnsafe(bytes) {
    if (typeof Buffer === "function") {
      const buffer = Buffer.allocUnsafe(bytes);
      return new _JsonBytesStringAdapter(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    }
    return new _JsonBytesStringAdapter(bytes);
  }
  toString() {
    return this.s();
  }
  valueOf() {
    return this.s();
  }
  includes(searchString, position) {
    if (typeof searchString === "string") {
      return this.s().includes(searchString, position);
    }
    return Uint8Array.prototype.includes.call(this, searchString, position);
  }
  indexOf(searchString, position) {
    if (typeof searchString === "string") {
      return this.s().indexOf(searchString, position);
    }
    return Uint8Array.prototype.indexOf.call(this, searchString, position);
  }
  lastIndexOf(searchString, position) {
    if (typeof searchString === "string") {
      return this.s().lastIndexOf(searchString, position);
    }
    const fn = Uint8Array.prototype.lastIndexOf;
    if (position !== void 0) {
      return fn.call(this, searchString, position);
    }
    return fn.call(this, searchString);
  }
  startsWith(searchString, position) {
    return this.s().startsWith(searchString, position);
  }
  endsWith(searchString, endPosition) {
    return this.s().endsWith(searchString, endPosition);
  }
  match(regexp) {
    return this.s().match(regexp);
  }
  replace(searchValue, replaceValue) {
    return this.s().replace(searchValue, replaceValue);
  }
  search(regexp) {
    return this.s().search(regexp);
  }
  split(separator, limit) {
    return this.s().split(separator, limit);
  }
  substring(start, end) {
    return this.s().substring(start, end);
  }
  trim() {
    return this.s().trim();
  }
  trimStart() {
    return this.s().trimStart();
  }
  trimEnd() {
    return this.s().trimEnd();
  }
  charAt(pos) {
    return this.s().charAt(pos);
  }
  charCodeAt(index) {
    return this.s().charCodeAt(index);
  }
  padStart(maxLength, fillString) {
    return this.s().padStart(maxLength, fillString);
  }
  padEnd(maxLength, fillString) {
    return this.s().padEnd(maxLength, fillString);
  }
  repeat(count) {
    return this.s().repeat(count);
  }
  toUpperCase() {
    return this.s().toUpperCase();
  }
  toLowerCase() {
    return this.s().toLowerCase();
  }
  s() {
    if (this.string == null) {
      const n = Date.now();
      if (n > warned + 6e4) {
        console.warn("@aws-sdk/core/protocols - WARN - JsonCodec2: you have called a string method on a Uint8Array request body. It has been automatically converted to string. In a future version this will throw an error.");
        warned = n;
      }
      this.string = toUtf8(this);
    }
    return this.string;
  }
};
var warned = 0;

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/codec-v2/JsonShapeSerializer2.js
var encoder = new TextEncoder();
var OPEN_BRACE = 123;
var CLOSE_BRACE = 125;
var OPEN_BRACKET = 91;
var CLOSE_BRACKET = 93;
var QUOTE = 34;
var COLON = 58;
var COMMA = 44;
var BACKSLASH = 92;
var TRUE = new Uint8Array([116, 114, 117, 101]);
var FALSE = new Uint8Array([102, 97, 108, 115, 101]);
var NULL = new Uint8Array([110, 117, 108, 108]);
var ESCAPE_TABLE = new Array(128).fill(null);
ESCAPE_TABLE[8] = "b";
ESCAPE_TABLE[9] = "t";
ESCAPE_TABLE[10] = "n";
ESCAPE_TABLE[12] = "f";
ESCAPE_TABLE[13] = "r";
ESCAPE_TABLE[34] = '"';
ESCAPE_TABLE[92] = "\\";
for (let i = 0; i < 32; i++) {
  if (ESCAPE_TABLE[i] === null) {
    ESCAPE_TABLE[i] = "u00" + i.toString(16).padStart(2, "0");
  }
}
var INITIAL_BUFFER_SIZE = 2048;
function alloc(size) {
  return JsonBytesStringAdapter.allocUnsafe(size);
}
var JsonShapeSerializer2 = class _JsonShapeSerializer2 extends SerdeContextConfig {
  settings;
  json;
  i = 0;
  rootSchema;
  rawValue;
  passthrough = false;
  constructor(settings) {
    super();
    this.settings = settings;
    this.json = alloc(INITIAL_BUFFER_SIZE);
  }
  write(schema, value) {
    this.i = 0;
    this.rawValue = value;
    this.rootSchema = NormalizedSchema.of(schema);
    this.passthrough = this.rootSchema.isBlobSchema() || this.rootSchema.isStringSchema();
    if (!this.passthrough) {
      this.writeValue(this.rootSchema, value, void 0);
    }
  }
  writeDiscriminatedDocument(schema, value) {
    this.i = 0;
    this.rootSchema = NormalizedSchema.of(schema);
    const ns = this.rootSchema;
    if (ns.isStructSchema() && value != null && typeof value === "object") {
      this.writeValue(ns, value, void 0);
      const prefix = `"__type":"${ns.getName(true) ?? "Unknown"}",`;
      const z = prefix.length;
      this.ensure(z);
      this.json.copyWithin(1 + z, 1, this.i);
      encoder.encodeInto(prefix, this.json.subarray(1));
      this.i += z;
    } else {
      this.writeValue(ns, value, void 0);
    }
  }
  flush() {
    this.rootSchema = void 0;
    const finalPosition = this.i;
    this.i = 0;
    const raw = this.rawValue;
    this.rawValue = void 0;
    if (finalPosition === 0) {
      return raw;
    }
    const result = this.json.subarray(0, finalPosition);
    this.json = alloc(INITIAL_BUFFER_SIZE);
    return result;
  }
  ensure(byteCount) {
    const { i, json } = this;
    if (i + byteCount > json.length) {
      let newSize = json.length * 2;
      while (newSize < i + byteCount) {
        newSize *= 2;
      }
      const next = alloc(newSize);
      next.set(this.json);
      this.json = next;
    }
  }
  writeAscii(s) {
    const z = s.length;
    this.ensure(z);
    let { i, json } = this;
    for (let j = 0; j < z; ++j) {
      json[i] = s.charCodeAt(j);
      i += 1;
    }
    this.i = i;
  }
  writeAsciiQuoted(s) {
    const z = s.length;
    this.ensure(z + 4);
    let { json, i } = this;
    json[i++] = QUOTE;
    for (let j = 0; j < z; ++j) {
      json[i++] = s.charCodeAt(j);
    }
    json[i++] = QUOTE;
    this.i = i;
  }
  writeJsonString(s) {
    this.ensure(s.length * 3 + 2);
    this.json[this.i++] = QUOTE;
    const z = s.length;
    for (let j = 0; j < z; ++j) {
      const c = s.charCodeAt(j);
      if (c > 34 && c < 92) {
        this.json[this.i++] = c;
      } else if (c < 128) {
        const esc = ESCAPE_TABLE[c];
        if (esc !== null) {
          this.ensure(esc.length + 1);
          this.json[this.i++] = BACKSLASH;
          for (let k = 0; k < esc.length; k++) {
            this.json[this.i++] = esc.charCodeAt(k);
          }
        } else {
          this.json[this.i++] = c;
        }
      } else if (c >= 55296 && c <= 56319) {
        const next = j + 1 < z ? s.charCodeAt(j + 1) : 0;
        if (next >= 56320 && next <= 57343) {
          this.ensure(4);
          const { written } = encoder.encodeInto(s.substring(j, j + 2), this.json.subarray(this.i));
          this.i += written;
          ++j;
        } else {
          this.ensure(6);
          this.writeUnicodeEscape(c);
        }
      } else if (c >= 56320 && c <= 57343) {
        this.ensure(6);
        this.writeUnicodeEscape(c);
      } else {
        let { i, json } = this;
        if (c < 2048) {
          json[i++] = 192 | c >> 6;
          json[i++] = 128 | c & 63;
        } else {
          json[i++] = 224 | c >> 12;
          json[i++] = 128 | c >> 6 & 63;
          json[i++] = 128 | c & 63;
        }
        this.i = i;
      }
    }
    this.json[this.i++] = QUOTE;
  }
  writeUnicodeEscape(code) {
    let { json, i } = this;
    json[i++] = BACKSLASH;
    json[i++] = 117;
    const hex = code.toString(16).padStart(4, "0");
    for (let j = 0; j < 4; ++j) {
      json[i++] = hex.charCodeAt(j);
    }
    this.i = i;
  }
  static B64 = (() => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const table = new Uint8Array(64);
    for (let i = 0; i < 64; ++i) {
      table[i] = chars.charCodeAt(i);
    }
    return table;
  })();
  writeBase64(data) {
    const b64Len = Math.ceil(data.length / 3) * 4;
    this.ensure(b64Len + 2);
    const json = this.json;
    const B64 = _JsonShapeSerializer2.B64;
    let i = this.i;
    json[i++] = QUOTE;
    const len = data.length;
    const remainder = len % 3;
    const mainLen = len - remainder;
    for (let j = 0; j < mainLen; j += 3) {
      const a = data[j];
      const b = data[j + 1];
      const c = data[j + 2];
      json[i++] = B64[a >> 2];
      json[i++] = B64[(a & 3) << 4 | b >> 4];
      json[i++] = B64[(b & 15) << 2 | c >> 6];
      json[i++] = B64[c & 63];
    }
    if (remainder === 2) {
      const a = data[mainLen];
      const b = data[mainLen + 1];
      json[i++] = B64[a >> 2];
      json[i++] = B64[(a & 3) << 4 | b >> 4];
      json[i++] = B64[(b & 15) << 2];
      json[i++] = 61;
    } else if (remainder === 1) {
      const a = data[mainLen];
      json[i++] = B64[a >> 2];
      json[i++] = B64[(a & 3) << 4];
      json[i++] = 61;
      json[i++] = 61;
    }
    json[i++] = QUOTE;
    this.i = i;
  }
  writeValue(schema, value, container) {
    if (value == null) {
      if (container?.isStructSchema()) {
        if (value === void 0) {
          const ns2 = NormalizedSchema.of(schema);
          if (ns2.isIdempotencyToken()) {
            this.writeAsciiQuoted(generateIdempotencyToken());
            return;
          }
        }
        return;
      }
      this.ensure(4);
      this.json.set(NULL, this.i);
      this.i += 4;
      return;
    }
    const ns = NormalizedSchema.of(schema);
    const isObject = typeof value === "object";
    if (ns.isStringSchema()) {
      const mediaType = ns.getMergedTraits().mediaType;
      if (mediaType) {
        const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
        if (isJson) {
          this.writeJsonString(LazyJsonString.from(value).toString());
          return;
        }
      }
    }
    if (isObject) {
      if (ns.isStructSchema()) {
        this.writeStruct(ns, value);
        return;
      }
      if (Array.isArray(value) && (ns.isListSchema() || ns.isDocumentSchema())) {
        this.writeList(ns, value, ns.isDocumentSchema());
        return;
      }
      if (ns.isMapSchema()) {
        this.writeMap(ns, value, false);
        return;
      }
      if (value instanceof Uint8Array && (ns.isBlobSchema() || ns.isDocumentSchema())) {
        this.writeBase64(value);
        return;
      }
      if (value instanceof Date && (ns.isTimestampSchema() || ns.isDocumentSchema())) {
        this.writeTimestamp(ns, value);
        return;
      }
      if (value instanceof NumericValue) {
        this.writeAscii(value.string);
        return;
      }
      if (ns.isDocumentSchema()) {
        if (Array.isArray(value)) {
          this.writeList(ns, value, true);
        } else {
          this.writeMap(ns, value, true);
        }
        return;
      }
      const json = JSON.stringify(value);
      this.writeAscii(json);
      return;
    }
    if (typeof value === "string") {
      if (ns.isBlobSchema()) {
        const b64 = (this.serdeContext?.base64Encoder ?? toBase64)(value);
        this.writeAsciiQuoted(b64);
        return;
      }
      this.writeJsonString(value);
      return;
    }
    if (typeof value === "number") {
      if (Math.abs(value) === Infinity || Number.isNaN(value)) {
        this.writeAsciiQuoted(String(value));
        return;
      }
      const numStr = String(value);
      this.writeAscii(numStr);
      return;
    }
    if (typeof value === "boolean") {
      this.ensure(5);
      let { i, json } = this;
      if (value) {
        json.set(TRUE, i);
        i += 4;
      } else {
        json.set(FALSE, i);
        i += 5;
      }
      this.i = i;
      return;
    }
    if (typeof value === "bigint") {
      this.writeAscii(value.toString());
      return;
    }
    this.writeAscii(String(value));
  }
  writeStruct(ns, value) {
    this.ensure(2);
    this.json[this.i++] = OPEN_BRACE;
    let wroteAny = false;
    const hasType = typeof value.__type === "string";
    let writtenKeys;
    if (hasType) {
      writtenKeys = /* @__PURE__ */ new Set();
    }
    for (const [memberName, memberSchema] of ns.structIterator()) {
      const item = value[memberName];
      if (item == null && !memberSchema.isIdempotencyToken()) {
        continue;
      }
      if (wroteAny) {
        this.ensure(1);
        this.json[this.i++] = COMMA;
      }
      wroteAny = true;
      const targetKey = this.settings.jsonName ? memberSchema.getMergedTraits().jsonName ?? memberName : memberName;
      if (writtenKeys) {
        writtenKeys.add(memberName);
        writtenKeys.add(targetKey);
      }
      this.writeAsciiQuoted(targetKey);
      this.json[this.i++] = COLON;
      this.writeValue(memberSchema, item, ns);
    }
    if (!wroteAny && ns.isUnionSchema()) {
      const { $unknown } = value;
      if (Array.isArray($unknown)) {
        const [k, v] = $unknown;
        this.writeAsciiQuoted(k);
        this.ensure(1);
        this.json[this.i++] = COLON;
        this.writeValue(15, v, ns);
      }
    } else if (hasType) {
      for (const k in value) {
        if (writtenKeys.has(k)) {
          continue;
        }
        writtenKeys.add(k);
        const v = value[k];
        if (wroteAny) {
          this.ensure(1);
          this.json[this.i++] = COMMA;
        }
        wroteAny = true;
        this.writeAsciiQuoted(k);
        this.ensure(1);
        this.json[this.i++] = COLON;
        this.writeValue(15, v, void 0);
      }
    }
    this.ensure(1);
    this.json[this.i++] = CLOSE_BRACE;
  }
  writeList(ns, value, isDocument) {
    const sparse = !!ns.getMergedTraits().sparse;
    const valueSchema = ns.getValueSchema();
    if (!isDocument) {
      if (valueSchema.isStringSchema() || valueSchema.isNumericSchema() || valueSchema.isBooleanSchema()) {
        let hasSpecials = false;
        for (let i = 0; i < value.length; ++i) {
          const v = value[i];
          if (Number.isNaN(v) || v === Infinity || v === -Infinity || v == null && !sparse) {
            hasSpecials = true;
            break;
          }
        }
        let json;
        if (!hasSpecials) {
          json = JSON.stringify(value);
        } else {
          const out = [];
          for (let i = 0; i < value.length; ++i) {
            const v = value[i];
            if (v == null && !sparse)
              continue;
            if (Number.isNaN(v) || v === Infinity || v === -Infinity) {
              out.push(String(v));
            } else {
              out.push(v);
            }
          }
          json = JSON.stringify(out);
        }
        this.ensure(json.length * 3);
        this.i += encoder.encodeInto(json, this.json.subarray(this.i)).written;
        return;
      }
    }
    this.ensure(2);
    this.json[this.i++] = OPEN_BRACKET;
    let wroteFirstItem = false;
    for (let i = 0; i < value.length; ++i) {
      const item = value[i];
      if (isDocument ? item === void 0 : item == null && !sparse) {
        continue;
      }
      if (wroteFirstItem) {
        this.ensure(1);
        this.json[this.i++] = COMMA;
      }
      this.writeValue(valueSchema, item, void 0);
      wroteFirstItem = true;
    }
    this.ensure(1);
    this.json[this.i++] = CLOSE_BRACKET;
  }
  writeMap(ns, value, isDocument) {
    const sparse = !!ns.getMergedTraits().sparse;
    const valueSchema = ns.getValueSchema();
    if (!isDocument) {
      if (valueSchema.isStringSchema() || valueSchema.isNumericSchema() || valueSchema.isBooleanSchema()) {
        let modifications;
        for (const k in value) {
          const v = value[k];
          if (Number.isNaN(v) || v === Infinity || v === -Infinity) {
            (modifications ??= {})[k] = v;
            value[k] = String(v);
          } else if (v === null && !sparse) {
            (modifications ??= {})[k] = null;
            value[k] = void 0;
          }
        }
        const json = JSON.stringify(value);
        if (modifications) {
          Object.assign(value, modifications);
        }
        this.ensure(json.length * 3);
        this.i += encoder.encodeInto(json, this.json.subarray(this.i)).written;
        return;
      }
    }
    this.ensure(2);
    this.json[this.i++] = OPEN_BRACE;
    let first = true;
    for (const k in value) {
      const v = value[k];
      if (isDocument ? v === void 0 : v == null && !sparse) {
        continue;
      }
      if (!first) {
        this.ensure(1);
        this.json[this.i++] = COMMA;
      }
      first = false;
      this.writeJsonString(k);
      this.ensure(1);
      this.json[this.i++] = COLON;
      this.writeValue(valueSchema, v, void 0);
    }
    this.ensure(1);
    this.json[this.i++] = CLOSE_BRACE;
  }
  writeTimestamp(ns, value) {
    const format = determineTimestampFormat(ns, this.settings);
    switch (format) {
      case 5: {
        const iso = value.toISOString().replace(".000Z", "Z");
        this.writeAsciiQuoted(iso);
        return;
      }
      case 6: {
        this.writeAsciiQuoted(dateToUtcString(value));
        return;
      }
      case 7: {
        const epochSecs = String(value.getTime() / 1e3);
        this.writeAscii(epochSecs);
        return;
      }
      default: {
        const epochSecs = String(value.getTime() / 1e3);
        this.writeAscii(epochSecs);
        return;
      }
    }
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/codec-v2/JsonCodec2.js
var JsonCodec2 = class extends SerdeContextConfig {
  settings;
  constructor(settings) {
    super();
    this.settings = settings;
  }
  createSerializer() {
    const serializer = new JsonShapeSerializer2(this.settings);
    serializer.setSerdeContext(this.serdeContext);
    return serializer;
  }
  createDeserializer() {
    const deserializer = new JsonShapeDeserializer2(this.settings);
    deserializer.setSerdeContext(this.serdeContext);
    return deserializer;
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJsonRpcProtocol.js
var AwsJsonRpcProtocol = class extends RpcProtocol {
  serializer;
  deserializer;
  serviceTarget;
  codec;
  mixin;
  awsQueryCompatible;
  constructor({ defaultNamespace, errorTypeRegistries, serviceTarget, awsQueryCompatible, jsonCodec }) {
    super({
      defaultNamespace,
      errorTypeRegistries
    });
    this.serviceTarget = serviceTarget;
    this.codec = jsonCodec ?? new JsonCodec2({
      timestampFormat: {
        useTrait: true,
        default: 7
      },
      jsonName: false
    });
    this.serializer = this.codec.createSerializer();
    this.deserializer = this.codec.createDeserializer();
    this.awsQueryCompatible = !!awsQueryCompatible;
    this.mixin = new ProtocolLib(this.awsQueryCompatible);
  }
  async serializeRequest(operationSchema, input, context) {
    const request = await super.serializeRequest(operationSchema, input, context);
    if (!request.path.endsWith("/")) {
      request.path += "/";
    }
    request.headers["content-type"] = `application/x-amz-json-${this.getJsonRpcVersion()}`;
    request.headers["x-amz-target"] = `${this.serviceTarget}.${operationSchema.name}`;
    if (this.awsQueryCompatible) {
      request.headers["x-amzn-query-mode"] = "true";
    }
    if (deref(operationSchema.input) === "unit" || !request.body) {
      request.body = "{}";
    }
    return request;
  }
  getPayloadCodec() {
    return this.codec;
  }
  async handleError(operationSchema, context, response, dataObject, metadata) {
    const { awsQueryCompatible } = this;
    if (awsQueryCompatible) {
      this.mixin.setQueryCompatError(dataObject, response);
    }
    const errorIdentifier = loadJsonRpcErrorCode(response, dataObject, awsQueryCompatible) ?? "Unknown";
    this.mixin.compose(this.compositeErrorRegistry, errorIdentifier, this.options.defaultNamespace);
    const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata, awsQueryCompatible ? this.mixin.findQueryCompatibleError : void 0);
    const ns = NormalizedSchema.of(errorSchema);
    const message = dataObject.message ?? dataObject.Message ?? "UnknownError";
    const ErrorCtor = this.compositeErrorRegistry.getErrorCtor(errorSchema) ?? Error;
    const exception = new ErrorCtor({});
    const output = {};
    const errorDeserializer = this.codec.createDeserializer();
    for (const [name, member] of ns.structIterator()) {
      if (dataObject[name] != null) {
        output[name] = errorDeserializer.readObject(member, dataObject[name]);
      }
    }
    if (awsQueryCompatible) {
      this.mixin.queryCompatOutput(dataObject, output);
    }
    throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
      $fault: ns.getMergedTraits().error,
      message
    }, output), dataObject);
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_1Protocol.js
var AwsJson1_1Protocol = class extends AwsJsonRpcProtocol {
  constructor({ defaultNamespace, errorTypeRegistries, serviceTarget, awsQueryCompatible, jsonCodec }) {
    super({
      defaultNamespace,
      errorTypeRegistries,
      serviceTarget,
      awsQueryCompatible,
      jsonCodec
    });
  }
  getShapeId() {
    return "aws.protocols#awsJson1_1";
  }
  getJsonRpcVersion() {
    return "1.1";
  }
  getDefaultContentType() {
    return "application/x-amz-json-1.1";
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsRestJsonProtocol.js
init_esm_shims();
var AwsRestJsonProtocol = class extends HttpBindingProtocol {
  serializer;
  deserializer;
  codec;
  mixin = new ProtocolLib();
  constructor({ defaultNamespace, errorTypeRegistries, jsonCodec }) {
    super({
      defaultNamespace,
      errorTypeRegistries
    });
    const settings = {
      timestampFormat: {
        useTrait: true,
        default: 7
      },
      httpBindings: true,
      jsonName: true
    };
    this.codec = jsonCodec ?? new JsonCodec2(settings);
    this.serializer = new HttpInterceptingShapeSerializer(this.codec.createSerializer(), settings);
    this.deserializer = new HttpInterceptingShapeDeserializer(this.codec.createDeserializer(), settings);
  }
  getShapeId() {
    return "aws.protocols#restJson1";
  }
  getPayloadCodec() {
    return this.codec;
  }
  setSerdeContext(serdeContext) {
    this.codec.setSerdeContext(serdeContext);
    super.setSerdeContext(serdeContext);
  }
  async serializeRequest(operationSchema, input, context) {
    const request = await super.serializeRequest(operationSchema, input, context);
    const inputSchema = NormalizedSchema.of(operationSchema.input);
    if (!request.headers["content-type"]) {
      const contentType = this.mixin.resolveRestContentType(this.getDefaultContentType(), inputSchema);
      if (contentType) {
        request.headers["content-type"] = contentType;
      }
    }
    if (request.body == null && request.headers["content-type"] === this.getDefaultContentType()) {
      request.body = "{}";
    }
    return request;
  }
  async deserializeResponse(operationSchema, context, response) {
    const output = await super.deserializeResponse(operationSchema, context, response);
    const outputSchema = NormalizedSchema.of(operationSchema.output);
    for (const [name, member] of outputSchema.structIterator()) {
      if (member.getMemberTraits().httpPayload && !(name in output)) {
        output[name] = null;
      }
    }
    return output;
  }
  async handleError(operationSchema, context, response, dataObject, metadata) {
    const errorIdentifier = loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
    this.mixin.compose(this.compositeErrorRegistry, errorIdentifier, this.options.defaultNamespace);
    const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata);
    const ns = NormalizedSchema.of(errorSchema);
    const message = dataObject.message ?? dataObject.Message ?? "UnknownError";
    const ErrorCtor = this.compositeErrorRegistry.getErrorCtor(errorSchema) ?? Error;
    const exception = new ErrorCtor({});
    await this.deserializeHttpMessage(errorSchema, context, response, dataObject);
    const output = {};
    const errorDeserializer = this.codec.createDeserializer();
    for (const [name, member] of ns.structIterator()) {
      const target = member.getMergedTraits().jsonName ?? name;
      output[name] = errorDeserializer.readObject(member, dataObject[target]);
    }
    throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
      $fault: ns.getMergedTraits().error,
      message
    }, output), dataObject);
  }
  getDefaultContentType() {
    return "application/json";
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsQueryProtocol.js
init_esm_shims();

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeDeserializer.js
init_esm_shims();

// node_modules/@aws-sdk/xml-builder/dist-es/index.js
init_esm_shims();

// node_modules/@aws-sdk/xml-builder/dist-es/xml-parser.js
init_esm_shims();
function writeKey2(obj) {
  Object.defineProperty(obj, "__proto__", { value: void 0, writable: true, enumerable: true, configurable: true });
}
function parseXML(xml) {
  const state = new AwsXmlParser(xml);
  return state.parse();
}
var AwsXmlParser = class _AwsXmlParser {
  x;
  i = 0;
  z;
  constructor(x) {
    this.x = x;
    this.x = x.replace(/\r\n?/g, "\n");
    this.z = this.x.length;
  }
  parse() {
    const p = this;
    const { z } = p;
    while (p.i < z) {
      p.trim();
      if (p.i >= z) {
        break;
      }
      if (p.isNext("<?")) {
        p.readTo("?>");
        p.trim();
      } else if (p.isNext("<!--")) {
        p.readTo("-->");
        p.trim();
      } else if (p.isNext("<!DOCTYPE", false)) {
        p.skipDoctype();
        p.trim();
      } else if (p.x[p.i] === "<") {
        const root = p.parseTag();
        return { [root.tag]: root.value };
      } else {
        throw new Error("@aws-sdk XML parse error: unexpected content.");
      }
    }
    throw new Error("@aws-sdk XML parse error: no root element.");
  }
  isNext(s, caseSensitive = true) {
    const p = this;
    if (caseSensitive) {
      return p.x.startsWith(s, p.i);
    }
    return p.x.toLowerCase().startsWith(s.toLowerCase(), p.i);
  }
  readTo(stop) {
    const p = this;
    const _i = p.x.indexOf(stop, p.i);
    if (_i === -1) {
      throw new Error(`@aws-sdk XML parse error: expected "${stop}" not found.`);
    }
    const result = p.x.slice(p.i, _i);
    p.i = _i + stop.length;
    return result;
  }
  trim() {
    const p = this;
    while (p.i < p.z && " 	\r\n".includes(p.x[p.i])) {
      ++p.i;
    }
  }
  readAttrValue() {
    const p = this;
    const quote = p.x[p.i];
    ++p.i;
    let value = "";
    while (p.i < p.z && p.x[p.i] !== quote) {
      value += p.x[p.i++];
    }
    ++p.i;
    return p.decodeEntities(value);
  }
  parseTag() {
    const p = this;
    ++p.i;
    let tag = "";
    while (p.i < p.z && !" 	\r\n>/".includes(p.x[p.i])) {
      tag += p.x[p.i++];
    }
    let hasAttrs = false;
    const attrs = {};
    while (p.i < p.z) {
      p.trim();
      if (">/".includes(p.x[p.i])) {
        break;
      }
      let name = "";
      while (p.i < p.z && !"= 	\r\n>/?".includes(p.x[p.i])) {
        name += p.x[p.i++];
      }
      p.trim();
      if (p.x[p.i] !== "=") {
        break;
      }
      ++p.i;
      p.trim();
      if (name === "__proto__") {
        writeKey2(attrs);
      }
      attrs[name] = p.readAttrValue();
      hasAttrs = true;
    }
    if (p.i >= p.z) {
      throw new Error("@aws-sdk XML parse error: unexpected end of input.");
    }
    if (p.x[p.i] === "/") {
      ++p.i;
      if (p.i >= p.z || p.x[p.i] !== ">") {
        throw new Error("@aws-sdk XML parse error: expected > at the end of self-closing tag.");
      }
      ++p.i;
      return { tag, value: hasAttrs ? attrs : "" };
    }
    if (p.x[p.i] !== ">") {
      throw new Error("@aws-sdk XML parse error: expected > at the end of opening tag.");
    }
    ++p.i;
    const textParts = [];
    const childTags = [];
    let hasElementChild = false;
    while (p.i < p.z) {
      if (p.isNext("</")) {
        break;
      }
      if (p.x[p.i] === "<") {
        if (p.isNext("<!--")) {
          p.readTo("-->");
        } else if (p.isNext("<![CDATA[")) {
          p.i += 9;
          textParts.push(p.readTo("]]>"));
        } else if (p.isNext("<?")) {
          p.readTo("?>");
        } else {
          hasElementChild = true;
          childTags.push(p.parseTag());
        }
      } else {
        let text = "";
        while (p.i < p.z && p.x[p.i] !== "<") {
          text += p.x[p.i++];
        }
        textParts.push(p.decodeEntities(text));
      }
    }
    if (!p.isNext("</")) {
      throw new Error(`@aws-sdk XML parse error: missing closing tag </${tag}>.`);
    }
    p.i += 2;
    const closeTag = p.readTo(">").trim();
    if (closeTag !== tag) {
      throw new Error(`@aws-sdk XML parse error: mismatched tags <${tag}> and </${closeTag}>.`);
    }
    if (!hasAttrs && textParts.length === 0 && !hasElementChild) {
      return { tag, value: "" };
    }
    if (!hasAttrs && !hasElementChild) {
      const text = textParts.length === 1 ? textParts[0] : textParts.join("");
      if (text.trim() === "" && text.includes("\n")) {
        return { tag, value: "" };
      }
      return { tag, value: text };
    }
    const obj = {};
    for (const text of textParts) {
      if (text.trim() === "" && text.includes("\n")) {
        continue;
      }
      obj["#text"] = "#text" in obj ? obj["#text"] + text : text;
    }
    for (const child of childTags) {
      if (child.tag === "__proto__") {
        writeKey2(obj);
      }
      if (child.tag in obj) {
        if (Array.isArray(obj[child.tag])) {
          obj[child.tag].push(child.value);
        } else {
          obj[child.tag] = [obj[child.tag], child.value];
        }
      } else {
        obj[child.tag] = child.value;
      }
    }
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "__proto__") {
        writeKey2(obj);
      }
      obj[k] = v;
    }
    return { tag, value: obj };
  }
  static ENTITIES = {
    amp: "&",
    lt: "<",
    gt: ">",
    quot: '"',
    apos: "'"
  };
  skipDoctype() {
    const p = this;
    p.i += 9;
    let depth = 0;
    while (p.i < p.z) {
      const c = p.x[p.i];
      if (c === "[") {
        ++depth;
      } else if (c === "]") {
        --depth;
      } else if (c === ">" && depth === 0) {
        ++p.i;
        return;
      }
      ++p.i;
    }
    throw new Error("@aws-sdk XML parse error: unclosed DOCTYPE.");
  }
  decodeEntities(s) {
    return s.replace(/&(?:#x([0-9a-fA-F]{1,6})|#(\d{1,7})|([a-zA-Z][a-zA-Z0-9]{0,30}));/g, (_, hex, dec, named) => {
      if (hex) {
        return String.fromCharCode(parseInt(hex, 16));
      }
      if (dec) {
        return String.fromCharCode(parseInt(dec, 10));
      }
      return _AwsXmlParser.ENTITIES[named] ?? "";
    });
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeDeserializer.js
var XmlShapeDeserializer = class extends SerdeContextConfig {
  settings;
  stringDeserializer;
  constructor(settings) {
    super();
    this.settings = settings;
    this.stringDeserializer = new FromStringShapeDeserializer(settings);
  }
  setSerdeContext(serdeContext) {
    this.serdeContext = serdeContext;
    this.stringDeserializer.setSerdeContext(serdeContext);
  }
  read(schema, bytes, key) {
    const ns = NormalizedSchema.of(schema);
    const memberSchemas = ns.getMemberSchemas();
    const isEventPayload = ns.isStructSchema() && ns.isMemberSchema() && !!Object.values(memberSchemas).find((memberNs) => {
      return !!memberNs.getMemberTraits().eventPayload;
    });
    if (isEventPayload) {
      const output = {};
      const memberName = Object.keys(memberSchemas)[0];
      const eventMemberSchema = memberSchemas[memberName];
      if (eventMemberSchema.isBlobSchema()) {
        output[memberName] = bytes;
      } else {
        output[memberName] = this.read(memberSchemas[memberName], bytes);
      }
      return output;
    }
    const xmlString = (this.serdeContext?.utf8Encoder ?? toUtf8)(bytes);
    const parsedObject = this.parseXml(xmlString);
    return this.readSchema(schema, key ? parsedObject[key] : parsedObject);
  }
  readSchema(_schema, value) {
    const ns = NormalizedSchema.of(_schema);
    if (ns.isUnitSchema()) {
      return;
    }
    const traits = ns.getMergedTraits();
    if (ns.isListSchema() && !Array.isArray(value)) {
      return this.readSchema(ns, [value]);
    }
    if (value == null) {
      return value;
    }
    if (typeof value === "object") {
      const flat = !!traits.xmlFlattened;
      if (ns.isListSchema()) {
        const listValue = ns.getValueSchema();
        const buffer2 = [];
        const sourceKey = listValue.getMergedTraits().xmlName ?? "member";
        const source = flat ? value : (value[0] ?? value)[sourceKey];
        if (source == null) {
          return buffer2;
        }
        const sourceArray = Array.isArray(source) ? source : [source];
        for (const v of sourceArray) {
          buffer2.push(this.readSchema(listValue, v));
        }
        return buffer2;
      }
      const buffer = {};
      if (ns.isMapSchema()) {
        const keyNs = ns.getKeySchema();
        const memberNs = ns.getValueSchema();
        let entries;
        if (flat) {
          entries = Array.isArray(value) ? value : [value];
        } else {
          entries = Array.isArray(value.entry) ? value.entry : [value.entry];
        }
        const keyProperty = keyNs.getMergedTraits().xmlName ?? "key";
        const valueProperty = memberNs.getMergedTraits().xmlName ?? "value";
        for (const entry of entries) {
          const key = entry[keyProperty];
          const value2 = entry[valueProperty];
          if (key === "__proto__") {
            writeKey(buffer);
          }
          buffer[key] = this.readSchema(memberNs, value2);
        }
        return buffer;
      }
      if (ns.isStructSchema()) {
        const union = ns.isUnionSchema();
        let unionSerde;
        if (union) {
          unionSerde = new UnionSerde(value, buffer);
        }
        for (const [memberName, memberSchema] of ns.structIterator()) {
          const memberTraits = memberSchema.getMergedTraits();
          const xmlObjectKey = !memberTraits.httpPayload ? memberSchema.getMemberTraits().xmlName ?? memberName : memberTraits.xmlName ?? memberSchema.getName();
          if (union) {
            unionSerde.mark(xmlObjectKey);
          }
          if (value[xmlObjectKey] != null) {
            buffer[memberName] = this.readSchema(memberSchema, value[xmlObjectKey]);
          }
        }
        if (union) {
          unionSerde.writeUnknown();
        }
        return buffer;
      }
      if (ns.isDocumentSchema()) {
        return value;
      }
      throw new Error(`@aws-sdk/core/protocols - xml deserializer unhandled schema type for ${ns.getName(true)}`);
    }
    if (ns.isListSchema()) {
      return [];
    }
    if (ns.isMapSchema() || ns.isStructSchema()) {
      return {};
    }
    return this.stringDeserializer.read(ns, value);
  }
  parseXml(xml) {
    if (xml.length) {
      let parsedObj;
      try {
        parsedObj = parseXML(xml);
      } catch (e) {
        if (e && typeof e === "object") {
          Object.defineProperty(e, "$responseBodyText", {
            value: xml
          });
        }
        throw e;
      }
      const textNodeName = "#text";
      const key = Object.keys(parsedObj)[0];
      const parsedObjToReturn = parsedObj[key];
      if (parsedObjToReturn[textNodeName]) {
        parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
        delete parsedObjToReturn[textNodeName];
      }
      return getValueFromTextNode(parsedObjToReturn);
    }
    return {};
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/QueryShapeSerializer.js
init_esm_shims();
var QueryShapeSerializer = class extends SerdeContextConfig {
  settings;
  buffer;
  constructor(settings) {
    super();
    this.settings = settings;
  }
  write(schema, value, prefix = "") {
    if (this.buffer === void 0) {
      this.buffer = "";
    }
    const ns = NormalizedSchema.of(schema);
    if (prefix && !prefix.endsWith(".")) {
      prefix += ".";
    }
    if (ns.isBlobSchema()) {
      if (typeof value === "string" || value instanceof Uint8Array) {
        this.writeKey(prefix);
        this.writeValue((this.serdeContext?.base64Encoder ?? toBase64)(value));
      }
    } else if (ns.isBooleanSchema() || ns.isNumericSchema() || ns.isStringSchema()) {
      if (value != null) {
        this.writeKey(prefix);
        this.writeValue(String(value));
      } else if (ns.isIdempotencyToken()) {
        this.writeKey(prefix);
        this.writeValue(generateIdempotencyToken());
      }
    } else if (ns.isBigIntegerSchema()) {
      if (value != null) {
        this.writeKey(prefix);
        this.writeValue(String(value));
      }
    } else if (ns.isBigDecimalSchema()) {
      if (value != null) {
        this.writeKey(prefix);
        this.writeValue(value instanceof NumericValue ? value.string : String(value));
      }
    } else if (ns.isTimestampSchema()) {
      if (value instanceof Date) {
        this.writeKey(prefix);
        const format = determineTimestampFormat(ns, this.settings);
        switch (format) {
          case 5:
            this.writeValue(value.toISOString().replace(".000Z", "Z"));
            break;
          case 6:
            this.writeValue(dateToUtcString(value));
            break;
          case 7:
            this.writeValue(String(value.getTime() / 1e3));
            break;
        }
      }
    } else if (ns.isDocumentSchema()) {
      if (Array.isArray(value)) {
        this.write(64 | 15, value, prefix);
      } else if (value instanceof Date) {
        this.write(4, value, prefix);
      } else if (value instanceof Uint8Array) {
        this.write(21, value, prefix);
      } else if (value && typeof value === "object") {
        this.write(128 | 15, value, prefix);
      } else {
        this.writeKey(prefix);
        this.writeValue(String(value));
      }
    } else if (ns.isListSchema()) {
      if (Array.isArray(value)) {
        if (value.length === 0) {
          if (this.settings.serializeEmptyLists) {
            this.writeKey(prefix);
            this.writeValue("");
          }
        } else {
          const member = ns.getValueSchema();
          const flat = this.settings.flattenLists || ns.getMergedTraits().xmlFlattened;
          let i = 1;
          for (const item of value) {
            if (item == null) {
              continue;
            }
            const traits = member.getMergedTraits();
            const suffix = this.getKey("member", traits.xmlName, traits.ec2QueryName);
            const key = flat ? `${prefix}${i}` : `${prefix}${suffix}.${i}`;
            this.write(member, item, key);
            ++i;
          }
        }
      }
    } else if (ns.isMapSchema()) {
      if (value && typeof value === "object") {
        const keySchema = ns.getKeySchema();
        const memberSchema = ns.getValueSchema();
        const flat = ns.getMergedTraits().xmlFlattened;
        let i = 1;
        for (const k in value) {
          const v = value[k];
          if (v == null) {
            continue;
          }
          const keyTraits = keySchema.getMergedTraits();
          const keySuffix = this.getKey("key", keyTraits.xmlName, keyTraits.ec2QueryName);
          const key = flat ? `${prefix}${i}.${keySuffix}` : `${prefix}entry.${i}.${keySuffix}`;
          const valTraits = memberSchema.getMergedTraits();
          const valueSuffix = this.getKey("value", valTraits.xmlName, valTraits.ec2QueryName);
          const valueKey = flat ? `${prefix}${i}.${valueSuffix}` : `${prefix}entry.${i}.${valueSuffix}`;
          this.write(keySchema, k, key);
          this.write(memberSchema, v, valueKey);
          ++i;
        }
      }
    } else if (ns.isStructSchema()) {
      if (value && typeof value === "object") {
        let didWriteMember = false;
        for (const [memberName, member] of ns.structIterator()) {
          if (value[memberName] == null && !member.isIdempotencyToken()) {
            continue;
          }
          const traits = member.getMergedTraits();
          const suffix = this.getKey(memberName, traits.xmlName, traits.ec2QueryName, "struct");
          const key = `${prefix}${suffix}`;
          this.write(member, value[memberName], key);
          didWriteMember = true;
        }
        if (!didWriteMember && ns.isUnionSchema()) {
          const { $unknown } = value;
          if (Array.isArray($unknown)) {
            const [k, v] = $unknown;
            const key = `${prefix}${k}`;
            this.write(15, v, key);
          }
        }
      }
    } else if (ns.isUnitSchema()) ; else {
      throw new Error(`@aws-sdk/core/protocols - QuerySerializer unrecognized schema type ${ns.getName(true)}`);
    }
  }
  flush() {
    if (this.buffer === void 0) {
      throw new Error("@aws-sdk/core/protocols - QuerySerializer cannot flush with nothing written to buffer.");
    }
    const str = this.buffer;
    delete this.buffer;
    return str;
  }
  getKey(memberName, xmlName, ec2QueryName, keySource) {
    const { ec2, capitalizeKeys } = this.settings;
    if (ec2 && ec2QueryName) {
      return ec2QueryName;
    }
    const key = xmlName ?? memberName;
    if (capitalizeKeys && keySource === "struct") {
      return key[0].toUpperCase() + key.slice(1);
    }
    return key;
  }
  writeKey(key) {
    if (key.endsWith(".")) {
      key = key.slice(0, key.length - 1);
    }
    this.buffer += `&${extendedEncodeURIComponent(key)}=`;
  }
  writeValue(value) {
    this.buffer += extendedEncodeURIComponent(value);
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsQueryProtocol.js
var AwsQueryProtocol = class extends RpcProtocol {
  options;
  serializer;
  deserializer;
  mixin = new ProtocolLib();
  constructor(options) {
    super({
      defaultNamespace: options.defaultNamespace,
      errorTypeRegistries: options.errorTypeRegistries
    });
    this.options = options;
    const settings = {
      timestampFormat: {
        useTrait: true,
        default: 5
      },
      httpBindings: false,
      xmlNamespace: options.xmlNamespace,
      serviceNamespace: options.defaultNamespace,
      serializeEmptyLists: true
    };
    this.serializer = new QueryShapeSerializer(settings);
    this.deserializer = new XmlShapeDeserializer(settings);
  }
  getShapeId() {
    return "aws.protocols#awsQuery";
  }
  setSerdeContext(serdeContext) {
    this.serializer.setSerdeContext(serdeContext);
    this.deserializer.setSerdeContext(serdeContext);
  }
  getPayloadCodec() {
    throw new Error("AWSQuery protocol has no payload codec.");
  }
  async serializeRequest(operationSchema, input, context) {
    const request = await super.serializeRequest(operationSchema, input, context);
    if (!request.path.endsWith("/")) {
      request.path += "/";
    }
    request.headers["content-type"] = "application/x-www-form-urlencoded";
    if (deref(operationSchema.input) === "unit" || !request.body) {
      request.body = "";
    }
    const action = operationSchema.name.split("#")[1] ?? operationSchema.name;
    request.body = `Action=${action}&Version=${this.options.version}` + request.body;
    if (request.body.endsWith("&")) {
      request.body = request.body.slice(-1);
    }
    return request;
  }
  async deserializeResponse(operationSchema, context, response) {
    const deserializer = this.deserializer;
    const ns = NormalizedSchema.of(operationSchema.output);
    const dataObject = {};
    if (response.statusCode >= 300) {
      const bytes2 = await collectBody(response.body, context);
      if (bytes2.byteLength > 0) {
        Object.assign(dataObject, await deserializer.read(15, bytes2));
      }
      await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
    }
    for (const header in response.headers) {
      const value = response.headers[header];
      delete response.headers[header];
      response.headers[header.toLowerCase()] = value;
    }
    const shortName = operationSchema.name.split("#")[1] ?? operationSchema.name;
    const awsQueryResultKey = ns.isStructSchema() && this.useNestedResult() ? shortName + "Result" : void 0;
    const bytes = await collectBody(response.body, context);
    if (bytes.byteLength > 0) {
      Object.assign(dataObject, await deserializer.read(ns, bytes, awsQueryResultKey));
    }
    dataObject.$metadata = this.deserializeMetadata(response);
    return dataObject;
  }
  useNestedResult() {
    return true;
  }
  async handleError(operationSchema, context, response, dataObject, metadata) {
    const errorIdentifier = this.loadQueryErrorCode(response, dataObject) ?? "Unknown";
    this.mixin.compose(this.compositeErrorRegistry, errorIdentifier, this.options.defaultNamespace);
    const errorData = this.loadQueryError(dataObject) ?? {};
    const message = this.loadQueryErrorMessage(dataObject);
    errorData.message = message;
    errorData.Error = {
      Type: errorData.Type,
      Code: errorData.Code,
      Message: message
    };
    const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, errorData, metadata, this.mixin.findQueryCompatibleError);
    const ns = NormalizedSchema.of(errorSchema);
    const ErrorCtor = this.compositeErrorRegistry.getErrorCtor(errorSchema) ?? Error;
    const exception = new ErrorCtor({});
    const output = {
      Type: errorData.Error.Type,
      Code: errorData.Error.Code,
      Error: errorData.Error
    };
    for (const [name, member] of ns.structIterator()) {
      const target = member.getMergedTraits().xmlName ?? name;
      const value = errorData[target] ?? dataObject[target];
      output[name] = this.deserializer.readSchema(member, value);
    }
    throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
      $fault: ns.getMergedTraits().error,
      message
    }, output), dataObject);
  }
  loadQueryErrorCode(output, data) {
    const code = (data.Errors?.[0]?.Error ?? data.Errors?.Error ?? data.Error)?.Code;
    if (code !== void 0) {
      return code;
    }
    if (output.statusCode == 404) {
      return "NotFound";
    }
  }
  loadQueryError(data) {
    return data.Errors?.[0]?.Error ?? data.Errors?.Error ?? data.Error;
  }
  loadQueryErrorMessage(data) {
    const errorData = this.loadQueryError(data);
    return errorData?.message ?? errorData?.Message ?? data.message ?? data.Message ?? "Unknown";
  }
  getDefaultContentType() {
    return "application/x-www-form-urlencoded";
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/index.js
init_esm_shims();

export { AwsJson1_1Protocol, AwsQueryProtocol, AwsRestJsonProtocol, AwsSdkSigV4ASigner, AwsSdkSigV4Signer, NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, NODE_SIGV4A_CONFIG_OPTIONS, package_default, resolveAwsSdkSigV4AConfig, resolveAwsSdkSigV4Config };
