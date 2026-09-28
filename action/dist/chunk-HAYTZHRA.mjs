import { createRequire } from 'module';
import { isValidHostLabel, IniSectionType } from './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';
import { homedir } from 'os';
import { join, sep } from 'path';
import { createHash } from 'crypto';
import { readFile } from 'fs/promises';

createRequire(import.meta.url);

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/config.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/getInstanceMetadataRegion.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/defaults-mode/constants.js
init_esm_shims();
var AWS_EXECUTION_ENV = "AWS_EXECUTION_ENV";
var AWS_REGION_ENV = "AWS_REGION";
var AWS_DEFAULT_REGION_ENV = "AWS_DEFAULT_REGION";
var ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
var DEFAULTS_MODE_OPTIONS = ["in-region", "cross-region", "mobile", "standard", "legacy"];
var IMDS_REGION_PATH = "/latest/meta-data/placement/region";
var IMDS_TOKEN_PATH = "/latest/api/token";
var X_AWS_EC2_METADATA_TOKEN = "x-aws-ec2-metadata-token";
var X_AWS_EC2_METADATA_TOKEN_TTL = "x-aws-ec2-metadata-token-ttl-seconds";

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/getInstanceMetadataRegion.js
var TIMEOUT_MS = 1e3;
var NEG_CACHE_TTL_MS = 6e4;
var negativeCacheUntil = 0;
var getInstanceMetadataRegion = async () => {
  if (process.env[ENV_IMDS_DISABLED]) {
    return void 0;
  }
  if (Date.now() < negativeCacheUntil) {
    return void 0;
  }
  try {
    const endpoint = resolveImdsEndpoint();
    const token = (await imdsRequest({
      ...endpoint,
      path: IMDS_TOKEN_PATH,
      method: "PUT",
      headers: {
        [X_AWS_EC2_METADATA_TOKEN_TTL]: "21600"
      }
    })).toString();
    const region = (await imdsRequest({
      ...endpoint,
      path: IMDS_REGION_PATH,
      method: "GET",
      headers: {
        [X_AWS_EC2_METADATA_TOKEN]: token
      }
    })).toString().trim();
    return region || cacheNegativeAndReturnUndefined();
  } catch {
    return cacheNegativeAndReturnUndefined();
  }
};
var cacheNegativeAndReturnUndefined = () => {
  negativeCacheUntil = Date.now() + NEG_CACHE_TTL_MS;
  return void 0;
};
var resolveImdsEndpoint = () => {
  const envEndpoint = process.env.AWS_EC2_METADATA_SERVICE_ENDPOINT;
  if (envEndpoint) {
    const url = new URL(envEndpoint);
    return {
      hostname: url.hostname.replace(/^\[(.+)]$/, "$1"),
      port: url.port ? Number(url.port) : void 0
    };
  }
  if (process.env.AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE === "IPv6") {
    return { hostname: "fd00:ec2::254" };
  }
  return { hostname: "169.254.169.254" };
};
var imdsRequest = async (options) => {
  const { request } = await import('http');
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: options.hostname,
      port: options.port,
      path: options.path,
      method: options.method,
      headers: options.headers,
      timeout: TIMEOUT_MS,
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    req.on("error", (err) => {
      reject(err);
      req.destroy();
    });
    req.on("timeout", () => {
      reject(new Error("TimeoutError from instance metadata service"));
      req.destroy();
    });
    req.on("response", (res) => {
      const { statusCode = 400 } = res;
      if (statusCode < 200 || statusCode >= 300) {
        reject(Object.assign(new Error("Error response received from instance metadata service"), { statusCode }));
        req.destroy();
        return;
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve(Buffer.concat(chunks));
        req.destroy();
      });
    });
    req.end();
  });
};

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/config.js
var REGION_ENV_NAME = "AWS_REGION";
var REGION_INI_NAME = "region";
var NODE_REGION_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => env[REGION_ENV_NAME],
  configFileSelector: (profile) => profile[REGION_INI_NAME],
  default: async () => {
    const region = await getInstanceMetadataRegion();
    if (region) {
      return region;
    }
    throw new Error("Region is missing");
  }
};
var NODE_REGION_CONFIG_FILE_OPTIONS = {
  preferredFile: "credentials"
};

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/resolveRegionConfig.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/checkRegion.js
init_esm_shims();
var validRegions = /* @__PURE__ */ new Set();
var checkRegion = (region, check = isValidHostLabel) => {
  if (!validRegions.has(region) && !check(region)) {
    if (region === "*") {
      console.warn(`@smithy/config-resolver WARN - Please use the caller region instead of "*". See "sigv4a" in https://github.com/aws/aws-sdk-js-v3/blob/main/supplemental-docs/CLIENTS.md.`);
    } else {
      throw new Error(`Region not accepted: region="${region}" is not a valid hostname component.`);
    }
  } else {
    validRegions.add(region);
  }
};

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/getRealRegion.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/isFipsRegion.js
init_esm_shims();
var isFipsRegion = (region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips"));

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/getRealRegion.js
var getRealRegion = (region) => isFipsRegion(region) ? ["fips-aws-global", "aws-fips"].includes(region) ? "us-east-1" : region.replace(/fips-(dkr-|prod-)?|-fips/, "") : region;

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/regionConfig/resolveRegionConfig.js
var resolveRegionConfig = (input) => {
  const { region, useFipsEndpoint } = input;
  if (!region) {
    throw new Error("Region is missing");
  }
  return Object.assign(input, {
    region: async () => {
      const providedRegion = typeof region === "function" ? await region() : region;
      const realRegion = getRealRegion(providedRegion);
      checkRegion(realRegion);
      return realRegion;
    },
    useFipsEndpoint: async () => {
      const providedRegion = typeof region === "string" ? region : await region();
      if (isFipsRegion(providedRegion)) {
        return true;
      }
      return typeof useFipsEndpoint !== "function" ? Promise.resolve(!!useFipsEndpoint) : useFipsEndpoint();
    }
  });
};

// node_modules/@smithy/core/dist-es/submodules/config/index.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/property-provider/ProviderError.js
init_esm_shims();
var ProviderError = class _ProviderError extends Error {
  name = "ProviderError";
  tryNextLink;
  constructor(message, options = true) {
    let logger;
    let tryNextLink = true;
    if (typeof options === "boolean") {
      logger = void 0;
      tryNextLink = options;
    } else if (options != null && typeof options === "object") {
      logger = options.logger;
      tryNextLink = options.tryNextLink ?? true;
    }
    super(message);
    this.tryNextLink = tryNextLink;
    Object.setPrototypeOf(this, _ProviderError.prototype);
    logger?.debug?.(`@smithy/property-provider ${tryNextLink ? "->" : "(!)"} ${message}`);
  }
  static from(error, options = true) {
    return Object.assign(new this(error.message, options), error);
  }
};

// node_modules/@smithy/core/dist-es/submodules/config/property-provider/CredentialsProviderError.js
init_esm_shims();
var CredentialsProviderError = class _CredentialsProviderError extends ProviderError {
  name = "CredentialsProviderError";
  constructor(message, options = true) {
    super(message, options);
    Object.setPrototypeOf(this, _CredentialsProviderError.prototype);
  }
};

// node_modules/@smithy/core/dist-es/submodules/config/property-provider/TokenProviderError.js
init_esm_shims();
var TokenProviderError = class _TokenProviderError extends ProviderError {
  name = "TokenProviderError";
  constructor(message, options = true) {
    super(message, options);
    Object.setPrototypeOf(this, _TokenProviderError.prototype);
  }
};

// node_modules/@smithy/core/dist-es/submodules/config/property-provider/chain.js
init_esm_shims();
var chain = (...providers) => async () => {
  if (providers.length === 0) {
    throw new ProviderError("No providers in chain");
  }
  let lastProviderError;
  for (const provider of providers) {
    try {
      const credentials = await provider();
      return credentials;
    } catch (err) {
      lastProviderError = err;
      if (err?.tryNextLink) {
        continue;
      }
      throw err;
    }
  }
  throw lastProviderError;
};

// node_modules/@smithy/core/dist-es/submodules/config/property-provider/fromValue.js
init_esm_shims();
var fromValue = (staticValue) => () => Promise.resolve(staticValue);

// node_modules/@smithy/core/dist-es/submodules/config/property-provider/memoize.js
init_esm_shims();
var memoize = (provider, isExpired, requiresRefresh) => {
  let resolved;
  let pending;
  let hasResult;
  let isConstant = false;
  const coalesceProvider = async () => {
    if (!pending) {
      pending = provider();
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
  {
    return async (options) => {
      if (!hasResult || options?.forceRefresh) {
        resolved = await coalesceProvider();
      }
      return resolved;
    };
  }
};

// node_modules/@smithy/core/dist-es/submodules/config/util-config-provider/booleanSelector.js
init_esm_shims();
var booleanSelector = (obj, key, type) => {
  if (!(key in obj))
    return void 0;
  if (obj[key] === "true")
    return true;
  if (obj[key] === "false")
    return false;
  throw new Error(`Cannot load ${type} "${key}". Expected "true" or "false", got ${obj[key]}.`);
};

// node_modules/@smithy/core/dist-es/submodules/config/util-config-provider/types.js
init_esm_shims();
var SelectorType;
(function(SelectorType2) {
  SelectorType2["ENV"] = "env";
  SelectorType2["CONFIG"] = "shared config entry";
})(SelectorType || (SelectorType = {}));

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/getHomeDir.js
init_esm_shims();
var homeDirCache = {};
var getHomeDirCacheKey = () => {
  if (process && process.geteuid) {
    return `${process.geteuid()}`;
  }
  return "DEFAULT";
};
var getHomeDir = () => {
  const { HOME, USERPROFILE, HOMEPATH, HOMEDRIVE = `C:${sep}` } = process.env;
  if (HOME)
    return HOME;
  if (USERPROFILE)
    return USERPROFILE;
  if (HOMEPATH)
    return `${HOMEDRIVE}${HOMEPATH}`;
  const homeDirCacheKey = getHomeDirCacheKey();
  if (!homeDirCache[homeDirCacheKey])
    homeDirCache[homeDirCacheKey] = homedir();
  return homeDirCache[homeDirCacheKey];
};

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/getProfileName.js
init_esm_shims();
var ENV_PROFILE = "AWS_PROFILE";
var DEFAULT_PROFILE = "default";
var getProfileName = (init) => init.profile || process.env[ENV_PROFILE] || DEFAULT_PROFILE;

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/getSSOTokenFilepath.js
init_esm_shims();
var getSSOTokenFilepath = (id) => {
  const hasher = createHash("sha1");
  const cacheName = hasher.update(id).digest("hex");
  return join(getHomeDir(), ".aws", "sso", "cache", `${cacheName}.json`);
};

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/getSSOTokenFromFile.js
init_esm_shims();
var tokenIntercept = {};
var getSSOTokenFromFile = async (id) => {
  if (tokenIntercept[id]) {
    return tokenIntercept[id];
  }
  const ssoTokenFilepath = getSSOTokenFilepath(id);
  const ssoTokenText = await readFile(ssoTokenFilepath, "utf8");
  return JSON.parse(ssoTokenText);
};

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/constants.js
init_esm_shims();
var CONFIG_PREFIX_SEPARATOR = ".";

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/loadSharedConfigFiles.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/getConfigData.js
init_esm_shims();
var getConfigData = (data) => Object.entries(data).filter(([key]) => {
  const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
  if (indexOfSeparator === -1) {
    return false;
  }
  return Object.values(IniSectionType).includes(key.substring(0, indexOfSeparator));
}).reduce((acc, [key, value]) => {
  const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
  const updatedKey = key.substring(0, indexOfSeparator) === IniSectionType.PROFILE ? key.substring(indexOfSeparator + 1) : key;
  acc[updatedKey] = value;
  return acc;
}, {
  ...data.default && { default: data.default }
});

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/getConfigFilepath.js
init_esm_shims();
var ENV_CONFIG_PATH = "AWS_CONFIG_FILE";
var getConfigFilepath = () => process.env[ENV_CONFIG_PATH] || join(getHomeDir(), ".aws", "config");

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/getCredentialsFilepath.js
init_esm_shims();
var ENV_CREDENTIALS_PATH = "AWS_SHARED_CREDENTIALS_FILE";
var getCredentialsFilepath = () => process.env[ENV_CREDENTIALS_PATH] || join(getHomeDir(), ".aws", "credentials");

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/parseIni.js
init_esm_shims();
var prefixKeyRegex = /^([\w-]+)\s(["'])?([\w-@+.%:/]+)\2$/;
var profileNameBlockList = ["__proto__", "profile __proto__"];
var parseIni = (iniData) => {
  const map = {};
  let currentSection;
  let currentSubSection;
  for (const iniLine of iniData.split(/\r?\n/)) {
    const trimmedLine = iniLine.split(/(^|\s)[;#]/)[0].trim();
    const isSection = trimmedLine[0] === "[" && trimmedLine[trimmedLine.length - 1] === "]";
    if (isSection) {
      currentSection = void 0;
      currentSubSection = void 0;
      const sectionName = trimmedLine.substring(1, trimmedLine.length - 1);
      const matches = prefixKeyRegex.exec(sectionName);
      if (matches) {
        const [, prefix, , name] = matches;
        if (Object.values(IniSectionType).includes(prefix)) {
          currentSection = [prefix, name].join(CONFIG_PREFIX_SEPARATOR);
        }
      } else {
        currentSection = sectionName;
      }
      if (profileNameBlockList.includes(sectionName)) {
        throw new Error(`Found invalid profile name "${sectionName}"`);
      }
    } else if (currentSection) {
      const indexOfEqualsSign = trimmedLine.indexOf("=");
      if (![0, -1].includes(indexOfEqualsSign)) {
        const [name, value] = [
          trimmedLine.substring(0, indexOfEqualsSign).trim(),
          trimmedLine.substring(indexOfEqualsSign + 1).trim()
        ];
        if (value === "") {
          currentSubSection = name;
        } else {
          if (currentSubSection && iniLine.trimStart() === iniLine) {
            currentSubSection = void 0;
          }
          map[currentSection] = map[currentSection] || {};
          const key = currentSubSection ? [currentSubSection, name].join(CONFIG_PREFIX_SEPARATOR) : name;
          map[currentSection][key] = value;
        }
      }
    }
  }
  return map;
};

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/readFile.js
init_esm_shims();
var filePromises = {};
var fileIntercept = {};
var readFile2 = (path, options) => {
  if (fileIntercept[path] !== void 0) {
    return fileIntercept[path];
  }
  if (!filePromises[path] || options?.ignoreCache) {
    filePromises[path] = readFile(path, "utf8");
  }
  return filePromises[path];
};

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/loadSharedConfigFiles.js
var swallowError = () => ({});
var loadSharedConfigFiles = async (init = {}) => {
  const { filepath = getCredentialsFilepath(), configFilepath = getConfigFilepath() } = init;
  const homeDir = getHomeDir();
  const relativeHomeDirPrefix = "~/";
  let resolvedFilepath = filepath;
  if (filepath.startsWith(relativeHomeDirPrefix)) {
    resolvedFilepath = join(homeDir, filepath.slice(2));
  }
  let resolvedConfigFilepath = configFilepath;
  if (configFilepath.startsWith(relativeHomeDirPrefix)) {
    resolvedConfigFilepath = join(homeDir, configFilepath.slice(2));
  }
  const parsedFiles = await Promise.all([
    readFile2(resolvedConfigFilepath, {
      ignoreCache: init.ignoreCache
    }).then(parseIni).then(getConfigData).catch(swallowError),
    readFile2(resolvedFilepath, {
      ignoreCache: init.ignoreCache
    }).then(parseIni).catch(swallowError)
  ]);
  return {
    configFile: parsedFiles[0],
    credentialsFile: parsedFiles[1]
  };
};

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/loadSsoSessionData.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/getSsoSessionData.js
init_esm_shims();
var getSsoSessionData = (data) => Object.entries(data).filter(([key]) => key.startsWith(IniSectionType.SSO_SESSION + CONFIG_PREFIX_SEPARATOR)).reduce((acc, [key, value]) => ({ ...acc, [key.substring(key.indexOf(CONFIG_PREFIX_SEPARATOR) + 1)]: value }), {});

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/loadSsoSessionData.js
var swallowError2 = () => ({});
var loadSsoSessionData = async (init = {}) => readFile2(init.configFilepath ?? getConfigFilepath()).then(parseIni).then(getSsoSessionData).catch(swallowError2);

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/parseKnownFiles.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/mergeConfigFiles.js
init_esm_shims();
var mergeConfigFiles = (...files) => {
  const merged = {};
  for (const file of files) {
    for (const [key, values] of Object.entries(file)) {
      if (merged[key] !== void 0) {
        Object.assign(merged[key], values);
      } else {
        merged[key] = values;
      }
    }
  }
  return merged;
};

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/parseKnownFiles.js
var parseKnownFiles = async (init) => {
  const parsedFiles = await loadSharedConfigFiles(init);
  return mergeConfigFiles(parsedFiles.configFile, parsedFiles.credentialsFile);
};

// node_modules/@smithy/core/dist-es/submodules/config/shared-ini-file-loader/externalDataInterceptor.js
init_esm_shims();
var externalDataInterceptor = {
  getFileRecord() {
    return fileIntercept;
  },
  interceptFile(path, contents) {
    fileIntercept[path] = Promise.resolve(contents);
  },
  getTokenRecord() {
    return tokenIntercept;
  },
  interceptToken(id, contents) {
    tokenIntercept[id] = contents;
  }
};

// node_modules/@smithy/core/dist-es/submodules/config/node-config-provider/configLoader.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/node-config-provider/fromEnv.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/node-config-provider/getSelectorName.js
init_esm_shims();
function getSelectorName(functionString) {
  try {
    const constants = new Set(Array.from(functionString.match(/([A-Z_]){3,}/g) ?? []));
    constants.delete("CONFIG");
    constants.delete("CONFIG_PREFIX_SEPARATOR");
    constants.delete("ENV");
    return [...constants].join(", ");
  } catch (ignored) {
    return functionString;
  }
}

// node_modules/@smithy/core/dist-es/submodules/config/node-config-provider/fromEnv.js
var fromEnv = (envVarSelector, options) => async () => {
  try {
    const config = envVarSelector(process.env, options);
    if (config === void 0) {
      throw new Error();
    }
    return config;
  } catch (e) {
    throw new CredentialsProviderError(e.message || `Not found in ENV: ${getSelectorName(envVarSelector.toString())}`, { logger: options?.logger });
  }
};

// node_modules/@smithy/core/dist-es/submodules/config/node-config-provider/fromSharedConfigFiles.js
init_esm_shims();
var fromSharedConfigFiles = (configSelector, { preferredFile = "config", ...init } = {}) => async () => {
  const profile = getProfileName(init);
  const { configFile, credentialsFile } = await loadSharedConfigFiles(init);
  const profileFromCredentials = credentialsFile[profile] || {};
  const profileFromConfig = configFile[profile] || {};
  const mergedProfile = preferredFile === "config" ? { ...profileFromCredentials, ...profileFromConfig } : { ...profileFromConfig, ...profileFromCredentials };
  try {
    const cfgFile = preferredFile === "config" ? configFile : credentialsFile;
    const configValue = configSelector(mergedProfile, cfgFile);
    if (configValue === void 0) {
      throw new Error();
    }
    return configValue;
  } catch (e) {
    throw new CredentialsProviderError(e.message || `Not found in config files w/ profile [${profile}]: ${getSelectorName(configSelector.toString())}`, { logger: init.logger });
  }
};

// node_modules/@smithy/core/dist-es/submodules/config/node-config-provider/fromStatic.js
init_esm_shims();
var isFunction = (func) => typeof func === "function";
var fromStatic = (defaultValue) => isFunction(defaultValue) ? async () => await defaultValue() : fromValue(defaultValue);

// node_modules/@smithy/core/dist-es/submodules/config/node-config-provider/configLoader.js
var loadConfig = ({ environmentVariableSelector, configFileSelector, default: defaultValue }, configuration = {}) => {
  const { signingName, logger } = configuration;
  const envOptions = { signingName, logger };
  return memoize(chain(fromEnv(environmentVariableSelector, envOptions), fromSharedConfigFiles(configFileSelector, configuration), fromStatic(defaultValue)));
};

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/endpointsConfig/NodeUseDualstackEndpointConfigOptions.js
init_esm_shims();
var ENV_USE_DUALSTACK_ENDPOINT = "AWS_USE_DUALSTACK_ENDPOINT";
var CONFIG_USE_DUALSTACK_ENDPOINT = "use_dualstack_endpoint";
var NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => booleanSelector(env, ENV_USE_DUALSTACK_ENDPOINT, SelectorType.ENV),
  configFileSelector: (profile) => booleanSelector(profile, CONFIG_USE_DUALSTACK_ENDPOINT, SelectorType.CONFIG),
  default: false
};

// node_modules/@smithy/core/dist-es/submodules/config/config-resolver/endpointsConfig/NodeUseFipsEndpointConfigOptions.js
init_esm_shims();
var ENV_USE_FIPS_ENDPOINT = "AWS_USE_FIPS_ENDPOINT";
var CONFIG_USE_FIPS_ENDPOINT = "use_fips_endpoint";
var NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => booleanSelector(env, ENV_USE_FIPS_ENDPOINT, SelectorType.ENV),
  configFileSelector: (profile) => booleanSelector(profile, CONFIG_USE_FIPS_ENDPOINT, SelectorType.CONFIG),
  default: false
};

// node_modules/@smithy/core/dist-es/submodules/config/defaults-mode/resolveDefaultsModeConfig.js
init_esm_shims();

// node_modules/@smithy/core/dist-es/submodules/config/defaults-mode/defaultsModeConfig.js
init_esm_shims();
var AWS_DEFAULTS_MODE_ENV = "AWS_DEFAULTS_MODE";
var AWS_DEFAULTS_MODE_CONFIG = "defaults_mode";
var NODE_DEFAULTS_MODE_CONFIG_OPTIONS = {
  environmentVariableSelector: (env) => {
    return env[AWS_DEFAULTS_MODE_ENV];
  },
  configFileSelector: (profile) => {
    return profile[AWS_DEFAULTS_MODE_CONFIG];
  },
  default: "legacy"
};

// node_modules/@smithy/core/dist-es/submodules/config/defaults-mode/resolveDefaultsModeConfig.js
var resolveDefaultsModeConfig = ({ region = loadConfig(NODE_REGION_CONFIG_OPTIONS), defaultsMode = loadConfig(NODE_DEFAULTS_MODE_CONFIG_OPTIONS) } = {}) => memoize(async () => {
  const mode = typeof defaultsMode === "function" ? await defaultsMode() : defaultsMode;
  switch (mode?.toLowerCase()) {
    case "auto":
      return resolveNodeDefaultsModeAuto(region);
    case "in-region":
    case "cross-region":
    case "mobile":
    case "standard":
    case "legacy":
      return Promise.resolve(mode?.toLocaleLowerCase());
    case void 0:
      return Promise.resolve("legacy");
    default:
      throw new Error(`Invalid parameter for "defaultsMode", expect ${DEFAULTS_MODE_OPTIONS.join(", ")}, got ${mode}`);
  }
});
var resolveNodeDefaultsModeAuto = async (clientRegion) => {
  if (clientRegion) {
    const resolvedRegion = typeof clientRegion === "function" ? await clientRegion() : clientRegion;
    const inferredRegion = await inferPhysicalRegion();
    if (!inferredRegion) {
      return "standard";
    }
    if (resolvedRegion === inferredRegion) {
      return "in-region";
    } else {
      return "cross-region";
    }
  }
  return "standard";
};
var inferPhysicalRegion = async () => {
  if (process.env[AWS_EXECUTION_ENV] && (process.env[AWS_REGION_ENV] || process.env[AWS_DEFAULT_REGION_ENV])) {
    return process.env[AWS_REGION_ENV] ?? process.env[AWS_DEFAULT_REGION_ENV];
  }
  return getInstanceMetadataRegion();
};

export { CONFIG_PREFIX_SEPARATOR, CredentialsProviderError, ENV_PROFILE, NODE_REGION_CONFIG_FILE_OPTIONS, NODE_REGION_CONFIG_OPTIONS, NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, ProviderError, REGION_ENV_NAME, REGION_INI_NAME, SelectorType, TokenProviderError, booleanSelector, chain, externalDataInterceptor, getProfileName, getSSOTokenFilepath, getSSOTokenFromFile, loadConfig, loadSsoSessionData, parseKnownFiles, resolveDefaultsModeConfig, resolveRegionConfig };
