import { createRequire } from 'module';
import { setCredentialFeature } from './chunk-CNVAVDG2.mjs';
import './chunk-TTV4QKES.mjs';
import './chunk-CKKARQCR.mjs';
import './chunk-2D7RHDR7.mjs';
import { parseKnownFiles, getProfileName, externalDataInterceptor, CredentialsProviderError } from './chunk-HAYTZHRA.mjs';
import './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';
import { exec } from 'child_process';
import { promisify } from 'util';

createRequire(import.meta.url);

// node_modules/@aws-sdk/credential-provider-process/dist-es/index.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-process/dist-es/fromProcess.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-process/dist-es/resolveProcessCredentials.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-process/dist-es/getValidatedProcessCredentials.js
init_esm_shims();
var getValidatedProcessCredentials = (profileName, data, profiles) => {
  if (data.Version !== 1) {
    throw Error(`Profile ${profileName} credential_process did not return Version 1.`);
  }
  if (data.AccessKeyId === void 0 || data.SecretAccessKey === void 0) {
    throw Error(`Profile ${profileName} credential_process returned invalid credentials.`);
  }
  if (data.Expiration) {
    const currentTime = /* @__PURE__ */ new Date();
    const expireTime = new Date(data.Expiration);
    if (expireTime < currentTime) {
      throw Error(`Profile ${profileName} credential_process returned expired credentials.`);
    }
  }
  let accountId = data.AccountId;
  if (!accountId && profiles?.[profileName]?.aws_account_id) {
    accountId = profiles[profileName].aws_account_id;
  }
  const credentials = {
    accessKeyId: data.AccessKeyId,
    secretAccessKey: data.SecretAccessKey,
    ...data.SessionToken && { sessionToken: data.SessionToken },
    ...data.Expiration && { expiration: new Date(data.Expiration) },
    ...data.CredentialScope && { credentialScope: data.CredentialScope },
    ...accountId && { accountId }
  };
  setCredentialFeature(credentials, "CREDENTIALS_PROCESS", "w");
  return credentials;
};

// node_modules/@aws-sdk/credential-provider-process/dist-es/resolveProcessCredentials.js
var resolveProcessCredentials = async (profileName, profiles, logger) => {
  const profile = profiles[profileName];
  if (profiles[profileName]) {
    const credentialProcess = profile["credential_process"];
    if (credentialProcess !== void 0) {
      const execPromise = promisify(externalDataInterceptor?.getTokenRecord?.().exec ?? exec);
      try {
        const { stdout } = await execPromise(credentialProcess);
        let data;
        try {
          data = JSON.parse(stdout.trim());
        } catch {
          throw Error(`Profile ${profileName} credential_process returned invalid JSON.`);
        }
        return getValidatedProcessCredentials(profileName, data, profiles);
      } catch (error) {
        throw new CredentialsProviderError(error.message, { logger });
      }
    } else {
      throw new CredentialsProviderError(`Profile ${profileName} did not contain credential_process.`, { logger });
    }
  } else {
    throw new CredentialsProviderError(`Profile ${profileName} could not be found in shared credentials file.`, {
      logger
    });
  }
};

// node_modules/@aws-sdk/credential-provider-process/dist-es/fromProcess.js
var fromProcess = (init = {}) => async ({ callerClientConfig } = {}) => {
  init.logger?.debug("@aws-sdk/credential-provider-process - fromProcess");
  const profiles = await parseKnownFiles(init);
  return resolveProcessCredentials(getProfileName({
    profile: init.profile ?? callerClientConfig?.profile
  }), profiles, init.logger);
};

export { fromProcess };
