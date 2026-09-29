import { createRequire } from 'module';
import { CredentialsProviderError } from './chunk-HAYTZHRA.mjs';
import './chunk-MBUECYHF.mjs';
import { init_esm_shims } from './chunk-MIA7WKEC.mjs';

createRequire(import.meta.url);

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/index.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/fromCognitoIdentity.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/resolveLogins.js
init_esm_shims();
function resolveLogins(logins) {
  return Promise.all(Object.keys(logins).reduce((arr, name) => {
    const tokenOrProvider = logins[name];
    if (typeof tokenOrProvider === "string") {
      arr.push([name, tokenOrProvider]);
    } else {
      arr.push(tokenOrProvider().then((token) => [name, token]));
    }
    return arr;
  }, [])).then((resolvedPairs) => resolvedPairs.reduce((logins2, [key, value]) => {
    logins2[key] = value;
    return logins2;
  }, {}));
}

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/fromCognitoIdentity.js
function fromCognitoIdentity(parameters) {
  return async (awsIdentityProperties) => {
    parameters.logger?.debug("@aws-sdk/credential-provider-cognito-identity - fromCognitoIdentity");
    const { GetCredentialsForIdentityCommand, CognitoIdentityClient } = await import('./loadCognitoIdentity-6OJZ7PB2.mjs');
    const fromConfigs = (property) => parameters.clientConfig?.[property] ?? parameters.parentClientConfig?.[property] ?? awsIdentityProperties?.callerClientConfig?.[property];
    const { Credentials: { AccessKeyId = throwOnMissingAccessKeyId(parameters.logger), Expiration, SecretKey = throwOnMissingSecretKey(parameters.logger), SessionToken } = throwOnMissingCredentials(parameters.logger) } = await (parameters.client ?? new CognitoIdentityClient(Object.assign({}, parameters.clientConfig ?? {}, {
      region: fromConfigs("region"),
      profile: fromConfigs("profile"),
      userAgentAppId: fromConfigs("userAgentAppId")
    }))).send(new GetCredentialsForIdentityCommand({
      CustomRoleArn: parameters.customRoleArn,
      IdentityId: parameters.identityId,
      Logins: parameters.logins ? await resolveLogins(parameters.logins) : void 0
    }));
    return {
      identityId: parameters.identityId,
      accessKeyId: AccessKeyId,
      secretAccessKey: SecretKey,
      sessionToken: SessionToken,
      expiration: Expiration
    };
  };
}
function throwOnMissingAccessKeyId(logger) {
  throw new CredentialsProviderError("Response from Amazon Cognito contained no access key ID", { logger });
}
function throwOnMissingCredentials(logger) {
  throw new CredentialsProviderError("Response from Amazon Cognito contained no credentials", { logger });
}
function throwOnMissingSecretKey(logger) {
  throw new CredentialsProviderError("Response from Amazon Cognito contained no secret key", { logger });
}

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/fromCognitoIdentityPool.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/localStorage.js
init_esm_shims();

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/IndexedDbStorage.js
init_esm_shims();
var STORE_NAME = "IdentityIds";
var IndexedDbStorage = class {
  dbName;
  constructor(dbName = "aws:cognito-identity-ids") {
    this.dbName = dbName;
  }
  getItem(key) {
    return this.withObjectStore("readonly", (store) => {
      const req = store.get(key);
      return new Promise((resolve) => {
        req.onerror = () => resolve(null);
        req.onsuccess = () => resolve(req.result ? req.result.value : null);
      });
    }).catch(() => null);
  }
  removeItem(key) {
    return this.withObjectStore("readwrite", (store) => {
      const req = store.delete(key);
      return new Promise((resolve, reject) => {
        req.onerror = () => reject(req.error);
        req.onsuccess = () => resolve();
      });
    });
  }
  setItem(id, value) {
    return this.withObjectStore("readwrite", (store) => {
      const req = store.put({ id, value });
      return new Promise((resolve, reject) => {
        req.onerror = () => reject(req.error);
        req.onsuccess = () => resolve();
      });
    });
  }
  getDb() {
    const openDbRequest = self.indexedDB.open(this.dbName, 1);
    return new Promise((resolve, reject) => {
      openDbRequest.onsuccess = () => {
        resolve(openDbRequest.result);
      };
      openDbRequest.onerror = () => {
        reject(openDbRequest.error);
      };
      openDbRequest.onblocked = () => {
        reject(new Error("Unable to access DB"));
      };
      openDbRequest.onupgradeneeded = () => {
        const db = openDbRequest.result;
        db.onerror = () => {
          reject(new Error("Failed to create object store"));
        };
        db.createObjectStore(STORE_NAME, { keyPath: "id" });
      };
    });
  }
  withObjectStore(mode, action) {
    return this.getDb().then((db) => {
      const tx = db.transaction(STORE_NAME, mode);
      tx.oncomplete = () => db.close();
      return new Promise((resolve, reject) => {
        tx.onerror = () => reject(tx.error);
        resolve(action(tx.objectStore(STORE_NAME)));
      }).catch((err) => {
        db.close();
        throw err;
      });
    });
  }
};

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/InMemoryStorage.js
init_esm_shims();
var InMemoryStorage = class {
  store;
  constructor(store = {}) {
    this.store = store;
  }
  getItem(key) {
    if (key in this.store) {
      return this.store[key];
    }
    return null;
  }
  removeItem(key) {
    delete this.store[key];
  }
  setItem(key, value) {
    this.store[key] = value;
  }
};

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/localStorage.js
var inMemoryStorage = new InMemoryStorage();
function localStorage() {
  if (typeof self === "object" && self.indexedDB) {
    return new IndexedDbStorage();
  }
  if (typeof window === "object" && window.localStorage) {
    return window.localStorage;
  }
  return inMemoryStorage;
}

// node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/fromCognitoIdentityPool.js
function fromCognitoIdentityPool({ accountId, cache = localStorage(), client, clientConfig, customRoleArn, identityPoolId, logins, userIdentifier = !logins || Object.keys(logins).length === 0 ? "ANONYMOUS" : void 0, logger, parentClientConfig }) {
  logger?.debug("@aws-sdk/credential-provider-cognito-identity - fromCognitoIdentity");
  const cacheKey = userIdentifier ? `aws:cognito-identity-credentials:${identityPoolId}:${userIdentifier}` : void 0;
  let provider = async (awsIdentityProperties) => {
    const { GetIdCommand, CognitoIdentityClient } = await import('./loadCognitoIdentity-6OJZ7PB2.mjs');
    const fromConfigs = (property) => clientConfig?.[property] ?? parentClientConfig?.[property] ?? awsIdentityProperties?.callerClientConfig?.[property];
    const _client = client ?? new CognitoIdentityClient(Object.assign({}, clientConfig ?? {}, {
      region: fromConfigs("region"),
      profile: fromConfigs("profile"),
      userAgentAppId: fromConfigs("userAgentAppId")
    }));
    let identityId = cacheKey && await cache.getItem(cacheKey);
    if (!identityId) {
      const { IdentityId = throwOnMissingId(logger) } = await _client.send(new GetIdCommand({
        AccountId: accountId,
        IdentityPoolId: identityPoolId,
        Logins: logins ? await resolveLogins(logins) : void 0
      }));
      identityId = IdentityId;
      if (cacheKey) {
        Promise.resolve(cache.setItem(cacheKey, identityId)).catch(() => {
        });
      }
    }
    provider = fromCognitoIdentity({
      client: _client,
      customRoleArn,
      logins,
      identityId
    });
    return provider(awsIdentityProperties);
  };
  return (awsIdentityProperties) => provider(awsIdentityProperties).catch(async (err) => {
    if (cacheKey) {
      Promise.resolve(cache.removeItem(cacheKey)).catch(() => {
      });
    }
    throw err;
  });
}
function throwOnMissingId(logger) {
  throw new CredentialsProviderError("Response from Amazon Cognito contained no identity ID", { logger });
}

export { fromCognitoIdentity, fromCognitoIdentityPool };
