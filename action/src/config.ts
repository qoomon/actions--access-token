import {getYamlInput} from './github-actions-utils.js';

// Type definitions for the configuration
type ConfigYaml = {
  api?: {
    url?: string;
    auth?: {
      aws?: {
        roleArn: string;
        region: string;
        service: AllowedService;
      }
    }
  }
};

interface Config {
  api: {
    url: URL
    auth?: {
      aws?: {
        roleArn: string
        region: string
        service: AllowedService
      }
    }
  }
}

// Only allow 'lambda' or 'execute-api' as valid service values.
const allowedServices = ['lambda', 'execute-api'] as const;
type AllowedService = typeof allowedServices[number];

export const defaultConfig : Config = {
  api: {
    url: new URL('https://github-actions-access-token.netlify.app'),
    // auth: {
    //   aws: {
    //     roleArn: 'arn:aws:iam::123456789012:role/github-actions-access-token-api-access',
    //     region: 'eu-central-1',
    //     service: 'lambda',
    //   },
    // },
  },
};

export const configYaml: ConfigYaml = getYamlInput('config') || {};
export const url = new URL(configYaml.api?.url || defaultConfig.api.url.toString());
export const auth = configYaml.api?.auth || defaultConfig.api.auth;

// Validate service value if present
const service = auth?.aws?.service;
if (service && !allowedServices.includes(service)) {
  throw new Error(`Invalid service: ${service}. Allowed values are: ${allowedServices.join(', ')}`);
}
// final configuration object
export const config: Config = {
  api: {
    url,
    auth: auth,
  },
};
