import {getYamlInput} from './github-actions-utils.js';

export const config: Config = {
  appServer: {
    // Replace with your deployed server URL
    // e.g. new URL('https://actions-access-token.example.com')
    url: await fetch(
        'https://raw.githubusercontent.com/qoomon/actions--access-token/refs/heads/main/server/public-host.json',
    ).then(response => response.json()).then(publicHost => new URL(publicHost.url)),
  },
};

const appServerInput = getYamlInput('app-server');
if (appServerInput) {
  if (typeof appServerInput !== 'object') {
    throw new Error('input app-server must be an object');
  }

  if (!('url' in appServerInput)) {
    throw new Error('input app-server.url is required');
  }
  appServerInput.url = new URL(appServerInput.url as string);

  if ('auth' in appServerInput && appServerInput.auth !== null) {
    if (typeof appServerInput.auth !== 'object') {
      throw new Error('input app-server.auth must be an object');
    }
    if (!('type' in appServerInput.auth)) {
      throw new Error('input app-server.auth.type is required');
    }
    if (appServerInput.auth.type === 'aws') {
      if (!('roleArn' in appServerInput.auth)) {
        throw new Error('input app-server.auth.roleArn is required for auth type aws');
      }

      if (!('region' in appServerInput.auth)) {
        throw new Error('input app-server.auth.region is required for auth type aws');
      }

      if (!('service' in appServerInput.auth)) {
        throw new Error('input app-server.auth.service is required for auth type aws');
      }
      if (appServerInput.auth.service !== 'lambda' && appServerInput.auth.service !== 'execute-api') {
        throw new Error(`input app-server.auth.service must be 'lambda' or 'execute-api',` +
            ` got '${appServerInput.auth.service}'`);
      }
    } else {
      throw new Error(`input app-server.auth.type must be 'aws', got '${appServerInput.auth.type}'`);
    }
  }

  config.appServer = appServerInput as Config['appServer'];
}

interface Config {
  appServer: {
    url: URL
    auth?: {
      type: 'aws'
      roleArn: string // e.g. 'arn:aws:iam::123456789012:role/github-actions-access-token-api-access'
      region: string // e.g. 'eu-central-1'
      service: 'lambda' | 'execute-api'
    }
  }
}
