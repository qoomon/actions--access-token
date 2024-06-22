export const config : Config = {
  api: {
    url: new URL('https://github-actions-access-token.vercel.app'),
    // auth: {
    //   aws: {
    //     roleArn: 'arn:aws:iam::123456789012:role/github-actions-access-token-api-access',
    //     region: 'eu-central-1',
    //     service: 'lambda',
    //   },
    // },
  },
};

interface Config {
  api: {
    url: URL
    auth?: {
      aws?: {
        roleArn: string
        region: string
        service: 'lambda' | 'execute-api'
      }
    }
  }
}


