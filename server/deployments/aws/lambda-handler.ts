import {handle, LambdaContext, LambdaEvent} from 'hono/aws-lambda';
import process from 'process';
import {GetFunctionUrlConfigCommand, LambdaClient} from '@aws-sdk/client-lambda';
import {GetSecretValueCommand, SecretsManager} from '@aws-sdk/client-secrets-manager';
import {logger} from '../../src/logger.js';
import {Context} from 'hono';

if (!process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE) {
  const lambda = new LambdaClient({region: process.env.AWS_REGION});
  const lambdaFunctionUrl = await lambda.send(new GetFunctionUrlConfigCommand({
    FunctionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
  })).then((output) => new URL(output.FunctionUrl ?? ''));

  // --- guess audience from AWS_LAMBDA_FUNCTION_NAME
  process.env.GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE = lambdaFunctionUrl.hostname;
}

const secretsManager = new SecretsManager({region: process.env.AWS_REGION});
const githubAppSecret = await secretsManager.send(new GetSecretValueCommand({
  SecretId: process.env.GITHUB_APP_SECRETS_NAME,
})).then((output) => JSON.parse(output.SecretString ?? '{}'));
process.env.GITHUB_APP_ID = githubAppSecret.appId;
process.env.GITHUB_APP_PRIVATE_KEY = githubAppSecret.privateKey;

const requestIdHeader = 'X-Request-Id';
process.env.REQUEST_ID_HEADER = requestIdHeader;

const {appInit} = await import('../../src/app.js');

const app = appInit((app) => {
  app.use(async (context: Context<{ Bindings: { event: LambdaEvent, lambdaContext: LambdaContext } }>, next) => {
    // Set request id header
    context.req.header()[requestIdHeader] = context.env.lambdaContext.awsRequestId;
    await next();
    // Ensure all logs are flushed before the function returns
    logger.flush();
  })
})

export const handler = handle(app);


