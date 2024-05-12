import {handle} from 'hono/aws-lambda'
import process from 'process'
import {GetFunctionUrlConfigCommand, LambdaClient} from '@aws-sdk/client-lambda'
import {GetSecretValueCommand, SecretsManager} from '@aws-sdk/client-secrets-manager'

if (!process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE']) {
  const lambda = new LambdaClient({region: process.env.AWS_REGION})
  const lambdaFunctionUrl = await lambda.send(new GetFunctionUrlConfigCommand({
    FunctionName: process.env['AWS_LAMBDA_FUNCTION_NAME'],
  })).then((output) => output.FunctionUrl!)

  // --- guess audience from AWS_LAMBDA_FUNCTION_NAME
  process.env['GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE'] = new URL(lambdaFunctionUrl).hostname
}

const secretsManager = new SecretsManager({region: process.env.AWS_REGION})
const githubAppSecret = await secretsManager.send(new GetSecretValueCommand({
  SecretId: process.env['GITHUB_APP_SECRETS_NAME'],
})).then((output) => JSON.parse(output.SecretString ?? '{}'))
process.env['GITHUB_ACTIONS_APP_ID'] = githubAppSecret.appId
process.env['GITHUB_ACTIONS_APP_PRIVATE_KEY'] = githubAppSecret.privateKey

const {app} = await import('../../app.js')
export const handler = handle(app)

