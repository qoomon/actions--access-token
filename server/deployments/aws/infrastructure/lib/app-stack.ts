import * as iam from 'aws-cdk-lib/aws-iam'
import {OpenIdConnectProvider} from 'aws-cdk-lib/aws-iam'
import {CfnOutput, Duration, SecretValue, Stack, StackProps} from 'aws-cdk-lib'
import {Construct} from 'constructs'
import * as lambda from 'aws-cdk-lib/aws-lambda'
import {FunctionUrlAuthType} from 'aws-cdk-lib/aws-lambda'
import * as path from 'path'
import * as secretManager from 'aws-cdk-lib/aws-secretsmanager'

const API_ACCESS_ROLE_NAME = 'github-actions-access-token-manager-api-access'
// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#example-subject-claims
const GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS: string[] = [] // e.g. ['repo:octo-org/*']

export class AppStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props)

    // --- GitHub App Secrets---------------------------------------------------------------------------------------

    const githubAppSecret = new secretManager.Secret(this, 'GitHubAppSecret', {
      secretName: `${this.stackName}/GitHubApp`, secretObjectValue: {
        appId: SecretValue.unsafePlainText('change-me'),
        privateKey: SecretValue.unsafePlainText('change-me'),
      },
    })
    new CfnOutput(this, 'GitHubAppSecretName', {value: githubAppSecret.secretName})

    // --- API Access Token Function--------------------------------------------------------------------------------

    const httpApiAccessTokenFunction = new lambda.Function(this, 'HttpApiAccessTokenFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      memorySize: 128,
      timeout: Duration.seconds(30),
      code: lambda.Code.fromAsset(path.join(__dirname, '../../../../../dist')),
      environment: {
        LOG_LEVEL: 'INFO',
        GITHUB_APP_SECRETS_NAME: githubAppSecret.secretName,
        GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS: GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS.join(','),
      },
    })
    githubAppSecret.grantRead(httpApiAccessTokenFunction.role!)

    // --- add function url
    const httpApiAccessTokenFunctionUrl = httpApiAccessTokenFunction.addFunctionUrl({
      authType: FunctionUrlAuthType.AWS_IAM,
    })

    // --- API Access Role------------------------------------------------------------------------------------------

    const githubOidcProvider = OpenIdConnectProvider.fromOpenIdConnectProviderArn(
        this, 'HttpApiAuthOidcProvider',
        `arn:aws:iam::${this.account}:oidc-provider/token.actions.githubusercontent.com`,
    )

    const httpApiAccessRole = new iam.Role(this, 'HttpApiAccessRole', {
      roleName: API_ACCESS_ROLE_NAME,
      maxSessionDuration: Duration.hours(1), // should set to minimum value for security reasons
      assumedBy: new iam.OpenIdConnectPrincipal(githubOidcProvider, {
        'StringEquals': {[`${githubOidcProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com'},
        'ForAnyValue:StringLike': {[`${githubOidcProvider.openIdConnectProviderIssuer}:sub`]: GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS},
      }),
    })
    httpApiAccessTokenFunctionUrl.grantInvokeUrl(httpApiAccessRole)

    // --- Outputs -------------------------------------------------------------------------------------------------

    new CfnOutput(this, 'GitHubAppSecret', {value: githubAppSecret.secretName})
    new CfnOutput(this, 'ApiRegion', {value: httpApiAccessTokenFunctionUrl.stack.region})
    new CfnOutput(this, 'ApiAccessRoleArn', {value: httpApiAccessRole.roleArn})
    new CfnOutput(this, 'ApiUrl', {value: httpApiAccessTokenFunctionUrl.url})
  }
}
