import {Stack, StackProps} from 'aws-cdk-lib';
import {Construct} from 'constructs';
import {OpenIdConnectPrincipal, OpenIdConnectProvider, Role} from 'aws-cdk-lib/aws-iam';

const GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS = ['repo:qoomon/actions--access-token:ref:refs/heads/main'];

export class DeploymentStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props)

    const githubOidcProvider = OpenIdConnectProvider.fromOpenIdConnectProviderArn(
        this, "GithubOpenIdConnectProvider",
        `arn:aws:iam::${this.account}:oidc-provider/token.actions.githubusercontent.com`);

    new Role(this, 'DeploymentRole', {
      roleName: this.stackName,
      managedPolicies: [
        {managedPolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess'},
      ],
      assumedBy: new OpenIdConnectPrincipal(githubOidcProvider, {
        'StringEquals': {
          // Official AWS GitHub Action https://github.com/aws-actions/configure-aws-credentials set audience to `sts.amazonaws.com` by default
          // https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services#adding-the-identity-provider-to-aws'
          [`${githubOidcProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com',
        },
        'ForAnyValue:StringLike': {
          [`${githubOidcProvider.openIdConnectProviderIssuer}:sub`]: ensureNotEmpty(GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS),
        }
      }),
    })
  }
}

function ensureNotEmpty<T extends Array<unknown>>(value: T, message: string = 'Array must not be empty'): T {
  if (value.length === 0) {
    throw new Error(message)
  }
  return value
}
