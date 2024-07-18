import {Stack, StackProps} from 'aws-cdk-lib';
import {Construct} from 'constructs';
import {OpenIdConnectPrincipal, OpenIdConnectProvider, Role} from 'aws-cdk-lib/aws-iam';

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
          [`${githubOidcProvider.openIdConnectProviderIssuer}:sub`]: ['repo:JH-JDS/actions--access-token:ref:refs/heads/main'],
        }
      }),
    })
  }
}
