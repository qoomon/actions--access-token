# GitHub Actions Access Token Server

This readme describes how to deploy a GitHub Actions Access Token Server.

## Prerequisites
> [!IMPORTANT]
> Be aware that this server is a security sensitive application.
> It is important to secure the access token server properly and update dependencies regularly.
> Keep GitHub App credentials as secret as possible.

1. **Create a GitHub App**

<details><summary>Click me</summary>

- Create a new GitHub App ([User Scope](https://github.com/settings/apps/new)
  or [Organizations Scope](https://github.com/organizations/YOUR_ORGANIZATION/settings/apps/new))
    - Fill out mandatory fields
    - Deactivate Webhook
    - Add Mandatory `Repository permissions`
        - Single file: `Read-only`
            - Add file path `.github/access-token.yaml` - for repository scoped token policy
              - Also add file path `.github/access-token.yml`
            - Add file path `access-token.yaml` - for owner scoped token policy
              - Also add file path `access-token.yml`
    - Choose permissions you want to allow to request
    - Hit `Create GitHub App` button
    - Take a note of `App ID`
    - Scroll down to `Private keys` section and click `Generate a private key` button
        - private key (`.pem` file) will be downloaded to your machine automatically

</details>

2. **Create an Owner Access Token Policy Repository**
> [!IMPORTANT]
> Ensure that this repository is present before installing the GitHub App
> Otherwise someone else could create this repo and effectively take over the owner access token policy configuration.

<details><summary>Click me</summary>

- Create a new private repository named `.github-access-token`
- Ensure only owner admins have access to this repository
    - Create owner `access-token.yaml` file at root of the repository with [this template content](/actions/docs/access-token.owner-template.yaml)
    - And adjust the access policy to your liking

</details>

3. **Install GitHub App for Target Repository**
> [!IMPORTANT]
> By installing the access token GitHub App **everybody** with `write` assess to `.github/access-token.yaml` can grant repository access permissions to GitHub Actions workflow runs.

> [!TIP]
> **For organizations on GitHub Enterprise plans** it is possible to restrict `write` access to `.github/access-token.yaml` to repository admins only by using a [push ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#push-rulesets)
> - [Create a new push ruleset](https://github.com/organizations/YOUR-ORGANIZATION/settings/rules/new?target=push)
> - Set `Ruleset Name` to `Protect access token policy`
> - Set `Enforcement status` to `Active`
> - Hit `Add bypass`, select `Repository admin` and hit `Add selected`
> - Set `Target repositories` to `All repositories`
> - Enable `Restrict file paths`
>   - Click `Add file path`, set `File path` to `.github/access-token.yaml` and hit `Add file path`
>     - Also add file path `.github/access-token.yml`
> - Hit `Create` button

<details><summary>Click me</summary>

- Go to GitHub Apps ([User Scope](https://github.com/settings/apps)
  or [Organizations Scope](https://github.com/organizations/YOUR_ORGANIZATION/settings/apps))
- Hit `Edit` button of your access token app
- Navigate to `Install App`
- Hit `Install` button of an account to install your access token app for
- Choose `All repositories` or `Only select repositories`
- Hit `Install` button

</details>

4. **Create a GitHub Actions Workflow**

- see [Action README](/action/README.md)

## Deploy Server

### Using Prebuilt Release Artifacts

> [!TIP]
> For easier deployment and version pinning with tools like Terraform and Renovate, prebuilt server artifacts are available as zip files in each GitHub release.

Each release includes the following prebuilt artifacts:
- `server-aws-lambda.zip` - AWS Lambda deployment package
- `server-vercel-function.zip` - Vercel Function deployment package
- `server-netlify-function.zip` - Netlify Function deployment package
- `server-cloudflare-worker.zip` - Cloudflare Worker deployment package

These artifacts contain all the bundled code and dependencies needed to deploy the server. Simply download the appropriate zip file for your deployment target from the [releases page](https://github.com/qoomon/actions--access-token/releases).

**Example: Using AWS Lambda artifact with Terraform**
```hcl
data "http" "lambda_zip" {
  url = "https://github.com/qoomon/actions--access-token/releases/download/v1.0.0/server-aws-lambda.zip"
}

resource "aws_lambda_function" "access_token" {
  filename      = data.http.lambda_zip.body
  function_name = "github-access-token"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs24.x"
  
  environment {
    variables = {
      GITHUB_APP_ID         = var.github_app_id
      GITHUB_APP_PRIVATE_KEY = var.github_app_private_key
    }
  }
}
```

### Docker Container

<details><summary>Click me</summary>

1. **Build Docker Image**
   ```shell
   npm run build:docker-container
   ```

2. **Run Docker Container**
    ```shell
    docker run --rm
     -e GITHUB_APP_ID=[YOUR_GITHUB_APP_ID]> \
     -e GITHUB_APP_PRIVATE_KEY=$(cat [YOUR_GITHUB_APP.pem]>) \
     -p 3000:3000 \
     localhost/github-access-token-server
    ```
    - **Optional environment variables**
        - `GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS`
            - A comma separated list of allowed subject patterns e.g. `repo:octocat/*`
            - If not set or empty all subjects are allowed

3. **Adjust [actions config](../action/src/config.ts) `api.url` to docker host**
    - e.g. http://YOUR-DOMAIN.com:3000

</details>

### Vercel

<details><summary>Click me</summary>

1. **Fork this repository**

2. **Create a [Vercel App](https://vercel.com/) for your fork**
    - Login to your [Vercel Account](https://vercel.com/)
    - `Add New...` > `Project`
    - `Import` your forked repository
    - Edit `Root Directory` to `server/deployments/vercel`
    - Set environment variables
        - `GITHUB_APP_ID`
        - `GITHUB_APP_PRIVATE_KEY`
        - `GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS`
            - A comma separated list of allowed subject patterns e.g. `repo:octocat/*`
            - If not set or empty all subjects are allowed
    - Hit `Deploy` button
    - Go to project `Settings` > `Domains`
        - `optional` adjust production domain to your liking
    - Take a note of `Production` domain
   - Set function environment variable `GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE` to vercel project `Production` domain

3. **Adjust [actions config](../action/src/config.ts) `api.url` to vercel project `Production` domain**

* e.g. https://github-actions-access-token.vercel.app

</details>

### AWS Lambda

> [!NOTE]
> This deployment will add extra layer of security by using IAM authenticator in front of the AWS Lambda,
> therefore the endpoint is secured by AWS identity and access management.
> All requests to the server are signed with AWS Signature Version 4.

<details><summary>Click me</summary>

1. **Fork this repository**

2. **Deploy Cloudformation Stack**
    - Adjust `GITHUB_ACTIONS_TOKEN_ALLOWED_SUBJECTS` in [app-stack.ts](deployments/aws/infrastructure/lib/app-stack.ts) to add additional layer of security by defining an ACL of subject patterns.
      - e.g. `repo:octocat/*` will allow only repositories of `octocat` owner to request access tokens
    - ```shell
      cd deployments/aws/infrastructure
      cdk deploy
      ```
    - Take a note of the cdk outputs
    - Login to your AWS account web console
    - Edit the `GitHubAppSecret` from cdk output
    - Set `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY` accordingly to your GitHub App

3. **Adjust [actions config](../action/src/config.ts) to cdk outputs as follows**
   ```ts
   export const config: Config = {
       api: {
           url: new URL('[cdk.output.ApiUrl]'),
           auth: {
               aws: {
                   roleArn: '[cdk.output.ApiRoleArn]',
                   region: '[cdk.output.ApiRegion]',
                   service: 'lambda',
               },
           },
       },
   }
   ```

</details>


### Netlify

<details><summary>Click me</summary>

1. **Fork this repository**

2. **TODO**

</details>

---

## Development

### Build Scripts

The following npm scripts are available for building deployment targets:

- `npm run build:aws-lambda` - Build AWS Lambda deployment package to `dist/aws-lambda/`
- `npm run build:vercel-function` - Build Vercel Function to `dist/vercel-function/`
- `npm run build:netlify-function` - Build Netlify Function to `dist/netlify-function/`
- `npm run build:cloudflare-worker` - Build Cloudflare Worker to `dist/cloudflare-worker/`
- `npm run build:all` - Build all deployment targets at once

> [!NOTE]
> The `dist/` directory is committed to the repository to ensure prebuilt artifacts are always available.
> After making changes to server code, run `npm run build:all` and commit the updated `dist/` directory.

### Start Server
  ```shell
  GITHUB_APP_ID=[YOUR_GITHUB_APP_ID] \
  GITHUB_APP_PRIVATE_KEY=$(cat [YOUR_GITHUB_APP.pem]) \
  GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE=... \
    npm start
  ```

## TODOs

- extract policy and permission evaluation to separate lib file

- ownerAccessPolicy
  - statements[].repositories
    - variable ${subject.repository} e.g. `repositories: [ "${subject.repo}" ]`

- Verify repository policy with action run
