# GitHub Actions Access Token Server

This readme describes how to deploy a GitHub Actions Access Token Server.

## Prerequisites
> [!IMPORTANT]
> Be aware by installing the access token GitHub App **everybody** with `write` assess to `.github/access-token.yaml` can grant repository access permissions to GitHub Actions workflow runs.
> <br>
> - **For organizations on GitHub Enterprise plan** it is possible to restrict `write` access to `.github/access-token.yaml` to repository admins only by using a [push ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#push-rulesets)
>   - [Create a new push ruleset](https://github.com/organizations/YOUR-ORGANIZATION/settings/rules/new?target=push)
>   - Set `Ruleset Name` to `Protect access token policy`
>   - Set `Enforcement status` to `Active`
>   - Hit `Add bypass`, select `Repository admin` and hit `Add selected`
>   - Set `Target repositories` to `All repositories`
>   - Enable `Restrict file paths`, hit `Add file path`, set `File path` to `.github/access-token.yaml` and hit `Add file path`
>   - Hit `Create` button

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
                - Add file path `access-token.yaml` - for owner scoped token policy
        - Choose permissions you want to allow to request
        - Hit `Create GitHub App` button
        - Take a note of `App ID`
        - Scroll down to `Private keys` section and click `Generate a private key` button
            - private key (`.pem` file) will be downloaded to your machine automatically
    
    </details>

2. **Install GitHub App for Granting Repository**
    <details><summary>Click me</summary>
    - Go to GitHub Apps ([User Scope](https://github.com/settings/apps)
      or [Organizations Scope](https://github.com/organizations/YOUR_ORGANIZATION/settings/apps))
    - Hit `Edit` button of your access token app
    - Navigate to `Install App`
    - Hit `Install` button of an account to install your access token app for
    - Choose `All repositories` or `Only select repositories`
    - Hit `Install` button

    </details>

## Deploy Server

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

3. **Adjust [actions config](../action/config.ts) `api.url` to docker host**
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

3. **Adjust [actions config](../action/config.ts) `api.url` to vercel project `Production` domain**

* e.g. https://github-actions-access-token.vercel.app

</details>

### AWS Lambda

<details><summary>Click me</summary>

> [!NOTE]
> This deployment will add extra layer of security by using IAM authenticator for AWS Lambda.
> That means that all requests to the server need to be signed with AWS Signature Version 4
> and therefore the server is secured by AWS identity and access management.

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

3. **Adjust [actions config](../action/config.ts) to cdk outputs as follows**
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

## Development
### Start Server
  ```shell
  GITHUB_APP_ID=[YOUR_GITHUB_APP_ID] \
  GITHUB_APP_PRIVATE_KEY=$(cat [YOUR_GITHUB_APP.pem]) \
    npm start 
  ```

## TODOs
- refactor startup debug logging and request response logging
- owner options
    - define allowed repo permissions
        - repo permissions
    - define allowed requesting subjects patterns
        - defaults to all owner repositories

- extract policy and permission evaluation to separate lib file

- review error messages and improve them
    - add artificial subjects to error messages

- add verify policy option to action to verify access policy
