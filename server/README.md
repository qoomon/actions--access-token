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
     -e GITHUB_ACTIONS_TOKEN_ALLOWED_AUDIENCE=localhost:3000 \
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
