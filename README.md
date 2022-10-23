
# ![](https://img.icons8.com/cotton/64/000000/grand-master-key.png)&nbsp; GitHub Actions Access Manager

Manage access from GitHub actions workflows by providing temporary app access tokens to repository resources.

## Workflow
<p>
  <picture>
    <source media="(prefers-color-scheme: dark)"
      srcset="docs/workflow_dark.png">
    <img src="docs/workflow.png">
  </picture>
</p>

1. [This GitHub action](https://github.com/marketplace/actions/access-manager-for-github-actions) will request an access token for a **Granting Repository** from the **App Server**, authorize by the GitHub Action ID Token (JWT signed by GitHub). 
1. The [App Server](server/) requests a **GitHub App Installation Token** to read `.github/access.yaml` file in **Granting Repository**.
1. The [App Server](server/) reads `.github/access.yaml` file from **Granting Repository** and determine which permissions should be granted to **Requesting Repository**, authorized by the **GitHub App Installation Token** from step `2.`.
1. The [App Server](server/) requests a **GitHub App Installation Token** with granted permissions for **Source Directory** and send it back in response to [this GitHub action](https://github.com/marketplace/actions/access-manager-for-github-actions) from step `1.`.
1. [This GitHub action](https://github.com/marketplace/actions/access-manager-for-github-actions) sets the token as environment variable `$GITHUB_ACCESS_MANAGER_TOKEN` and as step output `${{ steps.access-manager.outputs.GITHUB_ACCESS_MANAGER_TOKEN }}`.
1. Further steps can then utilize this token to access resources of the **Granting Repository**.

## Usage
### Install Access Manager App to Granting Repository `example/blue`
* Install [Access Manger App](https://github.com/marketplace/access-manager-for-github-actions)
* **or** [Deploy and Install your **Own** GitHub App](#Deploy-your-own-Access-Manager-App)

### Grant Access Permissions in Granting Repository `example/blue`
* Create `.github/access.yaml` file
* Set `self` to enclosing repository. 
  * This ensures no unintended access in case you fork a repository with `.github/access.yaml` file.  
* Add `policies` and [permissions](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token), see examples below.
  * `repository` value supports wildcards `*` e.g. `repository: octa-org/*`
  * ⚠ `metadata: read` permission is implicitly always granted.
##### Example Configurations
* Self access to trigger workflows from another workflow
  ```yaml
  self: qoomon/example
  policies:
  - repository: self
    permissions:
      actions: write
  ```
* Grant read access to GitHub Packages for an explicit repository
    ```yaml
    self: qoomon/example
    policies:
    - repository: qoomon/sandbox
      permissions:
        packages: read
    ```
* Grant read access to GitHub Packages for an entire organization
    ```yaml
    self: qoomon/example
    policies:
    - repository: octa-org/*
      permissions:
        packages: read
    ```
  
### Setup GitHub Action Workflow for Requesting Repository (`example/green`)
##### Example Workflow Files
* Clone a remote repository
  ```yaml
  on:
    # ...
    
  permissions:
    id-token: write # required to request id-token
    
  jobs:
    build:
      runs-on: ubuntu-latest
      steps:
        - name: Request access token
          uses: qoomon/github-actions-access-manager@v2
          with:
            repositories: |
              qoomon/sandbox
            permissions: |
              contents:read
        - name: Clone remote repository
          run: |
            git config --global credential.helper store
            git clone https://_:$GITHUB_ACCESS_MANAGER_TOKEN@github.com/qoomon/sandbox.git
        # ...
  ```
* Trigger another workflow within the repository
  ```yaml
  on:
    # ...
    
  permissions:
    id-token: write # required to request id-token
    
  jobs:
    build:
      runs-on: ubuntu-latest
      steps:
        - name: Request access token
          id: access-manager
          uses: qoomon/github-actions-access-manager@v2
          with:
            repositories: self
            permissions: actions:write
        - name: Trigger workflow
          run: |
            gh workflow run post_deploy_checks.yml \
              --ref my-branch \
              --field logLevel=debug
          env:
            GITHUB_TOKEN: ${{steps.access-manager.outputs.GITHUB_ACCESS_MANAGER_TOKEN}}
        # ...
  ```
  
## Deploy your own Access Manager App

###  Create a GitHub App
* Create a [new User App](https://github.com/settings/apps/new) or a [new Organizations App](https://github.com/organizations/YOUR_ORGANIZATION/settings/apps/new)
* Fill out mandatory fields
* Deactivate Webhook
* Choose `Repository permissions` you want to manage or see following suggestions
    * Actions: `Read and write`
    * Contents: `Read-only`
    * Packages: `Read-only`
* Add Mandatory `Repository permissions`
    * Single file: `Read-only`
        * Add file path `.github/access.yaml`

### Install GitHub App for Granting Repository
* Go to [User App Settings](https://github.com/settings/apps/new) or [Organizations App Settings](https://github.com/organizations/YOUR_ORGANIZATION/settings/apps)
* Click on `Edit` of your App
* Click on `Install App`
* Choose an account to install your app to

### Run GitHub Actions Access Manager Server
* Fork this repository
* Create [Vercel App](https://vercel.com/) of your fork
  * set root directory to `server/` 
  * set following environment variables. Copy values from [User App Details](https://github.com/settings/apps/) or from [Organizations App Details](https://github.com/organizations/YOUR_ORGANIZATION/settings/apps)
    * `GITHUB_APP_ID`
    * `GITHUB_APP_PRIVATE_KEY `
* change default `endpoint` in github action [action.yaml](action.yaml) to your vercel app url.
* Use your fork as GitHub action to request a access token,

## Development
#### Run Server Locally
* Start Server
  ```shell
  npm --prefix server/ start 
  ```
* Run GitHub Action
  ```shell
  export NODE_ENV=development
  export ACTIONS_ACCESS_MANAGER_ENDPOINT=http://localhost:3000/v2/access_token
  
  export ACTIONS_ID_TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImVCWl9jbjNzWFlBZDBjaDRUSEJLSElnT3dPRSIsImtpZCI6Ijc4MTY3RjcyN0RFQzVEODAxREQxQzg3ODRDNzA0QTFDODgwRUMwRTEifQ.eyJqdGkiOiJjOTAzODNiMC01YTVjLTQ2YTMtODUxZi0wYzQwMDRiMWRkYmUiLCJzdWIiOiJyZXBvOnFvb21vbi9naXRodWItYWN0aW9ucy1hY2Nlc3MtbWFuYWdlcjpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoiaHR0cHM6Ly9naXRodWIuY29tL3Fvb21vbiIsInJlZiI6InJlZnMvaGVhZHMvbWFpbiIsInNoYSI6ImE5Yzk1NDYyM2RkYWE5NTVhMmE3ZjJlYjViYWQ5MjJhNDAzZjAwYzgiLCJyZXBvc2l0b3J5IjoicW9vbW9uL2dpdGh1Yi1hY3Rpb25zLWFjY2Vzcy1tYW5hZ2VyIiwicmVwb3NpdG9yeV9vd25lciI6InFvb21vbiIsInJlcG9zaXRvcnlfb3duZXJfaWQiOiIzOTYzMzk0IiwicnVuX2lkIjoiMzI5MjgxMzc4NCIsInJ1bl9udW1iZXIiOiIxIiwicnVuX2F0dGVtcHQiOiIxIiwicmVwb3NpdG9yeV92aXNpYmlsaXR5IjoicHVibGljIiwicmVwb3NpdG9yeV9pZCI6IjUyMjkyNDUzMSIsImFjdG9yX2lkIjoiMzk2MzM5NCIsImFjdG9yIjoicW9vbW9uIiwid29ya2Zsb3ciOiIuZ2l0aHViL3dvcmtmbG93cy90b2tlbi55YW1sIiwiaGVhZF9yZWYiOiIiLCJiYXNlX3JlZiI6IiIsImV2ZW50X25hbWUiOiJ3b3JrZmxvd19kaXNwYXRjaCIsInJlZl90eXBlIjoiYnJhbmNoIiwiam9iX3dvcmtmbG93X3JlZiI6InFvb21vbi9naXRodWItYWN0aW9ucy1hY2Nlc3MtbWFuYWdlci8uZ2l0aHViL3dvcmtmbG93cy90b2tlbi55YW1sQHJlZnMvaGVhZHMvbWFpbiIsImlzcyI6Imh0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20iLCJuYmYiOjE2NjYyOTgxNjEsImV4cCI6MTY2NjI5OTA2MSwiaWF0IjoxNjY2Mjk4NzYxfQ.37dPzBp031doaTq1alL4s1vpn7ODAX8ks2_cPbloJd-Scaf9fbkdZjYON0Ogm0Gu3yURvSusFVbej22KwHYdTmxQh-NyudXpmqTnTI7RY-9ouiEScY0-D9mc7oUI8INb7phwUOdzOECb48HbPNA04MVwJ2YGQwyWBIXixScMMv3Au3g22NK6Kc_-MPXuSCbBzj2ZLyn2g57BMGs_OveFZy0uRzv5YuzS-QdjBgpesWuJrLgE4DPk3YTkpaLC0rTWo4feNUa53TZStrOREODO-TcWgIAkUJBcNoE3vhJJkBn2NFeovxzW5yj_sO3Kq4E24XYtUrXR52z_34yz9hzdsQ
  
  INPUT_REPOSITORIES=qoomon/github-actions-access-manager \
  INPUT_PERMISSIONS=contents:read \
  node index.js
  ```

## Resources
* App icon: https://img.icons8.com/cotton/256/000000/grand-master-key.png
