
# ![](https://img.icons8.com/cotton/64/000000/grand-master-key.png)&nbsp; GitHub Actions Access Manager

Manage access from GitHub actions workflows by providing temporary app access tokens to target repository resources.

## Workflow
<p>
  <picture>
    <source media="(prefers-color-scheme: dark)"
      srcset="docs/workflow_dark.png">
    <img src="docs/workflow.png">
  </picture>
</p>

1. This GitHub action will request an access token for a **Target Repository** from the **App Server**, authorize by the GitHub Action ID Token (JWT signed by GitHub). 
1. The [App Server](server/) requests a **GitHub App Installation Token** to read `.github/access.yaml` file in **Target Repository**.
1. The [App Server](server/) reads `.github/access.yaml` file from **Target Repository** and determine which permissions should be granted to **Requesting Repository**, authorized by the **GitHub App Installation Token** from step `2.`.
1. The [App Server](server/) requests a **GitHub App Installation Token** with granted permissions for **Source Directory** and send it back in response to the GitHub action from step `1.`.
1. The GitHub action sets the token as environment variable `$GITHUB_ACCESS_MANAGER_TOKEN` and as step output value `${{ steps.github-actions-access.outputs.token }}`.
1. Further steps can then utilize this token to access resources of the **Target Repository**.

## Usage
### Install Access Manager App to Your Target Repositories
* Install [Access Manger App](https://github.com/marketplace/access-manager-for-github-actions)
* **or** [Deploy and Install your **Own** GitHub App](#Deploy-your-own-Access-Manager-App)

### Configure Access Permissions for Target Repository
* Create `.github/access.yaml` file
* Set `self` to enclosing repository. 
  * This ensures no unintended access in case you fork a repository with `.github/access.yaml` file.  
* Add policies and [permissions](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions), see examples below.
##### Example configurations
* Grant read access to GitHub Packages
  ```yaml
  self: example/test
  policies:
  - repository: example/sandbox
    permissions:
      packages: read
  ```
* Self access to trigger workflows from another workflow
  ```yaml
  self: example/test
  policies:
  - repository: self
    permissions:
      actions: write
  ```

### Setup GitHub Action Workflow
```yaml
# ...
permissions:
  id-token: write # required to request id-token
  
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: qoomon/github-actions-access-manager@v1
        id: github-actions-access
        with:
          repository: example/test
      - name: Utilize access token by environment variable
        run: echo $GITHUB_ACCESS_MANAGER_TOKEN
      - name: Utilize access token by step output value
        run: echo ${{ steps.github-actions-access.outputs.token }}
      - name: Use access token to clone repository
        run: |
          git config --global credential.helper store
          git clone https://_:$GITHUB_ACCESS_MANAGER_TOKEN@github.com/example/test.git
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

### Install GitHub App for Target Repository
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
  INPUT_ENDPOINT=http://localhost:3000/oauth2/token \
  INPUT_REPOSITORY=qoomon/github-actions-access-manager \
  ACTIONS_ID_TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImVCWl9jbjNzWFlBZDBjaDRUSEJLSElnT3dPRSIsImtpZCI6Ijc4MTY3RjcyN0RFQzVEODAxREQxQzg3ODRDNzA0QTFDODgwRUMwRTEifQ.eyJqdGkiOiJjMjQ3NjVjOC04NDAxLTQ3MDEtODFmMi1iZGVmZDYwNzQ1NzIiLCJzdWIiOiJyZXBvOnFvb21vbi9zYW5kYm94OnJlZjpyZWZzL2hlYWRzL21hc3RlciIsImF1ZCI6Imh0dHBzOi8vcHV0c3JlcS5jb20vYUJCOE80czJEMFB1RFdUS2xTSzEiLCJyZWYiOiJyZWZzL2hlYWRzL21hc3RlciIsInNoYSI6ImNkNjMyMTg5ZThmNDI1MGEwNzE3MzEzMjZmNGU4ODk3YWNiNjVmNDMiLCJyZXBvc2l0b3J5IjoicW9vbW9uL3NhbmRib3giLCJyZXBvc2l0b3J5X293bmVyIjoicW9vbW9uIiwicmVwb3NpdG9yeV9vd25lcl9pZCI6IjM5NjMzOTQiLCJydW5faWQiOiIyODE5NjU3NTY2IiwicnVuX251bWJlciI6IjE4IiwicnVuX2F0dGVtcHQiOiIxIiwicmVwb3NpdG9yeV92aXNpYmlsaXR5IjoicHVibGljIiwicmVwb3NpdG9yeV9pZCI6IjM1MjgyNzQxIiwiYWN0b3JfaWQiOiIzOTYzMzk0IiwiYWN0b3IiOiJxb29tb24iLCJ3b3JrZmxvdyI6Ik1hbnVhbCIsImhlYWRfcmVmIjoiIiwiYmFzZV9yZWYiOiIiLCJldmVudF9uYW1lIjoicHVzaCIsInJlZl90eXBlIjoiYnJhbmNoIiwiam9iX3dvcmtmbG93X3JlZiI6InFvb21vbi9zYW5kYm94Ly5naXRodWIvd29ya2Zsb3dzL01hbnVhbC55YW1sQHJlZnMvaGVhZHMvbWFzdGVyIiwiaXNzIjoiaHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbSIsIm5iZiI6MTY1OTk3Nzk0MSwiZXhwIjoxNjU5OTc4ODQxLCJpYXQiOjE2NTk5Nzg1NDF9.iHGmLmUc2jWPww1H97xbOiKmWQv4XBW5eR2hEYhCh8aIoh0HofQLthdqd-cOpvmQ0QpkWtnSZqGmXWDCcUvLwlA2BzThVyCr3awkpiYp6JEdBvfN-_SG6TwZozUTGt4ucoEN5VwPWugfB0145rCa_tE8-HKuinDtzZDiq9MCcdNQzTcUe97fSq9quj4o53CjMkpMkmjWWpYkjuEWpRO007Yp_eDcQlMy3vM5LfUNP619uJ2mgkpNcw1ocjOjKJWgs6rBBAHu47nRpA2RAm3Y5aqM9Co5CnCUW9sccwb48sx3KO0XhGwLvcjOT7mz4qbZvLPH0u3Rz6jhOjl7TkUX7Q \
  NODE_ENV=development \
  node index.js
  ```

## Resources
* App icon: https://img.icons8.com/cotton/256/000000/grand-master-key.png
