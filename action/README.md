# ![](https://img.icons8.com/cotton/64/000000/grand-master-key.png) &nbsp; GitHub Actions Access Tokens [![starline](https://starlines.qoo.monster/assets/qoomon/actions--access-token)](https://github.com/qoomon/starlines)
&nbsp; [![Actions](https://img.shields.io/badge/qoomon-GitHub%20Actions-blue)](https://github.com/qoomon/actions)

Obtain temporary Access Tokens for GitHub Actions workflows by requesting GitHub App Installation Access Tokens.
Authorization is based on the GitHub Actions OIDC tokens and `.github/access-token.yaml` file in the target repositories.

## Concept
<p>
  <picture>
    <source media="(prefers-color-scheme: dark)"
      srcset="/action/docs/workflow_dark.png">
    <img alt="" src="/action/docs/workflow.png">
  </picture>
</p>

1. [This GitHub action](https://github.com/marketplace/actions/access-tokens-for-github-actions) will request an access token for a **Target Repository** from the **App Server**, authorize by the GitHub Action OIDC Token.
2. The [App Server](/server) requests a **GitHub App Installation Token** to read `.github/access-token.yaml` file in **Granting Repository**.
3. The [App Server](/server) reads `.github/access-token.yaml` file from **Target Repository** and determine which permissions should be granted to **Requesting GitHub Action Identity**.
4. The [App Server](/server) requests a **GitHub App Installation Token** with granted permissions for **Requesting GitHub Action Identity** and send it back in response to [this GitHub action](https://github.com/marketplace/actions/access-manager-for-github-actions) from step `1.`.
5. [This GitHub action](https://github.com/marketplace/actions/access-tokens-for-github-actions) sets the token as the step output field `token`
6. Further job steps can then utilize this token to access resources of the **Granting Repository** e.g. `${{ steps.<ACCESS_TOKEN_STEP_ID>.outputs.token }}`.

## Usage
See [Action Metadata](/action/action.yaml) and [Example Use Cases](#example-use-cases).

## Prerequisites

### 1. Install Access Manager App to Target Repositories

Install [Access Tokens for GitHub Actions from **Marketplace**](https://github.com/marketplace/access-manager-for-github-actions)
 **or** [host and install **your own** GitHub App](/server/README.md)

> [!WARNING]
> **Be aware** by installing the access token GitHub App **everybody** with `write` assess to `.github/access-token.yaml` can grant repository access permissions to GitHub Actions workflow runs.

> [!TIP]
> **For organizations on GitHub Enterprise plan** it is possible to restrict `write` access to `.github/access-token.yaml` to repository admins only by using a [push ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#push-rulesets)
<details><summary>Protect access token policy ruleset</summary>

- [Create a new push ruleset](https://github.com/organizations/YOUR-ORGANIZATION/settings/rules/new?target=push)
- Set `Ruleset Name` to `Protect access token policy`
- Set `Enforcement status` to `Active`
- Hit `Add bypass`, select `Repository admin` and hit `Add selected`
- Set `Target repositories` to `All repositories`
- Enable `Restrict file paths`
  - Click `Add file path`, set `File path` to `.github/access-token.yaml` and hit `Add file path`
    - Also add file path `.github/access-token.yml`
- Hit `Create` button

</details>

### 2. Create and Configure Owner Policy

Create a `OWNER/.github-access-token` repository and create an [owner `access-token.yaml`](/action/docs/access-token.owner-template.yaml) policy file at the root directory of the repository.

## Grant Permissions to Workflow Run

### Grant Repository Permissions

To grant repository permission create an [repository `access-token.yaml`](/action/docs/access-token.repo-template.yaml) policy file within the `.github/` directory of the target repository.

> [!IMPORTANT]
> Ensure repository permissions have been granted (`allowed-repository-permissions`) within the owner access policy file see [Create and Configure Owner Policy](#2-create-and-configure-owner-policy)

> [!Note]
> You can also grant repository permissions to all organization repositories within the owner access policy file see [Create and Configure Owner Policy](#2-create-and-configure-owner-policy)

### Grant Owner Permissions

To grant owner specific or owner wide permission create a `OWNER/.github-access-token` repository and create an `access-token.yaml` file at root of the repository with [this template content](/action/docs/access-token.owner-template.yaml)

## Example Use Cases

#### Update Secrets
<details><summary>Click me</summary>
  
```yaml
on:
  workflow_dispatch:
  schedule:
    - cron: '0 12 * * *' # every day at 12:00 UTC

jobs:
  update-secret:
    runs-on: ubuntu-latest
    permissions:
      id-token: write

    steps:
      - uses: qoomon/actions--access-token@v3
        id: access-token
        with:
          permissions: |
              secrets: write

      - name: Update secret
        run: >-
          gh secret
          set 'API_KEY'
          --body "$(date +%s)"
          --repo ${{ github.repository }}
        env:
          GITHUB_TOKEN: ${{ steps.access-token.outputs.token }}

  read-secret:
    needs: update-secret
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.API_KEY }}
```
</details>

#### Clone an Internal or Private Repository
<details><summary>Click me</summary>
 
```yaml
name: GitHub Actions Access Manager Example
on:
  workflow_dispatch:
  push:
    branches:
      - main

jobs:
  checkout:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - uses: qoomon/actions--access-token@v3
        id: access-token
        with:
          repository: [target repository]
          permissions: |
            contents: read

      - uses: actions/checkout@v4
        with:
          repository: [target repository]
          token: ${{ steps.access-token.outputs.token }}
```
</details>
 
#### Trigger a Workflow
<details><summary>Click me</summary>
  
```yaml
on:
workflow_dispatch:
push:
  branches:
    - main

permissions:
id-token: write

jobs:
build:
  runs-on: ubuntu-latest
  steps:
    - uses: qoomon/actions--access-token@v3
      id: access-token
      with:
        permissions: |
          actions: write

    - name: Trigger workflow
      run: >-
        gh workflow
        run [target workflow].yml
        --field logLevel=debug
      env:
        GITHUB_TOKEN: ${{steps.access-token.outputs.token}}
    # ...
```
</details>

---

## Development

### Action Release Workflow
- Run [actions-release workflow](https://github.com/qoomon/actions--access-token/actions/workflows/action-release.yml) to create a new action release

## Resources
* App icon: https://img.icons8.com/cotton/256/000000/grand-master-key.png
