# ![](https://img.icons8.com/cotton/64/000000/grand-master-key.png)&nbsp; GitHub Actions Access Tokens

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

1. [This GitHub action](https://github.com/marketplace/actions/access-tokens-for-github-actions) will request an access token for a **Granting Repository** from the **App Server**, authorize by the GitHub Action ID Token (JWT signed by GitHub).
2. The [App Server](/server/README.md) requests a **GitHub App Installation Token** to read `.github/access-token.yaml` file in **Granting Repository**.
3. The [App Server](/server/README.md) reads `.github/access-token.yaml` file from **Granting Repository** and determine which permissions should be granted to **Requesting Repository**, authorized by the **GitHub App Installation Token** from step `2.`.
4. The [App Server](/server/README.md) requests a **GitHub App Installation Token** with granted permissions for **Source Directory** and send it back in response to [this GitHub action](https://github.com/marketplace/actions/access-manager-for-github-actions) from step `1.`.
5. [This GitHub action](https://github.com/marketplace/actions/access-tokens-for-github-actions) sets the token as the step output field `token`
6. Further job steps can then utilize this token to access resources of the **Granting Repository** e.g. `${{ steps.<ACCESS_TOKEN_STEP_ID>.outputs.token }}`.

## Usage
> [!Note]
> Jump to [example use cases](#example-use-cases) to see how to use this action in workflows.

### Prerequisites

#### Install Access Manager App to Target Repositories

Install [Access Tokens for GitHub Actions from **Marketplace**](https://github.com/marketplace/access-manager-for-github-actions)
 **or** [host and install **your own** GitHub App](../server/README.md)

> [!WARNING]
> **Be aware** by installing the access token GitHub App **everybody** with `write` assess to `.github/access-token.yaml` can grant repository access permissions to GitHub Actions workflow runs.

> [!TIP]
> **For organizations on GitHub Enterprise plan** it is possible to restrict `write` access to `.github/access-token.yaml` to repository admins only by using a [push ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets#push-rulesets)
> - [Create a new push ruleset](https://github.com/organizations/YOUR-ORGANIZATION/settings/rules/new?target=push)
> - Set `Ruleset Name` to `Protect access token policy`
> - Set `Enforcement status` to `Active`
> - Hit `Add bypass`, select `Repository admin` and hit `Add selected`
> - Set `Target repositories` to `All repositories`
> - Enable `Restrict file paths`, hit `Add file path`, set `File path` to `.github/access-token.yaml` and hit `Add file path`
> - Hit `Create` button


#### Setup Repository Permission Access
> [!WARNING]
> Every statement will always implicitly grant `metadata: read` permission.

> [!Note]
> You can also grant repository permissions by owner access token policy see [Setup Owner Permission Access](#setup-owner-permission-access)

<details><summary>Click me</summary>

To grant repository permission create an `access-token.yaml` file within the `.github` directory of the target repository.

##### Repository Access Policy Example

```yaml
origin: sandbox_owner/sandbox # needs to equals to the repository name the policy file belongs to
statements:
  - subjects:
      # --- This repository subject examples ---
      - ref:refs/heads/main # grant access to jobs running on the main branch
      # - ref:refs/tags/v* # grant access jobs running on any tag starting with a v
      # - ref:refs/* # grant access to jobs running on any branches and tags
      # - environment:production # grant access to jobs using production environment
      # - workflow_ref:/.github/workflows/build.yml@refs/heads/main # grant access to jobs of a specific workflow file
      
      # --- Remote repository subject examples ---
      # - repo:remote_owner/sandbox:ref:refs/heads/main grant access to jobs running on the main branch
      # - repo:remote_owner/sandbox:ref:refs/* # grant access to jobs running on any branches and tags
      # - repo:remote_owner/sandbox:environment:production # grant access to jobs using production environment
      # - repo:remote_owner/sandbox:workflow_ref:/.github/workflows/build.yml@refs/heads/main # grant access to a remote job, if it uses a reusable workflow from this repository
    permissions: # https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps
        contents: read
        # --- Repository permissions ---
        # actions: read | write
        # actions_variables: read | write
        # checks: read | write
        # codespaces: read | write
        # codespaces_lifecycle_admin: read | write
        # codespaces_metadata: read | write
        # codespaces_secrets: read | write
        # contents: read | write
        # dependabot_secrets: read | write
        # deployments: read | write
        # discussions: read | write
        # environments: read | write
        # issues: read | write
        # merge_queues: read | write
        # metadata: read | write
        # packages: read | write
        # pull_requests: read | write
        # repository_advisories: read | write
        # repository_hooks: read | write
        # repository_projects: read | write | admin
        # secret_scanning_alerts: read | write
        # secrets: read | write
        # security_events: read | write
        # statuses: read | write
        # team_discussions: read | write
        # vulnerability_alerts: read | write
        # workflows: read | write
        # pages: read | write
```

</details>

#### Setup Owner Permission Access
> [!WARNING]
> Every statement will always implicitly grant `metadata: read` permission.

<details><summary>Click me</summary>

To grant owner specific or owner wide permission create a `OWNER/.github-access-token` repository and create an `access-token.yaml` file within.
`statements` are alike to the repository access policy file, but you can grant any permission including organization permissions and/or user permissions

##### Owner Access Policy Example

```yaml
origin: OWNER/.github-access-token # needs to equals to the repository name the policy file belongs to
statements:
  - subjects:
      # --- This repository subject examples ---
      - ref:refs/heads/main # grant access to jobs running on the main branch
      # - ref:refs/tags/v* # grant access jobs running on any tag starting with a v
      # - ref:refs/* # grant access to jobs running on any branches and tags
      # - environment:production # grant access to jobs using production environment
      # - workflow_ref:/.github/workflows/build.yml@refs/heads/main # grant access to jobs of a specific workflow file
      
      # --- Remote repository subject examples ---
      # - repo:remote_owner/sandbox:ref:refs/heads/main grant access to jobs running on the main branch
      # - repo:remote_owner/sandbox:ref:refs/* # grant access to jobs running on any branches and tags
      # - repo:remote_owner/sandbox:environment:production # grant access to jobs using production environment
      # - repo:remote_owner/sandbox:workflow_ref:/.github/workflows/build.yml@refs/heads/main # grant access to a remote job, if it uses a reusable workflow from this repository
    permissions: # https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps
        members: read
        # --- Organization permissions ---
        # members: read | write
        # organization_actions_variables: read | write
        # organization_administration: read | write
        # organization_announcement_banners: read | write
        # organization_codespaces: read | write
        # organization_codespaces_secrets: read | write
        # organization_codespaces_settings: read | write
        # organization_copilot_seat_management: read | write
        # organization_custom_org_roles: read | write
        # organization_custom_properties: read | write | admin
        # organization_custom_roles: read | write
        # organization_dependabot_secrets: read | write
        # organization_events: read 
        # organization_hooks: read | write
        # organization_personal_access_token_requests: read | write
        # organization_personal_access_tokens: read | write
        # organization_plan: read
        # organization_projects: read | write | admin
        # organization_secrets: read | write
        # organization_self_hosted_runners: read | write
        # organization_user_blocking: read | write
    
        # --- Repository permissions ---
        # actions: read | write
        # actions_variables: read | write
        # checks: read | write
        # codespaces: read | write
        # codespaces_lifecycle_admin: read | write
        # codespaces_metadata: read | write
        # codespaces_secrets: read | write
        # contents: read | write
        # custom_properties: read | write
        # dependabot_secrets: read | write
        # deployments: read | write
        # discussions: read | write
        # environments: read | write
        # issues: read | write
        # merge_queues: read | write
        # metadata: read | write
        # packages: read | write
        # pull_requests: read | write
        # repository_advisories: read | write
        # repository_hooks: read | write
        # repository_projects: read | write | admin
        # secret_scanning_alerts: read | write
        # secrets: read | write
        # security_events: read | write
        # statuses: read | write
        # team_discussions: read | write
        # vulnerability_alerts: read | write
        # workflows: read | write
        # pages: read | write
```

</details>

### Example Use Cases

##### Update Secrets
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

##### Clone an Internal or Private Repository
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

##### Trigger a Workflow
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
- Run [actions-release workflow](/.github/workflows/action-release.yml) to create a new action release

## Resources
* App icon: https://img.icons8.com/cotton/256/000000/grand-master-key.png

