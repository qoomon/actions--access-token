# GitHub Actions Access Manager Action

## Setup Repository Access

Create an access policy file `.github/access-policy.yaml` within the repository you want to manage access for.

### Repository Access Policy Example
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

### Example Usage - GitHub Action Workflow

#### Rotate Secrets
```yaml
name: GitHub Actions Access Manager Example
on:
  workflow_dispatch:
  push:
    branches:
      - main

jobs:
  update-secret:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      
    steps:
      - uses: JH-JDS/github-actions-access-manager@v1
        id: access-token
        with:
          permissions: |
              secrets: write

      - name: Update Secret
        run: gh secret set API_KEY --body "Hello-World"
        env:
          GITHUB_TOKEN: ${{ steps.access-token.outputs.token }}

  read-secret:
    needs: update-secret
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.API_KEY }}
```

#### Checkout Another Repository
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
      - uses: JH-JDS/github-actions-access-manager@v1
        with:
          repository: JH-JDS/sandbox
          permissions: |
            contents: read
        id: github-access-manager

      - uses: actions/checkout@v4
        with:
          repository: JH-JDS/sandbox
          token: ${{ steps.github-access-manager.outputs.token }}
```

---

## Setup Organization Access

Create an access policy file `.github/organization-access-policy.yaml` within the repository `YOUR_ORGANOZATION/.github` you want to manage access for.

### Organization Access Policy Example
```yaml
origin: YOUR_ORGANIZATION/.github # needs to equals to the repository name the policy file belongs to
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

## Example Usage - GitHub Action Workflow

### Rotate Secrets
```yaml
name: GitHub Actions Access Manager Example
on:
  workflow_dispatch:
  push:
    branches:
      - main

jobs:
  update-secret:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      
    steps:
      - uses: JH-JDS/github-actions-access-manager@v1
        id: access-token
        with:
          organization: sesame-street
          permissions: |
            organization_secrets: write
      - name: Update Secret
        run: gh secret set API_KEY --body "Hello-World" --org sesame-street
        env:
          GITHUB_TOKEN: ${{ steps.access-token.outputs.token }}

  read-secret:
    needs: update-secret
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.API_KEY }}
```

## Development

### Action Release Workflow

```bash
RELEASE_VERSION="0.0.0"

npm ci
npm run build

git add -f dist/
git commit -m "build(release): action release $RELEASE_VERSION"
git push

RELEASE_VERSION_TAG="v$RELEASE_VERSION"
git tag -a -m "$RELEASE_VERSION" "$RELEASE_VERSION_TAG"
git push origin "$RELEASE_VERSION_TAG"

# move the major version tag
git tag --force -a -m "$RELEASE_VERSION"  ${RELEASE_VERSION_TAG%%.*} 
git push --force origin  ${RELEASE_VERSION_TAG%%.*} 
```
