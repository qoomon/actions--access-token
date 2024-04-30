
# ![](https://img.icons8.com/cotton/64/000000/grand-master-key.png)&nbsp; GitHub Actions Access Manager Server

[//]: # (TODO)

## Development

### Deploy as Vercel Function

[//]: # (TODO)
Login to your Vercel account
- `Add New...` > `Project`
- `Import` your forked repository
- Edit `Root Directory` to `server/deployments/vercel`
- Set `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY` accordingly to your GitHub App
- Hit `Deploy` button

- Go to project `Settings` > `Domains`
- `optional` adjust production domain to your liking
- Copy and paste production domain to the [action](../action/index.ts) config

### Deploy as AWS Lambda Function

- `cd server/deployments/aws-lambda/infrastructure`
- `cdk deploy`
- Login to your AWS account web console
  - Edit `GitHubAppSecret` (from cdk output) 
  - Set `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY` accordingly to your GitHub App 
- Copy and paste cdk output to the [action](../action/index.ts) config
  ```
    {
        baseUrl: new URL('ApiUrl'),
        auth: {
            aws: {
                roleArn: 'ApiAccessRoleArn',
                region: 'ApiRegion',
                service: 'lambda',
            },
       }
    }
  ```
  
### Deploy as Docker Container
- `npm run build:docker-container`
  [//]: # (TODO)
- `docker run -p 3000:3000 -e GITHUB_APP_ID=... -e GITHUB_APP_PRIVATE_KEY=... xxx` 
- Adjust [action](../action/index.ts) config accordingly to docker host


### Run Server Locally
[//]: # (TODO)
* Start Server
  ```shell
  npm start
  ```


# TODOs
- refactor startup debug logging and request response logging
- owner options
    - define allowed repo permissions
        - repo permissions
    - define allowed requesting subjects patterns
        - defaults to all owner repositories

- extract policy and permission evaluation to separate lib file

- add verify policy option to action to verify access policy

- review error messages and improve them
  - add artificial subjects to error messages

- add paragraph to README.md about how to secure the access policy
  - create a push ruleset to allow only repo admins to change the access policy 
- https://github.com/causaly/zod-validation-error
