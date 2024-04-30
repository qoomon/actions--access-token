# ![](https://img.icons8.com/cotton/64/000000/grand-master-key.png)&nbsp; GitHub Actions Access Manager Server

## Endpoint

https://github-actions-access-manager.vercel.app/

## Development

#### Run Server Locally

* Start Server
  ```shell
  npm start
  ```

# TODOs

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
