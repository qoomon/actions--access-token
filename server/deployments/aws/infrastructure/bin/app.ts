import * as cdk from 'aws-cdk-lib'
import {AppStack} from '../lib/app-stack'
import {DeploymentStack} from '../lib/deployment-stack';

const app = new cdk.App()
const appStack = new AppStack(app, 'GitHubActionsAccessTokens')
// new DeploymentStack(app, appStack.stackName + '-Deployment')
