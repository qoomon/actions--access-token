import * as cdk from 'aws-cdk-lib'
import {Template} from 'aws-cdk-lib/assertions'
import * as Aws from '../lib/app-stack'

test('SQS Queue and SNS Topic Created', () => {
  const app = new cdk.App()
  // WHEN
  const stack = new Aws.AppStack(app, 'MyTestStack')
  // THEN

  const template = Template.fromStack(stack)

  template.hasResourceProperties('AWS::SQS::Queue', {
    VisibilityTimeout: 300,
  })
  template.resourceCountIs('AWS::SNS::Topic', 1)
})
