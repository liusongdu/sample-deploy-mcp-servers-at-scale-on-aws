import os

import aws_cdk as cdk
import cdk_nag # for CDK NAG

from aws_cdk import Aspects # for CDK NAG
from cdk_nag import NagSuppressions # for CDK NAG

from infra.infra_stack import InfraStack


app = cdk.App()
stack = InfraStack(
    app,
    'MCP-Enterprise',
    env=cdk.Environment(
        account=os.environ.get('CDK_DEFAULT_ACCOUNT'),
        region="us-east-1"
    ),
    # env={
    #     'account': "976193252250",
    #     'region': "us-east-1"
    # }
)

Aspects.of(app).add(cdk_nag.AwsSolutionsChecks(verbose=True)) # for CDK NAG

NagSuppressions.add_stack_suppressions(stack, [ # for CDK NAG
    { "id": 'AwsSolutions-IAM5', "reason": 'Required to grant access to all streams under a log group.'},
    { "id": 'AwsSolutions-L1', "reason": 'Using PYTHON_3_13 which is the latest runtime version avaailable.'},
    { "id": 'AwsSolutions-ECS2', "reason": 'Need to provide variables that are dynamic and defined at deployment runtime.  No sensitive secrets provided in environment variables.  Any secrets are specified via Secrets Manager.'},
    { "id": 'AwsSolutions-EC23', "reason": 'CdkNagValidationFailure - generally caused by a parameter referencing an intrinsic function.'},
    { "id": 'AwsSolutions-S1', "reason": 'The S3 buckets are already used for access logging.'},
    { "id": 'AwsSolutions-COG4', "reason": 'API Gateway endpoint protected using API key.  Cognito not required for demo purposes.'},
    { "id": 'AwsSolutions-APIG4', "reason": 'API Gateway endpoint protected using API key.  Cognito not required for demo purposes.'},
    { "id": 'AwsSolutions-SMG4', "reason": 'Using Secrets Manager to store API key which does not need to rotate for demo purposes.'},
])


app.synth()


