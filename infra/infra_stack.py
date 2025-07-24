import json
import time

import boto3

# from typing import Optional

from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    RemovalPolicy,
    CfnOutput,
    aws_iam as iam,
    Stack,
    aws_logs as logs,
    aws_ecs as ecs,
    aws_ecr as ecr,
    # aws_ecr_assets as ecr_assets,
    Fn,
    aws_elasticloadbalancingv2 as elbv2,
    aws_dynamodb as dynamodb,
    aws_wafv2 as waf,
    custom_resources as cr,
    aws_lambda as _lambda,
    Duration,
    aws_apigateway as apigateway,
    aws_secretsmanager as secretsmanager,
    aws_s3 as s3,
    Environment
)
from constructs import Construct


class InfraStack(Stack):

    # ███    ██ ███████ ████████ ██     ██  ██████  ██████  ██   ██ 
    # ████   ██ ██         ██    ██     ██ ██    ██ ██   ██ ██  ██  
    # ██ ██  ██ █████      ██    ██  █  ██ ██    ██ ██████  █████   
    # ██  ██ ██ ██         ██    ██ ███ ██ ██    ██ ██   ██ ██  ██  
    # ██   ████ ███████    ██     ███ ███   ██████  ██   ██ ██   ██
    """
    Below is the code for the AWS CDK stack that sets up the infrastructure for my AWS environment for my AWS environment.
    """
    def create_vpc(self, project_name, vpc_name, cidr_range="10.0.0.0/16", nat_gateways=0):
        # Create VPC with two private subnets
        vpc = ec2.Vpc(self, f"{project_name}-{vpc_name}",
            ip_addresses=ec2.IpAddresses.cidr(cidr_range),
            max_azs=2,
            nat_gateways=nat_gateways
        )
        vpc.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create VPC Flow Logs
        self.enable_vpc_flow_logs(project_name, vpc, vpc_name)

        return vpc

    def enable_vpc_flow_logs(self, project_name, vpc, vpc_name):
        # Create a log group for VPC Flow Logs
        flow_logs_log_group = logs.LogGroup(
            self,
            f"{project_name}-{vpc_name}-flow-logs",
            log_group_name=f"/aws/vpc-flow-logs/{project_name}-{vpc_name}",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY
        )

        # Create IAM role for VPC Flow Logs
        flow_logs_role = iam.Role(
            self,
            f"{project_name}-{vpc_name}-flow-logs-role",
            role_name=f"{project_name}-{vpc_name}-flow-logs-role",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com"),
            inline_policies={
                "flow-logs-policy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                                "logs:DescribeLogGroups",
                                "logs:DescribeLogStreams"
                            ],
                            resources=[
                                flow_logs_log_group.log_group_arn,
                                f"{flow_logs_log_group.log_group_arn}:*"
                            ]
                        )
                    ]
                )
            }
        )
        flow_logs_role.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create VPC Flow Logs
        ec2.FlowLog(
            self,
            f"{project_name}-{vpc_name}-flow-log",
            resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(flow_logs_log_group, flow_logs_role),
            traffic_type=ec2.FlowLogTrafficType.ALL,
            max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.ONE_MINUTE
        )
    """
    Up to this point, the code defines a CDK stack for AWS infrastructure setup for my AWS environment.
    """
    
    # ██    ██ ██████   ██████     ███████ ███    ██ ██████  ██████   ██████  ██ ███    ██ ████████ ███████ 
    # ██    ██ ██   ██ ██          ██      ████   ██ ██   ██ ██   ██ ██    ██ ██ ████   ██    ██    ██      
    # ██    ██ ██████  ██          █████   ██ ██  ██ ██   ██ ██████  ██    ██ ██ ██ ██  ██    ██    ███████ 
    #  ██  ██  ██      ██          ██      ██  ██ ██ ██   ██ ██      ██    ██ ██ ██  ██ ██    ██         ██ 
    #   ████   ██       ██████     ███████ ██   ████ ██████  ██       ██████  ██ ██   ████    ██    ███████ 
    
    def create_default_vpc_endpoints(self, project_name, vpc, vpc_name):
        # Create Security Group - VPC Endpoint
        sg_vpc_endpoint = ec2.SecurityGroup(
            self, f"{project_name}-{vpc_name}-endpoint-security-group",
            security_group_name=f"{project_name}-vpc-endpoint-security-group",
            vpc=vpc,
        )
        sg_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)
        sg_vpc_endpoint.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), connection=ec2.Port.tcp(443))
        """
        Below is the code for the alternative environment.
        """
        # sg_vpc_endpoint.add_ingress_rule(ec2.Peer.ipv4('10.1.0.0/16'), connection=ec2.Port.tcp(443))
        """
        Up to this point, the code is for for the alternative environment.
        """

        # Create VPC Gateway Endpoints for DynamoDB
        dynamodb_endpoint = vpc.add_gateway_endpoint(f"{project_name}-{vpc_name}-DynamoDbEndpoint",service=ec2.GatewayVpcEndpointAwsService.DYNAMODB, )
        dynamodb_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Create VPC Gateway Endpoints for S3
        s3_endpoint = vpc.add_gateway_endpoint(f"{project_name}-{vpc_name}-S3Endpoint",service=ec2.GatewayVpcEndpointAwsService.S3,)
        s3_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Create VPC Interface Endpoints for Bedrock Runtime
        bedrock_interface_vpc_endpoint = ec2.InterfaceVpcEndpoint(self, f"{project_name}-{vpc_name}-BedrockInterfaceVpcEndpoint",
            vpc=vpc,
            service=ec2.InterfaceVpcEndpointService(f"com.amazonaws.{self.region}.bedrock-runtime", 443),
            private_dns_enabled=True,
            security_groups=[sg_vpc_endpoint]
        )
        bedrock_interface_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Create VPC Interface Endpoints for Bedrock Runtime
        bedrock_agent_interface_vpc_endpoint = ec2.InterfaceVpcEndpoint(self, f"{project_name}-{vpc_name}-BedrockAgentInterfaceVpcEndpoint",
            vpc=vpc,
            service=ec2.InterfaceVpcEndpointService(f"com.amazonaws.{self.region}.bedrock-agent-runtime", 443),
            private_dns_enabled=True,
            security_groups=[sg_vpc_endpoint]
        )
        bedrock_agent_interface_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create VPC Interface Endpoints for ECR API
        ecr_api_interface_vpc_endpoint = ec2.InterfaceVpcEndpoint(self, f"{project_name}-{vpc_name}-ecr.api",
            vpc=vpc,
            service=ec2.InterfaceVpcEndpointService(f"com.amazonaws.{self.region}.ecr.api", 443),
            private_dns_enabled=True,
            security_groups=[sg_vpc_endpoint]
        )
        ecr_api_interface_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create VPC Interface Endpoints for ECR DKR
        ecr_dkr_interface_vpc_endpoint = ec2.InterfaceVpcEndpoint(self, f"{project_name}-{vpc_name}-ecr.dkr",
            vpc=vpc,
            service=ec2.InterfaceVpcEndpointService(f"com.amazonaws.{self.region}.ecr.dkr", 443),
            private_dns_enabled=True,
            security_groups=[sg_vpc_endpoint]
        )
        ecr_dkr_interface_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create VPC Interface Endpoints for Cloudwatch Logs
        logs_interface_vpc_endpoint = ec2.InterfaceVpcEndpoint(self, f"{project_name}-{vpc_name}-logs",
            vpc=vpc,
            service=ec2.InterfaceVpcEndpointService(f"com.amazonaws.{self.region}.logs", 443),
            private_dns_enabled=True,
            security_groups=[sg_vpc_endpoint]
        )
        logs_interface_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Create VPC Interface Endpoints for Secrets Manager
        secretsmanager_interface_vpc_endpoint = ec2.InterfaceVpcEndpoint(self, f"{project_name}-{vpc_name}-secretsmanager",
            vpc=vpc,
            service=ec2.InterfaceVpcEndpointService(f"com.amazonaws.{self.region}.secretsmanager", 443),
            private_dns_enabled=True,
            security_groups=[sg_vpc_endpoint]
        )
        secretsmanager_interface_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)


    # ███    ███  ██████ ██████      ███████ ███████ ██████  ██    ██ ███████ ██████      ██████  ███████  ██████  ██ ███████ ████████ ██████  ██    ██ 
    # ████  ████ ██      ██   ██     ██      ██      ██   ██ ██    ██ ██      ██   ██     ██   ██ ██      ██       ██ ██         ██    ██   ██  ██  ██  
    # ██ ████ ██ ██      ██████      ███████ █████   ██████  ██    ██ █████   ██████      ██████  █████   ██   ███ ██ ███████    ██    ██████    ████   
    # ██  ██  ██ ██      ██               ██ ██      ██   ██  ██  ██  ██      ██   ██     ██   ██ ██      ██    ██ ██      ██    ██    ██   ██    ██    
    # ██      ██  ██████ ██          ███████ ███████ ██   ██   ████   ███████ ██   ██     ██   ██ ███████  ██████  ██ ███████    ██    ██   ██    ██    

    def create_lambda_role(self, project_name, ddbtbl_mcp_server_registry):
        # Create Lambda Permission
        role_lambda = iam.Role(self, 
            f"{project_name}-lambda_role",
            role_name=f"{project_name}-lambda_role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "inline_policy_loggroup": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["logs:CreateLogGroup"],
                            resources=[f"arn:aws:logs:*:{self.account}:log-group:*"]
                        )
                    ]
                ),
                "inline_policy_logstream": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                            resources=[f"arn:aws:logs:*:{self.account}:log-group:*:log-stream:*"]
                        )
                    ]
                ),
                "inline_policy_readwrite_dynamodb": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "dynamodb:PutItem", 
                                "dynamodb:DeleteItem", 
                                "dynamodb:UpdateItem",
                                "dynamodb:Scan",
                                "dynamodb:Query",
                                "dynamodb:GetItem",
                                "dynamodb:BatchWriteItem"
                            ],
                            resources=[
                                ddbtbl_mcp_server_registry.table_arn,
                            ]
                        )
                    ]
                ),
                "inline_policy_attach_vpc": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "ec2:CreateNetworkInterface",
                                "ec2:DescribeNetworkInterfaces",
                                "ec2:DeleteNetworkInterface",
                                "ec2:AssignPrivateIpAddresses",
                                "ec2:UnassignPrivateIpAddresses"
                            ],
                            resources=["*"]
                        )
                    ]
                ), 
            }
        )
        role_lambda.apply_removal_policy(RemovalPolicy.DESTROY)
        self.role_lambda = role_lambda


    def create_mcp_registry_datastore(self, project_name):
        # Create DynamoDB table for MCP Server Registry
        table_name = f"{project_name}-mcp-server-registry"
        ddbtbl_mcp_server_registry = dynamodb.Table(self, id=table_name,
            table_name=table_name,
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.DESTROY
        )
        CfnOutput(self, "DynamoDB table for MCP Server Registry", value=ddbtbl_mcp_server_registry.table_name)
        self.ddbtbl_mcp_server_registry = ddbtbl_mcp_server_registry


    def create_mcp_registry_api(self, project_name, role_lambda, ddbtbl_mcp_server_registry, vpc_agents):
        function_name=f"{project_name}-api-mcp-server-discovery"
        fn_api_mcp_server_discovery = _lambda.Function(self, function_name,
            function_name=function_name,
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="index.lambda_handler",
            code=_lambda.Code.from_asset("./lambda/mcp-server-discovery"),
            timeout=Duration.minutes(15),
            role=role_lambda,
            environment={
                'DDBTBL_MCP_SERVER_REGISTRY': ddbtbl_mcp_server_registry.table_name
            },
            tracing=_lambda.Tracing.ACTIVE,
            memory_size=1024
        )
        fn_api_mcp_server_discovery.apply_removal_policy(RemovalPolicy.DESTROY)

        api_key_secret = secretsmanager.Secret(
            self, f"{project_name}-api-key",
            description="API Key",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                password_length=32,  
                exclude_punctuation=True,  
                require_each_included_type=False  
            )
        )
        api_key_secret.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create API Gateway CloudWatch Role Permission
        role_api_gateway_cloudwatch = iam.Role(self, 
            f"{project_name}-api_gateway_cloudwatch",
            role_name=f"{project_name}-api_gateway_cloudwatch",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
            inline_policies={
                "inline_policy_loggroup": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["logs:CreateLogGroup", "logs:DescribeLogGroups"],
                            resources=[f"arn:aws:logs:*:{self.account}:log-group:*"]
                        )
                    ]
                ),
                "inline_policy_logstream": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents", "logs:GetLogEvents", "logs:FilterLogEvents"],
                            resources=[f"arn:aws:logs:*:{self.account}:log-group:*:log-stream:*"]
                        )
                    ]
                )
            }
        )
        role_api_gateway_cloudwatch.apply_removal_policy(RemovalPolicy.DESTROY)
        account = apigateway.CfnAccount(self, "ApiGatewayAccount", cloud_watch_role_arn=role_api_gateway_cloudwatch.role_arn)
        account.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create API Gateway
        apigateway_log_group = logs.LogGroup(self, f"{project_name}-API-Gateway-Prod-Log-Group", 
            log_group_name=f"/aws/apigateway/{project_name}-prod",
            removal_policy=RemovalPolicy.DESTROY,
        )
        apigateway_log_group.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create a security group for the VPC endpoint
        sg_api_vpc_endpoint = ec2.SecurityGroup(
            self, f"{project_name}-api-endpoint-security-group",
            security_group_name=f"{project_name}-api-endpoint-security-group",
            vpc=vpc_agents,
            description="Security group for API Gateway VPC endpoint"
        )
        sg_api_vpc_endpoint.add_ingress_rule(ec2.Peer.ipv4(vpc_agents.vpc_cidr_block), ec2.Port.tcp(443))
        sg_api_vpc_endpoint.add_ingress_rule(ec2.Peer.ipv4('10.1.0.0/16'), ec2.Port.tcp(443))
        sg_api_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Create a VPC endpoint for the API Gateway
        api_vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self, f"{project_name}-api-vpc-endpoint",
            vpc=vpc_agents,
            service=ec2.InterfaceVpcEndpointService(f"com.amazonaws.{self.region}.execute-api", 443),
            private_dns_enabled=True,
            security_groups=[sg_api_vpc_endpoint]
        )
        api_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Create API Gateway as PRIVATE
        api = apigateway.RestApi(
            self, f"{project_name}-api",
            endpoint_types=[apigateway.EndpointType.PRIVATE],
            policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        principals=[iam.AnyPrincipal()],
                        actions=["execute-api:Invoke"],
                        resources=["execute-api:/*"],
                        conditions={
                            "StringEquals": {
                                "aws:SourceVpce": api_vpc_endpoint.vpc_endpoint_id
                            }
                        }
                    )
                ]
            ),
            default_cors_preflight_options={
                "allow_origins": apigateway.Cors.ALL_ORIGINS,
                "allow_methods": apigateway.Cors.ALL_METHODS,
                "allow_headers": ["*"],
                "allow_credentials": True,
            },
            deploy_options=apigateway.StageOptions(
                access_log_destination=apigateway.LogGroupLogDestination(
                    apigateway_log_group
                ),
                access_log_format=apigateway.AccessLogFormat.json_with_standard_fields(
                    caller=True,http_method=True,ip=True,protocol=True,request_time=True,resource_path=True,response_length=True,status=True,user=True
                ),
                logging_level=apigateway.MethodLoggingLevel.ERROR,
                tracing_enabled=True
            ),   
        )
        api.apply_removal_policy(RemovalPolicy.DESTROY)
        
        api.add_request_validator(
            id=f"{project_name}-RestAPIRequestValidator",
            request_validator_name="RestAPIRequestValidator",
            validate_request_body=True,
            validate_request_parameters=True
        )
        """
        Below is the code for the alternative environment.
        """
        # Create a WAFv2 web ACL for API GATEWAY REST API
        web_acl_api = waf.CfnWebACL(self, f"{project_name}-waf-acl-api",
            scope="REGIONAL",
            default_action=waf.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name=f"{project_name}-waf-acl-api",
                sampled_requests_enabled=True
            )
        )
        """
        Up to this point, the code is for for my environment.
        """
        # Associate the WAFv2 web ACL with the API Gateway REST API
        waf.CfnWebACLAssociation(self, f"{project_name}-WAFAssociation-API",
            resource_arn=f"arn:aws:apigateway:{self.region}::/restapis/{api.rest_api_id}/stages/{api.deployment_stage.stage_name}",
            web_acl_arn="arn:aws:wafv2:us-east-1:976193252250:regional/webacl/Cov-Lz-Waf-standard-REGIONAL-DEFAULT/230f7e42-8b77-4007-8724-957bc741b311"  # web_acl_api.attr_arn
        )
        
        # Create /registry resource with Lambda proxy integration
        registry_resource = api.root.add_resource('registry')
        registry_resource.add_method('GET', apigateway.LambdaIntegration(fn_api_mcp_server_discovery), api_key_required=True)
        registry_resource.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create API key and usage plan
        api_key = api.add_api_key(f"{project_name}-apiKey", api_key_name=f"{project_name}-apiKey", value=api_key_secret.secret_value.unsafe_unwrap())
        api_key.apply_removal_policy(RemovalPolicy.DESTROY)

        usage_plan = api.add_usage_plan(
            f"{project_name}-apiUsagePlan",
            name=f"{project_name}-apiUsagePlan",
            api_stages=[apigateway.UsagePlanPerApiStage(api=api, stage=api.deployment_stage)],
        )
        usage_plan.add_api_key(api_key)
        usage_plan.apply_removal_policy(RemovalPolicy.DESTROY)
        
        self.api_key_secret = api_key_secret
        self.api_url = api.url
        self.api_vpc_endpoint = api_vpc_endpoint


    
    # ███████  ██████ ███████      ██████ ██      ██    ██ ███████ ████████ ███████ ██████  
    # ██      ██      ██          ██      ██      ██    ██ ██         ██    ██      ██   ██ 
    # █████   ██      ███████     ██      ██      ██    ██ ███████    ██    █████   ██████  
    # ██      ██           ██     ██      ██      ██    ██      ██    ██    ██      ██   ██ 
    # ███████  ██████ ███████      ██████ ███████  ██████  ███████    ██    ███████ ██   ██ 

    def create_ecs_cluster(self, project_name, vpc, vpc_name, internet_facing):
        # Create ECS Cluster
        cluster = ecs.Cluster(self, f"{project_name}-{vpc_name}-ecs-cluster", 
            cluster_name=f"{project_name}-{vpc_name}-ecs-cluster", 
            vpc=vpc, 
            container_insights=True
        )
        cluster.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Create an S3 bucket for NLB access logs with appropriate permissions
        access_logs_bucket = s3.Bucket(
            self, 
            f"{project_name}-{vpc_name}-nlb-logs",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
        )
        
        # Add bucket policy to allow ELB to write logs
        access_logs_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("delivery.logs.amazonaws.com")],
                actions=["s3:PutObject"],
                resources=[access_logs_bucket.arn_for_objects(f"AWSLogs/{self.account}/*")],
                conditions={
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            )
        )
        
        access_logs_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("delivery.logs.amazonaws.com")],
                actions=["s3:GetBucketAcl"],
                resources=[access_logs_bucket.bucket_arn]
            )
        )
        
        # Add policy to enforce SSL/TLS for all requests
        access_logs_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:*"],
                resources=[
                    access_logs_bucket.bucket_arn,
                    access_logs_bucket.arn_for_objects("*")
                ],
                conditions={
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            )
        )
        
        # Create an Internet-facing Network Load Balancer
        nlb = elbv2.NetworkLoadBalancer(
            self, f"{project_name}-{vpc_name}-nlb",
            load_balancer_name=f"{project_name}-{vpc_name}-nlb",
            vpc=vpc,
            internet_facing=internet_facing,
            deletion_protection=False
        )
        nlb.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Enable access logs using the built-in method
        nlb.log_access_logs(access_logs_bucket, f"{project_name}-{vpc_name}")
        
        return cluster, nlb


    # ███████  ██████ ███████     ███████ ███████ ██████  ██    ██ ██  ██████ ███████ 
    # ██      ██      ██          ██      ██      ██   ██ ██    ██ ██ ██      ██      
    # █████   ██      ███████     ███████ █████   ██████  ██    ██ ██ ██      █████   
    # ██      ██           ██          ██ ██      ██   ██  ██  ██  ██ ██      ██      
    # ███████  ██████ ███████     ███████ ███████ ██   ██   ████   ██  ██████ ███████ 

    def create_ecs_service(
            self,
            project_name,
            vpc,
            vpc_name,
            cluster,
            nlb,
            service_name,
            repository_name,
            image_tag,
            source_port,
            target_port,
            environ={},
            secret_arn=None):
        # # Build Docker images and push to ECR
        # image = ecr_assets.DockerImageAsset(self,
        #     f"{project_name}-{vpc_name}-{service_name}",
        #     directory=directory,
        #     platform=ecr_assets.Platform.LINUX_AMD64
        # )
        # Reference an existing ECR repository
        repository = ecr.Repository.from_repository_name(
            self, f"{project_name}-{vpc_name}-{service_name}",
            repository_name=repository_name
        )
        # repository = ecr.Repository.from_repository_attributes(
        #     self, f"{project_name}-{vpc_name}-{service_name}",
        #     repository_name=repository_name,
        #     repository_arn=f"arn:aws:ecr:{self.region}:{self.account}:repository/mcp-enterprise"
        # )

        # Create Security Group - VPC Endpoint
        service_security_group = ec2.SecurityGroup(
            self, f"{project_name}-{vpc_name}-{service_name}-security-group",
            security_group_name=f"{project_name}-{vpc_name}-{service_name}-security-group",
            vpc=vpc,
        )
        service_security_group.apply_removal_policy(RemovalPolicy.DESTROY)
        service_security_group.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), connection=ec2.Port.tcp(target_port))
        service_security_group.add_ingress_rule(ec2.Peer.ipv4('10.1.0.0/16'), connection=ec2.Port.tcp(target_port))

        # Create Log Group for ECS Task
        service_log_group = logs.LogGroup(self, f"{project_name}-{vpc_name}-{service_name}-loggroup", 
            log_group_name=f"/aws/ecs/{project_name}-{vpc_name}-{service_name}-loggroup",
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Define Task Definitions for both services
        task_definition = ecs.FargateTaskDefinition(
            self, f"{project_name}-{vpc_name}-{service_name}-taskdef",
            memory_limit_mib=8192,
            cpu=4096,
        )
        task_definition.add_to_task_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["bedrock:InvokeModel", 
                         "bedrock:InvokeModelWithResponseStream", 
                         "bedrock:CreateInferenceProfile",
                         "bedrock:GetInferenceProfile",
                         "bedrock:ListInferenceProfiles",
                         "bedrock:DeleteInferenceProfile"
                         ],
                resources=[
                    f"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
                    f"arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
                    f"arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
                    f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                ]
            )
        )
        task_definition.add_to_task_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["bedrock:InvokeInlineAgent"],
                resources=["*"] # required for inline agent 
            )
        )
        if secret_arn: 
            task_definition.add_to_task_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["secretsmanager:GetSecretValue"],
                resources=[secret_arn]
            )
        )
        
        container = task_definition.add_container(
            f"{project_name}-{vpc_name}-{service_name}-container",
            # image=ecs.ContainerImage.from_docker_image_asset(image),
            image=ecs.ContainerImage.from_ecr_repository(repository, tag=image_tag),
            logging=ecs.LogDriver.aws_logs(stream_prefix=project_name, log_group=service_log_group),
            environment=environ
        )
        container.add_port_mappings(ecs.PortMapping(container_port=target_port))
        container.add_to_execution_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["logs:CreateLogGroup"],
                resources=[f"arn:aws:logs:*:{self.account}:log-group:*"]
            )
        )
        container.add_to_execution_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[f"arn:aws:logs:*:{self.account}:log-group:*:log-stream:*"]
            )
        )
        
        # Create ECS Services with Auto Scaling enabled
        service = ecs.FargateService(
            self, f"{project_name}-{vpc_name}-{service_name}-service",
            cluster=cluster,
            task_definition=task_definition,
            desired_count=1,
            min_healthy_percent=100,
            security_groups=[service_security_group],
            
        )
        service.auto_scale_task_count(
            min_capacity=1,
            max_capacity=5
        ).scale_on_cpu_utilization(f"{project_name}-{vpc_name}-{service_name}-service-scaling", target_utilization_percent=50)
        service.apply_removal_policy(RemovalPolicy.DESTROY)

        # Add listeners and target groups for both services
        listener = nlb.add_listener(f"{project_name}-{vpc_name}-{service_name}-listener-{source_port}", port=source_port)
        listener.add_targets(f"{project_name}-{vpc_name}-{service_name}-targetgroup-service",
                              port=target_port,
                              targets=[service])
        listener.apply_removal_policy(RemovalPolicy.DESTROY)




    #  ██████ ██    ██ ███████ ████████  ██████  ███    ███     ██████  ███████ ███████  ██████  ██    ██ ██████   ██████ ███████ 
    # ██      ██    ██ ██         ██    ██    ██ ████  ████     ██   ██ ██      ██      ██    ██ ██    ██ ██   ██ ██      ██      
    # ██      ██    ██ ███████    ██    ██    ██ ██ ████ ██     ██████  █████   ███████ ██    ██ ██    ██ ██████  ██      █████   
    # ██      ██    ██      ██    ██    ██    ██ ██  ██  ██     ██   ██ ██           ██ ██    ██ ██    ██ ██   ██ ██      ██      
    #  ██████  ██████  ███████    ██     ██████  ██      ██     ██   ██ ███████ ███████  ██████   ██████  ██   ██  ██████ ███████ 
    def create_custom_resource(self, project_name, role_lambda, ddbtbl_mcp_server_registry, mcp_server_clusters):
        function_name = f"{project_name}-custom-populate-mcp-server-clusters"
        fn_custom_populate_mcp_server_clusters = _lambda.Function(self, function_name,
            function_name=function_name,
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="index.lambda_handler",
            code=_lambda.Code.from_asset("./lambda/custom/populate-mcp-server-clusters"),
            timeout=Duration.minutes(15),
            role=role_lambda,
            environment={
                'DDBTBL_NAME': ddbtbl_mcp_server_registry.table_name,
                'MCP_SERVER_CLUSTERS': json.dumps(mcp_server_clusters),
            },
            tracing=_lambda.Tracing.ACTIVE,
            memory_size=1024
        )
        fn_custom_populate_mcp_server_clusters.apply_removal_policy(RemovalPolicy.DESTROY)
        
        # Create Custom Resource IAM Permission
        role_custom_resource = iam.Role(self,
            f"{project_name}-custom_resource_role",
            role_name=f"{project_name}-custom_resource_role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "inline_policy_invoke_function": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["lambda:InvokeFunction"],
                            resources=[fn_custom_populate_mcp_server_clusters.function_arn]
                        )
                    ]
                ),
                "inline_policy_readwrite_dynamodb": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "dynamodb:PutItem", 
                                "dynamodb:DeleteItem", 
                                "dynamodb:UpdateItem",
                                "dynamodb:Scan",
                                "dynamodb:Query",
                                "dynamodb:GetItem",
                            ],
                            resources=[
                                ddbtbl_mcp_server_registry.table_arn,
                            ]
                        )
                    ]
                ),
            }
        )
        role_custom_resource.apply_removal_policy(RemovalPolicy.DESTROY)
    
        # Create Custom Resource
        cr_populate_mcp_server_clusters = cr.AwsCustomResource(
            self, "invoke-populate_mcp_server_clusters",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": fn_custom_populate_mcp_server_clusters.function_name,
                    "Payload": "{}"
                },
                physical_resource_id=cr.PhysicalResourceId.of("CustomResourceId")
            ),
            on_update=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": fn_custom_populate_mcp_server_clusters.function_name,
                    "Payload": "{}"
                },
                physical_resource_id=cr.PhysicalResourceId.of("deployment_time:"+ str(time.time()))
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
            ),
            role=role_custom_resource
        )


    # ██ ███    ██ ██ ████████ 
    # ██ ████   ██ ██    ██    
    # ██ ██ ██  ██ ██    ██    
    # ██ ██  ██ ██ ██    ██    
    # ██ ██   ████ ██    ██    

    def __init__(self,
            scope: Construct,
            construct_id: str,
            env: Environment,
            **kwargs) -> None:
        super().__init__(scope, construct_id, env=env, **kwargs)
        """
        Below is the code for the alternative environment.
        """
        # self.vpc_tools = ec2.Vpc.from_lookup(
        #     self, "ImportedVPCTools",
        #     vpc_id="vpc-02c3dba8c55ba9310"
        # )
        # self.vpc_agents = ec2.Vpc.from_lookup(
        #     self, "ImportedVPCAgents",
        #     vpc_id="vpc-064d086f628253eb1"
        # )
        """
        Up to this point, the code is for the alternative environment.
        """
        project_name = self.stack_name
        
        # Define MCP servers across various business domain
        trading_mcp_servers = [
            { "name": "trading-trade-allocation", "description": "Trade allocation functions: allocateTrade, validateTrade", "image_tag": "trade-allocation", "source_port": 10001, "target_port": 8000 },
            { "name": "trading-trade-execution", "description": "Trade execution functions: executeTrade, sendTradeDetails", "image_tag": "trade-execution", "source_port": 10002, "target_port": 8000 },
        ]
        compliance_mcp_servers = [
            { "name": "compliance-policy-enforcement", "description": "Policy enforcement functions: auditCompliance, monitorMarketAbuse, updateComplianceRules", "image_tag": "policy-enforcement", "source_port": 10003, "target_port": 8000 },
            { "name": "compliance-regulatory-reporting", "description": "Regulatory reporting functions: generateUTI, submitReport, trackReportingStatus", "image_tag": "regulatory-reporting", "source_port": 10004, "target_port": 8000 },
        ]
        operations_mcp_servers = [
            { "name": "operations-settlement", "description": "Operations functions: matchConfirmation, processSettlement  ", "image_tag": "settlement", "source_port": 10005, "target_port": 8000 },
        ]
        risk_mgmt_mcp_servers = [
            { "name": "risk-mgmt-risk-assessment", "description": "Risk assessment functions: calculateMarketRisk, performStressTest, evaluateLiquidityRisk", "image_tag": "risk-assessment", "source_port": 10006, "target_port": 8000 },
            { "name": "risk-mgmt-risk-monitoring", "description": "Risk monitoring functions: monitorRiskLimits, generateRiskReport, flagRiskBreaches", "image_tag": "risk-monitoring", "source_port": 10007, "target_port": 8000 },
        ]
        mcp_server_clusters = [trading_mcp_servers, compliance_mcp_servers, operations_mcp_servers, risk_mgmt_mcp_servers]
        
        
        # Create VPCs
        vpc_tools_name = "vpc-tools"
        vpc_agents_name = "vpc-agents"
        vpc_tools = self.create_vpc(project_name, vpc_tools_name)
        vpc_agents = self.create_vpc(project_name, vpc_agents_name)
        """
        Below is the code for the alternative environment.
        """
        # Referencing existing VPCs in the alternative environment.
        # vpc_tools = self.vpc_tools
        # vpc_agents = self.vpc_agents
        """
        Up to this point, the code is for the alternative environment.
        """
        
        # Create VPC Endpoints        
        self.create_default_vpc_endpoints(project_name, vpc_tools, vpc_tools_name)
        self.create_default_vpc_endpoints(project_name, vpc_agents, vpc_agents_name)

        # Create MCP Server Registry
        self.create_mcp_registry_datastore(project_name)
        self.create_lambda_role(project_name, self.ddbtbl_mcp_server_registry) 
        self.create_mcp_registry_api(project_name, self.role_lambda, self.ddbtbl_mcp_server_registry, vpc_agents)
        
        # Create MCP Infra - Cluster + NLB        
        mcp_cluster, mcp_nlb = self.create_ecs_cluster(project_name, vpc_tools, vpc_tools_name, False) # False for non Internet facing nlb
        
        # Create App infra
        app_cluster, app_nlb = self.create_ecs_cluster(project_name, vpc_agents, vpc_agents_name, False)
        
        endpoint_service = ec2.VpcEndpointService(
            self, f"{project_name}-mcp-vpcendpointservice",
            vpc_endpoint_service_load_balancers=[mcp_nlb],
            acceptance_required=False,
            allowed_principals=[iam.ArnPrincipal(f"arn:aws:iam::{self.account}:root")],
        )
        
        # Create Security Group - VPC Endpoint
        sg_mcp_vpc_endpoint = ec2.SecurityGroup(
            self, f"{project_name}-{vpc_agents_name}-endpoint-mcp-security-group",
            security_group_name=f"{project_name}-vpc-endpoint-mcp-security-group",
            vpc=vpc_agents,
        )
        sg_mcp_vpc_endpoint.apply_removal_policy(RemovalPolicy.DESTROY)
        sg_mcp_vpc_endpoint.add_ingress_rule(ec2.Peer.ipv4(vpc_agents.vpc_cidr_block), connection=ec2.Port.all_traffic())
        sg_mcp_vpc_endpoint.add_ingress_rule(ec2.Peer.ipv4('10.1.0.0/16'), connection=ec2.Port.all_traffic())

        # Create Interface VPC Endpoint to access PrivateLink to NLB
        interface_endpoint = ec2.InterfaceVpcEndpoint(
            self, f"{project_name}-mcp-interfaceendpoint",
            vpc=vpc_agents,
            service=ec2.InterfaceVpcEndpointService(endpoint_service.vpc_endpoint_service_name, 443),
            security_groups=[sg_mcp_vpc_endpoint]
        )        
        vpce_dns = Fn.select(0,interface_endpoint.vpc_endpoint_dns_entries)
        
        # Create MCP Servers
        for mcp_server_cluster in mcp_server_clusters:
            for mcp_server in mcp_server_cluster:
                self.create_ecs_service(
                    project_name,
                    vpc_tools,
                    vpc_tools_name,
                    mcp_cluster,
                    mcp_nlb,
                    mcp_server["name"],
                    "mcp-enterprise",
                    mcp_server["image_tag"],
                    mcp_server["source_port"],
                    mcp_server["target_port"]
                )

        # Create App service - streamlit
        self.create_ecs_service(
            project_name,
            vpc_agents,
            vpc_agents_name,
            app_cluster,
            app_nlb,
            "streamlit",
            "mcp-enterprise",
            "streamlit",
            80,
            8501,
            {
                "SECRET_ARN": self.api_key_secret.secret_arn,
                "MCP_SERVERS": '["operations-settlement", "compliance-policy-enforcement", "risk-mgmt-risk-monitoring", "trading-trade-allocation", "trading-trade-execution", "risk-mgmt-risk-assessment", "compliance-regulatory-reporting"]',
                "REGISTRY_API_ENDPOINT": self.api_url
            },
            self.api_key_secret.secret_arn
        )

        self.create_custom_resource(project_name,
            self.role_lambda,
            self.ddbtbl_mcp_server_registry,
            [ 
                {
                    "VPCE_DNS": vpce_dns,
                    "MCP_SERVERS": [
                        {
                            "id": mcp_server["name"],
                            "description": mcp_server["description"],
                            "port": mcp_server['source_port']
                        } for mcp_server in mcp_server_cluster
                    ]
                } for mcp_server_cluster in mcp_server_clusters
            ]
        )
        
        #  ██████  ██    ██ ████████ ██████  ██    ██ ████████ 
        # ██    ██ ██    ██    ██    ██   ██ ██    ██    ██    
        # ██    ██ ██    ██    ██    ██████  ██    ██    ██    
        # ██    ██ ██    ██    ██    ██      ██    ██    ██    
        #  ██████   ██████     ██    ██       ██████     ██    

        CfnOutput(self, "Streamlit NLB URL", value=f"http://{app_nlb.load_balancer_dns_name}", description="Streamlit NLB URL")
        # CfnOutput(self, "MCP NLB URL", value=f"http://{mcp_nlb.load_balancer_dns_name}", description="MCP NLB URL")
        # CfnOutput(self, "Interface Endpoint DNS", value=vpce_dns, description="Interface Endpoint DNS")
        # CfnOutput(self, "Secret Managers ARN", value=self.api_key_secret.secret_arn)
        # CfnOutput(self, "API URL", value=self.api_url)

        