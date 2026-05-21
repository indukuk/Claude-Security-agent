"""Mapping from Terraform resource types to canonical AWS CloudFormation types."""

TF_TO_CFN_TYPE = {
    # Compute
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_ecs_task_definition": "AWS::ECS::TaskDefinition",
    "aws_ecs_service": "AWS::ECS::Service",
    "aws_instance": "AWS::EC2::Instance",
    "aws_apprunner_service": "AWS::AppRunner::Service",

    # Data stores
    "aws_dynamodb_table": "AWS::DynamoDB::Table",
    "aws_rds_instance": "AWS::RDS::DBInstance",
    "aws_rds_cluster": "AWS::RDS::DBCluster",
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_elasticache_cluster": "AWS::ElastiCache::CacheCluster",
    "aws_secretsmanager_secret": "AWS::SecretsManager::Secret",
    "aws_ssm_parameter": "AWS::SSM::Parameter",
    "aws_redshift_cluster": "AWS::Redshift::Cluster",

    # Networking / Public
    "aws_api_gateway_rest_api": "AWS::ApiGateway::RestApi",
    "aws_apigatewayv2_api": "AWS::ApiGatewayV2::Api",
    "aws_lb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "aws_alb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "aws_cloudfront_distribution": "AWS::CloudFront::Distribution",

    # IAM
    "aws_iam_role": "AWS::IAM::Role",
    "aws_iam_policy": "AWS::IAM::Policy",
    "aws_iam_role_policy": "AWS::IAM::RolePolicy",
    "aws_iam_role_policy_attachment": "AWS::IAM::RolePolicyAttachment",
    "aws_iam_user": "AWS::IAM::User",

    # Auth
    "aws_cognito_user_pool": "AWS::Cognito::UserPool",
    "aws_cognito_user_pool_client": "AWS::Cognito::UserPoolClient",

    # Network infrastructure
    "aws_vpc": "AWS::EC2::VPC",
    "aws_subnet": "AWS::EC2::Subnet",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_security_group_rule": "AWS::EC2::SecurityGroupRule",
    "aws_nat_gateway": "AWS::EC2::NatGateway",
    "aws_internet_gateway": "AWS::EC2::InternetGateway",

    # Monitoring
    "aws_cloudwatch_log_group": "AWS::Logs::LogGroup",
    "aws_cloudwatch_metric_alarm": "AWS::CloudWatch::Alarm",
    "aws_cloudtrail": "AWS::CloudTrail::Trail",

    # KMS
    "aws_kms_key": "AWS::KMS::Key",
    "aws_kms_alias": "AWS::KMS::Alias",

    # SNS/SQS
    "aws_sns_topic": "AWS::SNS::Topic",
    "aws_sqs_queue": "AWS::SQS::Queue",
}

COMPUTE_TYPES = {
    "AWS::Lambda::Function", "AWS::ECS::TaskDefinition",
    "AWS::EC2::Instance", "AWS::AppRunner::Service",
}

DATA_TYPES = {
    "AWS::DynamoDB::Table", "AWS::RDS::DBInstance", "AWS::RDS::DBCluster",
    "AWS::S3::Bucket", "AWS::ElastiCache::CacheCluster",
    "AWS::SecretsManager::Secret", "AWS::SSM::Parameter",
    "AWS::Redshift::Cluster",
}

PUBLIC_TYPES = {
    "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::CloudFront::Distribution",
}
