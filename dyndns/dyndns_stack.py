import aws_cdk as cdk
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_lambda as lambda_
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_iam as iam
import aws_cdk.aws_cloudfront as cloudfront
import aws_cdk.aws_cloudfront_origins as origins
import aws_cdk.aws_certificatemanager as acm
import aws_cdk.aws_route53 as route53
import aws_cdk.aws_route53_targets as targets
from cdk_nag import AwsSolutionsChecks, NagSuppressions, NagPackSuppression

class DyndnsStack(cdk.Stack):

    def __init__(self, scope: cdk.App, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
     
        
        #Create dynamoDB table
        table = dynamodb.Table(self, "dyndns_db",
            partition_key=dynamodb.Attribute(name="hostname", type=dynamodb.AttributeType.STRING),
            removal_policy=cdk.RemovalPolicy.DESTROY,
            point_in_time_recovery=True,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST
        )
        
        #Create Lambda role
        fn_role = iam.Role(self, "dyndns_fn_role",
            assumed_by = iam.ServicePrincipal("lambda.amazonaws.com"),
            description = "DynamicDNS Lambda role",
            inline_policies = {
                'r53': iam.PolicyDocument(
                    statements = [
                        iam.PolicyStatement(
                            effect = iam.Effect.ALLOW,
                            resources = [
                                "*"
                            ],
                          actions = [
                                "route53:ChangeResourceRecordSets","route53:ListResourceRecordSets"
                            ]
                        )
                    ],
                ),
                'cw': iam.PolicyDocument(
                    statements = [
                        iam.PolicyStatement(
                            effect = iam.Effect.ALLOW,
                            resources = [
                                "*"
                            ],
                          actions = [
                                "logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"
                            ]
                        )
                    ],
                )
            }
        ) 


        fn = lambda_.Function(self, "dyndns_fn",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.ARM_64,
            handler="index.lambda_handler",
            code=lambda_.Code.from_asset("lambda"),
            role=fn_role,
            timeout=cdk.Duration.seconds(8),
            #Provide DynammoDB table name as enviroment variable
            environment={
                "ddns_config_table":table.table_name
            }
        )            

        #Create FunctionURL for invocation - principal will be set to * as it required for invocation from any HTTP client
        lambda_fn = fn.add_function_url(
            #Allow unauthenticated access
            auth_type=lambda_.FunctionUrlAuthType.NONE,
            #Set CORS for any source
            cors=lambda_.FunctionUrlCorsOptions(
                allowed_origins=["*"]
            )
        )

        #Give lambda permissions to read DynamoDB table
        table.grant_read_data(fn)
        
        # Extract the domain from the Lambda Function URL (remove https:// and trailing /)
        lambda_url_domain = cdk.Fn.select(2, cdk.Fn.split("/", lambda_fn.url))
        
        # Create CloudFront distribution for HTTP port 80 support
        # This allows legacy routers that only support HTTP to use the DDNS service
        
        # Check if custom domain is provided via CDK context
        ddns_domain = self.node.try_get_context("ddns_domain")
        
        certificate = None
        hosted_zone = None
        
        if ddns_domain:
            # Validate domain format (must have at least subdomain.domain.tld)
            domain_parts = ddns_domain.split(".")
            if len(domain_parts) < 3:
                raise ValueError(
                    f"Invalid ddns_domain format: {ddns_domain}. "
                    "Must be in format subdomain.domain.tld (e.g., ddns.example.com) "
                    "with at least 3 parts."
                )
            
            # Extract base domain (last two parts: domain.tld)
            base_domain = ".".join(domain_parts[-2:])
            # Extract subdomain (all parts except last two)
            subdomain = ".".join(domain_parts[:-2])
            
            # Lookup the hosted zone
            try:
                hosted_zone = route53.HostedZone.from_lookup(
                    self, "Zone",
                    domain_name=base_domain
                )
            except Exception as e:
                raise ValueError(
                    f"Hosted zone for {base_domain} not found. "
                    f"Please create the hosted zone in Route53 first. Error: {str(e)}"
                )
            
            # Try to find existing wildcard certificate in us-east-1
            # CloudFront requires certificates to be in us-east-1
            wildcard_domain = f"*.{base_domain}"
            
            # Create certificate in us-east-1 with DNS validation
            # If a certificate already exists for the wildcard domain, this will reference it
            certificate = acm.Certificate(
                self, "Certificate",
                domain_name=wildcard_domain,
                validation=acm.CertificateValidation.from_dns(hosted_zone),
                # CloudFront requires certificates in us-east-1
                region="us-east-1"
            )
        
        # Configure CloudFront distribution
        distribution_props = {
            "comment": "DDNS update endpoint with HTTP support for legacy routers",
            "default_behavior": cloudfront.BehaviorOptions(
                origin=origins.HttpOrigin(
                    lambda_url_domain,
                    protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.ALLOW_ALL,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
                compress=False
            )
        }
        
        # Add custom domain configuration if provided
        if ddns_domain and certificate:
            distribution_props["domain_names"] = [ddns_domain]
            distribution_props["certificate"] = certificate
        
        distribution = cloudfront.Distribution(
            self, "Distribution",
            **distribution_props
        )
        
        # Suppress CDK NAG warnings for CloudFront
        # These are expected for a public DDNS service
        NagSuppressions.add_resource_suppressions(
            construct=distribution,
            suppressions=[
                NagPackSuppression(
                    id='AwsSolutions-CFR1',
                    reason='DDNS service needs to be globally accessible for users worldwide'
                ),
                NagPackSuppression(
                    id='AwsSolutions-CFR2',
                    reason='DDNS updates are authenticated via shared secret in DynamoDB, WAF not required'
                ),
                NagPackSuppression(
                    id='AwsSolutions-CFR3',
                    reason='Access logging not required for this simple DDNS update endpoint'
                ),
                NagPackSuppression(
                    id='AwsSolutions-CFR4',
                    reason='Using default CloudFront certificate for generic distribution, custom domain uses ACM cert with modern TLS'
                )
            ]
        )
        
        # Create Route53 A record alias if custom domain is configured
        if ddns_domain and hosted_zone:
            route53.ARecord(
                self, "DdnsAlias",
                zone=hosted_zone,
                record_name=subdomain,
                target=route53.RecordTarget.from_alias(
                    targets.CloudFrontTarget(distribution)
                )
            )
        
        # CloudFormation Outputs
        if ddns_domain:
            cdk.CfnOutput(
                self, "CustomDomain",
                value=ddns_domain,
                description="Custom domain for DDNS updates"
            )
            cdk.CfnOutput(
                self, "DdnsUpdateUrl",
                value=f"http://{ddns_domain}/nic/update",
                description="DDNS update endpoint URL"
            )
        else:
            cdk.CfnOutput(
                self, "CloudFrontDomain",
                value=distribution.distribution_domain_name,
                description="CloudFront domain for DDNS updates (supports HTTP port 80)"
            )
            cdk.CfnOutput(
                self, "DdnsUpdateUrl",
                value=f"http://{distribution.distribution_domain_name}/nic/update",
                description="DDNS update endpoint URL"
            )

        #Suppress AwsSolutions-IAM5 triggered by Resources::*
        NagSuppressions.add_resource_suppressions(
            construct= fn_role,
            suppressions=[
                NagPackSuppression(
                    id = 'AwsSolutions-IAM5',
                    reason="""
                    Lambda role created at line 29 has 2 inline policies allowing access to Route53 and CloudWatch. 
                    Route53 resources are set to "*" as the function will need to access any hosted zone.
                    CloudWatch resources are set to "*" to avoid having to specify a Logging group and consume the default one deployed by CDK.
                    """
                )
            ]
        )
