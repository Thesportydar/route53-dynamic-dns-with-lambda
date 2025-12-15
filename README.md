# Serverless Dynamic DNS

## Cloud Development Kit (CDK) Deployment

This repository contains all the required code to deploy a Serverless Dynamic DNS solution in AWS.

![Architecture diagram](images/architecture.png?raw=true "Architecture")

CDK will manage the deployment of the following resources:

- Lambda Function
- DynamoDB Table
- Lambda Function IAM Role
- **CloudFront Distribution** (for HTTP port 80 support)
- **Optional**: ACM Certificate and Route53 Alias (when using custom domain)

The Lambda function will be configured with a FunctionURL for PUBLIC invocation.
The Lambda IAM Role will have the following permissions in addition to the standard Lambda role:

- READ (all actions) for the deployed DynamoDB Table
- Route53 List and Change record set

## CloudFront Distribution for HTTP Port 80 Support

This solution includes a CloudFront distribution to enable **HTTP port 80** support for legacy routers and DDNS clients that don't support HTTPS. Many older routers (like Huawei HG8245U) and some DDNS clients can only use HTTP on port 80.

### How It Works

- **Client → CloudFront**: HTTP (port 80) or HTTPS (port 443)
- **CloudFront → Lambda**: HTTPS only (secure internal communication)
- **Caching**: Disabled (critical for DDNS to work correctly with real-time IP updates)

### Deployment Options

You can deploy the stack in two ways:

#### 1. Default Deployment (CloudFront Generic Domain)

```bash
cdk deploy
```

This creates a CloudFront distribution with a generic AWS domain like `d1234abcd5678.cloudfront.net`.

**Use this domain for your DDNS updates:**
- HTTP: `http://d1234abcd5678.cloudfront.net/nic/update`
- HTTPS: `https://d1234abcd5678.cloudfront.net/nic/update`

#### 2. Custom Domain Deployment (Optional)

```bash
cdk deploy -c ddns_domain=ddns.yourdomain.com
```

This configures CloudFront with your custom domain and automatically:
1. Looks up the Route53 hosted zone for `yourdomain.com`
2. Creates or finds an ACM wildcard certificate (`*.yourdomain.com`) in `us-east-1`
3. Configures CloudFront with the custom domain and certificate
4. Creates a Route53 A record (alias) pointing to the CloudFront distribution

**Requirements for custom domain:**
- Hosted zone for `yourdomain.com` must already exist in Route53
- The stack will automatically create an ACM certificate in `us-east-1` if one doesn't exist
- Certificate validation happens via DNS (automatic with Route53)

**Use your custom domain for DDNS updates:**
- HTTP: `http://ddns.yourdomain.com/nic/update`
- HTTPS: `https://ddns.yourdomain.com/nic/update`

## Deployment Instructions

To deploy the CDK stack to an AWS account is suggested to use a CloudShell session: 
https://docs.aws.amazon.com/cloudshell/latest/userguide/welcome.html

Clone this repository:
>` git clone https://github.com/awslabs/route53-dynamic-dns-with-lambda.git`

Install Python requirements:

> `pip install -r requirements.txt`

To test DNS record update on the CloudShell session `perl-Digest-SHA` must be installed to add the `shasum` package.
 ```
 sudo yum update
 sudo yum install perl-Digest-SHA
 ```

If CDK was never used in the deployment account bootstrap it for CDK:
https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html

> `cdk bootstrap`

If you get an error about CDK CLI not being up to date run the following:
> `sudo npm install -g aws-cdk`

> Then retry `cdk bootstrap`

Deploy the stack (choose one option):

**Option 1: Deploy with CloudFront generic domain (default)**
```bash
cdk deploy
```

**Option 2: Deploy with custom domain**
```bash
cdk deploy -c ddns_domain=ddns.yourdomain.com
```

After deployment completes, the stack outputs will show:
- `CloudFrontDomain` (or `CustomDomain` if using custom domain)
- `DdnsUpdateUrl` - The complete URL for DDNS updates

## Configuration

### Route53 Hosted zone and record set

A Route53 Hosted Zone (https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zones-working-with.html) is required to update the hostname, the Hosted Zone ID must be included in the configuration and stored in the deployed DynamoDB table using the hostname as key and in the _data_ attribute the following JSON object ([Sample configuration](www.example.com.json)):

```JSON
{
  "route_53_zone_id": "XYZ1234567890",
  "route_53_record_ttl": 60,
  "shared_secret": "SHARED_SECRET_1"
}
```

To facilitate the configuration process execute the included [newrecord.py](newrecord.py) Python script.
(Execute this script for each hostname to be configured)

> `python3 newrecord.py`

The script will verify CDK stack deployment is deployed, if not it will return:

```
Dyndns stack not found, ensure the right AWS CLI profile is being used.
```

If the stack is present but deployment is not completed it will return:

```
Stack not yet deployed try again in few minutes
```

if the stack is successfully deployed the script will prompt:

```
Hosted zone name, i.e. example.com
```

Type the Hosted Zone name:

> `example.com`

If the Hosted Zone does not exist a confirmation prompt will ask for confirmation to create a new one:

```bash
Hosted zone example.com not found.
Do you want to create it? (y/n)
```

> Type `y` to continue or `n` to abort.

In the next steps the script will prompt for:

- Hostname (default www. i.e.: www.example.com)
- TTL (default 60)

If the default configuration is correct, just press `Enter` to continue, if not for each prompt type the required settings, i.e. `test.example.com` for the hostname etc...

### Shared secret

The next prompt will ask to type a shared secret and confirm it. The shared secret will be saved in the JSON configuration and hashed when invoking the Lambda function. Lambda will read the shared secret from DynamoDB and hash it to validate the request is authorized. For example here `SHARED_SECRET_123` is provided.

```bash
Enter the secret for the new record set.
SHARED_SECRET_123
Confirm the secret:
SHARED_SECRET_123
```

The script will summarise the configuration and prompt to confirm:

```bash
##############################################
#                                            #
# The following configuration will be saved: #
#                                            #
  Host name:  www.example.com
  Hosted zone id: ZYZ12345678901234
  Record set TTL: 60
  Secret: SHARED_SECRET_123
#                                            #
#      do you want to continue? (y/n)        #
#                                            #
##############################################
```

Type `n` to abort if anything is incorrect.

> If a Hosted Zone was created during the configuration, a prompt will ask confirmation to delete the created Hosted Zone:

Type `y` to confirm and save the configuration:

```
#####################################################
#                                                   #
# The Serverless Dynamic DNS solution is now ready. #
#                                                   #
#####################################################

www.example.com can be updated with the following command:
./dyndns.sh -m set -u https://xyz1234567890xyz.lambda-url.eu-west-1.on.aws/ -h www.example.com -s SHARED_SECRET_123
```

The [dyndns.sh](dyndns.sh) bash script provided, can be use to invoke the deployed Lambda URL. This can be run via a CRON or SystemD timer to periodically update your hostname.
_newrecord.py_ provides all the flags to successfully run the script:

```bash
./dyndns.sh -m set -u https://xyz1234567890xyz.lambda-url.eu-west-1.on.aws/ -h www.example.com -s SHARED_SECRET_123
```

More information on how to invoke the Lambda URL can be found here: [invocation.md](invocation.md)

## Router and Device Configuration (DynDNS Protocol)

This solution supports the standard DynDNS protocol, allowing direct integration with routers and network devices.

**Important: Use the CloudFront domain** (or custom domain) from the stack outputs, not the Lambda URL directly. CloudFront enables HTTP port 80 support for legacy devices.

### Quick Setup

After running `newrecord.py`, configure your router's Dynamic DNS settings:

#### For Modern Routers (HTTPS Support)

- **Service/Provider**: Custom or DynDNS
- **Server/Hostname**: CloudFront domain from stack outputs (e.g., `d1234abcd5678.cloudfront.net` or `ddns.yourdomain.com`)
- **Protocol**: HTTPS
- **Port**: 443
- **Path/URI**: `/nic/update`
- **Username**: Your full hostname (e.g., `home.example.com`)
- **Password**: Your shared secret

#### For Legacy Routers (HTTP Only)

Many legacy routers only support HTTP on port 80:

- **Service/Provider**: Custom or DynDNS
- **Server/Hostname**: CloudFront domain from stack outputs (e.g., `d1234abcd5678.cloudfront.net` or `ddns.yourdomain.com`)
- **Protocol**: HTTP
- **Port**: 80
- **Path/URI**: `/nic/update`
- **Username**: Your full hostname (e.g., `home.example.com`)
- **Password**: Your shared secret

**Example legacy routers that require HTTP:**
- Huawei HG8245U
- Older TP-Link models
- Some ISP-provided routers

### Testing Your Configuration

Test with curl to verify both HTTP and HTTPS work:

```bash
# Get the CloudFront domain from stack outputs
CLOUDFRONT_DOMAIN=$(aws cloudformation describe-stacks --stack-name DyndnsStack --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontDomain`].OutputValue' --output text)

# Test HTTP (port 80) - for legacy routers
curl -v "http://$CLOUDFRONT_DOMAIN/nic/update?hostname=home.example.com" \
  -u "home.example.com:SHARED_SECRET_123"

# Test HTTPS (port 443) - for modern routers
curl -v "https://$CLOUDFRONT_DOMAIN/nic/update?hostname=home.example.com" \
  -u "home.example.com:SHARED_SECRET_123"

# Expected responses:
# - good <ip-address>  (IP was updated)
# - nochg <ip-address> (IP unchanged)
```

### Supported Devices

This solution works with any device supporting the DynDNS protocol:
- Consumer routers (TP-Link, ASUS, Netgear, etc.)
- pfSense, OPNsense
- MikroTik RouterOS
- DD-WRT, OpenWrt
- UniFi Security Gateway

For detailed configuration guides for specific devices, see [DYNDNS.md](DYNDNS.md)
