# DynDNS Protocol Support - Router Configuration Guide

## Introduction

This serverless dynamic DNS solution supports the standard DynDNS protocol, making it compatible with a wide range of routers and network devices. You can configure your router to automatically update your DNS records without needing to run scripts or scheduled tasks.

### CloudFront Distribution for HTTP Support

The solution includes a **CloudFront distribution** that provides:
- **HTTP port 80 support** for legacy routers that don't support HTTPS
- **HTTPS port 443** for modern devices (recommended)
- Secure communication to the Lambda backend (always HTTPS)
- No caching (ensures real-time DDNS updates work correctly)

**Why CloudFront?** Lambda Function URLs only support HTTPS (port 443), but many legacy routers and DDNS clients can only use HTTP on port 80. CloudFront solves this by accepting HTTP/HTTPS from clients while maintaining secure HTTPS communication with Lambda.

**Getting Your CloudFront Domain:**
After deploying the stack with `cdk deploy`, check the CloudFormation outputs:
```bash
aws cloudformation describe-stacks --stack-name DyndnsStack --query 'Stacks[0].Outputs'
```

You'll see either:
- `CloudFrontDomain`: Generic CloudFront domain (e.g., `d1234abcd5678.cloudfront.net`)
- `CustomDomain`: Your custom domain if deployed with `-c ddns_domain=ddns.example.com`

## How It Works

The DynDNS protocol is a simple HTTP-based protocol that allows devices to update DNS records by making a GET request to a specific endpoint with HTTP Basic Authentication. When your router detects an IP address change, it automatically sends an update request to the Lambda function, which updates your Route53 DNS record.

## General Configuration Parameters

Regardless of which device you're using, you'll need these values (obtained from CDK stack outputs after deployment):

| Parameter | Value | Example |
|-----------|-------|---------|
| **Service/Provider** | Custom or DynDNS | Custom |
| **Server/Hostname** | CloudFront domain from stack outputs | `d1234abcd5678.cloudfront.net` or `ddns.example.com` |
| **Protocol** | HTTPS (modern) or HTTP (legacy) | HTTPS or HTTP |
| **Port** | 443 (HTTPS) or 80 (HTTP) | 443 or 80 |
| **Path/URI** | `/nic/update` | `/nic/update` |
| **Username** | Your hostname | `home.example.com` |
| **Password** | Your shared secret | `SHARED_SECRET_123` |

**Important Notes:**
- **Always use the CloudFront domain** from the stack outputs (either the generic CloudFront domain or your custom domain if configured)
- **For legacy routers that only support HTTP**: Use `http://` and port `80`
- **For modern routers with HTTPS support**: Use `https://` and port `443` (recommended)
- CloudFront enables both HTTP and HTTPS access while maintaining secure HTTPS communication with the Lambda backend

## Device-Specific Configuration Guides

### TP-Link Routers

1. Log in to your TP-Link router's web interface
2. Navigate to **Advanced** → **Network** → **Dynamic DNS**
3. Click **Add** or enable Dynamic DNS
4. Configure the following:
   - **Service Provider**: Select "NO-IP" or "Custom" (if available)
   - **Domain Name**: Enter your hostname (e.g., `home.example.com`)
   - **Username**: Enter your hostname (e.g., `home.example.com`)
   - **Password**: Enter your shared secret
   - **Server Address** (if available): Enter your CloudFront domain (e.g., `d1234abcd5678.cloudfront.net/nic/update`)
   - **Port**: 80 (HTTP) or 443 (HTTPS) depending on router support
5. Click **Save** and then **Login** or **Connect**

**Note**: Some TP-Link models only support HTTP on port 80. If "Custom" is not available, you may need to use the dyndns.sh script instead.

### ASUS Routers (Including Merlin Firmware)

1. Log in to your ASUS router's web interface
2. Navigate to **Advanced Settings** → **WAN** → **DDNS**
3. Configure the following:
   - **Enable DDNS Client**: Yes
   - **Server**: Select "Custom"
   - **Hostname**: Enter your hostname (e.g., `home.example.com`)
   - **Username**: Enter your hostname (e.g., `home.example.com`)
   - **Password**: Enter your shared secret
   - **Server Address** (if available): Enter the full URL with your CloudFront domain: `https://d1234abcd5678.cloudfront.net/nic/update?hostname=home.example.com&myip=` (or use HTTP if HTTPS not supported)
4. Click **Apply**

**For Merlin Firmware**, you can use the Custom DDNS with the following settings:
- **Server**: Your CloudFront domain (e.g., `d1234abcd5678.cloudfront.net`)
- **Query Path**: `/nic/update?hostname=@HOST@&myip=@IP@`

### Netgear Routers

1. Log in to your Netgear router's web interface
2. Navigate to **Advanced** → **Dynamic DNS**
3. Select **Use a Dynamic DNS Service**: Yes
4. Configure the following:
   - **Service Provider**: Select "No-IP.com" or custom option if available
   - **Hostname**: Enter your hostname (e.g., `home.example.com`)
   - **Username**: Enter your hostname (e.g., `home.example.com`)
   - **Password**: Enter your shared secret
5. Click **Apply**

**Note**: Netgear routers may have limited custom DDNS support. Newer models with ReadyGEAR OS offer better custom DDNS configuration.

### pfSense

1. Log in to your pfSense web interface
2. Navigate to **Services** → **Dynamic DNS**
3. Click **Add** to create a new Dynamic DNS entry
4. Configure the following:
   - **Service Type**: Select "Custom"
   - **Interface**: Select your WAN interface
   - **Hostname**: Enter your hostname (e.g., `home.example.com`)
   - **Verbose logging**: Check if you want detailed logs
   - **Username**: Enter your hostname (e.g., `home.example.com`)
   - **Password**: Enter your shared secret
   - **Server**: Enter your CloudFront domain (e.g., `d1234abcd5678.cloudfront.net`)
   - **Update URL**: `/nic/update?hostname=%h&myip=%i`
5. Click **Save**

The %h will be replaced with your hostname and %i with your IP address.

### OPNsense

1. Log in to your OPNsense web interface
2. Navigate to **Services** → **Dynamic DNS**
3. Click **Add** to create a new Dynamic DNS entry
4. Configure the following:
   - **Service**: Select "Custom"
   - **Interface**: Select your WAN interface
   - **Hostname**: Enter your hostname (e.g., `home.example.com`)
   - **Username**: Enter your hostname (e.g., `home.example.com`)
   - **Password**: Enter your shared secret
   - **Server**: Enter your CloudFront domain (e.g., `d1234abcd5678.cloudfront.net`)
   - **Update URL**: `/nic/update?hostname=%h&myip=%i`
5. Check **Enable**
6. Click **Save**

### MikroTik RouterOS

MikroTik RouterOS supports custom DDNS through its scripting feature:

1. Log in to your MikroTik router via Winbox or SSH
2. Navigate to **System** → **Scripts**
3. Click **Add New** and create a script with the following content:

```routeros
:local username "home.example.com"
:local password "SHARED_SECRET_123"
:local hostname "home.example.com"
:local cloudfrontdomain "d1234abcd5678.cloudfront.net"

:local ipaddr [/ip address get [find interface="ether1"] address]
:set ipaddr [:pick $ipaddr 0 [:find $ipaddr "/"]]

/tool fetch mode=https url="https://$cloudfrontdomain/nic/update?hostname=$hostname&myip=$ipaddr" http-method=get user=$username password=$password dst-path=dyndns-result.txt

:log info "DDNS update completed for $hostname with IP $ipaddr"
```

4. Replace the values:
   - `username`: Your hostname
   - `password`: Your shared secret
   - `hostname`: Your hostname
   - `cloudfrontdomain`: Your CloudFront domain from stack outputs
   - `interface="ether1"`: Your WAN interface name

5. Save the script with a name like "ddns-update"
6. Navigate to **System** → **Scheduler**
7. Click **Add New** and configure:
   - **Name**: ddns-updater
   - **Start Time**: startup
   - **Interval**: 00:05:00 (5 minutes)
   - **On Event**: ddns-update
8. Click **OK**

### DD-WRT

1. Log in to your DD-WRT web interface
2. Navigate to **Setup** → **DDNS**
3. Configure the following:
   - **DDNS Service**: Select "Custom"
   - **Hostname**: Enter your hostname (e.g., `home.example.com`)
   - **Username**: Enter your hostname (e.g., `home.example.com`)
   - **Password**: Enter your shared secret
   - **URL**: `https://d1234abcd5678.cloudfront.net/nic/update?hostname=@HOST@&myip=@IP@` (replace with your CloudFront domain)
4. Click **Save** and then **Apply Settings**

The @HOST@ and @IP@ placeholders will be automatically replaced by DD-WRT.

**Note**: If your DD-WRT version doesn't support HTTPS, use `http://` instead.

### OpenWrt

OpenWrt uses the `ddns-scripts` package for dynamic DNS updates:

1. SSH into your OpenWrt router or use the LuCI web interface
2. Install the required packages (if not already installed):
   ```bash
   opkg update
   opkg install ddns-scripts
   opkg install luci-app-ddns
   ```

3. Navigate to **Services** → **Dynamic DNS** in the LuCI web interface
4. Click **Add** to create a new service
5. Configure the following:
   - **DDNS Service provider**: Select "custom"
   - **Hostname**: Enter your hostname (e.g., `home.example.com`)
   - **Username**: Enter your hostname (e.g., `home.example.com`)
   - **Password**: Enter your shared secret
   
6. Switch to the **Advanced Settings** tab:
   - **Update URL**: `https://d1234abcd5678.cloudfront.net/nic/update?hostname=[DOMAIN]&myip=[IP]` (replace with your CloudFront domain)
   - **Optional Encoded Parameters**: Leave empty
   - **Use HTTP Secure**: Checked

7. Save and enable the configuration

Alternatively, you can edit the configuration file directly:

```bash
vi /etc/config/ddns
```

Add a new section:

```
config service 'aws_cloudfront_ddns'
    option enabled '1'
    option service_name 'custom'
    option use_https '1'
    option cacert '/etc/ssl/certs'
    option domain 'home.example.com'
    option username 'home.example.com'
    option password 'SHARED_SECRET_123'
    option update_url 'https://d1234abcd5678.cloudfront.net/nic/update?hostname=[DOMAIN]&myip=[IP]'
    option ip_source 'web'
    option ip_url 'https://api.ipify.org'
    option check_interval '10'
    option check_unit 'minutes'
```

Replace `d1234abcd5678.cloudfront.net` with your actual CloudFront domain from the stack outputs.

Then restart the DDNS service:
```bash
/etc/init.d/ddns restart
```

### UniFi Security Gateway / Dream Machine

UniFi devices can be configured through the UniFi Controller or via SSH:

#### Method 1: UniFi Controller (Limited Support)

The UniFi Controller has limited DDNS provider options. For custom DDNS, you'll need to use SSH configuration.

#### Method 2: SSH Configuration

1. SSH into your UniFi device
2. Create a script file:

```bash
vi /config/scripts/post-config.d/update-ddns.sh
```

3. Add the following content:

```bash
#!/bin/sh

HOSTNAME="home.example.com"
SECRET="SHARED_SECRET_123"
CLOUDFRONT_DOMAIN="d1234abcd5678.cloudfront.net"

# Get current WAN IP
WAN_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

# Update DDNS using curl
curl -s -u "${HOSTNAME}:${SECRET}" \
  "https://${CLOUDFRONT_DOMAIN}/nic/update?hostname=${HOSTNAME}&myip=${WAN_IP}"
```

Replace `d1234abcd5678.cloudfront.net` with your actual CloudFront domain from the stack outputs.

4. Make the script executable:
```bash
chmod +x /config/scripts/post-config.d/update-ddns.sh
```

5. Create a cron job to run the script periodically:
```bash
vi /etc/cron.d/ddns-update
```

6. Add the following line to run every 5 minutes:
```
*/5 * * * * root /config/scripts/post-config.d/update-ddns.sh > /dev/null 2>&1
```

7. The script will run on boot and every 5 minutes.

**Note**: This configuration may be lost after firmware updates. Use the UniFi OS update scripts feature if available on Dream Machine Pro.

## Testing Your Configuration

Before configuring your router, test the endpoint manually to ensure it's working correctly.

### Using curl

First, get your CloudFront domain from the stack outputs:

```bash
CLOUDFRONT_DOMAIN=$(aws cloudformation describe-stacks --stack-name DyndnsStack --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontDomain`].OutputValue' --output text)
echo "CloudFront Domain: $CLOUDFRONT_DOMAIN"
```

Then test both HTTP and HTTPS:

```bash
# Test with HTTPS (port 443) - recommended
curl -v "https://$CLOUDFRONT_DOMAIN/nic/update?hostname=home.example.com&myip=1.2.3.4" \
  -u "home.example.com:SHARED_SECRET_123"

# Test with HTTP (port 80) - for legacy routers
curl -v "http://$CLOUDFRONT_DOMAIN/nic/update?hostname=home.example.com&myip=1.2.3.4" \
  -u "home.example.com:SHARED_SECRET_123"
```

**Expected successful responses:**

- `good 1.2.3.4` - Update successful, IP was changed to 1.2.3.4
- `nochg 1.2.3.4` - IP address already matches, no change needed

**Expected error responses:**

- `badauth` - Authentication failed (wrong username or password)
- `notfqdn` - Invalid hostname format
- `nohost` - Hostname not found in configuration
- `911` - Server error (check Lambda logs)

### Testing IP Change Detection

First request (sets IP):
```bash
curl "https://$CLOUDFRONT_DOMAIN/nic/update?hostname=home.example.com&myip=1.2.3.4" \
  -u "home.example.com:SHARED_SECRET_123"
```
Response: `good 1.2.3.4`

Second request (same IP):
```bash
curl "https://$CLOUDFRONT_DOMAIN/nic/update?hostname=home.example.com&myip=1.2.3.4" \
  -u "home.example.com:SHARED_SECRET_123"
```
Response: `nochg 1.2.3.4`

Third request (different IP):
```bash
curl "https://$CLOUDFRONT_DOMAIN/nic/update?hostname=home.example.com&myip=5.6.7.8" \
  -u "home.example.com:SHARED_SECRET_123"
```
Response: `good 5.6.7.8`

### Testing Without Specifying IP (Uses Source IP)

```bash
curl "https://$CLOUDFRONT_DOMAIN/nic/update?hostname=home.example.com" \
  -u "home.example.com:SHARED_SECRET_123"
```

This will use your current public IP address.

## Troubleshooting

### Router Shows "Update Failed" or "Authentication Error"

1. **Verify credentials**: Ensure the username (hostname) and password (shared secret) match exactly what was configured with `newrecord.py`
2. **Check hostname format**: Make sure you're using the full hostname (e.g., `home.example.com`, not just `home`)
3. **Test with curl**: Use the curl commands above to test the endpoint manually
4. **Check router logs**: Many routers provide DDNS update logs in their system logs

### Router Shows "Success" but DNS Not Updating

1. **Verify in Route53**: Log into AWS Console → Route53 → Hosted Zones → Check the A record
2. **Check Lambda logs**: Go to AWS Console → CloudWatch → Log Groups → Find the Lambda function logs
3. **DNS propagation**: DNS changes can take a few minutes to propagate
4. **Test with dig or nslookup**: 
   ```bash
   dig home.example.com
   nslookup home.example.com
   ```

### Getting "nohost" Response

1. **Hostname not configured**: Run `newrecord.py` to add the hostname to DynamoDB
2. **Typo in hostname**: Verify the hostname exactly matches what's in DynamoDB
3. **Wrong AWS region**: Ensure you're using the correct Lambda URL

### Getting "badauth" Response

1. **Wrong password**: Verify the shared secret matches what's in DynamoDB
2. **Wrong username**: The username must be the hostname, not something else
3. **Special characters**: If your shared secret contains special characters, ensure they're properly encoded

### Getting "911" Response

1. **Lambda error**: Check CloudWatch logs for the Lambda function
2. **Route53 permissions**: Verify the Lambda IAM role has Route53 permissions
3. **Invalid Zone ID**: Check the zone ID in DynamoDB configuration

### Router Doesn't Support Custom DDNS

If your router doesn't support custom DDNS providers, you have these alternatives:

1. **Use the dyndns.sh script**: Set up a cron job on a local computer or server to run the script periodically
2. **Upgrade firmware**: Some routers gain custom DDNS support with aftermarket firmware like DD-WRT or OpenWrt
3. **Use a Raspberry Pi**: Run the dyndns.sh script on a Raspberry Pi on your network
4. **Cloud VM**: Run the script from a small cloud VM (though this defeats some purpose of the solution)

## Monitoring and Logging

### Check Lambda Invocations

1. Go to AWS Console → Lambda → Functions → Your DDNS function
2. Click on the **Monitor** tab
3. View metrics for invocations, errors, and duration

### View Detailed Logs

1. Go to AWS Console → CloudWatch → Log Groups
2. Find the log group for your Lambda function (e.g., `/aws/lambda/DyndnsStack-DynDNSFunction...`)
3. View log streams to see detailed request/response information

### Set Up Alarms

You can create CloudWatch alarms to notify you of issues:

1. Go to CloudWatch → Alarms → Create Alarm
2. Select the Lambda function error metric
3. Set threshold (e.g., errors > 5 in 5 minutes)
4. Configure SNS notification to your email

## Security Considerations

1. **HTTPS Only**: Always use HTTPS for DDNS updates (all routers should support this)
2. **Strong Shared Secret**: Use a strong, random shared secret (at least 20 characters)
3. **Rotate Secrets**: Periodically rotate your shared secret for better security
4. **Monitor Access**: Regularly check CloudWatch logs for unauthorized access attempts
5. **IP Restrictions**: Consider adding IP range restrictions in Lambda if your ISP provides stable IP ranges

## Comparison: DynDNS Protocol vs. dyndns.sh Script

| Feature | DynDNS Protocol | dyndns.sh Script |
|---------|----------------|------------------|
| **Router Integration** | Native support | Requires separate system |
| **Automatic Updates** | Yes (router handles) | Requires cron/scheduler |
| **Authentication** | HTTP Basic Auth | SHA256 hash |
| **Compatibility** | Most modern routers | Any system with bash/curl |
| **Setup Complexity** | Configure router once | Set up cron job |
| **Dependencies** | None | Requires bash, curl, shasum |

Both methods are fully supported and can be used simultaneously or interchangeably.

## Additional Resources

- [Main README](README.md) - General setup and deployment instructions
- [invocation.md](invocation.md) - Details on Lambda invocation methods
- [DynDNS Protocol Specification](https://help.dyn.com/remote-access-api/) - Official protocol documentation
- [AWS Lambda Function URLs](https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html) - AWS documentation

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/awslabs/route53-dynamic-dns-with-lambda).
