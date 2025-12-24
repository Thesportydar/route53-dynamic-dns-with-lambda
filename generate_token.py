#!/usr/bin/env python3
"""
Generate temporary authentication tokens for DDNS updates via browser.

Usage:
    python generate_token.py <hostname> [ttl_seconds]

Examples:
    # Generate token valid for 5 minutes (300s, default)
    python generate_token.py casa.example.com
    
    # Generate token valid for 24 hours
    python generate_token.py casa.example.com 86400
    
    # Generate token valid for 3 days
    python generate_token.py casa.example.com 259200
"""

import boto3
import secrets
import sys
import time
from datetime import datetime, timedelta

def generate_token(hostname, ttl_seconds=300):
    """
    Generate a temporary token for DDNS updates.
    
    Args:
        hostname: The FQDN hostname (e.g., casa.example.com)
        ttl_seconds: Time-to-live in seconds (default: 300 = 5 minutes)
    
    Returns:
        The generated token string
    """
    # Generate cryptographically secure random token
    token = secrets.token_urlsafe(32)  # 43 characters, URL-safe
    
    # Calculate expiration timestamp
    expiration = datetime.now() + timedelta(seconds=ttl_seconds)
    ttl_timestamp = int(expiration.timestamp())
    
    # Get DynamoDB table name from CloudFormation stack
    try:
        cfn = boto3.client('cloudformation')
        response = cfn.describe_stacks(StackName='DyndnsStack')
        
        tokens_table_name = None
        for stack in response['Stacks']:
            for output in stack.get('Outputs', []):
                if 'tokens' in output.get('OutputKey', '').lower():
                    tokens_table_name = output['OutputValue']
                    break
        
        # Fallback: try to find table by name pattern
        if not tokens_table_name:
            dynamodb = boto3.client('dynamodb')
            tables = dynamodb.list_tables()
            for table in tables['TableNames']:
                if 'tokens' in table.lower() and 'dyndns' in table.lower():
                    tokens_table_name = table
                    break
        
        if not tokens_table_name:
            print("❌ Error: Could not find tokens DynamoDB table")
            print("   Make sure the stack is deployed with: cdk deploy")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error finding DynamoDB table: {e}")
        sys.exit(1)
    
    # Store token in DynamoDB
    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(tokens_table_name)
        
        table.put_item(
            Item={
                'token': token,
                'hostname': hostname,
                'ttl': ttl_timestamp,
                'created_at': int(time.time())
            }
        )
    except Exception as e:
        print(f"❌ Error storing token in DynamoDB: {e}")
        sys.exit(1)
    
    # Get CloudFront domain from stack outputs
    try:
        ddns_domain = None
        for stack in cfn.describe_stacks(StackName='DyndnsStack')['Stacks']:
            for output in stack.get('Outputs', []):
                key = output.get('OutputKey', '')
                if 'domain' in key.lower() or 'url' in key.lower():
                    value = output['OutputValue']
                    # Extract domain from URL if needed
                    if '://' in value:
                        ddns_domain = value.split('://')[1].split('/')[0]
                    else:
                        ddns_domain = value.split('/')[0]
                    break
    except:
        ddns_domain = "<your-cloudfront-domain>"
    
    # Print results
    print(f"✅ Token generated successfully")
    print(f"📋 Hostname: {hostname}")
    print(f"⏰ Expires: {expiration.strftime('%Y-%m-%d %H:%M:%S')} ({ttl_seconds}s)")
    print(f"🔑 Token: {token}")
    print(f"\n🔗 One-click update link:")
    print(f"http://{ddns_domain}/nic/update?hostname={hostname}&token={token}")
    print(f"\n💡 Share this link via WhatsApp, SMS, or email.")
    print(f"   Anyone with this link can update the DNS record for {hostname}")
    print(f"   until {expiration.strftime('%Y-%m-%d %H:%M:%S')}.")
    
    return token

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    hostname = sys.argv[1]
    ttl_seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    
    # Validate TTL
    if ttl_seconds < 60:
        print("⚠️  Warning: TTL less than 60 seconds may be too short")
    elif ttl_seconds > 2592000:  # 30 days
        print("⚠️  Warning: TTL longer than 30 days may be a security risk")
    
    generate_token(hostname, ttl_seconds)

if __name__ == '__main__':
    main()
