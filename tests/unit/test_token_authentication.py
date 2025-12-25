import sys
import os
import json
import base64
import unittest
from unittest.mock import MagicMock, patch
import time

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../lambda'))

import index


class TestTokenAuthentication(unittest.TestCase):
    """Test token-based authentication functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        os.environ['ddns_config_table'] = 'test-table'
        os.environ['TOKENS_TABLE_NAME'] = 'test-tokens-table'
    
    def test_validate_token_valid(self):
        """Test validating a valid token"""
        token = "test-token-123"
        hostname = "home.example.com"
        current_time = int(time.time())
        
        # Mock DynamoDB response with valid token
        mock_response = {
            'Item': {
                'token': {'S': token},
                'hostname': {'S': hostname},
                'ttl': {'N': str(current_time + 300)},  # Expires 5 minutes from now
                'created_at': {'N': str(current_time)}
            }
        }
        
        with patch('boto3.client') as mock_boto:
            mock_dynamodb = MagicMock()
            mock_dynamodb.get_item.return_value = mock_response
            mock_boto.return_value = mock_dynamodb
            
            result = index.validate_token(token, hostname)
            
            self.assertTrue(result)
            mock_dynamodb.get_item.assert_called_once()
    
    def test_validate_token_not_found(self):
        """Test validating a token that doesn't exist"""
        token = "non-existent-token"
        hostname = "home.example.com"
        
        # Mock DynamoDB response with no item
        mock_response = {}
        
        with patch('boto3.client') as mock_boto:
            mock_dynamodb = MagicMock()
            mock_dynamodb.get_item.return_value = mock_response
            mock_boto.return_value = mock_dynamodb
            
            result = index.validate_token(token, hostname)
            
            self.assertFalse(result)
    
    def test_validate_token_wrong_hostname(self):
        """Test validating a token for wrong hostname"""
        token = "test-token-123"
        request_hostname = "home.example.com"
        token_hostname = "other.example.com"
        current_time = int(time.time())
        
        # Mock DynamoDB response with token for different hostname
        mock_response = {
            'Item': {
                'token': {'S': token},
                'hostname': {'S': token_hostname},
                'ttl': {'N': str(current_time + 300)},
                'created_at': {'N': str(current_time)}
            }
        }
        
        with patch('boto3.client') as mock_boto:
            mock_dynamodb = MagicMock()
            mock_dynamodb.get_item.return_value = mock_response
            mock_boto.return_value = mock_dynamodb
            
            result = index.validate_token(token, request_hostname)
            
            self.assertFalse(result)
    
    def test_validate_token_expired(self):
        """Test validating an expired token"""
        token = "test-token-123"
        hostname = "home.example.com"
        current_time = int(time.time())
        
        # Mock DynamoDB response with expired token
        mock_response = {
            'Item': {
                'token': {'S': token},
                'hostname': {'S': hostname},
                'ttl': {'N': str(current_time - 100)},  # Expired 100 seconds ago
                'created_at': {'N': str(current_time - 400)}
            }
        }
        
        with patch('boto3.client') as mock_boto:
            mock_dynamodb = MagicMock()
            mock_dynamodb.get_item.return_value = mock_response
            mock_boto.return_value = mock_dynamodb
            
            result = index.validate_token(token, hostname)
            
            self.assertFalse(result)
    
    def test_validate_token_no_table_name(self):
        """Test validate_token when TOKENS_TABLE_NAME env var is not set"""
        token = "test-token-123"
        hostname = "home.example.com"
        
        # Remove TOKENS_TABLE_NAME env var
        del os.environ['TOKENS_TABLE_NAME']
        
        result = index.validate_token(token, hostname)
        
        self.assertFalse(result)
        
        # Restore env var
        os.environ['TOKENS_TABLE_NAME'] = 'test-tokens-table'
    
    def test_validate_token_dynamodb_error(self):
        """Test validate_token when DynamoDB throws an error"""
        token = "test-token-123"
        hostname = "home.example.com"
        
        with patch('boto3.client') as mock_boto:
            mock_dynamodb = MagicMock()
            mock_dynamodb.get_item.side_effect = Exception("DynamoDB error")
            mock_boto.return_value = mock_dynamodb
            
            result = index.validate_token(token, hostname)
            
            self.assertFalse(result)
    
    @patch('index.read_config')
    @patch('index.validate_token')
    @patch('index.route53_client')
    def test_handle_dyndns_update_with_valid_token(self, mock_route53, mock_validate, mock_read_config):
        """Test DynDNS update with valid token authentication"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock token validation
        mock_validate.return_value = True
        
        # Mock Route53 responses - IP change scenario
        mock_route53.side_effect = [
            {'return_status': 'success', 'return_message': '1.2.3.4'},  # get_record
            [201, {'return_status': 'success', 'return_message': 'Updated'}]  # set_record
        ]
        
        # Create test event with token
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8',
                'token': 'valid-token-123'
            },
            'headers': {},
            'requestContext': {
                'http': {
                    'sourceIp': '5.6.7.8'
                }
            }
        }
        
        response = index.handle_dyndns_update(event)
        
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body'], 'good 5.6.7.8')
        
        # Verify token validation was called
        mock_validate.assert_called_once_with('valid-token-123', 'home.example.com')
    
    @patch('index.read_config')
    @patch('index.validate_token')
    def test_handle_dyndns_update_with_invalid_token(self, mock_validate, mock_read_config):
        """Test DynDNS update with invalid token authentication"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock token validation - invalid token
        mock_validate.return_value = False
        
        # Create test event with invalid token
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8',
                'token': 'invalid-token-123'
            },
            'headers': {},
            'requestContext': {
                'http': {
                    'sourceIp': '5.6.7.8'
                }
            }
        }
        
        response = index.handle_dyndns_update(event)
        
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body'], 'badauth')
        
        # Verify token validation was called
        mock_validate.assert_called_once_with('invalid-token-123', 'home.example.com')
    
    @patch('index.read_config')
    @patch('index.validate_token')
    @patch('index.route53_client')
    def test_handle_dyndns_update_token_no_ip_change(self, mock_route53, mock_validate, mock_read_config):
        """Test DynDNS update with token when IP hasn't changed"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock token validation
        mock_validate.return_value = True
        
        # Mock Route53 response - same IP
        mock_route53.return_value = {
            'return_status': 'success',
            'return_message': '5.6.7.8'
        }
        
        # Create test event with token
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8',
                'token': 'valid-token-123'
            },
            'headers': {},
            'requestContext': {
                'http': {
                    'sourceIp': '5.6.7.8'
                }
            }
        }
        
        response = index.handle_dyndns_update(event)
        
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body'], 'nochg 5.6.7.8')
    
    @patch('index.read_config')
    @patch('index.route53_client')
    def test_handle_dyndns_update_basic_auth_still_works_with_token_feature(self, mock_route53, mock_read_config):
        """Test that Basic Auth still works after adding token feature"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock Route53 response - same IP
        mock_route53.return_value = {
            'return_status': 'success',
            'return_message': '5.6.7.8'
        }
        
        # Create test event with Basic Auth (no token)
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
                # No token parameter
            },
            'headers': {
                'authorization': f'Basic {encoded}'
            },
            'requestContext': {
                'http': {
                    'sourceIp': '5.6.7.8'
                }
            }
        }
        
        response = index.handle_dyndns_update(event)
        
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body'], 'nochg 5.6.7.8')
    
    def test_handle_dyndns_update_token_nohost(self):
        """Test DynDNS update with token when hostname doesn't exist in DB"""
        # Mock read_config to raise exception (hostname not found)
        with patch('index.read_config') as mock_read_config:
            mock_read_config.side_effect = Exception("Not found")
            
            event = {
                'queryStringParameters': {
                    'hostname': 'nonexistent.example.com',
                    'myip': '5.6.7.8',
                    'token': 'some-token'
                },
                'headers': {},
                'requestContext': {
                    'http': {
                        'sourceIp': '5.6.7.8'
                    }
                }
            }
            
            response = index.handle_dyndns_update(event)
            
            self.assertEqual(response['statusCode'], 200)
            self.assertEqual(response['body'], 'nohost')


if __name__ == '__main__':
    unittest.main()
