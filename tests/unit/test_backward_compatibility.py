import sys
import os
import json
import hashlib
import unittest
from unittest.mock import patch

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../lambda'))

import index

class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility with existing hash-based authentication"""
    
    def setUp(self):
        """Set up test fixtures"""
        os.environ['ddns_config_table'] = 'test-table'
    
    @patch('index.read_config')
    @patch('index.route53_client')
    def test_legacy_set_mode_with_valid_hash(self, mock_route53, mock_read_config):
        """Test legacy set mode with valid SHA256 hash still works"""
        hostname = 'www.example.com'
        shared_secret = 'SHARED_SECRET_123'
        source_ip = '1.2.3.4'
        
        # Calculate the hash as the legacy system does
        hashcheck = source_ip + hostname + shared_secret
        validation_hash = hashlib.sha256(hashcheck.encode('utf-8')).hexdigest()
        
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': shared_secret,
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock Route53 responses
        mock_route53.side_effect = [
            {'return_status': 'success', 'return_message': '0.0.0.0'},  # get_record
            [201, {'return_status': 'success', 'return_message': 'Updated'}]  # set_record
        ]
        
        # Create legacy event (POST with JSON body)
        event = {
            'rawPath': '/',
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': source_ip
                }
            },
            'body': json.dumps({
                'execution_mode': 'set',
                'ddns_hostname': hostname,
                'validation_hash': validation_hash
            })
        }
        
        response = index.lambda_handler(event, None)
        
        self.assertEqual(response['statusCode'], 201)
        response_body = json.loads(response['body'])
        self.assertEqual(response_body['return_status'], 'success')
    
    @patch('index.read_config')
    def test_legacy_set_mode_with_invalid_hash(self, mock_read_config):
        """Test legacy set mode with invalid hash fails properly"""
        hostname = 'www.example.com'
        shared_secret = 'SHARED_SECRET_123'
        source_ip = '1.2.3.4'
        
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': shared_secret,
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Use wrong hash
        validation_hash = 'a' * 64
        
        # Create legacy event
        event = {
            'rawPath': '/',
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': source_ip
                }
            },
            'body': json.dumps({
                'execution_mode': 'set',
                'ddns_hostname': hostname,
                'validation_hash': validation_hash
            })
        }
        
        response = index.lambda_handler(event, None)
        
        self.assertEqual(response['statusCode'], 401)
        response_body = json.loads(response['body'])
        self.assertEqual(response_body['return_status'], 'fail')
        self.assertIn('Validation hashes do not match', response_body['return_message'])
    
    def test_legacy_get_mode_returns_ip(self):
        """Test legacy get mode still returns source IP"""
        source_ip = '5.6.7.8'
        
        event = {
            'rawPath': '/',
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': source_ip
                }
            },
            'body': json.dumps({
                'execution_mode': 'get'
            })
        }
        
        response = index.lambda_handler(event, None)
        
        self.assertEqual(response['statusCode'], 200)
        response_body = json.loads(response['body'])
        self.assertEqual(response_body['return_status'], 'success')
        self.assertEqual(response_body['return_message'], source_ip)
    
    @patch('index.read_config')
    @patch('index.route53_client')
    def test_legacy_set_mode_with_no_ip_change(self, mock_route53, mock_read_config):
        """Test legacy set mode when IP hasn't changed"""
        hostname = 'www.example.com'
        shared_secret = 'SHARED_SECRET_123'
        source_ip = '1.2.3.4'
        
        # Calculate the hash
        hashcheck = source_ip + hostname + shared_secret
        validation_hash = hashlib.sha256(hashcheck.encode('utf-8')).hexdigest()
        
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': shared_secret,
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock Route53 to return same IP
        mock_route53.return_value = {
            'return_status': 'success',
            'return_message': source_ip
        }
        
        # Create legacy event
        event = {
            'rawPath': '/',
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': source_ip
                }
            },
            'body': json.dumps({
                'execution_mode': 'set',
                'ddns_hostname': hostname,
                'validation_hash': validation_hash
            })
        }
        
        response = index.lambda_handler(event, None)
        
        self.assertEqual(response['statusCode'], 200)
        response_body = json.loads(response['body'])
        self.assertEqual(response_body['return_status'], 'success')
        self.assertIn('matches', response_body['return_message'])


if __name__ == '__main__':
    unittest.main()
