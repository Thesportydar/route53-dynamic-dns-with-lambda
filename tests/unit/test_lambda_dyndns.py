import sys
import os
import json
import base64
import unittest
from unittest.mock import MagicMock, patch

# Add lambda directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../lambda'))

import index

class TestDynDNSProtocol(unittest.TestCase):
    """Test DynDNS protocol endpoint functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        os.environ['ddns_config_table'] = 'test-table'
    
    def test_parse_basic_auth_valid(self):
        """Test parsing valid Basic Auth header"""
        # Create valid Basic Auth header: "home.example.com:SECRET123"
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        auth_header = f"Basic {encoded}"
        
        username, password = index.parse_basic_auth(auth_header)
        
        self.assertEqual(username, "home.example.com")
        self.assertEqual(password, "SECRET123")
    
    def test_parse_basic_auth_with_colon_in_password(self):
        """Test parsing Basic Auth with colon in password"""
        credentials = "home.example.com:SECRET:WITH:COLONS"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        auth_header = f"Basic {encoded}"
        
        username, password = index.parse_basic_auth(auth_header)
        
        self.assertEqual(username, "home.example.com")
        self.assertEqual(password, "SECRET:WITH:COLONS")
    
    def test_parse_basic_auth_invalid_no_prefix(self):
        """Test parsing Basic Auth without 'Basic ' prefix"""
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        username, password = index.parse_basic_auth(encoded)
        
        self.assertIsNone(username)
        self.assertIsNone(password)
    
    def test_parse_basic_auth_invalid_encoding(self):
        """Test parsing Basic Auth with invalid base64"""
        auth_header = "Basic not-valid-base64!!!"
        
        username, password = index.parse_basic_auth(auth_header)
        
        self.assertIsNone(username)
        self.assertIsNone(password)
    
    def test_parse_basic_auth_no_colon(self):
        """Test parsing Basic Auth without colon separator"""
        credentials = "nocolonhere"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        auth_header = f"Basic {encoded}"
        
        username, password = index.parse_basic_auth(auth_header)
        
        self.assertIsNone(username)
        self.assertIsNone(password)
    
    def test_parse_basic_auth_none(self):
        """Test parsing None auth header"""
        username, password = index.parse_basic_auth(None)
        
        self.assertIsNone(username)
        self.assertIsNone(password)
    
    def test_is_valid_hostname_valid(self):
        """Test valid hostname formats"""
        valid_hostnames = [
            "home.example.com",
            "www.example.com",
            "sub.domain.example.com",
            "test-host.example.com",
            "a.b.c.d.example.com",
            "123.example.com",
            "host123.example.com"
        ]
        
        for hostname in valid_hostnames:
            with self.subTest(hostname=hostname):
                self.assertTrue(index.is_valid_hostname(hostname))
    
    def test_is_valid_hostname_invalid(self):
        """Test invalid hostname formats"""
        invalid_hostnames = [
            "",
            "localhost",
            "example",
            "-example.com",
            "example-.com",
            ".example.com",
            "example.com.",
            "exam ple.com",
            "a" * 256,  # Too long
            "exam@ple.com"
        ]
        
        for hostname in invalid_hostnames:
            with self.subTest(hostname=hostname):
                self.assertFalse(index.is_valid_hostname(hostname))
    
    @patch('index.read_config')
    @patch('index.route53_client')
    def test_handle_dyndns_update_success_good(self, mock_route53, mock_read_config):
        """Test successful DynDNS update with IP change (good response)"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock Route53 responses - old IP different from new IP
        # Note: route53_client returns dict for get_record, list for set_record
        mock_route53.side_effect = [
            {'return_status': 'success', 'return_message': '1.2.3.4'},  # get_record returns dict
            [201, {'return_status': 'success', 'return_message': 'Updated'}]  # set_record returns [status_code, dict]
        ]
        
        # Create test event
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
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
        self.assertEqual(response['headers']['Content-Type'], 'text/plain')
        self.assertEqual(response['body'], 'good 5.6.7.8')
    
    @patch('index.read_config')
    @patch('index.route53_client')
    def test_handle_dyndns_update_success_nochg(self, mock_route53, mock_read_config):
        """Test DynDNS update with no IP change (nochg response)"""
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
        
        # Create test event
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
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
    
    @patch('index.read_config')
    def test_handle_dyndns_update_use_source_ip(self, mock_read_config):
        """Test DynDNS update using source IP when myip not provided"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        with patch('index.route53_client') as mock_route53:
            # Mock Route53 to return same IP as source
            mock_route53.return_value = {
                'return_status': 'success',
                'return_message': '9.9.9.9'
            }
            
            event = {
                'queryStringParameters': {
                    'hostname': 'home.example.com'
                    # myip not provided
                },
                'headers': {
                    'authorization': f'Basic {encoded}'
                },
                'requestContext': {
                    'http': {
                        'sourceIp': '9.9.9.9'
                    }
                }
            }
            
            response = index.handle_dyndns_update(event)
            
            self.assertEqual(response['statusCode'], 200)
            self.assertEqual(response['body'], 'nochg 9.9.9.9')
    
    @patch('index.read_config')
    def test_handle_dyndns_update_use_x_forwarded_for(self, mock_read_config):
        """Test DynDNS update using X-Forwarded-For header (CloudFront scenario)"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        with patch('index.route53_client') as mock_route53:
            # Mock Route53 to return same IP as client (from X-Forwarded-For)
            mock_route53.return_value = {
                'return_status': 'success',
                'return_message': '203.0.113.1'
            }
            
            event = {
                'queryStringParameters': {
                    'hostname': 'home.example.com'
                    # myip not provided - should use X-Forwarded-For
                },
                'headers': {
                    'authorization': f'Basic {encoded}',
                    'x-forwarded-for': '203.0.113.1, 198.51.100.2'  # Client IP, proxy IP
                },
                'requestContext': {
                    'http': {
                        'sourceIp': '130.176.220.5'  # CloudFront IP - should be ignored
                    }
                }
            }
            
            response = index.handle_dyndns_update(event)
            
            self.assertEqual(response['statusCode'], 200)
            self.assertEqual(response['body'], 'nochg 203.0.113.1')
    
    def test_handle_dyndns_update_badauth_no_header(self):
        """Test DynDNS update with no auth header (badauth response)"""
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
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
    
    def test_handle_dyndns_update_badauth_wrong_username(self):
        """Test DynDNS update with wrong username (badauth response)"""
        credentials = "wrong.hostname.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
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
        self.assertEqual(response['body'], 'badauth')
    
    @patch('index.read_config')
    def test_handle_dyndns_update_badauth_wrong_password(self, mock_read_config):
        """Test DynDNS update with wrong password (badauth response)"""
        # Mock config with different secret
        mock_read_config.return_value = {
            'shared_secret': 'CORRECT_SECRET',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        credentials = "home.example.com:WRONG_SECRET"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
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
        self.assertEqual(response['body'], 'badauth')
    
    def test_handle_dyndns_update_notfqdn_no_hostname(self):
        """Test DynDNS update with no hostname (notfqdn response)"""
        event = {
            'queryStringParameters': {},
            'headers': {},
            'requestContext': {
                'http': {
                    'sourceIp': '5.6.7.8'
                }
            }
        }
        
        response = index.handle_dyndns_update(event)
        
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body'], 'notfqdn')
    
    def test_handle_dyndns_update_notfqdn_invalid_hostname(self):
        """Test DynDNS update with invalid hostname (notfqdn response)"""
        event = {
            'queryStringParameters': {
                'hostname': 'invalid-hostname'
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
        self.assertEqual(response['body'], 'notfqdn')
    
    @patch('index.read_config')
    def test_handle_dyndns_update_nohost(self, mock_read_config):
        """Test DynDNS update with hostname not in DB (nohost response)"""
        # Mock config to raise exception (hostname not found)
        mock_read_config.side_effect = Exception("Not found")
        
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
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
        self.assertEqual(response['body'], 'nohost')
    
    @patch('index.read_config')
    @patch('index.route53_client')
    def test_handle_dyndns_update_911_route53_get_error(self, mock_route53, mock_read_config):
        """Test DynDNS update with Route53 get error (911 response)"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock Route53 to return error
        mock_route53.return_value = {
            'return_status': 'fail',
            'return_message': 'Error'
        }
        
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
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
        self.assertEqual(response['body'], '911')
    
    @patch('index.read_config')
    @patch('index.route53_client')
    def test_handle_dyndns_update_911_route53_set_error(self, mock_route53, mock_read_config):
        """Test DynDNS update with Route53 set error (911 response)"""
        # Mock config
        mock_read_config.return_value = {
            'shared_secret': 'SECRET123',
            'route_53_zone_id': 'Z123456',
            'route_53_record_ttl': 60
        }
        
        # Mock Route53 responses - get succeeds, set fails
        # Note: route53_client returns dict for get_record, list for set_record
        mock_route53.side_effect = [
            {'return_status': 'success', 'return_message': '1.2.3.4'},  # get_record returns dict
            [500, {'return_status': 'fail', 'return_message': 'Error'}]  # set_record returns [status_code, dict]
        ]
        
        credentials = "home.example.com:SECRET123"
        encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        
        event = {
            'queryStringParameters': {
                'hostname': 'home.example.com',
                'myip': '5.6.7.8'
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
        self.assertEqual(response['body'], '911')


class TestLambdaHandlerRouting(unittest.TestCase):
    """Test lambda_handler routing between DynDNS and legacy endpoints"""
    
    def setUp(self):
        """Set up test fixtures"""
        os.environ['ddns_config_table'] = 'test-table'
    
    @patch('index.handle_dyndns_update')
    def test_lambda_handler_routes_to_dyndns(self, mock_dyndns):
        """Test lambda_handler routes to DynDNS for /nic/update GET"""
        mock_dyndns.return_value = {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'good 1.2.3.4'
        }
        
        event = {
            'rawPath': '/nic/update',
            'requestContext': {
                'http': {
                    'method': 'GET',
                    'sourceIp': '1.2.3.4'
                }
            },
            'queryStringParameters': {
                'hostname': 'home.example.com'
            },
            'headers': {}
        }
        
        response = index.lambda_handler(event, None)
        
        mock_dyndns.assert_called_once_with(event)
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(response['body'], 'good 1.2.3.4')
    
    def test_lambda_handler_routes_to_legacy_get(self):
        """Test lambda_handler routes to legacy for POST with get mode"""
        event = {
            'rawPath': '/',
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': '1.2.3.4'
                }
            },
            'body': json.dumps({'execution_mode': 'get'})
        }
        
        response = index.lambda_handler(event, None)
        
        self.assertEqual(response['statusCode'], 200)
        response_body = json.loads(response['body'])
        self.assertEqual(response_body['return_status'], 'success')
        self.assertEqual(response_body['return_message'], '1.2.3.4')
    
    @patch('index.run_set_mode')
    def test_lambda_handler_routes_to_legacy_set(self, mock_set_mode):
        """Test lambda_handler routes to legacy for POST with set mode"""
        mock_set_mode.return_value = [200, {
            'return_status': 'success',
            'return_message': 'Updated'
        }]
        
        event = {
            'rawPath': '/',
            'requestContext': {
                'http': {
                    'method': 'POST',
                    'sourceIp': '1.2.3.4'
                }
            },
            'body': json.dumps({
                'execution_mode': 'set',
                'ddns_hostname': 'home.example.com',
                'validation_hash': 'a' * 64
            })
        }
        
        response = index.lambda_handler(event, None)
        
        mock_set_mode.assert_called_once()
        self.assertEqual(response['statusCode'], 200)


class TestGetSourceIP(unittest.TestCase):
    """Test get_source_ip function for CloudFront and direct access scenarios"""
    
    def test_get_source_ip_from_x_forwarded_for_single_ip(self):
        """Test extracting client IP from X-Forwarded-For with single IP"""
        event = {
            'headers': {
                'x-forwarded-for': '203.0.113.1'
            },
            'requestContext': {
                'http': {
                    'sourceIp': '130.176.220.5'  # CloudFront IP
                }
            }
        }
        
        ip = index.get_source_ip(event)
        
        self.assertEqual(ip, '203.0.113.1')
    
    def test_get_source_ip_from_x_forwarded_for_multiple_ips(self):
        """Test extracting client IP from X-Forwarded-For with multiple IPs (comma-separated)"""
        event = {
            'headers': {
                'x-forwarded-for': '203.0.113.1, 198.51.100.2, 192.0.2.3'
            },
            'requestContext': {
                'http': {
                    'sourceIp': '130.176.220.5'  # CloudFront IP
                }
            }
        }
        
        ip = index.get_source_ip(event)
        
        # Should extract the first IP (client IP)
        self.assertEqual(ip, '203.0.113.1')
    
    def test_get_source_ip_from_x_forwarded_for_uppercase(self):
        """Test extracting IP from X-Forwarded-For header with uppercase"""
        event = {
            'headers': {
                'X-Forwarded-For': '203.0.113.1'
            },
            'requestContext': {
                'http': {
                    'sourceIp': '130.176.220.5'
                }
            }
        }
        
        ip = index.get_source_ip(event)
        
        self.assertEqual(ip, '203.0.113.1')
    
    def test_get_source_ip_fallback_to_source_ip(self):
        """Test fallback to sourceIp when X-Forwarded-For is absent (direct Lambda URL)"""
        event = {
            'headers': {},
            'requestContext': {
                'http': {
                    'sourceIp': '198.51.100.10'
                }
            }
        }
        
        ip = index.get_source_ip(event)
        
        self.assertEqual(ip, '198.51.100.10')
    
    def test_get_source_ip_empty_headers(self):
        """Test fallback when headers dict is empty"""
        event = {
            'requestContext': {
                'http': {
                    'sourceIp': '198.51.100.10'
                }
            }
        }
        
        ip = index.get_source_ip(event)
        
        self.assertEqual(ip, '198.51.100.10')
    
    def test_get_source_ip_with_spaces_in_forwarded_for(self):
        """Test handling X-Forwarded-For with extra spaces"""
        event = {
            'headers': {
                'x-forwarded-for': '  203.0.113.1  ,  198.51.100.2  '
            },
            'requestContext': {
                'http': {
                    'sourceIp': '130.176.220.5'
                }
            }
        }
        
        ip = index.get_source_ip(event)
        
        # Should strip whitespace
        self.assertEqual(ip, '203.0.113.1')


if __name__ == '__main__':
    unittest.main()
