import unittest
import json
import pyotp
from unittest.mock import patch
from app import app, USERS_DATA

class TestMFASystem(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True
        self.save_patcher = patch('app.save_users', return_value=True)
        self.mock_save_users = self.save_patcher.start()

    def tearDown(self):
        self.save_patcher.stop()
        for user in USERS_DATA:
            user['mfa_enabled'] = False
            user['mfa_secret'] = None
            user['backup_codes'] = []

    def test_mfa_setup(self):
        """Test MFA Setup endpoint returns valid TOTP secret and QR code base64 image."""
        response = self.client.post('/api/mfa/setup', json={'user_id': 2})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('secret', data)
        self.assertIn('qr_code_base64', data)
        self.assertTrue(data['qr_code_base64'].startswith('data:image/png;base64,'))
        self.assertEqual(data['user_id'], 2)

    def test_mfa_verification_success(self):
        """Test MFA Verification with a valid current TOTP code."""
        # 1. Setup MFA secret
        setup_resp = self.client.post('/api/mfa/setup', json={'user_id': 3})
        setup_data = setup_resp.get_json()
        secret = setup_data['secret']

        # 2. Generate valid TOTP token
        totp = pyotp.TOTP(secret)
        current_code = totp.now()

        # 3. Verify
        verify_resp = self.client.post('/api/mfa/verify', json={
            'user_id': 3,
            'secret': secret,
            'code': current_code
        })
        self.assertEqual(verify_resp.status_code, 200)
        verify_data = verify_resp.get_json()
        self.assertTrue(verify_data['success'])
        self.assertTrue(verify_data['mfa_enabled'])
        self.assertIn('backup_codes', verify_data)
        self.assertEqual(len(verify_data['backup_codes']), 5)

    def test_mfa_verification_failure(self):
        """Test MFA Verification with an invalid TOTP code."""
        setup_resp = self.client.post('/api/mfa/setup', json={'user_id': 3})
        secret = setup_resp.get_json()['secret']

        verify_resp = self.client.post('/api/mfa/verify', json={
            'user_id': 3,
            'secret': secret,
            'code': '000000'
        })
        self.assertEqual(verify_resp.status_code, 400)
        verify_data = verify_resp.get_json()
        self.assertFalse(verify_data['success'])
        self.assertEqual(verify_data['error'], 'Invalid verification code')

    def test_mfa_disable(self):
        """Test disabling MFA for a user."""
        disable_resp = self.client.post('/api/mfa/disable', json={'user_id': 1})
        self.assertEqual(disable_resp.status_code, 200)
        disable_data = disable_resp.get_json()
        self.assertTrue(disable_data['success'])
        self.assertFalse(disable_data['mfa_enabled'])

    def test_health_check_mfa_metrics(self):
        """Test health check includes MFA statistics."""
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('mfa_enabled_users', data['statistics'])
        self.assertIn('mfa_authenticator', data['services'])

    def test_mfa_verify_missing_user_id(self):
        """Test MFA verification fails when user_id is missing."""
        response = self.client.post('/api/mfa/verify', json={'code': '123456'})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertEqual(data['error'], 'Missing user_id or verification code')

    def test_mfa_verify_invalid_code_format(self):
        """Test MFA verification fails when code format is invalid."""
        response = self.client.post('/api/mfa/verify', json={'user_id': 1, 'code': 'abc'})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertIn('Invalid code format', data['error'])

    def test_mfa_setup_nonexistent_user(self):
        """Test MFA setup returns 404 for a non-existent user."""
        response = self.client.post('/api/mfa/setup', json={'user_id': 9999})
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertFalse(data['success'])
        self.assertEqual(data['error'], 'User not found')

if __name__ == '__main__':
    unittest.main()
