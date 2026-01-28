#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock
import base64
import json
from replication import get_oauth_token, fetch_and_post_submodels, main


class TestGetOAuthToken(unittest.TestCase):
    """Test OAuth2 token retrieval."""

    @patch('replication.requests.post')
    def test_get_oauth_token_success(self, mock_post):
        """Test successful token retrieval."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "test-token-123"}
        mock_post.return_value = mock_response

        token = get_oauth_token()

        self.assertEqual(token, "test-token-123")
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        self.assertEqual(call_kwargs['data']['grant_type'], 'client_credentials')

    @patch('replication.requests.post')
    def test_get_oauth_token_http_error(self, mock_post):
        """Test token request with HTTP error."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        with self.assertRaises(RuntimeError) as context:
            get_oauth_token()

        self.assertIn("Token request failed", str(context.exception))

    @patch('replication.requests.post')
    def test_get_oauth_token_missing_access_token(self, mock_post):
        """Test token response without access_token field."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token_type": "Bearer"}
        mock_post.return_value = mock_response

        with self.assertRaises(RuntimeError) as context:
            get_oauth_token()

        self.assertIn("access_token", str(context.exception))


class TestFetchSubmodels(unittest.TestCase):
    """Tests adapted to fetch_and_post_submodels (use DRY_RUN to avoid POSTs)."""

    @patch('replication.requests.get')
    def test_fetch_submodels_success(self, mock_get):
        """Test successful submodel fetching (DRY_RUN to avoid POST)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "submodel-id-1", "data": "test"}
        mock_get.return_value = mock_response

        with patch('replication.DRY_RUN', True):
            results = list(fetch_and_post_submodels("dummy-token"))

        # results are tuples like ("dry_run", label)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0][1], "submodel-id-1")

    @patch('replication.requests.get')
    def test_fetch_submodels_partial_failure(self, mock_get):
        """Test fetching with some failed requests (DRY_RUN)."""
        responses = [
            MagicMock(status_code=200, json=lambda: {"id": "submodel-id-1"}),
            MagicMock(status_code=404, text="Not found"),
            MagicMock(status_code=200, json=lambda: {"id": "submodel-id-3"}),
        ]
        mock_get.side_effect = responses

        with patch('replication.DRY_RUN', True):
            results = list(fetch_and_post_submodels("dummy-token"))

        # Should only return successful submodels
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1], "submodel-id-1")
        self.assertEqual(results[1][1], "submodel-id-3")

    @patch('replication.requests.get')
    def test_fetch_submodels_non_dict_response(self, mock_get):
        """Test fetching with non-dict response (DRY_RUN)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ["not", "a", "dict"]
        mock_get.return_value = mock_response

        with patch('replication.DRY_RUN', True):
            results = list(fetch_and_post_submodels("dummy-token"))

        # Should skip non-dict responses
        self.assertEqual(len(results), 0)

    @patch('replication.requests.get')
    def test_fetch_submodels_base64_encoding(self, mock_get):
        """Test that submodel IDs are properly base64 encoded (DRY_RUN)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "submodel-id-1"}
        mock_get.return_value = mock_response

        with patch('replication.DRY_RUN', True):
            list(fetch_and_post_submodels("dummy-token"))

        # Verify the first call used base64 encoding
        first_call = mock_get.call_args_list[0]
        url = first_call[0][0]
        
        # Extract the encoded part from URL
        encoded_part = url.split('/')[-1]
        decoded_part = base64.urlsafe_b64decode(encoded_part).decode()
        self.assertEqual(decoded_part, "submodel-id-1")


class TestMain(unittest.TestCase):
    """Test main function."""

    @patch('replication.requests.post')
    @patch('replication.requests.get')
    @patch('replication.get_oauth_token')
    def test_main_dry_run(self, mock_token, mock_get, mock_post):
        """Test main function in dry-run mode."""
        with patch('replication.DRY_RUN', True):
            mock_token.return_value = "test-token"
            mock_get_response = MagicMock()
            mock_get_response.status_code = 200
            mock_get_response.json.return_value = {"id": "submodel-id-1"}
            mock_get.return_value = mock_get_response

            # Should not raise and not make POST requests
            main()
            mock_post.assert_not_called()

    @patch('replication.requests.post')
    @patch('replication.requests.get')
    @patch('replication.get_oauth_token')
    def test_main_post_success(self, mock_token, mock_get, mock_post):
        """Test main function with successful POST."""
        with patch('replication.DRY_RUN', False):
            mock_token.return_value = "test-token"
            
            get_response = MagicMock()
            get_response.status_code = 200
            get_response.json.return_value = {"id": "submodel-id-1"}
            mock_get.return_value = get_response

            post_response = MagicMock()
            post_response.status_code = 201
            mock_post.return_value = post_response

            main()

            # Should have posted 3 times (one for each submodel)
            self.assertEqual(mock_post.call_count, 3)

    @patch('replication.requests.post')
    @patch('replication.requests.get')
    @patch('replication.get_oauth_token')
    def test_main_handles_409_conflict(self, mock_token, mock_get, mock_post):
        """Test main function handling 409 conflicts."""
        with patch('replication.DRY_RUN', False):
            mock_token.return_value = "test-token"
            
            get_response = MagicMock()
            get_response.status_code = 200
            get_response.json.return_value = {"id": "submodel-id-1"}
            mock_get.return_value = get_response

            post_response = MagicMock()
            post_response.status_code = 409
            mock_post.return_value = post_response

            main()

            # Should have attempted to post all 3
            self.assertEqual(mock_post.call_count, 3)

    @patch('replication.requests.post')
    @patch('replication.requests.get')
    @patch('replication.get_oauth_token')
    def test_main_handles_post_failure(self, mock_token, mock_get, mock_post):
        """Test main function handling POST errors."""
        with patch('replication.DRY_RUN', False):
            mock_token.return_value = "test-token"
            
            get_response = MagicMock()
            get_response.status_code = 200
            get_response.json.return_value = {"id": "submodel-id-1"}
            mock_get.return_value = get_response

            post_response = MagicMock()
            post_response.status_code = 500
            post_response.text = "Internal server error"
            mock_post.return_value = post_response

            main()

            # Should have attempted to post all 3
            self.assertEqual(mock_post.call_count, 3)


if __name__ == "__main__":
    unittest.main()
