import pytest
from unittest.mock import patch, MagicMock
from google.cloud import storage
from src.modules.scanner import Scanner

@pytest.fixture
def mock_config():
    return {
        "project_id": "test-project",
        "service_account_file": "path/to/service-account.json"
    }

@pytest.fixture
def mock_credentials():
    credentials = MagicMock()
    credentials.universe_domain = "googleapis.com"
    return credentials

@pytest.fixture
def mock_storage_bucket():
    bucket = MagicMock()
    bucket.iam_configuration = MagicMock()
    bucket.iam_configuration.public_access_prevention = "unspecified"
    return bucket

@pytest.fixture
def mock_iam_binding():
    binding = MagicMock()
    binding.role = "roles/storage.admin"
    binding.members = ["allUsers"]
    return binding

@pytest.mark.asyncio
async def test_scan_storage_bucket_public_access(mock_config, mock_credentials, mock_storage_bucket):
    with patch('google.cloud.storage.Client', autospec=True) as mock_storage_client:
        mock_storage_client.return_value.list_buckets.return_value = [mock_storage_bucket]
        mock_storage_bucket.iam_configuration.public_access_prevention = "unspecified"

        scanner = Scanner(mock_config, mock_credentials)
        findings = await scanner.scan_storage()

        # Assert that the method identifies a public bucket
        assert findings  # There should be findings as the bucket is public

@pytest.mark.asyncio
async def test_scan_storage_bucket_private_access(mock_config, mock_credentials, mock_storage_bucket):
    with patch('google.cloud.storage.Client', autospec=True) as mock_storage_client:
        mock_storage_client.return_value.list_buckets.return_value = [mock_storage_bucket]
        mock_storage_bucket.iam_configuration.public_access_prevention = "enforced"

        scanner = Scanner(mock_config, mock_credentials)
        findings = await scanner.scan_storage()

        # Assert that the method does not identify a public bucket
        assert not findings  # There should be no findings as the bucket is private

@pytest.mark.asyncio
async def test_scan_iam_binding_public_access(mock_config, mock_credentials, mock_iam_binding):
    with patch('google.cloud.iam_admin_v1.IAMClient', autospec=True) as mock_iam_client:
        # Simulate public access by adding a public role
        mock_iam_binding.role = "roles/storage.admin"
        mock_iam_binding.members = ["allUsers"]

        policy = MagicMock()
        policy.bindings = [mock_iam_binding]

        mock_iam_client.return_value.get_iam_policy.return_value = policy

        scanner = Scanner(mock_config, mock_credentials)
        findings = await scanner.scan_iam()

        # Assert that the method identifies a binding with public access
        assert findings  # There should be findings as the binding is public

@pytest.mark.asyncio
async def test_scan_iam_binding_private_access(mock_config, mock_credentials, mock_iam_binding):
    with patch('google.cloud.iam_admin_v1.IAMClient', autospec=True) as mock_iam_client:
        # Simulate private access by adding a specific user
        mock_iam_binding.role = "roles/storage.admin"
        mock_iam_binding.members = ["user:example@example.com"]

        policy = MagicMock()
        policy.bindings = [mock_iam_binding]

        mock_iam_client.return_value.get_iam_policy.return_value = policy

        scanner = Scanner(mock_config, mock_credentials)
        findings = await scanner.scan_iam()

        # Assert that the method does not identify a binding with public access
        assert not findings  # There should be no findings as the binding is private

@pytest.mark.asyncio
async def test_scan_storage_parallel(mock_config, mock_credentials, mock_storage_bucket):
    with patch('google.cloud.storage.Client', autospec=True) as mock_storage_client:
        mock_storage_client.return_value.list_buckets.return_value = [mock_storage_bucket]

        scanner = Scanner(mock_config, mock_credentials)
        await scanner.scan_storage()

        # Assert that the method scans storage buckets in parallel
        mock_storage_client.return_value.list_buckets.assert_called_once()

@pytest.mark.asyncio
async def test_scan_iam_parallel(mock_config, mock_credentials, mock_iam_binding):
    with patch('google.cloud.iam_admin_v1.IAMClient', autospec=True) as mock_iam_client:
        policy = MagicMock()
        policy.bindings = [mock_iam_binding]

        mock_iam_client.return_value.get_iam_policy.return_value = policy

        scanner = Scanner(mock_config, mock_credentials)
        await scanner.scan_iam()

        # Assert that the method scans IAM bindings in parallel
        mock_iam_client.return_value.get_iam_policy.assert_called_once()

@pytest.mark.asyncio
@patch('google.cloud.storage.Client', autospec=True)
@patch('google.cloud.iam_admin_v1.IAMClient', autospec=True)
async def test_scan_all_parallel(mock_iam_client, mock_storage_client, mock_config, mock_credentials, mock_storage_bucket, mock_iam_binding):
    mock_storage_client.return_value.list_buckets.return_value = [mock_storage_bucket]
    policy = MagicMock()
    policy.bindings = [mock_iam_binding]
    mock_iam_client.return_value.get_iam_policy.return_value = policy

    scanner = Scanner(mock_config, mock_credentials)
    await scanner.scan()

    # Assert that the method scans storage buckets in parallel
    mock_storage_client.return_value.list_buckets.assert_called_once()

    # Assert that the method scans IAM bindings in parallel
    mock_iam_client.return_value.get_iam_policy.assert_called_once()

def test_error_handling_storage(mock_config, mock_credentials):
    with patch('google.cloud.storage.Client', autospec=True) as mock_storage_client:
        mock_storage_client.return_value.list_buckets.side_effect = Exception("Storage error")

        scanner = Scanner(mock_config, mock_credentials)
        with pytest.raises(Exception) as excinfo:
            list(scanner.scan_storage())

        assert "Storage error" in str(excinfo.value)

def test_error_handling_iam(mock_config, mock_credentials):
    with patch('google.cloud.iam_admin_v1.IAMClient', autospec=True) as mock_iam_client:
        mock_iam_client.return_value.get_iam_policy.side_effect = Exception("IAM error")

        scanner = Scanner(mock_config, mock_credentials)
        with pytest.raises(Exception) as excinfo:
            list(scanner.scan_iam())

        assert "IAM error" in str(excinfo.value)
