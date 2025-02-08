import pytest
import yaml
from unittest.mock import Mock, patch, mock_open
from src.modules.scanner import Scanner, Finding

SAMPLE_BENCHMARK_YAML = """
cis_benchmarks:
  - id: "5.1"
    title: "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible"
    profile_applicability: "Level 1"
    description: "It is recommended that IAM policy on Cloud Storage bucket does not allow anonymous or public access."
    rationale: "Allowing anonymous or public access grants permissions to anyone to access bucket content."
    audit:
      gcloud_command: "gsutil iam get gs://BUCKET_NAME"
    remediation:
      steps:
        - "Remove allUsers and allAuthenticatedUsers from the IAM policy of the bucket."
    prevention:
      steps:
        - "Prevent buckets from becoming publicly accessible."
    references:
      - "https://cloud.google.com/storage/docs/access-control/iam-reference"
"""

@pytest.fixture
def mock_config():
    return {
        'scanner': {
            'max_workers': 3,
            'timeout': 30,
            'batch_size': 100,
            'cis_benchmarks_file': 'config/cis_benchmarks.yaml'
        }
    }

@pytest.fixture
def mock_credentials():
    credentials = Mock()
    credentials.project_id = "test-project"
    return credentials

@pytest.fixture
def mock_bucket():
    bucket = Mock()
    bucket.name = "test-bucket"
    bucket.iam_configuration = Mock()
    bucket.iam_configuration.uniform_bucket_level_access_enabled = False
    bucket.iam_configuration.public_access_prevention = "unspecified"
    return bucket

def test_load_cis_benchmarks(mock_config, mock_credentials):
    with patch('builtins.open', mock_open(read_data=SAMPLE_BENCHMARK_YAML)):
        scanner = Scanner(mock_config, mock_credentials)
        assert scanner.benchmarks is not None
        assert 'cis_benchmarks' in scanner.benchmarks
        benchmark = scanner.benchmarks['cis_benchmarks'][0]
        assert benchmark['id'] == "5.1"
        assert benchmark['title'] == "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible"

@pytest.mark.asyncio
async def test_scan_storage_bucket_public_access(mock_config, mock_credentials, mock_bucket):
    with patch('builtins.open', mock_open(read_data=SAMPLE_BENCHMARK_YAML)):
        scanner = Scanner(mock_config, mock_credentials)
        finding = await scanner._scan_storage_bucket(mock_bucket)
        
        assert finding is not None
        assert finding.cis_id == "5.1"
        assert finding.resource_id == "test-bucket"
        assert finding.resource_type == "storage_bucket"
        assert finding.status == "Non-Compliant"
        assert finding.risk_level == "High"
        assert finding.title == "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible"
        assert finding.profile_applicability == "Level 1"
        assert finding.audit_command == "gsutil iam get gs://BUCKET_NAME"
        assert len(finding.remediation_steps) == 1
        assert len(finding.prevention_steps) == 1
        assert len(finding.references) == 1

@pytest.mark.asyncio
async def test_scan_storage_bucket_compliant(mock_config, mock_credentials, mock_bucket):
    mock_bucket.iam_configuration.public_access_prevention = "enforced"
    with patch('builtins.open', mock_open(read_data=SAMPLE_BENCHMARK_YAML)):
        scanner = Scanner(mock_config, mock_credentials)
        finding = await scanner._scan_storage_bucket(mock_bucket)
        assert finding is None

@pytest.mark.asyncio
async def test_scan_storage_bucket_uniform_access(mock_config, mock_credentials, mock_bucket):
    mock_bucket.iam_configuration.uniform_bucket_level_access_enabled = True
    with patch('builtins.open', mock_open(read_data=SAMPLE_BENCHMARK_YAML)):
        scanner = Scanner(mock_config, mock_credentials)
        finding = await scanner._scan_storage_bucket(mock_bucket)
        assert finding is None
