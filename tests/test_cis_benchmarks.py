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
  - id: "3.1"
    title: "Ensure That the Default Network Does Not Exist in a Project"
    profile_applicability: "Level 2"
    description: "To prevent use of default network, a project should not have a default network."
    rationale: "The default network has preconfigured insecure firewall rules."
    audit:
      gcloud_command: "gcloud compute networks list"
    remediation:
      steps:
        - "Delete the default network if it exists."
    references:
      - "https://cloud.google.com/vpc/docs/using-firewalls"
  - id: "4.9"
    title: "Ensure That Compute Instances Do Not Have Public IP Addresses"
    profile_applicability: "Level 1"
    description: "Ensure that Compute Engine instances do not have public IP addresses."
    rationale: "Public IP addresses expose instances directly to the internet."
    audit:
      gcloud_command: "gcloud compute instances list"
    remediation:
      steps:
        - "Remove public IP addresses from instances."
    references:
      - "https://cloud.google.com/compute/docs/ip-addresses"
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

@pytest.fixture
def mock_network():
    network = Mock()
    network.name = "default"
    return network

@pytest.fixture
def mock_instance():
    instance = Mock()
    instance.name = "test-instance"
    interface = Mock()
    interface.access_configs = [Mock()]  # Has public IP
    instance.network_interfaces = [interface]
    return instance

@pytest.mark.asyncio
async def test_scan_network_default_network(mock_config, mock_credentials, mock_network):
    with patch('builtins.open', mock_open(read_data=SAMPLE_BENCHMARK_YAML)):
        scanner = Scanner(mock_config, mock_credentials)
        with patch.object(scanner.networks_client, 'list', return_value=[mock_network]), \
             patch.object(scanner.compute_client, 'list', return_value=[]), \
             patch.object(scanner.subnets_client, 'list', return_value=[]), \
             patch.object(scanner.firewall_client, 'list', return_value=[]), \
             patch.object(scanner.dns_client, 'list', return_value=[]):
            findings = await scanner._scan_network()
            assert len(findings) == 1
            assert findings[0].cis_id == "3.1"
            assert findings[0].resource_type == "network"
            assert findings[0].status == "Non-Compliant"

@pytest.mark.asyncio
async def test_scan_network_public_ip(mock_config, mock_credentials, mock_instance):
    with patch('builtins.open', mock_open(read_data=SAMPLE_BENCHMARK_YAML)):
        scanner = Scanner(mock_config, mock_credentials)
        with patch.object(scanner.networks_client, 'list', return_value=[]), \
             patch.object(scanner.compute_client, 'list', return_value=[mock_instance]), \
             patch.object(scanner.subnets_client, 'list', return_value=[]), \
             patch.object(scanner.firewall_client, 'list', return_value=[]), \
             patch.object(scanner.dns_client, 'list', return_value=[]):
            findings = await scanner._scan_network()
            assert len(findings) == 1
            assert findings[0].cis_id == "4.9"
            assert findings[0].resource_type == "compute_instance"
            assert findings[0].status == "Non-Compliant"
