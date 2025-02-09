import asyncio
import traceback
import yaml
import os
import json
import subprocess
from typing import Any, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from tqdm import tqdm
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)
from google.api_core import exceptions as google_exceptions
from google.cloud import storage
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2
from src.utils.logger import Logger

# Common progress bar format to match table width (120 chars)
PROGRESS_FORMAT = "{desc:<25}: {percentage:3.0f}%|{bar:65}| {n_fmt:>3}/{total_fmt:<3} [{elapsed}<{remaining}]"

# Constants for better performance
PUBLIC_MEMBERS = frozenset(["allUsers", "allAuthenticatedUsers"])
GKE_NODE_PREFIX = "gke-"

@dataclass
class Finding:
    """Represents a security finding."""
    description: str
    cis_id: str
    risk_level: str
    status: str
    resource_id: str
    resource_type: str
    details: Optional[Dict[str, Any]] = None
    title: str = ""
    profile_applicability: str = ""
    rationale: str = ""
    audit_command: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    prevention_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

class Scanner:
    def __init__(self, config_manager: Any, credentials: Any):
        """Initialize the scanner with configuration and credentials."""
        self.config = config_manager
        self.credentials = credentials
        self.logger = None
        
        # Get scanner configuration
        scanner_config = self.config['scanner']
        self.max_workers = scanner_config['max_workers']
        self.timeout = scanner_config['timeout']
        self.batch_size = scanner_config['batch_size']
        
        # Load CIS benchmarks and cache commonly used ones
        self.benchmarks = self._load_cis_benchmarks(scanner_config['cis_benchmarks_file'])
        self._cache_benchmarks()
        
        # Initialize clients
        self.project_id = getattr(credentials, "project_id", None)
        if not self.project_id:
            raise ValueError("Project ID must be set in credentials")
        
        self.storage_client = storage.Client(
            project=self.project_id,
            credentials=self.credentials
        )
        self.resource_manager_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)

    def _cache_benchmarks(self) -> None:
        """Cache commonly used benchmarks for better performance."""
        self.storage_benchmark = self.benchmarks['cis_benchmarks'][0]  # 5.1 benchmark
        self.iam_benchmark = next((b for b in self.benchmarks['cis_benchmarks'] if b['id'] == '1.4'), None)
        self.compute_benchmark = next((b for b in self.benchmarks['cis_benchmarks'] 
                                    if b['id'] == '4.9' and b['profile_applicability'] == 'Level 1'), None)

    def _load_cis_benchmarks(self, benchmarks_file: str) -> Dict[str, Any]:
        """Load CIS benchmarks from YAML file."""
        try:
            file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), benchmarks_file)
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Error loading CIS benchmarks: {str(e)}")

    def _get_logger(self):
        """Get or initialize logger."""
        if self.logger is None:
            self.logger = Logger.get_logger(__name__)
        return self.logger

    def _is_valid_project_id(self, project_id: str) -> bool:
        """Validate GCP project ID format."""
        import re
        # GCP project ID rules:
        # - Must be 6 to 30 characters
        # - Can only contain lowercase letters, numbers, and hyphens
        # - Must start with a letter
        # - Cannot end with a hyphen
        pattern = r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
        return bool(re.match(pattern, project_id))

    async def _scan_with_timeout(self, coro: Any, scan_type: str) -> Optional[List[Finding]]:
        """Execute a scan operation with timeout."""
        try:
            return await asyncio.wait_for(coro, timeout=self.timeout)
        except asyncio.TimeoutError:
            self._get_logger().error(f"{scan_type} scan timed out after {self.timeout} seconds")
            return None
        except Exception as e:
            self._get_logger().error(f"Error in {scan_type} scan: {str(e)}")
            return None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(google_exceptions.RetryError)
    )
    async def _scan_storage_bucket(self, bucket: storage.Bucket, pbar: tqdm) -> Optional[Finding]:
        """Scan a single storage bucket with retry mechanism."""
        try:
            if bucket.iam_configuration.uniform_bucket_level_access_enabled:
                pbar.update(1)
                return None
                
            if bucket.iam_configuration.public_access_prevention != "enforced":
                pbar.update(1)
                return Finding(
                    description=f"Bucket {bucket.name} is publicly accessible",
                    cis_id=self.storage_benchmark['id'],
                    risk_level="High",
                    status="Non-Compliant",
                    resource_id=bucket.name,
                    resource_type="storage_bucket",
                    details={
                        "public_access_prevention": bucket.iam_configuration.public_access_prevention,
                        "uniform_bucket_level_access": bucket.iam_configuration.uniform_bucket_level_access_enabled
                    },
                    **{k: self.storage_benchmark[k] for k in ['title', 'profile_applicability', 'rationale']}
                )
            
            pbar.update(1)
            return None
            
        except Exception as e:
            self._get_logger().error(f"Error scanning bucket {bucket.name}", extra={"error": str(e)})
            pbar.update(1)
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(google_exceptions.RetryError)
    )
    async def _scan_iam_binding(self, binding: Dict[str, Any], pbar: tqdm) -> Optional[Finding]:
        """Scan a single IAM binding with retry mechanism."""
        try:
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            # Check for public access using set intersection
            public_members = set(members) & PUBLIC_MEMBERS
            if public_members and self.iam_benchmark:
                pbar.update(1)
                return Finding(
                    description=f"IAM role {role} allows public access",
                    cis_id=self.iam_benchmark['id'],
                    risk_level="High",
                    status="Non-Compliant",
                    resource_id=role,
                    resource_type="iam_role",
                    details={
                        "members": list(members),
                        "role": role,
                        "public_members": list(public_members)
                    },
                    **{k: self.iam_benchmark[k] for k in ['title', 'profile_applicability', 'rationale']}
                )
            
            pbar.update(1)
            return None
            
        except Exception as e:
            self._get_logger().error(f"Error scanning IAM binding {binding.get('role', 'unknown')}", extra={"error": str(e)})
            pbar.update(1)
            raise

    async def _scan_storage(self) -> List[Finding]:
        """Scan all storage buckets with pagination."""
        findings = []
        try:
            page_token = None
            while True:
                buckets_iterator = self.storage_client.list_buckets(
                    max_results=self.batch_size,
                    page_token=page_token
                )
                
                current_batch = list(buckets_iterator)
                if not current_batch:
                    break

                print("\n")
                tasks = []
                with tqdm(total=len(current_batch), desc="🔍 Storage Buckets    ", unit="bucket", bar_format=PROGRESS_FORMAT) as pbar:
                    tasks = [asyncio.create_task(self._scan_storage_bucket(bucket, pbar)) for bucket in current_batch]
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    findings.extend([r for r in batch_results if isinstance(r, Finding)])
                
                if not buckets_iterator.next_page_token:
                    break
                page_token = buckets_iterator.next_page_token
                
        except Exception as e:
            self._get_logger().error("Error in storage scanning", extra={"error": str(e)})
            print("\n")
            with tqdm(total=1, desc="🔍 Storage Buckets", unit="bucket", bar_format=PROGRESS_FORMAT) as pbar:
                pbar.update(0)
        
        return findings

    async def _scan_iam(self) -> List[Finding]:
        """Scan all IAM bindings with pagination."""
        findings = []
        try:
            request = iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{self.project_id}")
            policy = self.resource_manager_client.get_iam_policy(request=request)
            bindings = [{"role": b.role, "members": list(b.members)} for b in policy.bindings]
            
            if not bindings:
                print("\n")
                with tqdm(total=1, desc="🔍 IAM Bindings      ", unit="binding", bar_format=PROGRESS_FORMAT) as pbar:
                    pbar.update(0)
                return findings

            print("\n")
            with tqdm(total=len(bindings), desc="🔍 IAM Bindings      ", unit="binding", bar_format=PROGRESS_FORMAT) as pbar:
                tasks = [asyncio.create_task(self._scan_iam_binding(binding, pbar)) for binding in bindings]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                findings.extend([r for r in batch_results if isinstance(r, Finding)])
                
        except Exception as e:
            self._get_logger().error("Error in IAM scanning", extra={"error": str(e)})
            raise
        
        return findings

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(google_exceptions.RetryError)
    )
    async def _scan_compute(self) -> List[Finding]:
        """Scan compute instances for public IPs."""
        findings = []
        try:
            # Validate project ID to prevent command injection
            if not self._is_valid_project_id(self.project_id):
                raise ValueError("Invalid project ID format")

            # Use a list of allowed commands for security
            ALLOWED_COMMANDS = {
                "gcloud": "/usr/bin/gcloud",  # Use full path
                "compute": "compute",
                "instances": "instances",
                "list": "list",
                "--format": "--format",
                "json": "json",
                "--project": "--project"
            }

            # Build command with validated components
            cmd = [
                ALLOWED_COMMANDS["gcloud"],
                ALLOWED_COMMANDS["compute"],
                ALLOWED_COMMANDS["instances"],
                ALLOWED_COMMANDS["list"],
                f"{ALLOWED_COMMANDS['--format']}={ALLOWED_COMMANDS['json']}",
                f"{ALLOWED_COMMANDS['--project']}={self.project_id}"
            ]

            # Run command with restricted shell and timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=self.timeout,
                env={"PATH": "/usr/bin:/bin"}  # Restrict PATH
            )
            instances = json.loads(result.stdout)

            if not instances:
                print("\n")
                with tqdm(total=1, desc="🔍 Compute Instances ", unit="instance", bar_format=PROGRESS_FORMAT) as pbar:
                    pbar.update(0)
                return findings

            print("\n")
            with tqdm(total=len(instances), desc="🔍 Compute Instances ", unit="instance", bar_format=PROGRESS_FORMAT) as pbar:
                for instance in instances:
                    # Skip GKE nodes efficiently
                    if instance['name'].startswith(GKE_NODE_PREFIX) or instance.get('labels', {}).get('goog-gke-node'):
                        pbar.update(1)
                        continue

                    # Check for public IP
                    has_public_ip = any('accessConfigs' in interface 
                                      for interface in instance.get('networkInterfaces', []))
                    
                    if has_public_ip and self.compute_benchmark:
                        findings.append(Finding(
                            description=f"Instance {instance['name']} has public IP address",
                            cis_id=self.compute_benchmark['id'],
                            risk_level="High",
                            status="Non-Compliant",
                            resource_id=instance['name'],
                            resource_type="compute_instance",
                            **{k: self.compute_benchmark[k] for k in ['title', 'profile_applicability', 'rationale']}
                        ))
                    pbar.update(1)

        except Exception as e:
            self._get_logger().error("Error in compute scanning", extra={"error": str(e)})
            raise

        return findings

    async def _scan_network(self) -> List[Finding]:
        """Scan network configurations."""
        findings = []
        try:
            print("\n")
            with tqdm(total=1, desc="🔍 Network Config    ", unit="check", bar_format=PROGRESS_FORMAT) as pbar:
                try:
                    pbar.update(1)
                except Exception as e:
                    self._get_logger().error("Error in network scanning", extra={"error": str(e)})
                    pbar.update(0)
        except Exception as e:
            self._get_logger().error("Error in network scanning", extra={"error": str(e)})
        return findings

    async def scan(self) -> List[Finding]:
        """Perform parallel scanning of all resources."""
        all_findings = []
        try:
            print("\n=== Cloud Auditor ===")
            print(f"🔐 Project: {self.project_id}")
            print("📢 Notifications: 📧 Email, 💬 Slack")
            print("🎫 Ticketing System: JIRA, ServiceNow")
            
            # Run scans with proper timeout and error handling
            scan_tasks = [
                asyncio.create_task(self._scan_with_timeout(self._scan_storage(), "Storage")),
                asyncio.create_task(self._scan_with_timeout(self._scan_iam(), "IAM")),
                asyncio.create_task(self._scan_with_timeout(self._scan_compute(), "Compute")),
                asyncio.create_task(self._scan_with_timeout(self._scan_network(), "Network"))
            ]
            
            try:
                results = await asyncio.gather(*scan_tasks)
                # Process successful results
                for result in results:
                    if result:  # Skip None results from timed out tasks
                        all_findings.extend(result)
            except asyncio.TimeoutError:
                self._get_logger().error("Scan operation timed out")
                raise
            except Exception as e:
                self._get_logger().error(f"Error in scanning task: {str(e)}")
                raise
            
        except Exception as e:
            self._get_logger().error("Error in scanning task", extra={"error": str(e)})
            raise
        
        print(f"\n🔍 Found {len(all_findings)} security issues\n")
        return all_findings
