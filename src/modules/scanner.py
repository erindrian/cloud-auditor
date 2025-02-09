import asyncio
import traceback
import yaml
import os
from typing import Any, Dict, List, Optional
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
        
        # Load CIS benchmarks
        self.benchmarks = self._load_cis_benchmarks(scanner_config['cis_benchmarks_file'])
        
        # Initialize clients
        self.project_id = getattr(credentials, "project_id", None)
        if not self.project_id:
            raise ValueError("Project ID must be set in credentials")
        
        self.storage_client = storage.Client(
            project=self.project_id,
            credentials=self.credentials
        )
        self.resource_manager_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)

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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(google_exceptions.RetryError)
    )
    async def _scan_storage_bucket(self, bucket: storage.Bucket, pbar: tqdm) -> Optional[Finding]:
        """Scan a single storage bucket with retry mechanism."""
        try:
            logger = self._get_logger()
            
            # Check bucket IAM configuration
            if bucket.iam_configuration.uniform_bucket_level_access_enabled:
                pbar.update(1)
                return None
                
            if bucket.iam_configuration.public_access_prevention != "enforced":
                benchmark = self.benchmarks['cis_benchmarks'][0]  # 5.1 benchmark
                pbar.update(1)
                return Finding(
                    description=f"Bucket {bucket.name} is publicly accessible",
                    cis_id=benchmark['id'],
                    risk_level="High",
                    status="Non-Compliant",
                    resource_id=bucket.name,
                    resource_type="storage_bucket",
                    details={
                        "public_access_prevention": bucket.iam_configuration.public_access_prevention,
                        "uniform_bucket_level_access": bucket.iam_configuration.uniform_bucket_level_access_enabled
                    },
                    title=benchmark['title'],
                    profile_applicability=benchmark['profile_applicability'],
                    rationale=benchmark['rationale'],
                    audit_command=benchmark['audit']['gcloud_command'],
                    remediation_steps=benchmark['remediation']['steps'],
                    prevention_steps=benchmark['prevention']['steps'],
                    references=benchmark['references']
                )
            
            pbar.update(1)
            return None
            
        except Exception as e:
            logger.error(f"Error scanning bucket {bucket.name}", extra={"error": str(e)})
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
            logger = self._get_logger()
            role = binding.get('role', '')
            members = binding.get('members', [])
            
            # Check for public access
            public_members = [m for m in members if m in ["allUsers", "allAuthenticatedUsers"]]
            if public_members:
                benchmark = next((b for b in self.benchmarks['cis_benchmarks'] if b['id'] == '1.4'), None)
                if benchmark:
                    pbar.update(1)
                    return Finding(
                        description=f"IAM role {role} allows public access",
                        cis_id=benchmark['id'],
                        risk_level="High",
                        status="Non-Compliant",
                        resource_id=role,
                        resource_type="iam_role",
                        details={
                            "members": list(members),
                            "role": role,
                            "public_members": public_members
                        },
                        title=benchmark['title'],
                        profile_applicability=benchmark['profile_applicability'],
                        rationale=benchmark['rationale'],
                        audit_command=benchmark['audit']['gcloud_command'],
                        remediation_steps=benchmark['remediation']['steps'],
                        prevention_steps=benchmark['prevention']['steps'],
                        references=benchmark['references']
                    )
            
            pbar.update(1)
            return None
            
        except Exception as e:
            logger.error(f"Error scanning IAM binding {binding.get('role', 'unknown')}", extra={"error": str(e)})
            pbar.update(1)
            raise

    async def _scan_storage(self) -> List[Finding]:
        """Scan all storage buckets with pagination."""
        findings = []
        try:
            logger = self._get_logger()
            page_token = None
            while True:
                buckets_iterator = self.storage_client.list_buckets(
                    max_results=self.batch_size,
                    page_token=page_token
                )
                
                current_batch = list(buckets_iterator)
                
                # Process current batch with progress bar
                tasks = []
                print("\n")  # Add consistent double spacing before progress bar
                with tqdm(total=len(current_batch), desc="🔍 Storage Buckets    ", unit="bucket", bar_format=PROGRESS_FORMAT) as pbar:
                    for bucket in current_batch:
                        task = asyncio.create_task(self._scan_storage_bucket(bucket, pbar))
                        tasks.append(task)
                    
                    # Wait for all tasks in the current batch
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error("Error in storage scanning batch", extra={"error": str(result)})
                    elif result is not None:
                        findings.append(result)
                
                # Check if there are more buckets to process
                if not buckets_iterator.next_page_token:
                    break
                page_token = buckets_iterator.next_page_token
                
        except Exception as e:
            logger.error("Error in storage scanning", extra={"error": str(e)})
            print("\n")  # Add consistent double spacing before error progress bar
            with tqdm(total=1, desc="🔍 Storage Buckets", unit="bucket", bar_format=PROGRESS_FORMAT) as pbar:
                pbar.update(0)  # Show 0/1 progress
        
        return findings

    async def _scan_iam(self) -> List[Finding]:
        """Scan all IAM bindings with pagination."""
        findings = []
        try:
            logger = self._get_logger()
            project_name = f"projects/{self.project_id}"
            
            # Get IAM policy
            request = iam_policy_pb2.GetIamPolicyRequest(resource=project_name)
            policy = self.resource_manager_client.get_iam_policy(request=request)
            bindings = [{"role": b.role, "members": list(b.members)} for b in policy.bindings]
            
            print("\n")  # Add consistent double spacing before progress bar
            with tqdm(total=max(len(bindings), 1), desc="🔍 IAM Bindings      ", unit="binding", bar_format=PROGRESS_FORMAT) as pbar:
                if not bindings:
                    pbar.update(0)  # Show 0/1 progress for no bindings
                else:
                    # Process bindings in batches
                    for i in range(0, len(bindings), self.batch_size):
                        batch = bindings[i:i + self.batch_size]
                        
                        # Create tasks for current batch
                        tasks = []
                        for binding in batch:
                            task = asyncio.create_task(self._scan_iam_binding(binding, pbar))
                            tasks.append(task)
                        
                        # Wait for all tasks in the current batch
                        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                        
                        # Process results
                        for result in batch_results:
                            if isinstance(result, Exception):
                                logger.error("Error in IAM scanning batch", extra={"error": str(result)})
                            elif result is not None:
                                findings.append(result)
                
        except Exception as e:
            logger.error("Error in IAM scanning", extra={"error": str(e)})
            raise  # Let the error be handled by the scan() method
        
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
            logger = self._get_logger()

            # Use gcloud command to list instances with public IPs
            import subprocess
            import json

            cmd = [
                "gcloud", "compute", "instances", "list",
                "--format=json",
                f"--project={self.project_id}"
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                instances = json.loads(result.stdout)

                print("\n")  # Add consistent double spacing before progress bar
                with tqdm(total=len(instances), desc="🔍 Compute Instances ", unit="instance", bar_format=PROGRESS_FORMAT) as pbar:
                    for instance in instances:
                        # Skip GKE nodes as per benchmark exception
                        if instance['name'].startswith('gke-') or 'labels' in instance and instance['labels'].get('goog-gke-node'):
                            pbar.update(1)
                            continue

                        for interface in instance.get('networkInterfaces', []):
                            if 'accessConfigs' in interface:
                                # Get the Level 1 version of 4.9 benchmark
                                benchmark = next((b for b in self.benchmarks['cis_benchmarks'] 
                                               if b['id'] == '4.9' and b['profile_applicability'] == 'Level 1'), None)
                                if benchmark:
                                    findings.append(Finding(
                                        description=f"Instance {instance['name']} has public IP address",
                                        cis_id=benchmark['id'],
                                        risk_level="High",
                                        status="Non-Compliant",
                                        resource_id=instance['name'],
                                        resource_type="compute_instance",
                                        title=benchmark['title'],
                                        profile_applicability=benchmark['profile_applicability'],
                                        rationale=benchmark['rationale'],
                                        audit_command=benchmark['audit']['gcloud_command'],
                                        remediation_steps=benchmark['remediation']['steps'],
                                        prevention_steps=benchmark['prevention']['steps'],
                                        references=benchmark['references']
                                    ))
                                break  # Found a public IP, no need to check other interfaces
                        pbar.update(1)

            except subprocess.CalledProcessError as e:
                logger.error(f"Error running gcloud command: {e.stderr}")
                raise
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing gcloud output: {e}")
                raise

        except Exception as e:
            logger.error("Error in compute scanning", extra={"error": str(e)})
            raise  # Let the error be handled by the scan() method

        return findings

    async def _scan_network(self) -> List[Finding]:
        """Scan network configurations."""
        findings = []
        try:
            logger = self._get_logger()
            print("\n")  # Add consistent double spacing before progress bar
            with tqdm(total=1, desc="🔍 Network Config    ", unit="check", bar_format=PROGRESS_FORMAT) as pbar:
                try:
                    # Network scanning logic would go here
                    # For now, just show progress
                    pbar.update(1)
                except Exception as e:
                    logger.error("Error in network scanning", extra={"error": str(e)})
                    pbar.update(0)  # Show 0/1 progress on error
        except Exception as e:
            logger.error("Error in network scanning", extra={"error": str(e)})
        return findings

    async def scan(self) -> List[Finding]:
        """Perform parallel scanning of all resources."""
        all_findings = []
        try:
            logger = self._get_logger()
            # Print header with notification systems
            print("\n=== Cloud Auditor ===")
            print(f"🔐 Project: {self.project_id}")
            print("📢 Notifications: 📧 Email, 💬 Slack")
            print("🎫 Ticketing System: JIRA, ServiceNow")
            
            # Run scans sequentially to maintain order
            try:
                storage_findings = await self._scan_storage()
                all_findings.extend(storage_findings)
            except Exception as e:
                logger.error("Error in Storage scanning", extra={"error": str(e)})

            try:
                iam_findings = await self._scan_iam()
                all_findings.extend(iam_findings)
            except Exception as e:
                logger.error("Error in IAM scanning", extra={"error": str(e)})
                print("\n")  # Add consistent double spacing before error progress bar
                with tqdm(total=1, desc="🔍 IAM Bindings", unit="binding", bar_format=PROGRESS_FORMAT) as pbar:
                    pbar.update(0)  # Show 0/1 progress

            try:
                compute_findings = await self._scan_compute()
                all_findings.extend(compute_findings)
            except Exception as e:
                logger.error("Error in Compute scanning", extra={"error": str(e)})
                print("\n")  # Add consistent double spacing before error progress bar
                with tqdm(total=1, desc="🔍 Compute Instances", unit="instance", bar_format=PROGRESS_FORMAT) as pbar:
                    pbar.update(0)  # Show 0/1 progress

            try:
                network_findings = await self._scan_network()
                all_findings.extend(network_findings)
            except Exception as e:
                logger.error("Error in Network scanning", extra={"error": str(e)})
            
        except Exception as e:
            logger.error("Error in scanning task", extra={"error": str(e)})
            raise
        
        print(f"\n🔍 Found {len(all_findings)} security issues\n")
        return all_findings
