import logging
import asyncio
import traceback
import yaml
import os
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
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
        print("Initializing Scanner...")
        self.config = config_manager
        self.credentials = credentials
        self.logger = None  # Will be initialized when needed
        
        # Get scanner configuration
        scanner_config = self.config['scanner']
        self.max_workers = scanner_config['max_workers']
        self.timeout = scanner_config['timeout']
        self.batch_size = scanner_config['batch_size']
        
        # Load CIS benchmarks
        self.benchmarks = self._load_cis_benchmarks(scanner_config['cis_benchmarks_file'])
        
        # Initialize clients
        print("Getting project ID...")
        self.project_id = getattr(credentials, "project_id", None)
        if not self.project_id:
            raise ValueError("Project ID must be set in credentials")
        
        print(f"Initializing storage client for project {self.project_id}...")
        self.storage_client = storage.Client(
            project=self.project_id,
            credentials=self.credentials
        )
        print("Storage client initialized")

        print("Initializing Resource Manager client...")
        self.resource_manager_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
        print("Resource Manager client initialized")
        print("Scanner initialization complete")

    def _load_cis_benchmarks(self, benchmarks_file: str) -> Dict[str, Any]:
        """Load CIS benchmarks from YAML file."""
        try:
            file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), benchmarks_file)
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading CIS benchmarks: {str(e)}")
            raise

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
    async def _scan_storage_bucket(self, bucket: storage.Bucket) -> Optional[Finding]:
        """Scan a single storage bucket with retry mechanism."""
        try:
            logger = self._get_logger()
            logger.info(f"Scanning bucket: {bucket.name}")
            print(f"Scanning bucket: {bucket.name}")
            
            # Check bucket IAM configuration
            if bucket.iam_configuration.uniform_bucket_level_access_enabled:
                logger.info(f"Bucket {bucket.name} has uniform access enabled")
                return None
                
            if bucket.iam_configuration.public_access_prevention != "enforced":
                logger.warning(f"Bucket {bucket.name} is publicly accessible")
                benchmark = self.benchmarks['cis_benchmarks'][0]  # 5.1 benchmark
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
            
            logger.info(f"Bucket {bucket.name} has public access prevention enforced")
            return None
            
        except Exception as e:
            logger = self._get_logger()
            logger.error(
                f"Error scanning bucket {bucket.name}",
                extra={"error": str(e), "stack_trace": traceback.format_exc()}
            )
            print(f"Error scanning bucket {bucket.name}: {str(e)}")
            traceback.print_exc()
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(google_exceptions.RetryError)
    )
    async def _scan_iam_binding(self, binding: Dict[str, Any]) -> Optional[Finding]:
        """Scan a single IAM binding with retry mechanism."""
        try:
            logger = self._get_logger()
            role = binding.get('role', '')
            members = binding.get('members', [])
            print(f"Scanning IAM binding: {role}")
            
            # Check for public access
            public_members = [m for m in members if m in ["allUsers", "allAuthenticatedUsers"]]
            if public_members:
                logger.warning(f"IAM role {role} allows public access")
                benchmark = next((b for b in self.benchmarks['cis_benchmarks'] if b['id'] == '1.4'), None)
                if benchmark:
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
            
            logger.info(f"IAM role {role} does not allow public access")
            return None
            
        except Exception as e:
            logger = self._get_logger()
            logger.error(
                f"Error scanning IAM binding {binding.get('role', 'unknown')}",
                extra={"error": str(e), "stack_trace": traceback.format_exc()}
            )
            print(f"Error scanning IAM binding {binding.get('role', 'unknown')}: {str(e)}")
            traceback.print_exc()
            raise

    async def _scan_storage(self) -> List[Finding]:
        """Scan all storage buckets with pagination."""
        findings = []
        try:
            print("Starting storage scan...")
            logger = self._get_logger()
            page_token = None
            while True:
                print("Listing storage buckets...")
                buckets_iterator = self.storage_client.list_buckets(
                    max_results=self.batch_size,
                    page_token=page_token
                )
                
                current_batch = list(buckets_iterator)
                print(f"Found {len(current_batch)} buckets")
                logger.info(f"Scanning batch of {len(current_batch)} storage buckets")
                
                # Process current batch
                tasks = []
                for bucket in current_batch:
                    task = asyncio.create_task(self._scan_storage_bucket(bucket))
                    tasks.append(task)
                
                # Wait for all tasks in the current batch
                print("Waiting for bucket scan tasks to complete...")
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error("Error in storage scanning batch",
                                        extra={"error": str(result)})
                        print(f"Error in batch: {str(result)}")
                    elif result is not None:
                        findings.append(result)
                
                # Check if there are more buckets to process
                if not buckets_iterator.next_page_token:
                    break
                page_token = buckets_iterator.next_page_token
                
        except Exception as e:
            logger = self._get_logger()
            logger.error("Error in storage scanning",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            print(f"Error in storage scanning: {str(e)}")
            traceback.print_exc()
        
        print(f"Storage scan complete. Found {len(findings)} findings.")
        return findings

    async def _scan_iam(self) -> List[Finding]:
        """Scan all IAM bindings with pagination."""
        findings = []
        try:
            print("Starting IAM scan...")
            logger = self._get_logger()
            project_name = f"projects/{self.project_id}"
            
            # Get IAM policy
            print("Getting IAM policy...")
            request = iam_policy_pb2.GetIamPolicyRequest(resource=project_name)
            policy = self.resource_manager_client.get_iam_policy(request=request)
            bindings = [{"role": b.role, "members": list(b.members)} for b in policy.bindings]
            print(f"Found {len(bindings)} IAM bindings")
            logger.info(f"Scanning {len(bindings)} IAM bindings")
            
            # Process bindings in batches
            for i in range(0, len(bindings), self.batch_size):
                batch = bindings[i:i + self.batch_size]
                print(f"Processing batch of {len(batch)} IAM bindings")
                logger.info(f"Scanning batch of {len(batch)} IAM bindings")
                
                # Create tasks for current batch
                tasks = []
                for binding in batch:
                    task = asyncio.create_task(self._scan_iam_binding(binding))
                    tasks.append(task)
                
                # Wait for all tasks in the current batch
                print("Waiting for IAM binding scan tasks to complete...")
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error("Error in IAM scanning batch",
                                        extra={"error": str(result)})
                        print(f"Error in batch: {str(result)}")
                    elif result is not None:
                        findings.append(result)
                
        except Exception as e:
            logger = self._get_logger()
            logger.error("Error in IAM scanning",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            print(f"Error in IAM scanning: {str(e)}")
            traceback.print_exc()
        
        print(f"IAM scan complete. Found {len(findings)} findings.")
        return findings

    async def scan(self) -> List[Finding]:
        """Perform parallel scanning of all resources."""
        all_findings = []
        try:
            print("Starting security scan...")
            logger = self._get_logger()
            # Run storage and IAM scans concurrently
            print("Starting concurrent scans...")
            storage_task = asyncio.create_task(self._scan_storage())
            iam_task = asyncio.create_task(self._scan_iam())
            
            # Wait for both scans to complete
            print("Waiting for scans to complete...")
            storage_findings, iam_findings = await asyncio.gather(
                storage_task, iam_task, return_exceptions=True
            )
            
            # Process storage findings
            if isinstance(storage_findings, Exception):
                logger.error("Error in storage scanning",
                                extra={"error": str(storage_findings)})
                print(f"Error in storage scanning: {str(storage_findings)}")
            else:
                all_findings.extend(storage_findings)
            
            # Process IAM findings
            if isinstance(iam_findings, Exception):
                logger.error("Error in IAM scanning",
                                extra={"error": str(iam_findings)})
                print(f"Error in IAM scanning: {str(iam_findings)}")
            else:
                all_findings.extend(iam_findings)
            
        except Exception as e:
            logger = self._get_logger()
            logger.error("Error in scanning task",
                            extra={"error": str(e), "stack_trace": traceback.format_exc()})
            print(f"Error in scanning task: {str(e)}")
            traceback.print_exc()
            raise
        
        print(f"Scan complete. Total findings: {len(all_findings)}")
        return all_findings
