"""CIS Benchmark Library for GCP Security Controls."""

CIS_BENCHMARK_LIBRARY = {
    "1.4": {
        "id": "1.4",
        "title": "Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level",
        "profile_applicability": "Level 1",
        "description": "It is recommended to assign Service Account User (iam.serviceAccountUser) and Service Account Token Creator (iam.serviceAccountTokenCreator) roles to users at the service account level rather than at project level.",
        "rationale": """
        Assigning Service Account User or Service Account Token Creator roles to a user gives the user access to all service accounts in the project. 
        This is because service accounts are resources that exist at project level.
        
        Instead, these roles should be assigned to users on specific service accounts, giving them access only to those service accounts they need to impersonate.
        """,
        "impact": "High - Allows users to impersonate any service account in the project",
        "remediation": """
        1. Navigate to IAM & Admin > IAM in the Cloud Console
        2. Identify the members with Service Account User or Service Account Token Creator roles
        3. Remove these role assignments at the project level
        4. Re-assign the roles at service account level for specific service accounts
        """,
        "audit": """
        From Console:
        1. Go to IAM & Admin > IAM
        2. Review the roles assigned to each member
        3. Identify any members with roles/iam.serviceAccountUser or roles/iam.serviceAccountTokenCreator
        
        From Command Line:
        gcloud projects get-iam-policy PROJECT_ID
        """,
        "references": [
            "https://cloud.google.com/iam/docs/service-accounts",
            "https://cloud.google.com/iam/docs/understanding-roles"
        ]
    },
    "5.1": {
        "id": "5.1",
        "title": "Ensure that Cloud Storage bucket is not anonymously or publicly accessible",
        "profile_applicability": "Level 1",
        "description": "It is recommended that IAM policy on Cloud Storage bucket does not allow anonymous or public access.",
        "rationale": """
        Allowing anonymous or public access grants permissions to anyone to access bucket content. 
        Such access might be useful for hosting static content but should be restricted for confidential data.
        """,
        "impact": "High - Allows anyone on the internet to access bucket content",
        "remediation": """
        1. Go to Cloud Storage in the Cloud Console
        2. Select the bucket with public access
        3. Go to Permissions tab
        4. Remove 'allUsers' and 'allAuthenticatedUsers' members
        5. Enable uniform bucket-level access
        6. Set public access prevention to 'enforced'
        """,
        "audit": """
        From Console:
        1. Go to Cloud Storage
        2. Select the bucket
        3. Check Permissions for 'allUsers' or 'allAuthenticatedUsers'
        4. Verify uniform bucket-level access is enabled
        5. Verify public access prevention is enforced
        
        From Command Line:
        gsutil iam get gs://BUCKET_NAME
        gsutil uniformbucketlevelaccess get gs://BUCKET_NAME
        """,
        "references": [
            "https://cloud.google.com/storage/docs/access-control/iam",
            "https://cloud.google.com/storage/docs/uniform-bucket-level-access"
        ]
    }
}
