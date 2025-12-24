# Automated Account Governance and Security Baseline

## Overview
Terraform configuration that implements a governance and security configuration baseline for an AWS account within an AWS organization.

## Controls implemented from AWS Organizations management account

### Centralized CloudTrail log bucket

### Security Control Policy - deny all regions except us-east-1 and us-west-2


## Controls implemented from AWS member account

### CloudTrail multi-region trail

#### KMS customer-managed key

### AWS Config

#### SSM QuickSetup

#### AWS-managed Config Rules

1. [IAM_PASSWORD_POLICY]() (global)
1. [IAM_ROOT_ACCESS_KEY_CHECK]() (global)
1. [ROOT_ACCOUNT_MFA_ENABLED]() (global)
1. [CLOUDTRAIL_SECURITY_TRAIL_ENABLED]() (regional)
1. [EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK]() (regional)
1. [EC2_EBS_ENCRYPTION_BY_DEFAULT]() (regional)
1. [EFS_FILESYSTEM_CT_ENCRYPTED]() (regional)
1. [EFS_MOUNT_TARGET_PUBLIC_ACCESSIBLE]() (regional)
1. [LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED]() (regional)
1. [RDS_CLUSTER_ENCRYPTED_AT_REST]() (regional)
1. [RDS_INSTANCE_PUBLIC_ACCESS_CHECK]() (regional)
1. [RDS_SNAPSHOT_ENCRYPTED]() (regional)
1. [RDS_STORAGE_ENCRYPTED]() (regional)
1. [RDS_SNAPSHOTS_PUBLIC_PROHIBITED]() (regional)
1. [REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK]() (regional)
1. [S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED]() (regional)

### IAM roles and policies

#### Role: Read-only administrator

- Trust Policy (custom)
- Permissions Policy (AWS-managed): ReadOnlyAccess

#### Role: Database administrator

- Trust Policy (custom)
- Permissions Policy (AWS-managed): DatabaseAdministrator

#### Role: Developer

- Trust Policy (custom)
- Permissions Policy (AWS-managed): PowerUserAccess
- Permissions Policy (AWS-managed): ReadOnlyAccess
- Permissions Policy (customer-managed): 
- Permissions Policy (customer-managed): `deny-iam-unless-tags-match`
