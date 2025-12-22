variable "primary_region" {
  type        = string
  description = "Home region for the account"
  default     = "us-east-1"
}

variable "allowed_regions" {
  type        = list(string)
  description = "List of regions that are allowed"
  default     = ["us-east-1", "us-west-2"]
}

variable "desired_managed_rules_regional" {
  type        = list(string)
  description = "List of AWS Managed Config Rules that should be enabled"
  default = [
    #    "CLOUDTRAIL_S3_BUCKET_PUBLIC_ACCESS_PROHIBITED",
    "CLOUDTRAIL_SECURITY_TRAIL_ENABLED",
    "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK",
    "EC2_EBS_ENCRYPTION_BY_DEFAULT",
    "EFS_FILESYSTEM_CT_ENCRYPTED",
    "EFS_MOUNT_TARGET_PUBLIC_ACCESSIBLE",
    "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED",
    "RDS_CLUSTER_ENCRYPTED_AT_REST",
    "RDS_INSTANCE_PUBLIC_ACCESS_CHECK",
    "RDS_SNAPSHOT_ENCRYPTED",
    "RDS_STORAGE_ENCRYPTED",
    "RDS_SNAPSHOTS_PUBLIC_PROHIBITED",
    "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK",
    "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  ]
}

variable "desired_managed_rules_global" {
  type        = list(string)
  description = "List of AWS Managed Config Rules that should be enabled for global resources"
  default = [
    #    "ACCESS_KEYS_ROTATED",
    "IAM_PASSWORD_POLICY",
    "IAM_ROOT_ACCESS_KEY_CHECK",
    "ROOT_ACCOUNT_MFA_ENABLED"
  ]
}
