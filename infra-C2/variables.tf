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

variable "member_trail_name" {
  type        = string
  description = "Name of the CloudTrail trail to create in the member account"
  default     = "management-events-trail"
}

variable "desired_managed_config_rules" {
  type = list(object({
    rule_id    = string
    global     = bool
    parameters = map(string)
  }))
  description = "List of AWS Managed Config Rules (represented as objects) that should be enabled"
  default = [
    {
      rule_id = "ACCESS_KEYS_ROTATED"
      global  = true
      parameters = {
        maxAccessKeyAge = 90
      }
    },
    {
      rule_id    = "CLOUDTRAIL_S3_BUCKET_PUBLIC_ACCESS_PROHIBITED"
      global     = false
      parameters = null
    },
    {
      rule_id    = "CLOUDTRAIL_SECURITY_TRAIL_ENABLED"
      global     = false
      parameters = null
    },
    {
      rule_id    = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
      global     = false
      parameters = null
    },
    {
      rule_id    = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
      global     = false
      parameters = null
    },
    {
      rule_id    = "EFS_FILESYSTEM_CT_ENCRYPTED"
      global     = false
      parameters = null
    },
    {
      rule_id    = "EFS_MOUNT_TARGET_PUBLIC_ACCESSIBLE"
      global     = false
      parameters = null
    },
    {
      rule_id = "IAM_PASSWORD_POLICY"
      global  = true
      parameters = {
        MinimumPasswordLength      = 14
        RequireUppercaseCharacters = true
        RequireLowercaseCharacters = true
        RequireSymbols             = true
        RequireNumbers             = true
        MaxPasswordAge             = 90
        PasswordReusePrevention    = 24
      }
    },
    {
      rule_id    = "IAM_ROOT_ACCESS_KEY_CHECK"
      global     = true
      parameters = null
    },
    {
      rule_id    = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
      global     = false
      parameters = null
    },
    {
      rule_id    = "RDS_CLUSTER_ENCRYPTED_AT_REST"
      global     = false
      parameters = null
    },
    {
      rule_id    = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
      global     = false
      parameters = null
    },
    {
      rule_id    = "RDS_SNAPSHOT_ENCRYPTED"
      global     = false
      parameters = null
    },
    {
      rule_id    = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
      global     = false
      parameters = null
    },
    {
      rule_id    = "RDS_STORAGE_ENCRYPTED"
      global     = false
      parameters = null
    },
    {
      rule_id    = "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK"
      global     = false
      parameters = null
    },
    {
      rule_id    = "ROOT_ACCOUNT_MFA_ENABLED"
      global     = true
      parameters = null
    },
    {
      rule_id    = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
      global     = false
      parameters = null
    }
  ]
}
