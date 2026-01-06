data "aws_caller_identity" "member" {}

data "aws_partition" "member" {}

data "aws_region" "member" {}


########## start: SCP to limit access to specific regions
resource "aws_organizations_policy" "restrict_regions" {
  provider = aws.mgmt

  name    = "restrict-to-allowed-regions-only"
  type    = "SERVICE_CONTROL_POLICY"
  content = file("${path.module}/policy/scp-restrict-regions.json")

  tags = {
    Name = "restrict-to-allowed-regions-only"
  }
}

resource "aws_organizations_policy_attachment" "account" {
  provider = aws.mgmt

  policy_id = aws_organizations_policy.restrict_regions.id
  target_id = data.aws_caller_identity.member.account_id
}
########## end: SCP to limit access to specific regions


########## start: CloudTrail logging to separate account
resource "aws_cloudtrail" "member_trail" {
  depends_on = [
    aws_s3_bucket_policy.cloudtrail_access,
    aws_kms_key_policy.member_key_policy
  ]

  name                          = var.member_trail_name
  s3_bucket_name                = aws_s3_bucket.central_log_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true
  kms_key_id                    = aws_kms_key.member_key.arn

  tags = {
    Name = var.member_trail_name
  }
}

resource "aws_kms_key" "member_key" {
  description = "CloudTrail log encryption key"

  tags = {
    Name = "cloudtrail-key-${data.aws_caller_identity.member.account_id}"
  }
}

resource "aws_kms_alias" "member_key" {
  name          = "alias/cloudtrail-key-${data.aws_caller_identity.member.account_id}"
  target_key_id = aws_kms_key.member_key.key_id
}

resource "aws_kms_key_policy" "member_key_policy" {
  key_id = aws_kms_key.member_key.id
  policy = data.aws_iam_policy_document.kms_cloudtrail_access.json
}

resource "aws_s3_bucket" "central_log_bucket" {
  provider = aws.mgmt

  bucket = "chpr-org-mz-central-cloudtrail"

  ## Uncomment only if destroying and redeploying from scratch
  #force_destroy = true

  tags = {
    Name = "chpr-org-mz-central-cloudtrail"
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_access" {
  provider = aws.mgmt

  bucket = aws_s3_bucket.central_log_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_access.json
}

locals {
  # List of possible CloudTrail ARNs must be pre-generated to avoid a cycle dependency error
  member_trail_arns = [
    for reg in var.allowed_regions :
    "arn:aws:cloudtrail:${reg}:${data.aws_caller_identity.member.account_id}:trail/${var.member_trail_name}"
  ]
}

data "aws_iam_policy_document" "cloudtrail_access" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.central_log_bucket.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = local.member_trail_arns
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.central_log_bucket.arn}/AWSLogs/${data.aws_caller_identity.member.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = local.member_trail_arns
    }
  }

  statement {
    sid    = "PolicyGenerationBucketPolicy"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.member.account_id}:root"]
    }
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.central_log_bucket.arn,
      "${aws_s3_bucket.central_log_bucket.arn}/AWSLogs/${data.aws_caller_identity.member.account_id}/*"
    ]
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam:::${data.aws_caller_identity.member.account_id}:role/service-role/AccessAnalyzerMonitorServiceRole*"]
    }
  }
}

data "aws_iam_policy_document" "kms_cloudtrail_access" {
  statement {
    sid    = "EnableIAMUserPermissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.member.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "EnableCloudTrailEncryptDecrypt"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*"
    ]
    resources = ["*"]

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.member.account_id}:trail/*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = local.member_trail_arns
    }
  }

  statement {
    sid    = "EnableCloudTrailDescribeKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = local.member_trail_arns
    }
  }

  statement {
    sid    = "AllowAccountPrincipalsDecryptLogs"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.member.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.member.account_id}:trail/*"]
    }
  }
}
########## end: CloudTrail logging to separate account


########## start: AWS Config setup for compliance checking using SSM Quick Setup
data "aws_iam_policy_document" "cfn_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudformation.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "member_ssm_admin_role" {
  name               = "AWS-QuickSetup-LocalAdministrationRole"
  description        = "Role used by SSM QuickSetup in local account to assume local execution role"
  assume_role_policy = data.aws_iam_policy_document.cfn_assume_role_policy.json

  tags = {
    Name = "AWS-QuickSetup-LocalAdministrationRole"
  }
}

resource "aws_iam_role_policy" "member_ssm_admin_policy" {
  name   = "inline-ssm-admin-policy"
  role   = aws_iam_role.member_ssm_admin_role.name
  policy = data.aws_iam_policy_document.member_ssm_admin.json
}

data "aws_iam_policy_document" "member_ssm_admin" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.member_ssm_exec_role.arn]
  }
}

data "aws_iam_policy_document" "ssm_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.member.account_id}:role/AWS-QuickSetup-LocalAdministrationRole"]
    }
  }
}

resource "aws_iam_role" "member_ssm_exec_role" {
  name               = "AWS-QuickSetup-LocalExecutionRole"
  description        = "Execution role used by SSM QuickSetup in local account"
  assume_role_policy = data.aws_iam_policy_document.ssm_assume_role_policy.json

  tags = {
    Name = "AWS-QuickSetup-LocalExecutionRole"
  }
}

resource "aws_iam_role_policy_attachment" "member_ssm_deployment" {
  role       = aws_iam_role.member_ssm_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSQuickSetupSSMDeploymentRolePolicy"
}

resource "aws_iam_role_policy_attachment" "member_qs_deployment" {
  role       = aws_iam_role.member_ssm_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSQuickSetupDeploymentRolePolicy"
}

resource "aws_iam_service_linked_role" "member_config" {
  aws_service_name = "config.amazonaws.com"
}

resource "aws_ssmquicksetup_configuration_manager" "member_config_quicksetup" {
  depends_on = [aws_iam_service_linked_role.member_config]
  name       = "config-recording-all-regions"

  configuration_definition {
    type                                     = "AWSQuickSetupType-CFGRecording"
    local_deployment_administration_role_arn = aws_iam_role.member_ssm_admin_role.arn
    local_deployment_execution_role_name     = aws_iam_role.member_ssm_exec_role.name
    parameters = {
      "RecordAllResources" : true,
      "RecordGlobalResourceTypes" : true,
      "GlobalResourceTypesRegion" : var.primary_region,
      "UseCustomBucket" : false, #allow quicksetup to create bucket for delivery channel
      "DeliveryBucketName" : "", #allow quicksetup to create bucket for delivery channel
      "TargetAccounts" : data.aws_caller_identity.member.account_id,
      "TargetRegions" : join(",", var.allowed_regions)
    }
  }

  tags = {
    Name = "config-recording-all-regions"
  }
}
########## end: AWS Config setup for compliance checking using SSM Quick Setup


########## start: Alternative approach to AWS Config setup (without Quick Setup)
### S3 bucket for Config delivery channel must be setup manually
###
#resource "aws_s3_bucket" "member_config" {
#
#  #  Default naming convention
#  bucket = "config-bucket-${data.aws_caller_identity.member.account_id}"
#  #  force_destroy = true
#
#  tags = {
#    Name = "config-bucket-${data.aws_caller_identity.member.account_id}"
#  }
#}
#
#resource "aws_s3_bucket_policy" "config_access" {
#  #provider = aws.member
#
#  bucket = aws_s3_bucket.member_config.id
#  policy = data.aws_iam_policy_document.config_access.json
#}
#
### Service role for AWS Config must be created
##
#data "aws_iam_policy_document" "assume_role" {
#  statement {
#    effect = "Allow"
#
#    principals {
#      type        = "Service"
#      identifiers = ["config.amazonaws.com"]
#    }
#
#    actions = ["sts:AssumeRole"]
#  }
#}
#
#resource "aws_iam_role" "awsconfig-example" {
#  name               = "awsconfig-example"
#  assume_role_policy = data.aws_iam_policy_document.assume_role.json
#}
#data "aws_iam_policy_document" "config_access" {
#  statement {
#    sid    = "AWSConfigBucketCheck"
#    effect = "Allow"
#
#    principals {
#      type        = "Service"
#      identifiers = ["config.amazonaws.com"]
#    }
#    actions = [
#      "s3:GetBucketAcl",
#      "s3:ListBucket"
#    ]
#    resources = [aws_s3_bucket.member_config.arn]
#    condition {
#      test     = "StringEquals"
#      variable = "aws:SourceAccount"
#      values   = [data.aws_caller_identity.member.account_id]
#    }
#  }
#
#  statement {
#    sid    = "AWSConfigBucketDelivery"
#    effect = "Allow"
#
#    principals {
#      type        = "Service"
#      identifiers = ["config.amazonaws.com"]
#    }
#
#    actions   = ["s3:PutObject"]
#    resources = ["${aws_s3_bucket.member_config.arn}/AWSLogs/${data.aws_caller_identity.member.account_id}/Config/*"]
#    condition {
#     test     = "StringEquals"
#     variable = "s3:x-amz-acl"
#     values   = ["bucket-owner-full-control"]
#   }
#   condition {
#     test     = "StringEquals"
#     variable = "aws:SourceAccount"
#     values   = [data.aws_caller_identity.member.account_id]
#   }
# }
#}
#
### IMPORTANT: Delivery Channel must be set up in each region
###
#resource "aws_config_delivery_channel" "member" {
#  provider = aws.member
#  depends_on     = [aws_config_configuration_recorder.member]
#
#  s3_bucket_name = aws_s3_bucket.member_config.bucket
#  snapshot_delivery_properties {
#    delivery_frequency = "One_Hour"
#  }
#}
#
### IMPORTANT: Configuration Recorder must be set up in each region
###
#resource "aws_config_configuration_recorder" "member" {
#  provider = aws.member
#
#  name     = "member-config-recorder"
#  role_arn = aws_iam_role.r.arn
#}
########## end: Alternative approach to AWS Config setup (without Quick Setup)


########## start: Config Rules for compliance checking
resource "aws_config_config_rule" "member_guardrails_all" {
  depends_on = [aws_ssmquicksetup_configuration_manager.member_config_quicksetup]

  for_each = tomap(local.all_managed_rules)
  name     = each.key
  region   = each.value.region

  source {
    owner             = "AWS"
    source_identifier = each.value.rule_id
  }

  input_parameters = each.value.parameters != null ? jsonencode(each.value.parameters) : null

  tags = {
    Name = "${each.key}"
  }
}

locals {
  global_rules = [
    for rule in toset(var.desired_managed_config_rules) : {
      region     = var.primary_region
      rule_id    = rule.rule_id
      parameters = rule.parameters
    } if rule.global
  ]
  regional_rules = [
    for pair in setproduct(var.allowed_regions, var.desired_managed_config_rules) : {
      region     = pair[0]
      rule_id    = pair[1].rule_id
      parameters = pair[1].parameters
    } if !pair[1].global
  ]
  all_managed_rules = {
    for rule in toset(concat(local.global_rules, local.regional_rules)) :
    "${rule.rule_id}__${rule.region}" => rule
  }
}
########## end: Config Rules for compliance checking


########## start: Baseline IAM Roles
data "aws_iam_policy_document" "default_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.member.account_id}:root"]
    }
  }
}

#### ReadOnlyAdmin role
####
resource "aws_iam_role" "readonly_admin" {
  name               = "ReadOnlyAdmin"
  description        = "Baseline read-only role"
  path               = "/base/"
  assume_role_policy = data.aws_iam_policy_document.default_assume_role_policy.json
  tags = {
    Name = "ReadOnlyAdmin"
  }
}

## 'ReadOnlyAccess' (AWS-managed policy) provides access to view all
##    services, configuration, and data (including secrets!)
resource "aws_iam_role_policy_attachment" "readonly_managed" {
  role       = aws_iam_role.readonly_admin.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

#### Developer role
####
resource "aws_iam_role" "developer" {
  name               = "Developer"
  description        = "Baseline developer role"
  path               = "/base/"
  assume_role_policy = data.aws_iam_policy_document.default_assume_role_policy.json
  tags = {
    Name = "Developer"
    env  = "dev"
  }
}

## 'PowerUserAccess' (AWS-managed policy) provides near-Administrator access,
##    except for IAM, Billing, Organizations, and Account Management
resource "aws_iam_role_policy_attachment" "dev_poweruser" {
  role       = aws_iam_role.developer.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

## Custom policy grants read-only IAM permissions to enable developers to
##    troubleshoot access issues
resource "aws_iam_policy" "allow_iam_readonly_policy" {
  name        = "allow-iam-readonly"
  path        = "/base/"
  description = "Allow IAM read-only and simulate policy actions"
  policy      = file("${path.module}/policy/iam-allow-iam-readonly.json")
  tags = {
    Name = "allow-iam-readonly"
  }
}

resource "aws_iam_role_policy_attachment" "dev_iam_readonly" {
  role       = aws_iam_role.developer.name
  policy_arn = aws_iam_policy.allow_iam_readonly_policy.arn
}

## Custom policy to deny access to resources that are not tagged with an
##    'env' value matching the value of the IAM principal
resource "aws_iam_policy" "restrict_nonmatching_tags_policy" {
  name        = "deny-unless-tags-match"
  path        = "/base/"
  description = "Deny actions unless principal and resource env tags match"
  policy      = file("${path.module}/policy/iam-deny-unless-tags-match.json")
  tags = {
    Name = "deny-unless-tags-match"
  }
}

resource "aws_iam_role_policy_attachment" "dev_restrict_nonmatching_tags" {
  role       = aws_iam_role.developer.name
  policy_arn = aws_iam_policy.restrict_nonmatching_tags_policy.arn
}

#### DatabaseAdmin role
####
resource "aws_iam_role" "database_admin" {
  name               = "DatabaseAdmin"
  description        = "Baseline database administrator role, initially based on AWS-managed job function policy"
  path               = "/base/"
  assume_role_policy = data.aws_iam_policy_document.default_assume_role_policy.json
  tags = {
    Name = "DatabaseAdmin"
  }
}

## 'DatabaseAdministrator' (AWS-managed policy) provides broad access to
##    data services like DynamoDB, ElastiCache, and RDS
resource "aws_iam_role_policy_attachment" "database_admin_managed" {
  role       = aws_iam_role.database_admin.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/DatabaseAdministrator"
}
########## end: Baseline IAM Roles
