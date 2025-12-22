data "aws_caller_identity" "member" {
  #  provider = aws.member
}

data "aws_partition" "member" {
  #provider = aws.member
}

data "aws_region" "member" {
  #provider = aws.member
}

########## SCP to limit access to specific regions
##########   //start//
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
########## SCP to limit access to specific regions
##########   //end//

########## CloudTrail logging to separate account
##########   //start//
resource "aws_cloudtrail" "member_trail" {
  #  provider = aws.member
  depends_on = [
    aws_s3_bucket_policy.cloudtrail_access,
    aws_kms_key_policy.member_key_policy
  ]

  name                          = "management-events-trail"
  s3_bucket_name                = aws_s3_bucket.central_log_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true
  kms_key_id                    = aws_kms_key.member_key.arn

  tags = {
    Name = "management-events-trail"
  }
}

resource "aws_kms_key" "member_key" {
  #provider    = aws.member
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
  #provider = aws.member
  key_id = aws_kms_key.member_key.id
  policy = data.aws_iam_policy_document.kms_cloudtrail_access.json
}

resource "aws_s3_bucket" "central_log_bucket" {
  provider = aws.mgmt

  bucket = "chpr-org-mz-central-cloudtrail"
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
  #  member_trail_arn = provider::aws::arn_build("aws", "cloudtrail", "*", data.aws_caller_identity.member.account_id, "trail/*management-events-trail")
  member_trail_arns = [
    "arn:aws:cloudtrail:us-east-1:${data.aws_caller_identity.member.account_id}:trail/management-events-trail",
    "arn:aws:cloudtrail:us-west-2:${data.aws_caller_identity.member.account_id}:trail/management-events-trail",
  ]
}

#        aws_cloudtrail.member_trail.arn

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
      #      values   = [aws_cloudtrail.member_trail.arn]
      values = local.member_trail_arns
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
      #      values   = local.member_trail_arns
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      #      values   = [aws_cloudtrail.member_trail.arn]
      values = local.member_trail_arns
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
      #values   = [aws_cloudtrail.member_trail.arn]
      values = local.member_trail_arns
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
########## CloudTrail logging to separate account
##########   //end//

########## Config Rules for compliance checking
##########   //start//
#resource "aws_iam_service_linked_role" "member_config" {
#  aws_service_name = "configservice.amazonaws.com"
#}
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
  name        = "AWS-QuickSetup-LocalAdministrationRole"
  description = "Role used by SSM QuickSetup in local account to assume local execution role"
  #  path = "/service-role/"
  assume_role_policy = data.aws_iam_policy_document.cfn_assume_role_policy.json
  #  inline_policy {
  #  name = "inline-ssm-admin-policy"
  #  policy = data.aws_iam_policy_document.member_ssm_admin.json
  #}

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

#resource "aws_iam_role_policy_attachment" "member_cfn_admin" {
#  role = aws_iam_role.member_cloudformation_role.name
#  policy_arn = "arn:aws:iam::aws:policy/AWSCloudFormationFullAccess"
#}

data "aws_iam_policy_document" "ssm_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      #      identifiers = [aws_iam_role.member_ssm_admin_role.arn]
      #      identifiers = ["arn:aws:iam::${data.aws_caller_identity.member.account_id}:role/service-role/AWS-QuickSetup-LocalAdministrationRole"]
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.member.account_id}:role/AWS-QuickSetup-LocalAdministrationRole"]
    }
  }
}

resource "aws_iam_role" "member_ssm_exec_role" {
  name        = "AWS-QuickSetup-LocalExecutionRole"
  description = "Execution role used by SSM QuickSetup in local account"
  #  path = "/service-role/"
  #  assume_role_policy = data.aws_iam_policy_document.default_assume_role_policy.json
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

resource "aws_ssmquicksetup_configuration_manager" "member_config_quicksetup" {
  #  provider = aws.member
  name = "config-recording-all-regions"

  configuration_definition {
    type                                     = "AWSQuickSetupType-CFGRecording"
    local_deployment_administration_role_arn = aws_iam_role.member_ssm_admin_role.arn
    local_deployment_execution_role_name     = aws_iam_role.member_ssm_exec_role.name
    parameters = {
      "RecordAllResources" : true,
      "GlobalResourceTypesRegion" : data.aws_region.member.region,
      "DeliveryBucketName" : aws_s3_bucket.member_config.bucket,
      "TargetAccounts" : data.aws_caller_identity.member.account_id,
      "TargetRegions" : join(",", var.allowed_regions)
    }
  }

  tags = {
    Name = "config-recording-all-regions"
  }
}

resource "aws_iam_service_linked_role" "member_config" {
  #provider         = aws.member
  aws_service_name = "config.amazonaws.com"
}

#resource "aws_config_delivery_channel" "member" {
#  provider = aws.member
#  depends_on     = [aws_config_configuration_recorder.member]
#
#  s3_bucket_name = aws_s3_bucket.member_config.bucket
#  sns_topic_arn = aws_sns_config.member_notifications
#  snapshot_delivery_properties {
#    delivery_frequency = "One_Hour"
#  }
#}

#resource "aws_sns_topic" "member_config_delivery" {
#  name = "config-delivery-topic"
#  kms_master_key_id = "alias/aws/sns"
#}

resource "aws_s3_bucket" "member_config" {
  #provider = aws.member

  #  bucket        = "chprorg-${data.aws_caller_identity.member.account_id}-${data.aws_region.member.region}"
  bucket = "config-bucket-${data.aws_caller_identity.member.account_id}"
  #  force_destroy = true

  tags = {
    Name = "config-bucket-${data.aws_caller_identity.member.account_id}"
  }
}

resource "aws_s3_bucket_policy" "config_access" {
  #provider = aws.member

  bucket = aws_s3_bucket.member_config.id
  policy = data.aws_iam_policy_document.config_access.json
}

data "aws_iam_policy_document" "config_access" {
  statement {
    sid    = "AWSConfigBucketCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = [
      "s3:GetBucketAcl",
      "s3:ListBucket"
    ]
    resources = [aws_s3_bucket.member_config.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.member.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.member_config.arn}/AWSLogs/${data.aws_caller_identity.member.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.member.account_id]
    }
  }
}


#resource "aws_config_configuration_recorder" "member" {
#  provider = aws.member
#
#  name     = "member-config-recorder"
#  role_arn = aws_iam_role.r.arn
#}
#
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
#resource "aws_iam_role" "r" {
#  name               = "awsconfig-example"
#  assume_role_policy = data.aws_iam_policy_document.assume_role.json
#}

resource "aws_config_config_rule" "member_guardrails_global" {
  #provider = aws.member
  #  depends_on = [aws_config_configuration_recorder.member]
  depends_on = [aws_ssmquicksetup_configuration_manager.member_config_quicksetup]

  for_each = toset(var.desired_managed_rules_global)
  name     = each.key

  source {
    owner             = "AWS"
    source_identifier = each.key
  }

  tags = {
    Name = "Baseline__${each.key}"
  }
}

#locals {
#  rules_by_region = [
#    for pair in setproduct(var.allowed_regions, var.desired_managed_rules_regional) : {
#      region_key = pair[0]
#      rule_key   = pair[1]
#    }
#  ]
#}

resource "aws_config_config_rule" "member_guardrails_region0" {
  #provider = aws.member
  #  depends_on = [aws_config_configuration_recorder.foo]

  #  for_each = tomap({
  #  for rule in local.rules_by_region : 
  #    "${rule.rule_key}_${rule.region_key}" => rule
  #})

  for_each = toset(var.desired_managed_rules_regional)
  name     = each.key

  source {
    owner             = "AWS"
    source_identifier = each.key
  }

  tags = {
    Name = "Baseline__${each.key}"
  }
}

resource "aws_config_config_rule" "member_guardrails_region1" {
  #provider = aws.member
  region = one(setsubtract(toset(var.allowed_regions), toset([var.primary_region])))
  #  depends_on = [aws_config_configuration_recorder.foo]

  for_each = toset(var.desired_managed_rules_regional)
  name     = each.key

  source {
    owner             = "AWS"
    source_identifier = each.key
  }

  tags = {
    Name = "Baseline__${each.key}"
  }
}
########## Config Rules for compliance checking
##########   //end//



########## Baseline IAM Roles
##########   //start//
data "aws_iam_policy_document" "default_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.member.account_id}:root"]
    }
  }
}

#data "aws_iam_policy_document" "default_boundary_policy" {
#
#}

#resource "aws_iam_policy" "default_boundary_policy" {
#  name   = "boundary-policy-standard"
#  path   = "/base/"
#  #  policy = data.aws_iam_policy_document.default_boundary_policy.json
#  policy = file("${path.module}/policy/default_boundary.json")
#}

resource "aws_iam_role" "readonly_admin" {
  #provider             = aws.member
  name               = "ReadOnlyAdmin"
  description        = "Baseline read-only role"
  path               = "/base/"
  assume_role_policy = data.aws_iam_policy_document.default_assume_role_policy.json
  #  permissions_boundary = aws_iam_policy.default_boundary_policy.arn
}

resource "aws_iam_role_policy_attachment" "readonly_managed" {
  #provider   = aws.member
  role       = aws_iam_role.readonly_admin.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role" "developer" {
  #provider             = aws.member
  name               = "Developer"
  description        = "Baseline developer role"
  path               = "/base/"
  assume_role_policy = data.aws_iam_policy_document.default_assume_role_policy.json
  #  permissions_boundary = aws_iam_policy.default_boundary_policy.arn
  tags = {
    env = "dev"
  }
}

resource "aws_iam_role_policy_attachment" "dev_readonly" {
  role       = aws_iam_role.developer.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "dev_poweruser" {
  role       = aws_iam_role.developer.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

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

resource "aws_iam_policy" "restricted_iam_policy" {
  name        = "deny-iam-unless-tags-match"
  path        = "/base/"
  description = "Deny IAM actions unless principal and resource env tags match"
  policy      = file("${path.module}/policy/iam-deny-unless-tags-match.json")
  tags = {
    Name = "deny-iam-unless-tags-match"
  }
}

resource "aws_iam_role_policy_attachment" "dev_restricted_iam" {
  role       = aws_iam_role.developer.name
  policy_arn = aws_iam_policy.restricted_iam_policy.arn
}

resource "aws_iam_role" "database_admin" {
  name               = "DatabaseAdmin"
  description        = "Baseline database administrator role, initially based on AWS-managed job function policy"
  path               = "/base/"
  assume_role_policy = data.aws_iam_policy_document.default_assume_role_policy.json
  #  permissions_boundary = aws_iam_policy.default_boundary_policy.arn
  tags = {
    Name = "DatabaseAdmin"
  }
}

resource "aws_iam_role_policy_attachment" "database_admin_managed" {
  #provider   = aws.member
  role       = aws_iam_role.database_admin.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/DatabaseAdministrator"
}

########## Baseline IAM Roles
##########   //end//
