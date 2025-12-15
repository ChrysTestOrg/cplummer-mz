data "aws_caller_identity" "member" {
  provider = aws.member
}

data "aws_partition" "member" {
  provider = aws.member
}

data "aws_region" "member" {
  provider = aws.member
}

########## SCP to limit access to specific regions
##########   //start//
resource "aws_organizations_policy" "restrict_regions" {
  name    = "restrict-to-allowed-regions-only"
  type    = "SERVICE_CONTROL_POLICY"
  content = file("${path.module}/policy/scp-restrict-regions.json")
}

resource "aws_organizations_policy_attachment" "account" {
  policy_id = aws_organizations_policy.restrict_regions.id
  target_id = data.aws_caller_identity.member.account_id
}
########## SCP to limit access to specific regions
##########   //end//

########## CloudTrail logging to separate account
##########   //start//
resource "aws_cloudtrail" "member_trail" {
  provider = aws.member

  name                          = "management-events-trail"
  s3_bucket_name                = aws_s3_bucket.central_log_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true
  kms_key_id                    = aws_kms_key.member_key.arn
}

resource "aws_kms_key" "member_key" {
  provider    = aws.member
  description = "CloudTrail log encryption key"
}

resource "aws_kms_key_policy" "member_key_policy" {
  provider = aws.member
  key_id   = aws_kms_key.member_key.id
  policy   = data.aws_iam_policy_document.kms_cloudtrail_access.json
}

resource "aws_s3_bucket" "central_log_bucket" {
  bucket        = "chpr-org-mz-central-cloudtrail"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "cloudtrail_access" {
  bucket = aws_s3_bucket.central_log_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_access.json
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
      values = [
        aws_cloudtrail.member_trail.arn
      ]
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
      values   = [aws_cloudtrail.member_trail.arn]
    }
  }
}

data "aws_iam_policy_document" "kms_cloudtrail_access" {
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
      values   = [aws_cloudtrail.member_trail.arn]
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
    resources = [aws_kms_key.member_key.id]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudtrail.member_trail.arn]
    }
  }
}
########## CloudTrail logging to separate account
##########   //end//

########## Config Rules for compliance checking
##########   //start//
resource "aws_ssmquicksetup_configuration_manager" "example" {
  provider = aws.member
  name     = "config-recording-all-regions"

  configuration_definition {
    type = "AWSQuickSetupType-CFGRecording"
    parameters = {
      "RecordAllResources" : true,
      "GlobalResourceTypesRegion" : data.aws_region.member.region,
      "DeliveryBucketName" : aws_s3_bucket.member_config.bucket,
      "TargetRegions" : join(",", var.allowed_regions)
    }
  }
}

resource "aws_iam_service_linked_role" "member_config" {
  provider         = aws.member
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
  provider = aws.member

  #  bucket        = "chprorg-${data.aws_caller_identity.member.account_id}-${data.aws_region.member.region}"
  bucket        = "config-bucket-${data.aws_caller_identity.member.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "config_access" {
  provider = aws.member

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
  provider = aws.member
  #  depends_on = [aws_config_configuration_recorder.foo]

  for_each = toset(var.desired_managed_rules_global)
  name     = each.key

  source {
    owner             = "AWS"
    source_identifier = each.key
  }
}

locals {
  rules_by_region = [
    for pair in setproduct(var.allowed_regions, var.desired_managed_rules_regional) : {
      region_key = pair[0]
      rule_key   = pair[1]
    }
  ]
}

resource "aws_config_config_rule" "member_guardrails_region0" {
  provider = aws.member
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
}

resource "aws_config_config_rule" "member_guardrails_region1" {
  provider = aws.member
  region   = one(setsubtract(toset(var.allowed_regions), toset([var.primary_region])))
  #  depends_on = [aws_config_configuration_recorder.foo]

  for_each = toset(var.desired_managed_rules_regional)
  name     = each.key

  source {
    owner             = "AWS"
    source_identifier = each.key
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

data "aws_iam_policy_document" "default_boundary_policy" {

}

resource "aws_iam_policy" "default_boundary_policy" {
  name   = "boundary-policy-standard"
  path   = "/base/"
  policy = data.aws_iam_policy_document.default_boundary_policy.json
}

resource "aws_iam_role" "readonly_admin" {
  provider             = aws.member
  name                 = "ReadOnlyAdmin"
  path                 = "/base/"
  assume_role_policy   = data.aws_iam_policy_document.default_assume_role_policy.json
  permissions_boundary = aws_iam_policy.default_boundary_policy.arn
}

resource "aws_iam_role_policy_attachment" "readonly_managed" {
  provider   = aws.member
  role       = aws_iam_role.readonly_admin
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role" "developer" {
  provider             = aws.member
  name                 = "Developer"
  path                 = "/base/"
  assume_role_policy   = data.aws_iam_policy_document.default_assume_role_policy.json
  permissions_boundary = aws_iam_policy.default_boundary_policy.arn
}

resource "aws_iam_role" "database_admin" {
  provider             = aws.member
  name                 = "DatabaseAdmin"
  path                 = "/base/"
  assume_role_policy   = data.aws_iam_policy_document.default_assume_role_policy.json
  permissions_boundary = aws_iam_policy.default_boundary_policy.arn
}

########## Baseline IAM Roles
##########   //end//
