#Resource GuardDuty Detector
resource "aws_guardduty_detector" "primary" {
  enable                            = var.enable_detector
  finding_publishing_frequency      = var.detector_publishing_frequency
  
  datasources {
      dynamic "s3_logs" {
          for_each                  = var.detector_datasource != null ? 1 : 0
          content {
              enable                = lookup(detector_datasource , "enable" , true)
          }
      }
  }
  tags                              = var.tags
}

#Provides a resource to manage a GuardDuty filter.
resource "aws_guardduty_filter" "primary" {
  count                             = var.create_filter == 1 ? 1 : 0
  name                              = var.filter_name 
  action                            = var.filter_action
  detector_id                       = aws_guardduty_detector.primary.id
  rank                              = var.filter_rank 

  finding_criteria {
      dynamic "criterion" {
          for_each                  = var.filter_criteria
          content {
              field                 =
              equals                =
              not_equals            =
              greater_than          =
              greater_than_or_equal =
              less_than             =
              less_than_or_equal    =
          }
           
      }
 
  }
}
#Provides a resource to manage a GuardDuty IPSet.
resource "aws_guardduty_ipset" "primary" {
  count                             = var.create_ipset ==  ? 1 : 0
  activate                          = var.activate_ipset
  detector_id                       = aws_guardduty_detector.primary.id
  format                            = var.ipset_format
  location                          = var.ipset_URI
  name                              = var.ipset_name
  tags                              = var.tags 
}

#Provides a resource to manage a GuardDuty PublishingDestination.
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "bucket_pol" {
  statement {
    sid = "Allow PutObject"
    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.this.arn}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid = "Allow GetBucketLocation"
    actions = [
      "s3:GetBucketLocation"
    ]

    resources = [
      aws_s3_bucket.this.arn
    ]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "this" {

  statement {
    sid = "Allow GuardDuty to encrypt findings"
    actions = [
      "kms:GenerateDataKey"
    ]

    resources = [
      "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid = "Allow all users to modify/delete key (test only)"
    actions = [
      "kms:*"
    ]

    resources = [
      "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

}

resource "aws_s3_bucket" "this" {
  count                             = var.create_publishing == 1 ?  : 0
  bucket                            = var.bucket_name
  acl                               = "private"
  force_destroy                     = var.bucket_force_destroy
}

resource "aws_s3_bucket_policy" "this" {
  count                             = var.create_publishing == 1 ?  : 0
  bucket                            = aws_s3_bucket.this.id
  policy                            = data.aws_iam_policy_document.this.json
}

resource "aws_kms_key" "this" {
  count                             = var.create_publishing == 1 ?  : 0
  description                       = var.kms_key_description
  deletion_window_in_days           = var.kms_key_deletion_window
  policy                            = data.aws_iam_policy_document.this.json
}

resource "aws_guardduty_publishing_destination" "this" {
  count                             = var.create_publishing == 1 ?  : 0
  detector_id                       = aws_guardduty_detector.this.id
  destination_arn                   = aws_s3_bucket.this.arn
  kms_key_arn                       = aws_kms_key.this.arn

  depends_on                        = [
    aws_s3_bucket_policy.this,
  ]
}

#Provides a resource to manage a GuardDuty ThreatIntelSet.
resource "aws_guardduty_threatintelset" "this" {
  count                             = var.create_threat_intel_set == 1 ?  : 0
  activate                          = var.activate_threat_intel_set
  detector_id                       = aws_guardduty_detector.primary.id
  format                            = var.threat_intel_set_format
  location                          = var.threat_intel_set_URI
  name                              = var.threat_intel_set_name
  tags                              = var.tags
}
#Resource GuardDuty invite acceptor(Provides a resource to accept a pending GuardDuty invite on creation, ensure the detector has the correct primary account on read, and disassociate with the primary account upon removal.)
resource "aws_guardduty_invite_accepter" "member" {
  count                             = var.create_member == 1 ? 1 : 0
  depends_on                        = [aws_guardduty_member.member]
  #Detector account ID of member account
  detector_id                       = aws_guardduty_detector.member.id 
  #AWS account ID for primary account.
  master_account_id                 = aws_guardduty_detector.primary.account_id
}

#Provides a resource to manage a GuardDuty member.
resource "aws_guardduty_member" "member" {
  count                             = var.create_member == 1 ? 1 : 0
  provider                          = aws.primary
  # AWS account ID of member account
  account_id                        = aws_guardduty_detector.member.account_id
  # Detector ID of primary account
  detector_id                       = aws_guardduty_detector.primary.id
  email                             = var.email
  invite                            = var.invite
  invitation_message                = var.invitation_message
  disable_email_notification        = var.disable_email_notification
}

