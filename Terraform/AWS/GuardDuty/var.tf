#Provides a GuardDuty detector
variable "enable_detector" {
  type              = bool
  description       = "Enable monitoring and feedback reporting. Setting to false is equivalent to suspending GuardDuty. Defaults to true."
  default           = true
}

variable "detector_publishing_frequency" {
  type              = string
  description       = "Specifies the frequency of notifications sent for subsequent finding occurrences. If the detector is a GuardDuty member account, the value is determined by the GuardDuty primary account and cannot be modified, otherwise defaults to SIX_HOURS. For standalone and GuardDuty primary accounts, it must be configured in Terraform to enable drift detection. Valid values for standalone and primary accounts: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  default           = ""
}

variable "tags" {
  type              = map
  description       = "Tag for the resource"
  default           = {}
}

#Provides a resource to manage a GuardDuty member.
variable "email" {
  type              = string
  description       = "Email address for member account."
  default           = ""
}

variable "invite" {
  type              = bool
  description       = "Boolean whether to invite the account to GuardDuty as a member. Defaults to false. To detect if an invitation needs to be (re-)sent, the Terraform state value is true based on a relationship_status of Disabled, Enabled, Invited, or EmailVerificationInProgress."
  default           = null
}

variable "invitation_message" {
  type              = string
  description       = "Message for invitation."
  default           = ""
}

variable "disable_email_notification" {
  type              = bool
  description       = "Boolean whether an email notification is sent to the accounts. Defaults to false."
  default           = false
}

#Provides GuardDuty Detector filter
variable "filter_name" {
  type              = string
  description       = "Name of filter"
}

variable "filter_action" {
  type              = string
  description       = "Specifies the action that is to be applied to the findings that match the filter. Can be one of ARCHIVE or NOOP."
}

variable "filter_rank" {
  type              = number
  description       = "Specifies the position of the filter in the list of current filters. Also specifies the order in which this filter is applied to the findings."
}

variable "filter_criteria" {
  type              = map
  description       = "Represents the criteria to be used in the filter for querying findings. Contains one or more criterion blocks"
}

#Detector ipset
variable "activate_ipset" {
  type              = bool
  description       = "Specifies whether GuardDuty is to start using the uploaded IPSet."
}

variable "ipset_format" {
  type              = string
  description       = "he format of the file that contains the IPSet. Valid values: TXT | STIX | OTX_CSV | ALIEN_VAULT | PROOF_POINT | FIRE_EYE"
}

variable "ipset_URI" {
  type              = string
  description       = "The URI of the file that contains the IPSet."
}

variable "ipset_name" {
  type              = string
  description       = "The friendly name to identify the IPSet."
}

#Create Detector publishing location
variable "bucket_name" {
  type              = string
  description       = "s3 bucket name"
}

variable "bucket_force_destroy" {
  type              = bool
  description       = ""
}

variable "kms_key_description" {
  type              = string
  description       = "Descripion of KMS key"
}

variable "kms_key_deletion_window" {
  type              = number
  description       = ""
}

#GuardDuty ThreatIntelSet.
variable "activate_threat_intel_set" {
  type              = bool
  description       = "Specifies whether GuardDuty is to start using the uploaded ThreatIntelSet."
}

variable "threat_intel_set_format" {
  type              = string
  description       = "The format of the file that contains the ThreatIntelSet. Valid values: TXT | STIX | OTX_CSV | ALIEN_VAULT | PROOF_POINT | FIRE_EYE"
}

variable "threat_intel_set_URI" {
  type              = string
  description       = "The URI of the file that contains the ThreatIntelSet."
}

variable "threat_intel_set_name" {
  type              = string
  description       = "The friendly name to identify the ThreatIntelSet."
}

