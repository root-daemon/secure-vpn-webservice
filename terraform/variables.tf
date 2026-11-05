variable "project" {
  description = "Short project name used as a prefix for every resource."
  type        = string
  default     = "securevpn"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project))
    error_message = "project must be 3-21 chars, lowercase letters, digits and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, stg, prd)."
  type        = string
  default     = "dev"
}

variable "owner" {
  description = "Owner tag value (your name or team)."
  type        = string
  default     = "cloud-devops-student"
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address that receives alarm and security notifications (confirm the SNS subscription email)."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "client_vpn_cidr" {
  description = "CIDR assigned to VPN clients. Must not overlap the VPC or your home network; /22 minimum."
  type        = string
  default     = "10.100.0.0/22"
}

variable "internal_domain" {
  description = "Private Route 53 zone. The app is served at app.<internal_domain>; must match APP_FQDN used by scripts/gen-certs.sh."
  type        = string
  default     = "securevpn.internal"
}

variable "instance_type" {
  description = "EC2 instance type for the web server."
  type        = string
  default     = "t3.micro"
}

variable "endpoint_az_count" {
  description = "Number of AZs that get interface VPC endpoints (1 = cheapest, 2 = highly available)."
  type        = number
  default     = 1

  validation {
    condition     = var.endpoint_az_count >= 1 && var.endpoint_az_count <= 2
    error_message = "endpoint_az_count must be 1 or 2."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days."
  type        = number
  default     = 30
}

variable "vpn_session_timeout_hours" {
  description = "Maximum Client VPN session duration (8, 10, 12 or 24)."
  type        = number
  default     = 8
}

variable "synthetic_check_rate_minutes" {
  description = "How often the in-VPC synthetic check probes the app."
  type        = number
  default     = 5
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget; alerts at 80% actual and 100% forecast."
  type        = number
  default     = 25
}

variable "enable_guardduty" {
  description = "Enable GuardDuty threat detection (30-day free trial, then paid). Leave false if GuardDuty is already enabled in the account."
  type        = bool
  default     = false
}

variable "enable_ebs_encryption_by_default" {
  description = "Turn on account/region-wide EBS encryption by default (reverted on destroy)."
  type        = bool
  default     = true
}

variable "cors_allowed_origins" {
  description = "Origins (e.g. a hosted copy of the UI) allowed to call the vault API cross-origin from a VPN-connected browser. Empty keeps the API same-origin only."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for o in var.cors_allowed_origins : can(regex("^https://[a-z0-9.-]+$", o))])
    error_message = "Each origin must look like https://host (no path or trailing slash)."
  }
}
