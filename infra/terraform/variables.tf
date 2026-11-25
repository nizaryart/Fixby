variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-3"
}

variable "admin_cidr" {
  description = "Only network allowed to reach SSH and the Kubernetes API, e.g. 203.0.113.10/32"
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_cidr, 0)) && !contains(["0.0.0.0/0", "::/0"], var.admin_cidr)
    error_message = "admin_cidr must be a valid CIDR and must not open access to the whole internet."
  }
}

variable "ssh_public_key" {
  description = "Public key installed for the admin user"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for the single k3s node"
  type        = string
  default     = "t3.small"
}

variable "vpc_cidr" {
  description = "CIDR of the VPC"
  type        = string
  default     = "10.20.0.0/16"
}
