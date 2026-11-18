# Deliberately-misconfigured AWS sandbox — OPTIONAL, review before applying.
# See README.md in this directory. Apply ONLY in a throwaway account you own.
#
# Everything is commented out so `terraform validate` on a fresh checkout does
# not accidentally create insecure resources. Uncomment deliberately.

# terraform {
#   required_providers {
#     aws = { source = "hashicorp/aws", version = "~> 5.0" }
#   }
# }
#
# provider "aws" {
#   region = var.region
# }
#
# variable "region" {
#   type    = string
#   default = "us-east-1"
# }
#
# # (1) public_storage — a public-readable S3 bucket
# resource "aws_s3_bucket" "sandbox_reports" {
#   bucket = "acme-sandbox-reports-REPLACE-ME"
# }
# resource "aws_s3_bucket_public_access_block" "open" {
#   bucket                  = aws_s3_bucket.sandbox_reports.id
#   block_public_acls       = false
#   block_public_policy     = false
#   ignore_public_acls      = false
#   restrict_public_buckets = false
# }
#
# # (2) network_exposure — SSH open to the world
# resource "aws_security_group" "open_ssh" {
#   name        = "sandbox-open-ssh"
#   description = "INSECURE sandbox SG"
#   ingress {
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }
#
# # (3) unencrypted_data — an unencrypted EBS volume
# resource "aws_ebs_volume" "unencrypted" {
#   availability_zone = "${var.region}a"
#   size              = 1
#   encrypted         = false
# }
#
# Add logging_disabled (no CloudTrail) and excessive_permissions (admin policy on
# a user) as needed, then scan with Prowler. Run `terraform destroy` when done.
