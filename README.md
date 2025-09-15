# terraform-aws-iam

Batteries-included Terraform module for **AWS IAM**:
- Roles (with flexible trust policies, managed & inline policies)
- Instance profiles
- Customer-managed policies
- Users & groups (attachments, inline policies, memberships)
- Optional access keys
- Optional account password policy

## Usage

```hcl
provider "aws" {
  region = "us-east-1"
}

module "iam" {
  source  = "YOUR_GH_USER/iam/aws"
  version = "0.1.0"

  tags = {
    project = "platform"
    owner   = "observability"
  }

  policies = [
    {
      name        = "deny-dangerous-actions"
      description = "Deny ec2:TerminateInstances"
      statements = [{
        effect    = "Deny"
        actions   = ["ec2:TerminateInstances"]
        resources = ["*"]
      }]
    }
  ]

  roles = [
    {
      name = "ec2-app-role"
      description = "EC2 role for app servers"
      trust = {
        service_principals = ["ec2.amazonaws.com"]
      }
      managed_policy_arns = [
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      ]
      inline_policies = {
        "logs" = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect   = "Allow"
            Action   = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]
            Resource = "*"
          }]
        })
      }
      create_instance_profile = true
    },
    {
      name = "datadog-integration-role"
      description = "Datadog assumes this role with ExternalId"
      trust = {
        aws_principals = ["arn:aws:iam::464622532012:root"] # example Datadog account
        external_id    = ["your-external-id"]
      }
      max_session_duration = 3600
    }
  ]

  groups = [
    {
      name = "readers"
      managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    }
  ]

  users = [
    {
      name  = "alice"
      tags  = { team = "platform" }
      groups = ["readers"]
      create_access_key = true
      # pgp_key = "keybase:alice" # uncomment to encrypt the secret
    }
  ]

  account_password_policy = {
    minimum_password_length = 14
    require_symbols         = true
    require_numbers         = true
    require_uppercase_characters = true
    require_lowercase_characters = true
    password_reuse_prevention     = 24
    max_password_age              = 90
    allow_users_to_change_password = true
  }
}
