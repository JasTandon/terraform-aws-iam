##examples/basic/main.tf`
terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "iam" {
  source = "../.."

  tags = { env = "dev" }

  policies = [
    {
      name = "app-read-logs"
      statements = [{
        effect    = "Allow"
        actions   = ["logs:Describe*", "logs:Get*", "logs:FilterLogEvents"]
        resources = ["*"]
      }]
    }
  ]

  roles = [
    {
      name                    = "ec2-dev-role"
      trust                   = { service_principals = ["ec2.amazonaws.com"] }
      managed_policy_arns     = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
      create_instance_profile = true
    }
  ]

  groups = [{ name = "dev-readers" }]

  users = [
    { name = "dev-user", groups = ["dev-readers"] }
  ]
}
