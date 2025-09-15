output "role_arns" {
  description = "ARNs of created IAM roles keyed by role name."
  value       = { for k, v in aws_iam_role.this : k => v.arn }
}

output "instance_profile_arns" {
  description = "ARNs of created instance profiles keyed by role name."
  value       = { for k, v in aws_iam_instance_profile.this : k => v.arn }
}

output "policy_arns" {
  description = "ARNs of customer-managed policies keyed by policy name."
  value       = { for k, v in aws_iam_policy.this : k => v.arn }
}

output "group_names" {
  description = "Group names keyed by input key."
  value       = { for k, v in aws_iam_group.this : k => v.name }
}

output "user_names" {
  description = "User names keyed by input key."
  value       = { for k, v in aws_iam_user.this : k => v.name }
}

output "user_access_keys" {
  description = "Access key IDs (and encrypted secrets if PGP key was provided), keyed by user name."
  sensitive   = true
  value = {
    for k, v in aws_iam_access_key.this :
    k => {
      id                 = v.id
      secret             = try(v.secret, null)                 # only available if pgp_key not set
      encrypted_secret   = try(v.encrypted_secret, null)       # available if pgp_key set
      ses_smtp_password_v4 = try(v.ses_smtp_password_v4, null)
    }
  }
}
