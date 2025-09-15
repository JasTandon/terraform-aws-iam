variable "tags" {
  description = "Default tags applied to all supported resources."
  type        = map(string)
  default     = {}
}

# ============================= ROLES =============================
variable "roles" {
  description = <<EOT
List of IAM roles to create.

Fields:
- name (string, required)
- path (string, optional, default "/")
- description (string, optional)
- max_session_duration (number, optional; seconds 3600-43200)
- permissions_boundary_arn (string, optional)
- tags (map(string), optional)
- assume_role_policy_json (string, optional) — raw JSON. If set, 'trust' is ignored.
- trust (object, optional) — build trust policy if JSON not provided:
  - service_principals (list(string), optional)   e.g., ["ec2.amazonaws.com","lambda.amazonaws.com"]
  - aws_principals (list(string), optional)       e.g., ["arn:aws:iam::123456789012:root"]
  - federated_principals (list(string), optional) e.g., ["arn:aws:iam::123456789012:oidc-provider/oidc.eks..."]
  - external_id (list(string), optional)          when using aws_principals
  - conditions (list(object), optional)           { test, variable, values }
  - sts_actions (list(string), optional)          default ["sts:AssumeRole"]
  - federated_actions (list(string), optional)    default ["sts:AssumeRoleWithWebIdentity"]
- managed_policy_arns (list(string), optional)
- inline_policies (map(string), optional) — name => JSON
- create_instance_profile (bool, optional, default false)
EOT
  type = list(object({
    name                        = string
    path                        = optional(string, "/")
    description                 = optional(string)
    max_session_duration        = optional(number)
    permissions_boundary_arn    = optional(string)
    tags                        = optional(map(string), {})
    assume_role_policy_json     = optional(string)
    trust = optional(object({
      service_principals  = optional(list(string), [])
      aws_principals      = optional(list(string), [])
      federated_principals= optional(list(string), [])
      external_id         = optional(list(string), [])
      conditions          = optional(list(object({
        test     = string
        variable = string
        values   = list(string)
      })), [])
      sts_actions         = optional(list(string), ["sts:AssumeRole"])
      federated_actions   = optional(list(string), ["sts:AssumeRoleWithWebIdentity"])
    }), null)
    managed_policy_arns         = optional(list(string), [])
    inline_policies             = optional(map(string), {})
    create_instance_profile     = optional(bool, false)
  }))
  default = []
}

# ============================= POLICIES =============================
variable "policies" {
  description = <<EOT
Customer-managed IAM policies to create.

Provide either policy_json OR statements.

- name (string, required)
- path (string, optional)
- description (string, optional)
- tags (map(string), optional)
- policy_json (string, optional) — full policy JSON
- statements (list(object), optional) — builds JSON if policy_json is not set
  statement object:
    - sid (string, optional)
    - effect (string, "Allow"|"Deny")
    - actions (list(string))
    - resources (list(string))
    - condition (list(object), optional) { test, variable, values }
EOT
  type = list(object({
    name        = string
    path        = optional(string)
    description = optional(string)
    tags        = optional(map(string), {})
    policy_json = optional(string)
    statements  = optional(list(object({
      sid       = optional(string)
      effect    = string
      actions   = list(string)
      resources = list(string)
      condition = optional(list(object({
        test     = string
        variable = string
        values   = list(string)
      })), [])
    })))
  }))
  default = []
}

# ============================= GROUPS =============================
variable "groups" {
  description = <<EOT
IAM groups to create.

- name (string, required)
- path (string, optional)
- managed_policy_arns (list(string), optional)
- inline_policies (map(string), optional) — name => JSON
EOT
  type = list(object({
    name                = string
    path                = optional(string)
    managed_policy_arns = optional(list(string), [])
    inline_policies     = optional(map(string), {})
  }))
  default = []
}

# ============================= USERS =============================
variable "users" {
  description = <<EOT
IAM users to create.

- name (string, required)
- path (string, optional)
- permissions_boundary_arn (string, optional)
- tags (map(string), optional)
- groups (list(string), optional) — group names
- managed_policy_arns (list(string), optional)
- inline_policies (map(string), optional) — name => JSON
- create_access_key (bool, optional; default false)
- pgp_key (string, optional) — if set, will PGP-encrypt the secret access key
EOT
  type = list(object({
    name                      = string
    path                      = optional(string)
    permissions_boundary_arn  = optional(string)
    tags                      = optional(map(string), {})
    groups                    = optional(list(string), [])
    managed_policy_arns       = optional(list(string), [])
    inline_policies           = optional(map(string), {})
    create_access_key         = optional(bool, false)
    pgp_key                   = optional(string)
  }))
  default = []
}

# ====================== ACCOUNT PASSWORD POLICY (optional) ======================
variable "account_password_policy" {
  description = "Optional AWS account password policy."
  type = object({
    minimum_password_length        = optional(number)
    require_lowercase_characters   = optional(bool)
    require_uppercase_characters   = optional(bool)
    require_numbers                = optional(bool)
    require_symbols                = optional(bool)
    allow_users_to_change_password = optional(bool)
    hard_expiry                    = optional(bool)
    password_reuse_prevention      = optional(number)
    max_password_age               = optional(number)
  })
  default = null
}
