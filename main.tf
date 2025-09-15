##############################################
# Locals
##############################################
locals {
  default_tags = var.tags

  roles_by_name = { for r in var.roles : r.name => r }

  # --- Attachments as lists (kept same shape) ---
  role_policy_attachments = flatten([
    for r in var.roles : [
      for arn in coalesce(try(r.managed_policy_arns, []), []) : {
        key        = "${r.name}|${arn}"
        role       = r.name
        policy_arn = arn
      }
    ]
  ])

  group_policy_attachments = flatten([
    for g in var.groups : [
      for arn in coalesce(try(g.managed_policy_arns, []), []) : {
        key        = "${g.name}|${arn}"
        group      = g.name
        policy_arn = arn
      }
    ]
  ])

  user_policy_attachments = flatten([
    for u in var.users : [
      for arn in coalesce(try(u.managed_policy_arns, []), []) : {
        key        = "${u.name}|${arn}"
        user       = u.name
        policy_arn = arn
      }
    ]
  ])

  # --- Inline policies as maps (no varargs) ---
  role_inline_policies = tomap({
    for item in flatten([
      for r in var.roles : [
        for pname, pjson in coalesce(try(r.inline_policies, {}), {}) : {
          key         = "${r.name}|${pname}"
          role        = r.name
          policy_name = pname
          policy_json = pjson
        }
      ]
      ]) : item.key => {
      role        = item.role
      policy_name = item.policy_name
      policy_json = item.policy_json
    }
  })

  group_inline_policies = tomap({
    for item in flatten([
      for g in var.groups : [
        for pname, pjson in coalesce(try(g.inline_policies, {}), {}) : {
          key         = "${g.name}|${pname}"
          group       = g.name
          policy_name = pname
          policy_json = pjson
        }
      ]
      ]) : item.key => {
      group       = item.group
      policy_name = item.policy_name
      policy_json = item.policy_json
    }
  })

  user_inline_policies = tomap({
    for item in flatten([
      for u in var.users : [
        for pname, pjson in coalesce(try(u.inline_policies, {}), {}) : {
          key         = "${u.name}|${pname}"
          user        = u.name
          policy_name = pname
          policy_json = pjson
        }
      ]
      ]) : item.key => {
      user        = item.user
      policy_name = item.policy_name
      policy_json = item.policy_json
    }
  })

  # --- Group memberships map (no varargs) ---
  user_group_memberships = {
    for u in var.users :
    u.name => { user = u.name, groups = try(u.groups, []) }
    if length(try(u.groups, [])) > 0
  }
}

##############################################
# Data: Assume Role Policies (generated when JSON not provided)
##############################################
data "aws_iam_policy_document" "assume_role" {
  for_each = {
    for r in var.roles :
    r.name => r
    if r.assume_role_policy_json == null
  }

  # Service principals (e.g., ec2.amazonaws.com)
  dynamic "statement" {
    for_each = length(try(each.value.trust.service_principals, [])) > 0 ? [1] : []
    content {
      sid     = "ServicePrincipals"
      effect  = "Allow"
      actions = try(each.value.trust.sts_actions, ["sts:AssumeRole"])
      principals {
        type        = "Service"
        identifiers = each.value.trust.service_principals
      }
      dynamic "condition" {
        for_each = try(each.value.trust.conditions, [])
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }

  # AWS account/user/role ARNs
  dynamic "statement" {
    for_each = length(try(each.value.trust.aws_principals, [])) > 0 ? [1] : []
    content {
      sid     = "AwsPrincipals"
      effect  = "Allow"
      actions = try(each.value.trust.sts_actions, ["sts:AssumeRole"])
      principals {
        type        = "AWS"
        identifiers = each.value.trust.aws_principals
      }
      dynamic "condition" {
        for_each = length(try(each.value.trust.external_id, [])) > 0 ? [1] : []
        content {
          test     = "StringEquals"
          variable = "sts:ExternalId"
          values   = each.value.trust.external_id
        }
      }
      dynamic "condition" {
        for_each = try(each.value.trust.conditions, [])
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }

  # Federated (OIDC/SAML) — defaults to web identity action
  dynamic "statement" {
    for_each = length(try(each.value.trust.federated_principals, [])) > 0 ? [1] : []
    content {
      sid     = "FederatedPrincipals"
      effect  = "Allow"
      actions = try(each.value.trust.federated_actions, ["sts:AssumeRoleWithWebIdentity"])
      principals {
        type        = "Federated"
        identifiers = each.value.trust.federated_principals
      }
      dynamic "condition" {
        for_each = try(each.value.trust.conditions, [])
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

##############################################
# Managed Policies (customer-managed)
##############################################
# Build JSON from statements when policy_json is not supplied
data "aws_iam_policy_document" "managed" {
  for_each = {
    for p in var.policies : p.name => p
    if p.policy_json == null && p.statements != null
  }

  dynamic "statement" {
    for_each = try(each.value.statements, [])
    content {
      sid       = try(statement.value.sid, null)
      effect    = statement.value.effect
      actions   = statement.value.actions
      resources = statement.value.resources

      dynamic "condition" {
        for_each = try(statement.value.condition, [])
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

resource "aws_iam_policy" "this" {
  for_each = { for p in var.policies : p.name => p }

  name        = each.value.name
  path        = try(each.value.path, null)
  description = try(each.value.description, null)
  policy      = each.value.policy_json != null ? each.value.policy_json : data.aws_iam_policy_document.managed[each.key].json
  tags        = merge(local.default_tags, try(each.value.tags, {}))
}

##############################################
# Roles + (optional) Instance Profiles
##############################################
resource "aws_iam_role" "this" {
  for_each = local.roles_by_name

  name                 = each.value.name
  path                 = try(each.value.path, "/")
  description          = try(each.value.description, null)
  max_session_duration = try(each.value.max_session_duration, null)
  permissions_boundary = try(each.value.permissions_boundary_arn, null)
  assume_role_policy   = each.value.assume_role_policy_json != null ? each.value.assume_role_policy_json : data.aws_iam_policy_document.assume_role[each.key].json
  tags                 = merge(local.default_tags, try(each.value.tags, {}))
}

# Attach managed policies to roles
resource "aws_iam_role_policy_attachment" "this" {
  for_each   = { for x in local.role_policy_attachments : x.key => x }
  role       = aws_iam_role.this[each.value.role].name
  policy_arn = each.value.policy_arn
}

# Inline policies for roles
resource "aws_iam_role_policy" "this" {
  for_each = local.role_inline_policies

  name   = each.value.policy_name
  role   = aws_iam_role.this[each.value.role].name
  policy = each.value.policy_json
}

# Instance profiles (optional per role)
resource "aws_iam_instance_profile" "this" {
  for_each = { for r in var.roles : r.name => r if try(r.create_instance_profile, false) }

  name = each.value.name
  path = try(each.value.path, null)
  role = aws_iam_role.this[each.key].name
  tags = merge(local.default_tags, try(each.value.tags, {}))
}

##############################################
# Groups
##############################################
resource "aws_iam_group" "this" {
  for_each = { for g in var.groups : g.name => g }
  name     = each.value.name
  path     = try(each.value.path, null)
}

resource "aws_iam_group_policy_attachment" "this" {
  for_each   = { for x in local.group_policy_attachments : x.key => x }
  group      = aws_iam_group.this[each.value.group].name
  policy_arn = each.value.policy_arn
}

resource "aws_iam_group_policy" "this" {
  for_each = local.group_inline_policies
  name     = each.value.policy_name
  group    = aws_iam_group.this[each.value.group].name
  policy   = each.value.policy_json
}

##############################################
# Users
##############################################
resource "aws_iam_user" "this" {
  for_each = { for u in var.users : u.name => u }

  name                 = each.value.name
  path                 = try(each.value.path, null)
  permissions_boundary = try(each.value.permissions_boundary_arn, null)
  tags                 = merge(local.default_tags, try(each.value.tags, {}))
}

# Attach managed policies to users
resource "aws_iam_user_policy_attachment" "this" {
  for_each   = { for x in local.user_policy_attachments : x.key => x }
  user       = aws_iam_user.this[each.value.user].name
  policy_arn = each.value.policy_arn
}

# Inline policies for users
resource "aws_iam_user_policy" "this" {
  for_each = local.user_inline_policies
  name     = each.value.policy_name
  user     = aws_iam_user.this[each.value.user].name
  policy   = each.value.policy_json
}

# Group memberships (per user)
resource "aws_iam_user_group_membership" "this" {
  for_each = local.user_group_memberships
  user     = aws_iam_user.this[each.value.user].name
  groups   = [for g in each.value.groups : aws_iam_group.this[g].name]
}

# Optional access keys (defaults to not created)
resource "aws_iam_access_key" "this" {
  for_each = { for u in var.users : u.name => u if try(u.create_access_key, false) }

  user    = aws_iam_user.this[each.key].name
  pgp_key = try(each.value.pgp_key, null)
}

##############################################
# Account Password Policy (optional)
##############################################
resource "aws_iam_account_password_policy" "this" {
  count = var.account_password_policy == null ? 0 : 1

  minimum_password_length        = try(var.account_password_policy.minimum_password_length, null)
  require_lowercase_characters   = try(var.account_password_policy.require_lowercase_characters, null)
  require_uppercase_characters   = try(var.account_password_policy.require_uppercase_characters, null)
  require_numbers                = try(var.account_password_policy.require_numbers, null)
  require_symbols                = try(var.account_password_policy.require_symbols, null)
  allow_users_to_change_password = try(var.account_password_policy.allow_users_to_change_password, null)
  hard_expiry                    = try(var.account_password_policy.hard_expiry, null)
  password_reuse_prevention      = try(var.account_password_policy.password_reuse_prevention, null)
  max_password_age               = try(var.account_password_policy.max_password_age, null)
}