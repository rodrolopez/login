CREATE TABLE identity_api.organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
  slug TEXT NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended', 'archived')),
  created_by UUID REFERENCES identity_api.users (id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT organizations_slug_unique UNIQUE (slug)
);

CREATE TABLE identity_api.organization_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES identity_api.organizations (id) ON DELETE CASCADE,
  role_key TEXT NOT NULL CHECK (role_key IN ('owner', 'admin', 'member')),
  display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 80),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT organization_roles_org_role_unique UNIQUE (organization_id, role_key),
  CONSTRAINT organization_roles_id_org_unique UNIQUE (id, organization_id)
);

CREATE TABLE identity_api.organization_role_permissions (
  organization_id UUID NOT NULL,
  role_id UUID NOT NULL,
  permission TEXT NOT NULL CHECK (permission IN (
    'organization.read',
    'members.read',
    'members.manage',
    'resources.read',
    'resources.write'
  )),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, role_id, permission),
  CONSTRAINT role_permissions_role_org_fk
    FOREIGN KEY (role_id, organization_id)
    REFERENCES identity_api.organization_roles (id, organization_id)
    ON DELETE CASCADE
);

CREATE TABLE identity_api.organization_memberships (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES identity_api.organizations (id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES identity_api.users (id) ON DELETE CASCADE,
  role_id UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('invited', 'active', 'suspended', 'disabled', 'revoked')),
  created_by UUID REFERENCES identity_api.users (id) ON DELETE SET NULL,
  activated_at TIMESTAMPTZ,
  disabled_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT memberships_org_user_unique UNIQUE (organization_id, user_id),
  CONSTRAINT memberships_id_org_unique UNIQUE (id, organization_id),
  CONSTRAINT memberships_role_org_fk
    FOREIGN KEY (role_id, organization_id)
    REFERENCES identity_api.organization_roles (id, organization_id),
  CONSTRAINT memberships_state_timestamp_check CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL)
    OR (status <> 'revoked' AND revoked_at IS NULL)
  ),
  CONSTRAINT memberships_disabled_timestamp_check CHECK (
    (status = 'disabled' AND disabled_at IS NOT NULL)
    OR (status <> 'disabled' AND disabled_at IS NULL)
  ),
  CONSTRAINT memberships_active_timestamp_check CHECK (
    status <> 'active' OR activated_at IS NOT NULL
  )
);

CREATE INDEX organization_memberships_user_status_idx
  ON identity_api.organization_memberships (user_id, status, organization_id);
CREATE INDEX organization_memberships_org_status_role_idx
  ON identity_api.organization_memberships (organization_id, status, role_id);
CREATE INDEX organization_role_permissions_lookup_idx
  ON identity_api.organization_role_permissions (organization_id, permission, role_id);

CREATE TABLE identity_api.audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES identity_api.organizations (id) ON DELETE SET NULL,
  actor_user_id UUID REFERENCES identity_api.users (id) ON DELETE SET NULL,
  subject_user_id UUID REFERENCES identity_api.users (id) ON DELETE SET NULL,
  event_type TEXT NOT NULL CHECK (event_type IN (
    'organization.created',
    'membership.added',
    'membership.role_changed',
    'membership.suspended',
    'membership.disabled',
    'membership.revoked',
    'membership.reactivated'
  )),
  details JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_org_time_idx
  ON identity_api.audit_events (organization_id, occurred_at DESC);
CREATE INDEX audit_events_actor_time_idx
  ON identity_api.audit_events (actor_user_id, occurred_at DESC);
