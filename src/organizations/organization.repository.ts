import type { Pool, PoolClient } from 'pg';
import { withTransaction } from '../infrastructure/postgres/pool.js';
import {
  OrganizationAccessDeniedError,
  OrganizationConflictError,
  type Membership,
  type MembershipStatus,
  type Organization,
  type OrganizationPermission,
  type OrganizationRoleKey,
} from './types.js';

interface OrganizationRow {
  id: string;
  name: string;
  slug: string;
  status: Organization['status'];
  created_at: Date;
  updated_at: Date;
}

interface MembershipRow {
  id: string;
  organization_id: string;
  user_id: string;
  role_key: OrganizationRoleKey;
  status: MembershipStatus;
  created_at: Date;
  updated_at: Date;
}

interface ActorRoleRow {
  role_key: OrganizationRoleKey;
}

const rolePermissions: Record<OrganizationRoleKey, OrganizationPermission[]> = {
  owner: [
    'organization.read',
    'members.read',
    'members.manage',
    'resources.read',
    'resources.write',
  ],
  admin: [
    'organization.read',
    'members.read',
    'members.manage',
    'resources.read',
    'resources.write',
  ],
  member: ['organization.read', 'resources.read'],
};

function toOrganization(row: OrganizationRow): Organization {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toMembership(row: MembershipRow): Membership {
  return {
    id: row.id,
    organizationId: row.organization_id,
    userId: row.user_id,
    role: row.role_key,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function normalizeSlug(slug: string): string {
  return slug.trim().toLowerCase();
}

export class OrganizationRepository {
  constructor(private readonly pool: Pool) {}

  async createOrganization(input: {
    name: string;
    slug: string;
    ownerUserId: string;
  }): Promise<Organization> {
    const name = input.name.trim();
    const slug = normalizeSlug(input.slug);
    if (!name || name.length > 160 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(slug)) {
      throw new Error('Invalid organization details');
    }

    return withTransaction(this.pool, async (client) => {
      const owner = await client.query(
        `SELECT id FROM identity_api.users
         WHERE id = $1 AND account_status = 'active' FOR UPDATE`,
        [input.ownerUserId],
      );
      if (!owner.rows[0]) throw new OrganizationAccessDeniedError();

      const organizationResult = await client.query<OrganizationRow>(
        `INSERT INTO identity_api.organizations (name, slug, created_by)
         VALUES ($1, $2, $3)
         RETURNING id, name, slug, status, created_at, updated_at`,
        [name, slug, input.ownerUserId],
      );
      const organization = organizationResult.rows[0];
      if (!organization) throw new Error('Organization insert returned no row');

      const roleIds = new Map<OrganizationRoleKey, string>();
      for (const role of ['owner', 'admin', 'member'] as const) {
        const roleResult = await client.query<{ id: string }>(
          `INSERT INTO identity_api.organization_roles (organization_id, role_key, display_name)
           VALUES ($1, $2, $3) RETURNING id`,
          [organization.id, role, role[0]!.toUpperCase() + role.slice(1)],
        );
        const roleId = roleResult.rows[0]?.id;
        if (!roleId) throw new Error('Organization role insert returned no row');
        roleIds.set(role, roleId);
        await client.query(
          `INSERT INTO identity_api.organization_role_permissions
             (organization_id, role_id, permission)
           SELECT $1, $2, permission FROM unnest($3::text[]) AS permission`,
          [organization.id, roleId, rolePermissions[role]],
        );
      }

      const ownerRoleId = roleIds.get('owner');
      if (!ownerRoleId) throw new Error('Owner role was not created');
      const membershipResult = await client.query<MembershipRow>(
        `INSERT INTO identity_api.organization_memberships
           (organization_id, user_id, role_id, status, created_by, activated_at)
         VALUES ($1, $2, $3, 'active', $2, now())
         RETURNING id, organization_id, user_id, status, created_at, updated_at`,
        [organization.id, input.ownerUserId, ownerRoleId],
      );
      if (!membershipResult.rows[0]) throw new Error('Owner membership insert returned no row');

      await this.insertAuditEvent(client, {
        organizationId: organization.id,
        actorUserId: input.ownerUserId,
        subjectUserId: input.ownerUserId,
        eventType: 'organization.created',
        details: { slug },
      });
      await this.insertAuditEvent(client, {
        organizationId: organization.id,
        actorUserId: input.ownerUserId,
        subjectUserId: input.ownerUserId,
        eventType: 'membership.added',
        details: { role: 'owner' },
      });

      return toOrganization(organization);
    });
  }

  async findOrganizationWithPermission(input: {
    organizationId: string;
    userId: string;
    permission: OrganizationPermission;
  }): Promise<Organization | undefined> {
    const result = await this.pool.query<OrganizationRow>(
      `SELECT o.id, o.name, o.slug, o.status, o.created_at, o.updated_at
       FROM identity_api.organizations AS o
       JOIN identity_api.organization_memberships AS m
         ON m.organization_id = o.id AND m.user_id = $2 AND m.status = 'active'
       JOIN identity_api.organization_role_permissions AS rp
         ON rp.organization_id = m.organization_id AND rp.role_id = m.role_id
        AND rp.permission = $3
       JOIN identity_api.users AS u ON u.id = m.user_id
       WHERE o.id = $1 AND o.status = 'active'
         AND u.account_status = 'active'
       LIMIT 1`,
      [input.organizationId, input.userId, input.permission],
    );
    const row = result.rows[0];
    return row ? toOrganization(row) : undefined;
  }

  async addMember(input: {
    organizationId: string;
    actorUserId: string;
    userId: string;
    role: 'admin' | 'member';
  }): Promise<Membership> {
    return withTransaction(this.pool, async (client) => {
      const actorRole = await this.requireActorPermission(
        client,
        input.organizationId,
        input.actorUserId,
        'members.manage',
      );
      if (input.role === 'admin' && actorRole !== 'owner') {
        throw new OrganizationAccessDeniedError();
      }
      const target = await client.query(
        `SELECT id FROM identity_api.users
         WHERE id = $1 AND account_status = 'active' FOR UPDATE`,
        [input.userId],
      );
      if (!target.rows[0]) throw new OrganizationConflictError('Target account is unavailable');

      const existing = await client.query<MembershipRow>(
        `SELECT m.id, m.organization_id, m.user_id, r.role_key, m.status,
                m.created_at, m.updated_at
         FROM identity_api.organization_memberships AS m
         JOIN identity_api.organization_roles AS r
           ON r.id = m.role_id AND r.organization_id = m.organization_id
         WHERE m.organization_id = $1 AND m.user_id = $2 FOR UPDATE OF m`,
        [input.organizationId, input.userId],
      );
      const previous = existing.rows[0];
      if (previous?.status === 'active') {
        throw new OrganizationConflictError('User already has an active membership');
      }
      const role = await this.findRole(client, input.organizationId, input.role);
      const membershipResult = previous
        ? await client.query<MembershipRow>(
            `UPDATE identity_api.organization_memberships
             SET role_id = $3, status = 'active', created_by = $4,
                 activated_at = now(), disabled_at = NULL, revoked_at = NULL, updated_at = now()
             WHERE organization_id = $1 AND user_id = $2
             RETURNING id, organization_id, user_id, status, created_at, updated_at`,
            [input.organizationId, input.userId, role.id, input.actorUserId],
          )
        : await client.query<MembershipRow>(
            `INSERT INTO identity_api.organization_memberships
               (organization_id, user_id, role_id, status, created_by, activated_at)
             VALUES ($1, $2, $3, 'active', $4, now())
             RETURNING id, organization_id, user_id, status, created_at, updated_at`,
            [input.organizationId, input.userId, role.id, input.actorUserId],
          );
      const row = membershipResult.rows[0];
      if (!row) throw new Error('Membership insert returned no row');
      const mapped = toMembership({ ...row, role_key: input.role });
      await this.insertAuditEvent(client, {
        organizationId: input.organizationId,
        actorUserId: input.actorUserId,
        subjectUserId: input.userId,
        eventType: previous ? 'membership.reactivated' : 'membership.added',
        details: { role: input.role },
      });
      return mapped;
    });
  }

  async changeMemberRole(input: {
    organizationId: string;
    actorUserId: string;
    userId: string;
    role: 'admin' | 'member';
  }): Promise<Membership> {
    return withTransaction(this.pool, async (client) => {
      const actorRole = await this.requireActorPermission(
        client,
        input.organizationId,
        input.actorUserId,
        'members.manage',
      );
      if (input.role === 'admin' && actorRole !== 'owner') {
        throw new OrganizationAccessDeniedError();
      }
      const target = await this.lockMembership(client, input.organizationId, input.userId);
      if (!target || target.status !== 'active' || target.role === 'owner') {
        throw new OrganizationConflictError('Membership cannot be changed');
      }
      const role = await this.findRole(client, input.organizationId, input.role);
      await client.query(
        `UPDATE identity_api.organization_memberships
         SET role_id = $3, updated_at = now()
         WHERE organization_id = $1 AND user_id = $2`,
        [input.organizationId, input.userId, role.id],
      );
      await this.insertAuditEvent(client, {
        organizationId: input.organizationId,
        actorUserId: input.actorUserId,
        subjectUserId: input.userId,
        eventType: 'membership.role_changed',
        details: { from: target.role, to: input.role },
      });
      return { ...target, role: input.role, updatedAt: new Date() };
    });
  }

  async setMembershipStatus(input: {
    organizationId: string;
    actorUserId: string;
    userId: string;
    status: 'suspended' | 'disabled' | 'revoked';
  }): Promise<Membership> {
    return withTransaction(this.pool, async (client) => {
      await this.requireActorPermission(
        client,
        input.organizationId,
        input.actorUserId,
        'members.manage',
      );
      const target = await this.lockMembership(client, input.organizationId, input.userId);
      if (!target || target.status !== 'active' || target.role === 'owner') {
        throw new OrganizationConflictError('Membership cannot be changed');
      }
      await client.query(
        `UPDATE identity_api.organization_memberships
         SET status = $3,
             disabled_at = CASE WHEN $3 = 'disabled' THEN now() ELSE NULL END,
             revoked_at = CASE WHEN $3 = 'revoked' THEN now() ELSE NULL END,
             updated_at = now()
         WHERE organization_id = $1 AND user_id = $2`,
        [input.organizationId, input.userId, input.status],
      );
      const eventType =
        input.status === 'disabled'
          ? 'membership.disabled'
          : input.status === 'suspended'
            ? 'membership.suspended'
            : 'membership.revoked';
      await this.insertAuditEvent(client, {
        organizationId: input.organizationId,
        actorUserId: input.actorUserId,
        subjectUserId: input.userId,
        eventType,
        details: { status: input.status },
      });
      return { ...target, status: input.status, updatedAt: new Date() };
    });
  }

  async listAuditEvents(
    organizationId: string,
    limit = 100,
  ): Promise<
    Array<{
      eventType: string;
      actorUserId: string | null;
      subjectUserId: string | null;
      details: Record<string, unknown>;
      occurredAt: Date;
    }>
  > {
    const safeLimit = Math.max(1, Math.min(100, Math.trunc(limit)));
    const result = await this.pool.query<{
      event_type: string;
      actor_user_id: string | null;
      subject_user_id: string | null;
      details: Record<string, unknown>;
      occurred_at: Date;
    }>(
      `SELECT event_type, actor_user_id, subject_user_id, details, occurred_at
       FROM identity_api.audit_events WHERE organization_id = $1
       ORDER BY occurred_at DESC LIMIT $2`,
      [organizationId, safeLimit],
    );
    return result.rows.map((row) => ({
      eventType: row.event_type,
      actorUserId: row.actor_user_id,
      subjectUserId: row.subject_user_id,
      details: row.details,
      occurredAt: row.occurred_at,
    }));
  }

  private async requireActorPermission(
    client: PoolClient,
    organizationId: string,
    userId: string,
    permission: OrganizationPermission,
  ): Promise<OrganizationRoleKey> {
    const result = await client.query<ActorRoleRow>(
      `SELECT r.role_key
       FROM identity_api.organizations AS o
       JOIN identity_api.organization_memberships AS m
         ON m.organization_id = o.id AND m.user_id = $2 AND m.status = 'active'
       JOIN identity_api.organization_roles AS r
         ON r.id = m.role_id AND r.organization_id = m.organization_id
       JOIN identity_api.organization_role_permissions AS rp
         ON rp.organization_id = m.organization_id AND rp.role_id = m.role_id
        AND rp.permission = $3
       JOIN identity_api.users AS u ON u.id = m.user_id
       WHERE o.id = $1 AND o.status = 'active'
         AND u.account_status = 'active'
       FOR UPDATE OF m`,
      [organizationId, userId, permission],
    );
    const row = result.rows[0];
    if (!row) throw new OrganizationAccessDeniedError();
    return row.role_key;
  }

  private async lockMembership(
    client: PoolClient,
    organizationId: string,
    userId: string,
  ): Promise<Membership | undefined> {
    const result = await client.query<MembershipRow>(
      `SELECT m.id, m.organization_id, m.user_id, r.role_key, m.status,
              m.created_at, m.updated_at
       FROM identity_api.organization_memberships AS m
       JOIN identity_api.organization_roles AS r
         ON r.id = m.role_id AND r.organization_id = m.organization_id
       WHERE m.organization_id = $1 AND m.user_id = $2
       FOR UPDATE OF m`,
      [organizationId, userId],
    );
    const row = result.rows[0];
    return row ? toMembership(row) : undefined;
  }

  private async findRole(
    client: PoolClient,
    organizationId: string,
    roleKey: OrganizationRoleKey,
  ): Promise<{ id: string }> {
    const result = await client.query<{ id: string }>(
      `SELECT id FROM identity_api.organization_roles
       WHERE organization_id = $1 AND role_key = $2`,
      [organizationId, roleKey],
    );
    const role = result.rows[0];
    if (!role) throw new OrganizationConflictError('Organization role is unavailable');
    return role;
  }

  private async insertAuditEvent(
    client: PoolClient,
    input: {
      organizationId: string;
      actorUserId: string;
      subjectUserId: string;
      eventType: string;
      details: Record<string, string>;
    },
  ): Promise<void> {
    await client.query(
      `INSERT INTO identity_api.audit_events
         (organization_id, actor_user_id, subject_user_id, event_type, details)
       VALUES ($1, $2, $3, $4, $5::jsonb)`,
      [
        input.organizationId,
        input.actorUserId,
        input.subjectUserId,
        input.eventType,
        JSON.stringify(input.details),
      ],
    );
  }
}
