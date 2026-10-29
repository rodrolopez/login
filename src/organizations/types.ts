export type OrganizationRoleKey = 'owner' | 'admin' | 'member';
export type OrganizationPermission =
  'organization.read' | 'members.read' | 'members.manage' | 'resources.read' | 'resources.write';
export type MembershipStatus = 'invited' | 'active' | 'suspended' | 'disabled' | 'revoked';

export interface Organization {
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'suspended' | 'archived';
  createdAt: Date;
  updatedAt: Date;
}

export interface Membership {
  id: string;
  organizationId: string;
  userId: string;
  role: OrganizationRoleKey;
  status: MembershipStatus;
  createdAt: Date;
  updatedAt: Date;
}

export class OrganizationAccessDeniedError extends Error {
  constructor() {
    super('Organization access denied');
    this.name = 'OrganizationAccessDeniedError';
  }
}

export class OrganizationConflictError extends Error {
  constructor(message = 'Organization operation conflicts with current state') {
    super(message);
    this.name = 'OrganizationConflictError';
  }
}
