import { Router, type Request, type Response } from 'express';
import type { Redis } from 'ioredis';
import type { Pool } from 'pg';
import { z } from 'zod';
import { ApiSessionService } from '../sessions/session.service.js';
import { OrganizationRepository } from './organization.repository.js';
import {
  OrganizationAccessDeniedError,
  OrganizationConflictError,
  type OrganizationPermission,
} from './types.js';

export interface OrganizationRouteDependencies {
  pool: Pool;
  redis: Redis;
}

const createOrganizationSchema = z
  .object({
    name: z.string().trim().min(1).max(160),
    slug: z
      .string()
      .trim()
      .toLowerCase()
      .regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/),
  })
  .strict();

const addMemberSchema = z
  .object({
    userId: z.string().uuid(),
    role: z.enum(['admin', 'member']),
  })
  .strict();

const changeRoleSchema = z.object({ role: z.enum(['admin', 'member']) }).strict();

const changeStatusSchema = z
  .object({ status: z.enum(['suspended', 'disabled', 'revoked']) })
  .strict();

function errorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) return undefined;
  return typeof error.code === 'string' ? error.code : undefined;
}

function validId(value: string): boolean {
  return z.string().uuid().safeParse(value).success;
}

export function createOrganizationRouter(dependencies: OrganizationRouteDependencies): Router {
  const router = Router();
  const repository = new OrganizationRepository(dependencies.pool);
  const sessions = new ApiSessionService(dependencies.pool, dependencies.redis);

  const authenticatedUser = async (
    request: Request,
    response: Response,
  ): Promise<string | undefined> => {
    try {
      const userId = await sessions.accountForRequest(request);
      if (!userId) {
        sessions.clearCookie(response);
        response.status(401).json({ error: 'Authentication required.' });
        return undefined;
      }
      return userId;
    } catch {
      response.status(503).json({ error: 'Organization service is temporarily unavailable.' });
      return undefined;
    }
  };

  const requirePermission = async (
    request: Request,
    response: Response,
    userId: string,
    permission: OrganizationPermission,
  ): Promise<boolean> => {
    const organizationId = request.params.organizationId;
    if (typeof organizationId !== 'string' || !validId(organizationId)) {
      response.status(404).json({ error: 'Organization not found.' });
      return false;
    }
    try {
      const organization = await repository.findOrganizationWithPermission({
        organizationId,
        userId,
        permission,
      });
      if (!organization) {
        response.status(403).json({ error: 'Organization access denied.' });
        return false;
      }
      response.locals.organization = organization;
      return true;
    } catch {
      response.status(503).json({ error: 'Organization service is temporarily unavailable.' });
      return false;
    }
  };

  router.post('/', async (request, response) => {
    const userId = await authenticatedUser(request, response);
    if (!userId) return;
    const parsed = createOrganizationSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: 'Invalid organization data.' });
    try {
      const organization = await repository.createOrganization({
        ...parsed.data,
        ownerUserId: userId,
      });
      return response.status(201).json(organization);
    } catch (error) {
      if (error instanceof OrganizationAccessDeniedError) {
        return response.status(403).json({ error: 'Organization access denied.' });
      }
      if (errorCode(error) === '23505') {
        return response.status(409).json({ error: 'Organization slug is already in use.' });
      }
      return response
        .status(503)
        .json({ error: 'Organization service is temporarily unavailable.' });
    }
  });

  router.get('/:organizationId/resources', async (request, response) => {
    const userId = await authenticatedUser(request, response);
    if (!userId) return;
    if (!(await requirePermission(request, response, userId, 'resources.read'))) return;
    const organization = response.locals.organization as {
      id: string;
      name: string;
    };
    return response.status(200).json({
      organizationId: organization.id,
      organizationName: organization.name,
      resources: [],
    });
  });

  router.get('/:organizationId/audit', async (request, response) => {
    const userId = await authenticatedUser(request, response);
    if (!userId) return;
    if (!(await requirePermission(request, response, userId, 'members.read'))) return;
    const organizationId = request.params.organizationId as string;
    try {
      const events = await repository.listAuditEvents(organizationId);
      return response.status(200).json({ events });
    } catch {
      return response
        .status(503)
        .json({ error: 'Organization service is temporarily unavailable.' });
    }
  });

  router.post('/:organizationId/members', async (request, response) => {
    const userId = await authenticatedUser(request, response);
    if (!userId) return;
    const organizationId = request.params.organizationId;
    if (typeof organizationId !== 'string' || !validId(organizationId)) {
      return response.status(404).json({ error: 'Organization not found.' });
    }
    const parsed = addMemberSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: 'Invalid membership data.' });
    try {
      const membership = await repository.addMember({
        organizationId,
        actorUserId: userId,
        ...parsed.data,
      });
      return response.status(201).json({ membership });
    } catch (error) {
      if (error instanceof OrganizationAccessDeniedError) {
        return response.status(403).json({ error: 'Organization access denied.' });
      }
      if (error instanceof OrganizationConflictError || errorCode(error) === '23505') {
        return response.status(409).json({ error: 'Membership cannot be created in this state.' });
      }
      return response
        .status(503)
        .json({ error: 'Organization service is temporarily unavailable.' });
    }
  });

  router.patch('/:organizationId/members/:memberUserId/role', async (request, response) => {
    const userId = await authenticatedUser(request, response);
    if (!userId) return;
    const organizationId = request.params.organizationId;
    const memberUserId = request.params.memberUserId;
    if (
      typeof organizationId !== 'string' ||
      !validId(organizationId) ||
      typeof memberUserId !== 'string' ||
      !validId(memberUserId)
    ) {
      return response.status(404).json({ error: 'Membership not found.' });
    }
    const parsed = changeRoleSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: 'Invalid role data.' });
    try {
      const membership = await repository.changeMemberRole({
        organizationId,
        actorUserId: userId,
        userId: memberUserId,
        ...parsed.data,
      });
      return response.status(200).json({ membership });
    } catch (error) {
      if (error instanceof OrganizationAccessDeniedError) {
        return response.status(403).json({ error: 'Organization access denied.' });
      }
      if (error instanceof OrganizationConflictError) {
        return response.status(409).json({ error: 'Membership cannot be changed in this state.' });
      }
      return response
        .status(503)
        .json({ error: 'Organization service is temporarily unavailable.' });
    }
  });

  router.patch('/:organizationId/members/:memberUserId/status', async (request, response) => {
    const userId = await authenticatedUser(request, response);
    if (!userId) return;
    const organizationId = request.params.organizationId;
    const memberUserId = request.params.memberUserId;
    if (
      typeof organizationId !== 'string' ||
      !validId(organizationId) ||
      typeof memberUserId !== 'string' ||
      !validId(memberUserId)
    ) {
      return response.status(404).json({ error: 'Membership not found.' });
    }
    const parsed = changeStatusSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: 'Invalid membership status.' });
    try {
      const membership = await repository.setMembershipStatus({
        organizationId,
        actorUserId: userId,
        userId: memberUserId,
        ...parsed.data,
      });
      return response.status(200).json({ membership });
    } catch (error) {
      if (error instanceof OrganizationAccessDeniedError) {
        return response.status(403).json({ error: 'Organization access denied.' });
      }
      if (error instanceof OrganizationConflictError) {
        return response.status(409).json({ error: 'Membership cannot be changed in this state.' });
      }
      return response
        .status(503)
        .json({ error: 'Organization service is temporarily unavailable.' });
    }
  });

  return router;
}
