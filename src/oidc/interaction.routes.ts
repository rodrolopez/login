import { Router, type Request, type Response } from 'express';
import type Provider from 'oidc-provider';
import type { IdentityRepository } from '../identity/identity.repository.js';

function interactionError(response: Response, status = 400) {
  return response.status(status).json({ error: 'OIDC interaction is invalid or expired.' });
}

export function createOidcInteractionRouter(provider: Provider): Router {
  const router = Router();

  router.get('/interaction/:uid', async (request: Request, response: Response) => {
    try {
      const details = await provider.interactionDetails(request, response);
      if (details.uid !== request.params.uid) return interactionError(response);
      return response.status(200).json({
        interactionUid: details.uid,
        prompt: details.prompt.name,
        ...(details.prompt.name === 'consent'
          ? {
              requestedScopes: typeof details.params.scope === 'string' ? details.params.scope : '',
            }
          : {}),
      });
    } catch {
      return interactionError(response);
    }
  });

  router.post('/interaction/:uid/consent', async (request: Request, response: Response) => {
    const body: unknown = request.body;
    if (
      typeof body !== 'object' ||
      body === null ||
      !('approve' in body) ||
      body.approve !== true
    ) {
      return interactionError(response);
    }

    try {
      const details = await provider.interactionDetails(request, response);
      if (
        details.uid !== request.params.uid ||
        details.prompt.name !== 'consent' ||
        !details.session?.accountId ||
        typeof details.params.client_id !== 'string'
      ) {
        return interactionError(response);
      }

      const grant = details.grantId
        ? ((await provider.Grant.find(details.grantId)) ??
          new provider.Grant({
            accountId: details.session.accountId,
            clientId: details.params.client_id,
          }))
        : new provider.Grant({
            accountId: details.session.accountId,
            clientId: details.params.client_id,
          });
      const detailsToApprove = details.prompt.details;
      const missingScopes = detailsToApprove.missingOIDCScope;
      if (
        Array.isArray(missingScopes) &&
        missingScopes.every((scope) => typeof scope === 'string')
      ) {
        grant.addOIDCScope(missingScopes as string[]);
      }
      const missingClaims = detailsToApprove.missingOIDCClaims;
      if (
        Array.isArray(missingClaims) &&
        missingClaims.every((claim) => typeof claim === 'string')
      ) {
        grant.addOIDCClaims(missingClaims as string[]);
      }
      const grantId = await grant.save();
      await provider.interactionFinished(
        request,
        response,
        { consent: { grantId } },
        { mergeWithLastSubmission: true },
      );
      return;
    } catch {
      return interactionError(response);
    }
  });

  return router;
}

export async function completeOidcLogin(
  provider: Provider,
  repository: IdentityRepository,
  request: Request,
  response: Response,
  uid: string,
  accountId: string,
): Promise<boolean> {
  try {
    const details = await provider.interactionDetails(request, response);
    if (details.uid !== uid || details.prompt.name !== 'login') return false;
    const account = await repository.findAccountById(accountId);
    if (
      !account ||
      account.status !== 'active' ||
      !account.emails.some((email) => email.isPrimary && email.verifiedAt !== null)
    ) {
      return false;
    }
    await provider.interactionFinished(
      request,
      response,
      { login: { accountId, remember: false } },
      { mergeWithLastSubmission: true },
    );
    return true;
  } catch {
    return false;
  }
}
