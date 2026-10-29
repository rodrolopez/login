import express, { type Express } from 'express';
import { createAuthRouter, type AuthRouteDependencies } from './auth/auth.routes.js';
import { createOidcInteractionRouter } from './oidc/interaction.routes.js';
import { languageMiddleware, messages, requestLanguage } from './auth/i18n.js';
import { healthRouter } from './routes/health.routes.js';
import { createOrganizationRouter } from './organizations/organization.routes.js';
import { createCorsMiddleware, securityHeaders } from './http/security.js';
import { requestTraceMiddleware } from './infrastructure/telemetry.js';

export function createApp(authDependencies?: AuthRouteDependencies): Express {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use(requestTraceMiddleware);
  app.use(securityHeaders);
  app.use(languageMiddleware);
  app.use((_request, response, next) => {
    response.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(createCorsMiddleware(authDependencies?.corsAllowedOrigins ?? []));
  app.use(express.json({ limit: '32kb' }));
  app.use('/health', healthRouter);
  if (authDependencies) {
    if (authDependencies.oidcProvider) {
      const issuerUrl = new URL(authDependencies.oidcProvider.issuer);
      const oidcHost = issuerUrl.host;
      const localAlias =
        issuerUrl.hostname === '127.0.0.1'
          ? `localhost${issuerUrl.port ? `:${issuerUrl.port}` : ''}`
          : issuerUrl.hostname === 'localhost'
            ? `127.0.0.1${issuerUrl.port ? `:${issuerUrl.port}` : ''}`
            : undefined;
      app.use((request, _response, next) => {
        if (request.path !== '/oidc' && !request.path.startsWith('/oidc/')) {
          return next();
        }
        if (
          process.env.NODE_ENV !== 'production' &&
          localAlias &&
          request.headers.host === localAlias
        ) {
          request.headers.host = oidcHost;
        }
        return next();
      });
    }
    app.use('/auth', createAuthRouter(authDependencies));
    app.use('/organizations', createOrganizationRouter(authDependencies));
    if (authDependencies.oidcProvider) {
      const oidcHost = new URL(authDependencies.oidcProvider.issuer).host;
      app.use('/oidc', (request, response, next) => {
        if (request.headers.host !== oidcHost) {
          return response.status(400).json({ error: 'Invalid OIDC host.' });
        }
        return next();
      });
      app.use('/oidc', createOidcInteractionRouter(authDependencies.oidcProvider));
      app.use('/oidc', authDependencies.oidcProvider.callback());
    }
  }

  app.use((_request, response) => {
    const language = requestLanguage(response);
    return response.status(404).json({ error: messages[language].notFound });
  });

  app.use(
    (
      error: unknown,
      _request: express.Request,
      response: express.Response,
      _next: express.NextFunction,
    ) => {
      void _next;
      const language = requestLanguage(response);
      if (
        typeof error === 'object' &&
        error !== null &&
        'type' in error &&
        error.type === 'entity.parse.failed'
      ) {
        return response.status(400).json({ error: messages[language].validation });
      }
      if (
        typeof error === 'object' &&
        error !== null &&
        'type' in error &&
        error.type === 'entity.too.large'
      ) {
        return response.status(413).json({ error: messages[language].payloadTooLarge });
      }
      return response.status(500).json({ error: messages[language].internal });
    },
  );

  return app;
}
