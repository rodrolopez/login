# Documento Maestro de Integración

Este documento es normativo para los proyectos que consuman la Identity API. Cada integración web debe respetar las fases en orden, conservar la separación Backend/Frontend y mantener el patrón **MRC (Model–Route–Controller)** en su BFF. No avanzar a una fase posterior hasta completar y revisar la anterior.

## Arquitectura esperada: BFF

El navegador no debe recibir ni almacenar ID Tokens, Access Tokens, Refresh Tokens, secretos OIDC o credenciales del cliente. Los tokens son credenciales portadoras: quien los obtiene puede usarlos hasta su expiración o revocación. `localStorage`, `sessionStorage`, URLs y JavaScript del navegador no son almacenes aceptables para ellos.

El Backend for Frontend (BFF) del proyecto consumidor actúa como cliente OIDC confidencial: inicia Authorization Code con PKCE `S256`, mantiene `state`, `nonce` y `code_verifier` en el servidor, intercambia el código, valida los tokens con `openid-client` y guarda los tokens en un session store del servidor. Al navegador entrega únicamente una cookie de sesión local con un identificador opaco de alta entropía.

La cookie se debe proteger con un mecanismo mantenido de cifrado autenticado o con un identificador aleatorio opaco firmado, junto con `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, sin `Domain` y expiración corta. No implementar criptografía propia. El contenido de la cookie nunca debe ser un JWT ni incluir tokens, roles, correo o datos de perfil. El session store debe cifrar los tokens en reposo, rotar Refresh Tokens atómicamente y revocar la sesión al logout o ante errores de validación.

La Identity API actual publica un issuer OIDC en `/oidc`, requiere Authorization Code con PKCE `S256`, y admite los scopes `openid`, `email` y `offline_access`. Su interacción de login entrega un prompt JSON que el BFF debe resolver; no se debe asumir que existe una página universal de login alojada por el proveedor. Consultar [OIDC integration](./docs/oidc-integration.md), [BFF integration](./docs/bff-integration.md) y [API reference](./docs/api-reference.md) para el contrato vigente.

## Fase 1: Backend BFF con MRC estricto

Implementar primero el BFF y verificarlo de manera independiente. La capa Route solo enlaza paths y middleware; el Controller solo traduce HTTP y coordina; el Model/Service concentra OIDC, persistencia de sesión y validación de identidad. Las rutas no deben contener SQL ni lógica de protocolo, y los controllers no deben construir URLs OIDC ni intercambiar códigos.

### Archivos requeridos

| Archivo                              | Responsabilidad obligatoria                                                                                                                                                                                                            |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/routes/auth.routes.ts`          | Declarar rutas estándar de frontend y enlazarlas a sus controllers. Aplicar middleware de sesión y CSRF donde corresponda. No implementar lógica de negocio.                                                                           |
| `src/controllers/auth.controller.ts` | Traducir parámetros/cookies a llamadas del Model, manejar códigos HTTP y redirects, establecer/limpiar la cookie local protegida y devolver solo un perfil público mínimo. No devolver tokens.                                         |
| `src/models/auth.model.ts`           | Implementar la integración `openid-client`: discovery, Authorization Code + PKCE, `state`, `nonce`, callback, UserInfo, rotación de refresh y logout. Persistir las transacciones y tokens exclusivamente en stores del servidor.      |
| `src/middlewares/auth.middleware.ts` | Abrir la cookie local, validar sesión/expiración/revocación contra el store y establecer el principal autenticado para la petición. Cargar los permisos actuales desde autorización server-side antes de permitir recursos protegidos. |

El proyecto debe además configurar dependencias mediante composición explícita, por ejemplo desde `src/app.ts`, y definir stores server-side para transacciones OIDC y sesiones. Si esos componentes se separan en archivos propios, deben mantener las responsabilidades MRC de arriba y no crear una segunda implementación de OIDC.

### Rutas estándar

- `GET /api/auth/login`: inicia un intento nuevo, guarda `state`/`nonce`/verifier en el servidor y redirige al authorization endpoint descubierto.
- `GET /api/auth/callback`: valida el estado ligado a la transacción local, intercambia el código, valida identidad y crea sesión BFF. Nunca acepta un callback sin transacción válida.
- `GET /api/auth/session`: requiere la cookie local y devuelve únicamente `{ authenticated, user }` con claims permitidos. Devuelve `401` si falta, expiró o se revocó la sesión.
- `POST /api/auth/logout`: requiere sesión y protección CSRF. Revoca primero la sesión local, limpia la cookie y comienza RP-Initiated Logout con `id_token_hint`, `state` aleatorio y `post_logout_redirect_uri` registrado.
- `GET /api/auth/logout/callback`: valida el `state` de logout, finaliza la UX de salida y no recrea una sesión.

El store debe conservar el estado de logout en un registro temporal separado de la sesión. `destroyLocalSession()` revoca la sesión, pero no debe borrar el registro pendiente que `completeLogout()` necesita validar después del redirect del proveedor.

Como la Identity API resuelve prompts de login, MFA y consentimiento mediante su contrato de interacción, el BFF deberá implementar la UX de esos pasos. Si usa formularios, añadir rutas BFF específicas, por ejemplo `POST /api/auth/credentials` y `POST /api/auth/mfa`; esas rutas solo aceptan solicitudes same-origin protegidas contra CSRF, revalidan entradas en backend y llaman desde servidor a los endpoints propios de la Identity API. El navegador nunca debe llamar directamente a `/auth/login`, `/auth/mfa/totp/verify`, `/oidc/token` ni endpoints de interacción del proveedor.

### Esqueleto: `src/routes/auth.routes.ts`

```ts
import { Router } from 'express';
import { createAuthController } from '../controllers/auth.controller.js';
import { createAuthMiddleware } from '../middlewares/auth.middleware.js';
import type { AuthModel } from '../models/auth.model.js';
import type { SessionCookieCodec } from '../services/session-cookie.js';
import type { CsrfMiddleware } from '../services/csrf.js';
import type { AuthorizationModel } from '../models/authorization.model.js';

export function createAuthRouter(
  model: AuthModel,
  cookieCodec: SessionCookieCodec,
  csrf: CsrfMiddleware,
  authorization: AuthorizationModel,
) {
  const router = Router();
  const controller = createAuthController(model, cookieCodec);
  const requireSession = createAuthMiddleware(model, cookieCodec, authorization);

  router.get('/login', controller.login);
  router.get('/callback', controller.callback);
  router.get('/session', requireSession, controller.session);
  router.post('/logout', requireSession, csrf, controller.logout);
  router.get('/logout/callback', controller.logoutCallback);

  return router;
}
```

Montar el router una sola vez desde `src/app.ts` con `app.use('/api/auth', createAuthRouter(...))`. El `csrf` debe comprobar `Origin`/`Referer` same-origin y comparar el header `X-CSRF-Token` contra un valor aleatorio ligado a la sesión; `GET /api/auth/session` lo devuelve junto al estado y al perfil mínimo para que la SPA pueda enviar el logout. Ese token CSRF no es una credencial OIDC. `SameSite` por sí solo no sustituye esta validación.

### Esqueleto: `src/controllers/auth.controller.ts`

```ts
import type { RequestHandler } from 'express';
import type { AuthModel } from '../models/auth.model.js';
import type { SessionCookieCodec } from '../services/session-cookie.js';

const COOKIE = '__Host-project_session';
const cookieOptions = {
  httpOnly: true,
  secure: true, // En desarrollo HTTP usar otro nombre/configuración local, nunca en producción.
  sameSite: 'lax' as const,
  path: '/',
  maxAge: 8 * 60 * 60 * 1000,
};

export function createAuthController(model: AuthModel, cookieCodec: SessionCookieCodec) {
  const login: RequestHandler = async (_req, res, next) => {
    try {
      const flow = await model.beginLogin();
      res.cookie('oidc_flow', await cookieCodec.seal(flow.state), {
        ...cookieOptions,
        maxAge: 5 * 60 * 1000,
      });
      res.redirect(302, flow.authorizationUrl);
    } catch (error) {
      next(error);
    }
  };

  const callback: RequestHandler = async (req, res, next) => {
    try {
      const stateCookie = await cookieCodec.open(req.cookies?.oidc_flow);
      const returnedState = typeof req.query.state === 'string' ? req.query.state : '';
      if (!stateCookie || !returnedState || stateCookie !== returnedState) {
        return res.status(400).json({ error: 'No se pudo completar el inicio de sesión.' });
      }

      const result = await model.completeLogin(new URL(req.originalUrl, model.callbackOrigin));
      const localCookie = await cookieCodec.seal(result.sessionId);
      res.clearCookie('oidc_flow', {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
      });
      res.cookie(COOKIE, localCookie, cookieOptions);
      return res.redirect(303, '/');
    } catch (error) {
      next(error); // El middleware de errores devuelve un mensaje genérico, sin detalles OIDC.
    }
  };

  const session: RequestHandler = (_req, res) => {
    const principal = res.locals.principal;
    return res.status(200).json({
      authenticated: true,
      user: principal,
      csrfToken: res.locals.csrfToken,
    });
  };

  const logout: RequestHandler = async (_req, res, next) => {
    try {
      const sessionId = res.locals.sessionId as string;
      const endSessionUrl = await model.beginLogout(sessionId);
      await model.destroyLocalSession(sessionId);
      res.clearCookie(COOKIE, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
      });
      return res.redirect(303, endSessionUrl);
    } catch (error) {
      next(error);
    }
  };

  const logoutCallback: RequestHandler = async (req, res, next) => {
    try {
      const state = typeof req.query.state === 'string' ? req.query.state : '';
      await model.completeLogout(state);
      return res.redirect(303, '/');
    } catch (error) {
      next(error);
    }
  };

  return { login, callback, session, logout, logoutCallback };
}
```

El código es un esqueleto de responsabilidades: `req.cookies`, cookie codec, CSRF, session store y manejo de errores deben conectarse a implementaciones mantenidas del proyecto. El valor cookie es un identificador opaco sellado, no un token. Usar el prefijo `__Host-` solo con HTTPS, `Secure`, `Path=/` y sin atributo `Domain`.

### Esqueleto: `src/models/auth.model.ts`

```ts
import { randomBytes } from 'node:crypto';
import * as oidc from 'openid-client';

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: string; // Debe coincidir exactamente con el redirect URI registrado.
  logoutCallbackUrl: string;
}

export interface LoginTransaction {
  state: string;
  nonce: string;
  verifier: string;
  createdAt: number;
}

export interface OidcSessionStore {
  putLogin(transaction: LoginTransaction, ttlSeconds: number): Promise<void>;
  consumeLogin(state: string): Promise<LoginTransaction | undefined>;
  create(input: {
    sessionId: string;
    subject: string;
    csrfToken: string;
    email?: string;
    emailVerified?: boolean;
    accessToken: string;
    idToken: string;
    refreshToken?: string;
    accessTokenExpiresAt: number;
    sessionExpiresAt: number;
  }): Promise<void>; // Cifrar tokens en reposo y guardar solo hash/key protegida del sessionId.
  readSession(sessionId: string): Promise<
    | {
        subject: string;
        csrfToken: string;
        email?: string;
        emailVerified?: boolean;
        accessToken: string;
        idToken: string;
        refreshToken?: string;
        accessTokenExpiresAt: number;
        sessionExpiresAt: number;
      }
    | undefined
  >;
  revoke(sessionId: string): Promise<void>;
  rotateTokens(
    sessionId: string,
    expectedRefreshToken: string,
    next: {
      accessToken: string;
      refreshToken?: string;
      accessTokenExpiresAt: number;
    },
  ): Promise<void>;
  putLogoutState(state: string, sessionId: string, ttlSeconds: number): Promise<void>;
  consumeLogoutState(state: string): Promise<boolean>;
}

export class AuthModel {
  private constructor(
    private readonly client: oidc.Configuration,
    private readonly config: OidcConfig,
    private readonly sessions: OidcSessionStore,
  ) {}

  static async create(config: OidcConfig, sessions: OidcSessionStore) {
    const client = await oidc.discovery(
      new URL(config.issuer),
      config.clientId,
      { redirect_uris: [config.callbackUrl], response_types: ['code'] },
      oidc.ClientSecretBasic(config.clientSecret),
    );
    return new AuthModel(client, config, sessions);
  }

  get callbackOrigin(): string {
    return this.config.callbackUrl;
  }

  async beginLogin() {
    const transaction: LoginTransaction = {
      state: oidc.randomState(),
      nonce: oidc.randomNonce(),
      verifier: oidc.randomPKCECodeVerifier(),
      createdAt: Date.now(),
    };
    await this.sessions.putLogin(transaction, 300);
    const challenge = await oidc.calculatePKCECodeChallenge(transaction.verifier);
    const authorizationUrl = oidc.buildAuthorizationUrl(this.client, {
      redirect_uri: this.config.callbackUrl,
      response_type: 'code',
      scope: 'openid email offline_access',
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    return { state: transaction.state, authorizationUrl: authorizationUrl.href };
  }

  async completeLogin(callbackUrl: URL) {
    const state = callbackUrl.searchParams.get('state') ?? '';
    const transaction = await this.sessions.consumeLogin(state);
    if (!transaction || transaction.state !== state) throw new Error('Invalid login transaction');

    const tokens = await oidc.authorizationCodeGrant(this.client, callbackUrl, {
      pkceCodeVerifier: transaction.verifier,
      expectedState: transaction.state,
      expectedNonce: transaction.nonce,
    });
    const claims = tokens.claims();
    if (!tokens.access_token || !tokens.id_token || !claims || typeof claims.sub !== 'string') {
      throw new Error('Invalid token response');
    }

    const userInfo = await oidc.fetchUserInfo(this.client, tokens.access_token, claims.sub);
    if (userInfo.sub !== claims.sub) throw new Error('UserInfo subject mismatch');

    const sessionId = randomBytes(32).toString('base64url');
    const csrfToken = randomBytes(32).toString('base64url');
    await this.sessions.create({
      sessionId,
      subject: claims.sub,
      csrfToken,
      ...(typeof userInfo.email === 'string' ? { email: userInfo.email } : {}),
      ...(typeof userInfo.email_verified === 'boolean'
        ? { emailVerified: userInfo.email_verified }
        : {}),
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
      accessTokenExpiresAt: Date.now() + Number(tokens.expires_in ?? 600) * 1000,
      sessionExpiresAt: Date.now() + 8 * 60 * 60 * 1000,
    });
    return { sessionId, principal: { sub: claims.sub, email: userInfo.email } };
  }

  async beginLogout(sessionId: string): Promise<string> {
    const session = await this.sessions.readSession(sessionId);
    if (!session) throw new Error('Session is no longer active');
    const state = oidc.randomState();
    await this.sessions.putLogoutState(state, sessionId, 300);
    return oidc.buildEndSessionUrl(this.client, {
      id_token_hint: session.idToken,
      post_logout_redirect_uri: this.config.logoutCallbackUrl,
      state,
    }).href;
  }

  async completeLogout(state: string): Promise<void> {
    if (!state || !(await this.sessions.consumeLogoutState(state))) {
      throw new Error('Invalid logout state');
    }
  }

  async authenticateSession(sessionId: string) {
    let session = await this.sessions.readSession(sessionId);
    if (!session || session.sessionExpiresAt <= Date.now()) return undefined;

    if (session.accessTokenExpiresAt <= Date.now() + 30_000) {
      if (!session.refreshToken) {
        await this.sessions.revoke(sessionId);
        return undefined;
      }
      const previousRefreshToken = session.refreshToken;
      const refreshed = await oidc.refreshTokenGrant(this.client, previousRefreshToken);
      if (!refreshed.access_token || !refreshed.refresh_token) {
        await this.sessions.revoke(sessionId);
        return undefined;
      }
      await this.sessions.rotateTokens(sessionId, previousRefreshToken, {
        accessToken: refreshed.access_token,
        refreshToken: refreshed.refresh_token,
        accessTokenExpiresAt: Date.now() + Number(refreshed.expires_in ?? 600) * 1000,
      }); // CAS/transacción: una sola petición puede consumir cada refresh token.
      session = await this.sessions.readSession(sessionId);
      if (!session) return undefined;
    }

    try {
      const userInfo = await oidc.fetchUserInfo(this.client, session.accessToken, session.subject);
      if (userInfo.sub !== session.subject) throw new Error('UserInfo subject mismatch');
      return {
        sub: session.subject,
        csrfToken: session.csrfToken,
        ...(typeof userInfo.email === 'string' ? { email: userInfo.email } : {}),
        ...(typeof userInfo.email_verified === 'boolean'
          ? { emailVerified: userInfo.email_verified }
          : {}),
      };
    } catch {
      await this.sessions.revoke(sessionId);
      return undefined;
    }
  }

  // Si la revocación local falla, no completar el logout ni conservar la cookie.
  async destroyLocalSession(sessionId: string): Promise<void> {
    await this.sessions.revoke(sessionId);
  }
}
```

El session store, `cookieCodec`, secret manager y protección CSRF quedan deliberadamente como adaptadores del proyecto; no deben implementarse con criptografía artesanal ni almacenamiento en memoria en producción. La API puede responder un prompt `login`, `mfa` o `consent`: implementar esas interacciones siguiendo su contrato y preservar sus cookies HTTP-only. No marcar al usuario autenticado hasta terminar MFA y el callback OIDC.

### Esqueleto: `src/middlewares/auth.middleware.ts`

```ts
import type { RequestHandler } from 'express';
import type { AuthModel } from '../models/auth.model.js';
import type { SessionCookieCodec } from '../services/session-cookie.js';
import type { AuthorizationModel } from '../models/authorization.model.js';

const COOKIE = '__Host-project_session';

export function createAuthMiddleware(
  authModel: AuthModel,
  cookieCodec: SessionCookieCodec,
  authorization: AuthorizationModel,
): RequestHandler {
  return async (req, res, next) => {
    try {
      const sealedCookie = req.cookies?.[COOKIE];
      const sessionId = await cookieCodec.open(sealedCookie);
      if (!sessionId) return res.status(401).json({ error: 'Authentication required.' });

      // Debe cargar la sesión del store; allí reside el Access Token, no en el navegador.
      // authModel valida vigencia, puede rotar el refresh token y mantiene el token en servidor.
      const principal = await authModel.authenticateSession(sessionId);
      if (!principal) {
        res.clearCookie(COOKIE, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
        return res.status(401).json({ error: 'Authentication required.' });
      }

      // La API actual no emite roles de organización en los claims OIDC.
      // Cargar roles/permisos propios desde el almacén de autorización del consumidor.
      const permissions = await authorization.permissionsForSubject(principal.sub);
      res.locals.sessionId = sessionId;
      res.locals.csrfToken = principal.csrfToken;
      res.locals.principal = {
        sub: principal.sub,
        ...(principal.email ? { email: principal.email } : {}),
        permissions,
        emailVerified: principal.emailVerified,
      };
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

export function requirePermission(permission: string): RequestHandler {
  return (_req, res, next) => {
    const permissions = res.locals.principal?.permissions as string[] | undefined;
    if (!permissions?.includes(permission)) {
      return res.status(403).json({ error: 'Forbidden.' });
    }
    return next();
  };
}
```

`authenticateSession()` debe tomar el Access Token del store server-side para llamadas OIDC/UserInfo cuando corresponda; nunca debe parsear un JWT sin validar firma/issuer/audience/expiración/nonce. No copiar el token a una respuesta, HTML, log, error, header del navegador o variable global. El perfil y los permisos que `GET /api/auth/session` devuelve sirven para mostrar la interfaz; no son prueba de autorización. Para proteger operaciones de alto valor, verificar además revocación, estado de cuenta y autorización por recurso en cada petición.

## Fase 2: Frontend — consumo estándar

El Frontend no implementa discovery, OIDC, PKCE, refresh, validación criptográfica ni manejo de tokens. El flujo de interfaz debe:

1. Navegar al BFF mediante `window.location.assign('/api/auth/login')` o un enlace normal. No construir la URL del proveedor desde el cliente.
2. Presentar formularios de credenciales/MFA propios solo si la integración BFF de la aplicación lo requiere. Zod/Yup en navegador es una mejora UX; el BFF debe validar nuevamente y aplicar límites de tamaño/rate limiting.
3. Consultar `GET /api/auth/session` al cargar la aplicación, usando cookie same-origin. Para `fetch`, usar `credentials: 'same-origin'`; no almacenar ni inspeccionar tokens.
4. En logout, enviar `POST /api/auth/logout` con el token CSRF requerido y dejar que el BFF gestione la salida del proveedor.
5. Tratar `401` como sesión inexistente/expirada y regresar al flujo de login. No asumir que una ruta oculta en UI constituye autorización.

El navegador nunca debe enviar `client_secret`, `code_verifier`, Refresh Token, Access Token, ID Token o cookies OIDC manuales. Evitar guardar sesión en `localStorage`/`sessionStorage`; no incluir credenciales ni tokens en telemetría de frontend.

## Fase 3: Autorización y roles

La autenticación OIDC responde quién es el sujeto (`sub`); cada proyecto consumidor decide qué puede hacer ese sujeto en sus propios recursos. Los controllers/rutas protegidos deben requerir `auth.middleware.ts` y un control de permiso por operación, por ejemplo `requirePermission('billing.invoice.read')`.

- Cargar roles y permisos desde la base/autorización del servidor, vinculados al `sub` OIDC estable. Nunca aceptar `role`, `permissions`, `userId` o propietario enviados por el Frontend como evidencia de autorización.
- Comprobar membresía y permiso en la base de datos dentro de la organización/recurso solicitado. Un `organizationId` recibido del cliente solo identifica el recurso candidato; no prueba acceso.
- Denegar por defecto, responder `401` si no existe sesión, `403` si el principal no tiene autorización y evitar filtrar existencia de recursos cuando la política de seguridad lo requiera.
- Actualizar permisos y estado de membresía inmediatamente; no confiar indefinidamente en roles copiados a una sesión o token.
- La Identity API actual anuncia `sub`, `email`, `email_verified`, `sid`, `auth_time` e `iss`; actualmente no incluye roles de organización en los claims OIDC. No inventar ni inferir claims. Para roles propios, consultar el almacén del proyecto; para autorización multiempresa centralizada, consumir una interfaz explícitamente autorizada y documentada por la Identity API.
- Si un servicio backend llama a la Identity API u otro recurso protegido, adjuntar el Access Token solo desde el session store del BFF y exclusivamente server-to-server. No reenviarlo al browser.

## Secuencia obligatoria de aceptación

Antes de integrar el Frontend, validar en el BFF: issuer exacto por discovery, redirect URI registrada, `state`/`nonce` inválidos rechazados, PKCE S256, code replay rechazado, sujeto UserInfo igual al `sub` del ID Token, MFA/consent cuando se soliciten, cookie segura, ausencia de tokens en respuestas/logs, expiración/rotación de Refresh Token y logout con validación de state. Luego validar que cada endpoint protegido rechace sesiones inexistentes, usuarios deshabilitados y accesos cross-tenant.

Mantener las variables OIDC y secretos en un secret manager: issuer HTTPS, client ID, client secret exclusivo por aplicación BFF, callback/logout exactos y claves de cookie/sesión. Usar clientes registrados de producción; los clientes `*-test` y `bff-reference-client` de desarrollo no son credenciales de producción.
