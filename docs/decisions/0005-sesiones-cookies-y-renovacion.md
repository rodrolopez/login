# ADR 0005: Sesiones, cookies y renovación

- **Estado:** Implementado en Fase 6.
- **Fecha:** 2026-10-26.
- **Alcance:** cookie de sesión propia de la API, sesiones OIDC, renovación rotativa, logout y revocación al cambiar el estado de una cuenta.

## Sesión de la API

- Un login autónomo emite un identificador aleatorio opaco de 256 bits. Redis almacena únicamente el SHA-256 del identificador como clave y una referencia al UUID de la cuenta; el identificador de cookie no se guarda en claro.
- La cookie `identity_session` lleva `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age=28800` y no define `Domain`. Agrega `Secure` cuando `NODE_ENV=production`; en desarrollo local lo omite para que funcione sobre HTTP.
- `GET /auth/session` verifica la cookie en Redis y vuelve a consultar el estado autoritativo en PostgreSQL. Solo `pending` y `active` se consideran autenticables. La sesión dura ocho horas fijas; no se extiende en cada solicitud.
- `POST /auth/logout` elimina la sesión de Redis y vence la cookie con los mismos atributos. El borrado es idempotente.

## Sesiones OIDC y refresh tokens

- Las cookies de `oidc-provider` usan `HttpOnly`, `SameSite=Lax` y `Secure` solo en producción, con firma mediante las claves configuradas para cookies.
- En producción `oidc-provider` acepta el esquema reenviado para detectar HTTPS detrás del terminador TLS. El servicio debe quedar accesible solo desde ese proxy confiable; no se debe exponer directamente manteniendo confianza en `X-Forwarded-*` arbitrarios.
- La sesión OIDC tiene TTL de ocho horas. Access Tokens e ID Tokens duran diez minutos. Refresh Tokens duran catorce días y se rotan en cada uso; la reutilización de un token consumido revoca la cadena según la política de `oidc-provider`.
- Se emiten refresh tokens solo si el cliente permite `refresh_token` y la autorización incluye `offline_access`. Los códigos, access tokens y refresh tokens quedan ligados a la sesión. RP-Initiated Logout usa la confirmación y protección XSRF de `oidc-provider`, destruye la cookie/sesión y revoca los artefactos asociados al grant.
- Los clientes estáticos de desarrollo aceptan `offline_access` para poder probar la rotación. En despliegues reales, cada cliente debe recibir scopes y grants mínimos.

## Cambio de estado e invalidación

- `IdentitySessionRevocationService` es el punto de dominio para deshabilitar, suspender o anonimizar cuentas. Después de actualizar PostgreSQL, elimina las sesiones API de Redis, los artefactos OIDC Redis indexados por cuenta y los grants durables PostgreSQL.
- El adaptador indexa los artefactos OIDC por `accountId` y limpia los índices secundarios al revocar. `findAccount` y las sesiones API consultan PostgreSQL en las operaciones de uso/renovación y rechazan estados distintos de `pending` y `active`; por ello, la cuenta queda bloqueada por la fuente de verdad incluso si la invalidación de caché requiere reintento.
- Los cambios administrativos deben usar el servicio de dominio. Escrituras directas que modifiquen la tabla `users` fuera del servicio pueden omitir la limpieza inmediata de Redis y grants.
- Los access tokens opacos emitidos por el proveedor dejan de validarse dentro del proveedor al revocar sus artefactos. Un sistema tercero que valide tokens localmente sin introspección puede conservarlos hasta su expiración de diez minutos; un ID Token ya emitido tampoco se puede retirar del cliente. Esta fase no implementa introspección para resource servers externos.

## Verificación

Las pruebas de integración verifican cookies API en desarrollo, mantenimiento y cierre de sesión; la emisión y rotación de refresh tokens; el logout OIDC con destrucción de cookie e invalidación de tokens; y la revocación de sesión API, Refresh Token y Grant al deshabilitar una cuenta. También verifican que deshabilitar, suspender y anonimizar borre sesiones API.
