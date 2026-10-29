# ADR 0004: Proveedor OpenID Connect

- **Estado:** Implementado en Fase 5 y ampliado en Fase 6.
- **Fecha:** 2026-10-26.
- **Alcance:** proveedor OpenID Connect con `oidc-provider`, adaptador Redis/PostgreSQL, clientes estáticos de desarrollo, interacciones locales de login/consentimiento y pruebas de Authorization Code con PKCE.

## Proveedor y endpoints

- `oidc-provider` 9.x se monta en Express bajo `/oidc`; el issuer de desarrollo predeterminado es `http://127.0.0.1:3005/oidc`.
- Los endpoints OIDC validan `Host` contra el host estático del issuer para evitar que metadata y URLs se construyan desde un host arbitrario. En desarrollo se normaliza el alias local `localhost`/`127.0.0.1`; en producción no hay alias.
- `devInteractions` y el registro dinámico de clientes quedan deshabilitados explícitamente. Las rutas propias exponen el prompt de interacción como JSON y no aceptan un identificador de cuenta como prueba de autenticación.
- `POST /auth/login` continúa devolviendo el ID de cuenta si se usa de forma independiente. Cuando recibe un `interactionUid`, valida la interacción vigente y termina el prompt de login mediante la API del proveedor. Solo credenciales válidas de cuentas `pending` o `active` completan ese prompt.
- El consentimiento se otorga explícitamente en `POST /oidc/interaction/:uid/consent`; se persiste como Grant del proveedor antes de reanudar la solicitud. Los identificadores de interacción y los resultados se atan a las cookies firmadas por el proveedor.
- Se publican solo los claims `sub`, `email` y `email_verified` bajo scopes `openid` y `email`. El correo sale solo si el cliente solicitó `email`; su verificación se refleja desde `verified_at` y no se exige hasta Fase 9.

## Clientes y PKCE

El entorno de desarrollo contiene dos clientes estáticos. El cliente público usa Authorization Code, autenticación `none` y exige PKCE. El cliente confidencial usa `client_secret_basic`. Ambos tienen callback HTTP local exacto y alcance `openid email offline_access`; esos URIs son únicamente para pruebas. La política de PKCE del proveedor se fuerza globalmente porque `oidc-provider` 9 no requiere PKCE por defecto. El proveedor valida `client_id` y cada redirect URI registrado.

Los secretos no están codificados en el repositorio. En desarrollo, si faltan, el secreto confidencial, la clave de firma RSA y la clave de cookies se generan aleatoriamente al iniciar; reiniciar invalida sesiones y tokens previos. Se pueden persistir localmente mediante `.env` ignorado. Producción falla al arrancar si no se configuran `OIDC_ISSUER`, `OIDC_CLIENTS`, `OIDC_JWKS` y `OIDC_COOKIE_KEYS`; su suministro y rotación se hará por un gestor de secretos. Los clientes de prueba no se cargan en producción.

## Almacenamiento del Adapter

- Redis mantiene modelos efímeros (interacciones, sesiones, códigos, tokens de vida limitada y detección de replay), con TTL, índices secundarios para UID/códigos de usuario, cuenta y Grant.
- PostgreSQL almacena solo los modelos `Grant` de consentimiento en `identity_api.oidc_grants`: payload JSONB, cuenta, cliente y vencimiento opcional. Las consultas son parametrizadas. La migración `0004` crea tabla e índices y no se ejecuta automáticamente al iniciar la API.
- Los grants no guardan secretos de cliente ni tokens emitidos. La anonimización de una cuenta elimina sus grants dentro de la misma transacción de anonimización.
- El adaptador usa índices Redis simples para `uid`, `userCode` y `grantId`. Una caída de Redis durante una petición OIDC hace fallar esa petición; no hay degradación a almacenamiento local en memoria.

## Riesgos y límites

- Las claves generadas al iniciar son apropiadas solo para desarrollo y pruebas; no permiten sesiones ni validación de tokens después de reinicios. Producción requiere claves externas estables, rotación con ventana de solapamiento, backups/restore y pruebas de recuperación.
- Los clientes/callbacks incluidos son de prueba local. No deben utilizarse como configuración de clientes reales. La configuración JSON de clientes de producción requiere revisión de cada URI y secreto antes del despliegue.
- El endpoint de consentimiento y la confirmación RP-Initiated Logout son interfaces mínimas; todavía falta la interfaz web/BFF de login y consentimiento, CSRF independiente para una interfaz web, auditoría e instrumentación. La cookie OIDC protege la correlación de la interacción; no es una aplicación de usuario final completa.
- La decisión original permitió cuentas `pending` hasta Fase 9. ADR 0008 la reemplaza: solo cuentas `active` con correo primario verificado pueden iniciar o completar una interacción OIDC.
- La suite de interoperabilidad prueba un flujo local sintético, no certifica perfiles avanzados ni la conformidad completa OIDC.

## Referencias

- [`oidc-provider` y documentación oficial](https://github.com/panva/node-oidc-provider)
- [Configuración e interacciones](https://github.com/panva/node-oidc-provider/blob/main/docs/configuration.md)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
