# ADR 0003: Registro y login básico

- **Estado:** Implementado en Fase 4.
- **Fecha:** 2026-10-26.
- **Alcance:** rutas HTTP de registro y login local; no incluye sesiones, tokens, cookies definitivas ni flujos OIDC.

## Contraseñas y entradas

- Se usa `argon2` con Argon2id, 19.456 KiB (19 MiB) de memoria, 2 iteraciones, paralelismo 1 y hash de 32 bytes. La biblioteca genera la sal individual y codifica los parámetros en el hash PHC. Los parámetros coinciden con la configuración mínima publicada por OWASP; hay que medirlos en el entorno Node 24 y aumentarlos cuando el presupuesto de latencia lo permita.
- El formato PHC de `argon2` serializa los costos como `m=...,p=...,t=...`; el repositorio y la migración `0003` aceptan ese orden y también hashes previos estructuralmente válidos (`m=...,t=...,p=...`) para que la restricción nueva no rompa datos ya guardados. La migración `0002` tenía una comprobación estructural demasiado restrictiva para el orden emitido por la biblioteca, así que `0003` la reemplaza sin editar una migración versionada.
- Registro acepta contraseñas de 12 a 128 caracteres y limita a 256 bytes UTF-8. Login valida formato y longitud máxima, pero no reaplica el mínimo de registro para permitir credenciales históricas. Los valores de contraseña no se recortan ni normalizan.
- Zod valida objetos estrictos (rechaza claves desconocidas), correo, contraseña y cuerpo JSON. Los correos se recortan y convierten a minúsculas antes de persistir y autenticar.
- La consulta busca por correo normalizado con SQL parametrizado. Un hash Argon2id dummy se verifica para correos inexistentes, cuentas sin credencial o estados que no permiten login, reduciendo diferencias de tiempo por enumeración.

## Endpoints y estados

- `POST /auth/register` crea la cuenta en estado `pending` y devuelve `201 { "userId": "…" }`.
- `POST /auth/login` acepta cuentas `pending` o `active` con credencial válida y devuelve `200 { "userId": "…" }`. Se rechazan credenciales incorrectas, usuarios sin credencial, cuentas `suspended`, `disabled` o `anonymized` con la misma respuesta `401`.
- Ninguna ruta emite JWT/tokens ni establece cookies. Las respuestas de autenticación usan `Cache-Control: no-store`.
- Las colisiones de correo en registro devuelven un error de conflicto genérico. Login no distingue correo inexistente, contraseña incorrecta o cuenta no elegible.

## Limitación distribuida

Un script Lua atómico en Redis mantiene ventanas fijas, sin estado local de Node: hasta 5 intentos por combinación correo/IP durante 15 minutos y hasta 60 intentos por IP en esa ventana para login; registro aplica 5 por correo/IP y 20 por IP durante una hora para contener abuso de hashing. Se aplica el límite a solicitudes válidas de login y registro. Al excederlo se responde `429` con `Retry-After`; si Redis no está disponible, esos endpoints fallan cerrados con `503`.

Las claves usan HMAC-SHA-256 de correo e IP, con la contraseña Redis como clave de HMAC; no se guardan direcciones de correo sin transformar en Redis. Express no confía en `X-Forwarded-For` (`trust proxy=false`). Detrás de un proxy confiable habrá que configurar explícitamente la lista de proxies antes de usar la IP de cliente; no habilitar confianza genérica.

## Errores e idioma

El middleware interpreta `Accept-Language` y sirve mensajes en español o inglés (español por defecto). Los errores de validación son genéricos y traducidos. Login usa `Credenciales inválidas` para todos los fallos de credenciales; los errores internos no exponen stack, SQL, valores ni mensajes de drivers. El rate limiter y la persistencia fallan con mensajes genéricos.

## Límites y trabajo futuro

- No se añadió verificación de propiedad del correo ni envío de correo; por eso una cuenta nueva queda `pending`, pero el login básico de esta fase permite autenticarla. La emisión de tokens y cookies queda para `oidc-provider` en Fase 5.
- El rate limiter fijo puede reiniciarse al expirar la ventana o rotar la contraseña Redis, y un límite por IP puede agrupar usuarios detrás de NAT. Antes de producción deben calibrarse límites, proxy de borde, telemetría y política de abuso con carga representativa.
- Las respuestas traducidas cubren inglés y español; no es todavía una integración completa de i18next ni localización de correos.

## Referencia

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): configuración mínima Argon2id de 19 MiB, 2 iteraciones y paralelismo 1.
