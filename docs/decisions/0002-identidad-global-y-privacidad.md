# ADR 0002: Modelo de identidad global y privacidad

- **Estado:** Implementado en Fase 3.
- **Fecha:** 2026-10-26.
- **Alcance:** cuentas globales, correos, credenciales e identidades externas; sin endpoints de autenticación.

## Modelo relacional

- `identity_api.users` usa UUID generado por PostgreSQL como identificador interno estable. El estado es explícito: `pending`, `active`, `suspended`, `disabled` o `anonymized`. `disabled_at` y `anonymized_at` deben concordar con el estado mediante restricciones de base de datos.
- `identity_api.user_emails` permite más de una dirección por usuario, conserva `verified_at` y `is_primary`, y aplica unicidad sin distinguir mayúsculas/minúsculas. El repositorio normaliza las direcciones a minúsculas. Cada usuario puede tener un solo correo principal.
- `identity_api.password_credentials` tiene como máximo una credencial por cuenta. Sólo acepta la estructura de una cadena Argon2id PHC con versión y parámetros; el repositorio no genera ni verifica hashes. El hash está fuera de la representación normal de una cuenta.
- `identity_api.external_identities` vincula proveedor, emisor y subject. Un issuer/subject sólo puede pertenecer a una cuenta, y cada cuenta admite como máximo una identidad por proveedor. El esquema admite `google` sin incorporar aún el flujo OIDC.
- Las claves foráneas son explícitas y las tablas subordinadas usan `ON DELETE CASCADE`. Los valores se persisten mediante consultas SQL parametrizadas; no hay ORM.

## Desactivación, anonimización y borrado físico

1. **Desactivación reversible:** `disableAccount` cambia el estado a `disabled` y conserva correo, credenciales e identidades vinculadas. La consulta de cuenta representa ese estado; no elimina datos.
2. **Anonimización para el derecho al olvido:** `anonymizeAccount` bloquea la fila de usuario y en una transacción elimina correos, credenciales e identidades externas, y deja sólo un registro UUID sin PII con estado `anonymized`. La operación es idempotente. Las identidades nuevas no se pueden vincular a cuentas suspendidas, deshabilitadas o anonimizadas.
3. **Borrado físico:** `deleteAnonymizedAccountPermanently` sólo elimina una cuenta que ya está anonimizada; no permite borrar directamente una cuenta activa o deshabilitada. La fila se elimina físicamente y las relaciones subordinadas se eliminan por cascada. Los consumidores pueden usar primero la anonimización para invalidar relaciones, preservar referencias internas temporalmente y luego purgar el tombstone según una política de retención aprobada.

Las tablas de auditoría y exportación de datos todavía no existen en esta fase. Cuando se agreguen, los eventos no deben copiar correo, hash, subject de proveedor ni otros identificadores directos en payloads. Un flujo de borrado deberá anonimizar o eliminar esos atributos y exportación requerirá un mecanismo separado, autenticado y con entrega segura. La fila UUID anonimizada no reemplaza una revisión legal de períodos de retención ni acredita por sí sola cumplimiento normativo.

## Integridad y transacciones

La creación de una cuenta escribe usuario, correo principal y credencial opcional en una única transacción. El enlace de una identidad externa bloquea la cuenta y escribe en transacción, para coordinarse con la anonimización. Las restricciones únicas y las FK permanecen como última línea de integridad ante concurrencia. Las migraciones siguen siendo comandos explícitos (`npm run db:migrate`) y no se ejecutan al arrancar la API.

## Límites

- El repositorio valida que la credencial parezca un hash Argon2id, pero la generación con `argon2`, la política de parámetros y la verificación pertenecen a la fase de credenciales/autenticación.
- No se definió una política temporal de retención para el tombstone anonimizado; debe decidirse antes de usar el mecanismo en producción.
- La normalización básica de correo no resuelve todas las reglas internacionales de direcciones de correo. Validación de producto y verificación de propiedad pertenecen a fases posteriores.
