# ADR 0007: organizaciones, membresías y autorización multiempresa

## Estado

Aceptada para la Fase 8.

## Decisiones

- Cada organización tiene roles y permisos propios. La migración `0005_create_organizations_and_authorization.sql` usa UUIDs y claves foráneas compuestas `(role_id, organization_id)` para impedir que una membresía use por error un rol perteneciente a otro tenant.
- Se crean los roles `owner`, `admin` y `member` por organización. `owner` y `admin` pueden leer y administrar membresías; solo `owner` puede asignar el rol `admin`. `member` puede leer información organizacional y recursos. Todos los permisos se verifican contra PostgreSQL para cada request; los roles o permisos enviados por el navegador nunca se consideran autoridad.
- Se conserva una fila de membresía por par organización/usuario. Estados `invited`, `active`, `suspended`, `disabled` y `revoked` son explícitos. La autorización requiere membresía `active`, organización `active`, cuenta global `pending` o `active`, y el permiso solicitado. Así una suspensión o revocación surte efecto en la siguiente consulta, sin invalidar la sesión global.
- Las operaciones de creación de organización, alta/reactivación de membresía, cambio de rol y cambio de estado se ejecutan en transacciones. Sus eventos de auditoría se escriben en la misma transacción y no guardan correo, contraseñas, secretos ni tokens. Se conservan actor y sujeto mediante UUID interno, además de rol/estado.
- `POST /organizations` crea organización, roles y membresía inicial de owner para el usuario autenticado. `POST /organizations/:organizationId/members`, cambios de rol/estado y lecturas de recursos validan sesión y permisos en servidor. `GET /organizations/:organizationId/resources` es el primer recurso protegido de ejemplo y devuelve una colección vacía hasta que una fase posterior agregue datos de negocio.

## Riesgos y límites

- La capa de auditoría garantiza eventos para cambios realizados por el repositorio/API; operaciones manuales directas en la base de datos no pasan por esa lógica.
- Los UUID de actor/sujeto en auditoría son identificadores internos pseudónimos y siguen siendo datos vinculables; las referencias se nulifican ante borrado físico de usuarios.
- No se implementan invitaciones por correo ni un panel administrativo; la alta inicial se dirige a una cuenta existente por UUID y solo la procesa un owner/admin autorizado.
