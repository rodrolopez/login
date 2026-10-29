# Manual operativo

Este manual describe operaciones que deben ejecutarse con una ventana de cambio, monitoreo y acceso restringido. No incluye credenciales ni claves. Guardar los archivos de entorno y backups cifrados fuera del repositorio.

## Roles de PostgreSQL y migraciones

La API runtime se conecta como `identity_app`, nunca como `postgres`, dueño de base de datos ni `identity_migrator`. `identity_migrator` es un rol separado usado solo para cambios de esquema; el rol bootstrap `postgres` se reserva para provisionamiento.

El script [provision-production-db.sql](../scripts/ops/provision-production-db.sql) es de un solo uso sobre una instancia nueva. Crea `identity_api`, el rol de migraciones como propietario de la base/esquema y el rol de runtime con DML sobre tablas/secuencias del esquema `identity_api`. El rol runtime no obtiene `CREATE`, `ALTER`, permisos de superusuario ni permisos para tocar `public.schema_migrations`. Si se ejecutan migraciones con otro propietario, actualizar `ALTER DEFAULT PRIVILEGES` para ese rol antes de migrar.

Procedimiento inicial (generar claves distintas y aleatorias de al menos 32 caracteres):

1. Cargar contraseñas nuevas desde un gestor de secretos en variables de entorno `IDENTITY_APP_PASSWORD` e `IDENTITY_MIGRATOR_PASSWORD`; no escribirlas en el historial del shell.
2. Arrancar solo PostgreSQL con el archivo protegido indicado en `docs/deployment.md`.
3. Enviar el SQL por stdin a `psql` dentro del contenedor (la instancia debe ser nueva; el script no es idempotente):

   ```sh
   export PRODUCTION_ENV_FILE=/secure/path/identity-api.production.env
   docker compose --env-file "$PRODUCTION_ENV_FILE" -f docker-compose.prod.yml \
     exec -T -e IDENTITY_APP_PASSWORD -e IDENTITY_MIGRATOR_PASSWORD postgres \
     psql -U postgres -d postgres < scripts/ops/provision-production-db.sql
   ```

4. Confirmar en una sesión administrativa que `identity_app` no es superusuario ni propietario y que solo tiene `CONNECT`, `USAGE` y DML en `identity_api`. No registrar las contraseñas en la salida.
5. Cambiar el usuario runtime en el env protegido a `PGUSER=identity_app` y `PGPASSWORD` igual a su secreto.
6. Ejecutar migraciones desde la imagen ya construida y con la credencial migratoria, no con la credencial runtime:

   ```sh
   read -r -s -p 'Migration DB password: ' IDENTITY_MIGRATOR_PASSWORD
   printf '\n'
   export PGPASSWORD="$IDENTITY_MIGRATOR_PASSWORD"
   docker compose --env-file "$PRODUCTION_ENV_FILE" -f docker-compose.prod.yml \
     run --rm --no-deps -e PGUSER=identity_migrator -e PGPASSWORD api npm run db:migrate:prod
   unset PGPASSWORD IDENTITY_MIGRATOR_PASSWORD
   ```

   Compose toma `PGPASSWORD` del entorno del operador; no escribir una contraseña literal en la línea de comandos ni guardarla en el historial.

Las migraciones son versionadas, checksum-verificadas y transaccionales, pero requieren revisión de SQL y backup antes de cada cambio. No ejecutar `npm run db:migrate` automáticamente al arrancar. Para rollbacks, preparar una migración compensatoria revisada; no editar migraciones ya aplicadas ni ejecutar `DROP` manual sin aprobación y un plan probado.

## Backups y restauración

El backup genera formato custom de `pg_dump`, con archivo local modo `0600`. Definir `PRODUCTION_ENV_FILE` y opcionalmente `BACKUP_DIR`/`BACKUP_DATABASE`; ejecutar desde el operador de backup:

```sh
PRODUCTION_ENV_FILE=/secure/path/identity-api.production.env \
  BACKUP_DIR=/secure/backups scripts/ops/backup-postgres.sh
```

Copiar luego el archivo a almacenamiento externo cifrado, con control de acceso, retención aprobada y protección contra borrado. Supervisar el resultado y alertar por backup ausente o fallido. Coordinar consistencia de PostgreSQL, Redis y las claves OIDC/MFA: la restauración de DB sola no recupera sesiones Redis ni secretos criptográficos.

La restauración nunca pisa la base activa: requiere una base destino nueva cuyo nombre termine en `_restore`, por ejemplo `identity_api_20261029_restore`.

```sh
read -r -s -p 'Migration DB password: ' IDENTITY_MIGRATOR_PASSWORD
printf '\n'
export IDENTITY_MIGRATOR_PASSWORD
PRODUCTION_ENV_FILE=/secure/path/identity-api.production.env \
  RESTORE_DATABASE=identity_api_20261029_restore \
  scripts/ops/restore-postgres.sh /secure/backups/identity_api-<timestamp>.dump
unset IDENTITY_MIGRATOR_PASSWORD
```

Validar integridad, checksums de migraciones, conteos, relaciones y una prueba funcional sobre la base recuperada antes de planificar un cutover. Mantener API fuera de servicio durante un cutover y preservar la base previa hasta completar observación y aprobación. El script conserva la base nueva si `pg_restore` falla para permitir investigación; eliminarla requiere una operación explícita del DBA.

Definir RPO/RTO, frecuencia y retención por política de negocio, y ejecutar restauraciones de ensayo periódicas. Un archivo de backup no verificado no cuenta como recuperación comprobada.

## Monitoreo y alertas

- Verificar disponibilidad del issuer/discovery/JWKS desde una red externa y salud del API detrás del proxy.
- Alertar por errores 5xx, latencia p95/p99, reinicios, memoria/CPU, conexiones activas y pool saturado.
- Monitorear PostgreSQL conexiones, locks, espacio, autovacuum y lag si se incorpora replicación.
- Monitorear Redis memoria, persistencia, latencia, rechazos `noeviction`, desconexiones y expiración de sesiones.
- Confirmar recepción de trazas OTLP y correlación con `X-Trace-Id`/`trace_id` de los logs. Las spans no contienen URLs ni datos de usuario por diseño.
- Revisar logs del borde WAF/CDN y proxy, incluyendo bloqueos, cambios de origen, rate limits y expiración TLS.
- Evitar registrar payloads, `Authorization`, cookies, códigos OIDC, contraseñas, secretos, cuerpos de recuperación o URI de Google con parámetros.

## Rotación de claves OIDC

Las claves privadas JWKS y las claves de cookies OIDC deben permanecer estables entre réplicas y reinicios, almacenadas en un gestor de secretos y accesibles solo al runtime. Mantener backup cifrado, propietario responsable, expiración/alertas y un registro de versión sin material secreto.

Rotación de firma planificada:

1. Generar un nuevo par RSA/algoritmo permitido en un entorno controlado; nunca modificar `kid`/material en el código ni compartir claves en tickets.
2. Publicar la clave pública nueva en JWKS junto a la clave anterior; mantener la privada anterior temporalmente solo si el proveedor necesita validar tokens firmados antes del corte.
3. Desplegar de forma coordinada el JWKS con ambas claves a todas las réplicas, comprobar discovery/JWKS, `kid` y emisión/validación con clientes.
4. Cambiar la clave activa para firmar con la nueva; observar rechazos y asegurar que los consumidores refrescan JWKS.
5. Esperar como mínimo el TTL máximo de los tokens firmados con la clave anterior, más tolerancia de reloj y cachés documentada; luego retirar la clave anterior de JWKS y borrar su material según la política.
6. Rotar `OIDC_COOKIE_KEYS` con ventana de solapamiento compatible con `oidc-provider`, despliegue coordinado y prueba de sesiones antes de retirar la antigua. Si no se puede conservar compatibilidad, planificar invalidación de sesiones.
7. Registrar fechas, responsables, versión de `kid`, instancias y pruebas; nunca registrar claves privadas.

Ensayar el proceso con clientes de prueba y validar restauración de claves antes de una rotación real. Una pérdida de clave privada o de `MFA_ENCRYPTION_KEY` requiere respuesta a incidente: los secretos MFA cifrados pueden quedar irrecuperables sin backup.

## Respuesta a incidentes

1. Declarar incidente, asignar responsable y preservar logs de WAF/proxy/API/PostgreSQL/Redis sin copiar secretos a herramientas de tickets.
2. Identificar alcance, periodo, cuentas/clients potencialmente afectados y cambios administrativos. Revocar sesiones y grants afectados mediante el servicio y procedimientos aprobados.
3. Si hay compromiso de credenciales, rotar secretos de cliente, contraseñas de DB/Redis y claves expuestas con despliegue coordinado; invalidar tokens cuando corresponda.
4. Para sospecha de clave OIDC comprometida, detener emisión afectada, retirar `kid` comprometido, publicar clave nueva, coordinar actualización de clientes y evaluar revocación/TTL de tokens.
5. Para exfiltración o corrupción de datos, preservar evidencia, detener escrituras si hace falta, restaurar a una base aislada y validar antes del cutover.
6. Notificar a los responsables de privacidad/legal y usuarios según obligaciones aplicables. Documentar cronología, impacto, decisiones y acciones correctivas.
7. Cerrar con análisis de causa raíz, pruebas de controles y actualización del modelo de amenazas y checklist.

Este manual es una base operativa; objetivos de continuidad, guardias, contactos y plazos legales deben definirse antes de producción.
