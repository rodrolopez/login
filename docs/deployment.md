# Despliegue de producción

Este manifiesto prepara una instalación en un único host Docker. No publica puertos del host: la API solo es alcanzable desde las redes Docker conectadas; PostgreSQL y Redis permanecen exclusivamente en la red privada interna.

## Topología obligatoria

```text
Internet
  -> CDN/WAF administrado (TLS público, mitigación DDoS y reglas de aplicación)
  -> proxy inverso Nginx/Caddy (HTTPS, host permitido, límites de cuerpo y timeouts)
  -> red Docker identity-edge
  -> API Identity (puerto interno 3005)
  -> red identity-private -> PostgreSQL 18 y Redis 7
  -> red identity-observability -> colector OTLP privado
```

El CDN/WAF debe ser el borde público y el proxy inverso debe terminar HTTPS y enviar tráfico a la API por la red `identity-edge`. No se debe exponer directamente el puerto Node, PostgreSQL o Redis. La API no debe confiar en cabeceras `Forwarded` o `X-Forwarded-*` enviadas por clientes arbitrarios: el proxy debe reemplazarlas y restringir su origen. Antes de habilitar `trust proxy` en Express, definir y probar la lista exacta de proxies confiables.

Aplicar reglas de egress del host para permitir únicamente destinos necesarios (por ejemplo Google OAuth cuando está habilitado, el colector OTLP privado, DNS y repositorios de actualización aprobados). El acceso a la red edge no debe convertirse en acceso irrestricto a servicios de administración.

El servicio `api` no contiene un servidor TLS. El CDN/WAF, el certificado y Nginx/Caddy son componentes externos y deben administrarse, monitorearse y actualizarse por separado. Configurar HSTS en el borde solo después de validar HTTPS para todos los hosts y subdominios incluidos.

## Construcción y redes

Requisitos operativos: Docker Engine con Docker Compose v2, un entorno de secretos protegido, una instancia/colector OTLP compatible con OTLP/HTTP y redes externas preparadas para el proxy y el colector.

Crear redes dedicadas. El proxy/CDN connector se une a `identity-edge`; el colector se une a `identity-observability`. Mantener PostgreSQL y Redis únicamente en la red privada creada por Compose.

```sh
docker network create identity-edge
docker network create --internal identity-observability
```

Construir la imagen sin secretos dentro del contexto:

```sh
docker compose --env-file /secure/path/identity-api.production.env \
  -f docker-compose.prod.yml build api
```

Luego crear/provisionar los roles de PostgreSQL siguiendo [el procedimiento de privilegios](./operations.md#roles-de-postgresql-y-migraciones), ejecutar migraciones de manera explícita y levantar el stack. La operación `up` nunca ejecuta migraciones.

```sh
docker compose --env-file /secure/path/identity-api.production.env \
  -f docker-compose.prod.yml up -d --wait postgres redis

# Ejecutar el procedimiento de migración manual de docs/operations.md.

docker compose --env-file /secure/path/identity-api.production.env \
  -f docker-compose.prod.yml up -d --wait api
```

El archivo de entorno no debe estar en el repositorio. Mantenerlo fuera del árbol de trabajo, propiedad del usuario de despliegue y con permisos `0600`; preferir un gestor de secretos con inyección al proceso. No pegar credenciales en comandos compartidos ni en tickets. Los valores JSON de `OIDC_CLIENTS` y `OIDC_JWKS` deben ir en una sola línea y con quoting compatible con el formato de entorno de Compose; probar el resultado de `docker compose config` sin imprimirlo en terminales o logs compartidos porque expande secretos.

Variables obligatorias de despliegue: `POSTGRES_SUPERUSER_PASSWORD`, `PGPASSWORD`, `REDIS_PASSWORD`, `OIDC_ISSUER`, `OIDC_CLIENTS`, `OIDC_COOKIE_KEYS`, `OIDC_JWKS`, `MFA_ENCRYPTION_KEY` y `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`. Completar Google OAuth solo si ese proveedor se habilita. `OIDC_ISSUER` y el callback de Google deben ser HTTPS públicos. El colector OTLP debe estar en una red privada confiable y no aceptar tráfico público sin autenticación.

## Controles del contenedor

- La API usa una imagen multi-stage de Node 24, ejecuta como usuario `node`, filesystem de solo lectura, `/tmp` temporal y `no-new-privileges`.
- Los puertos se declaran como `expose`, nunca `ports`; Compose no publica sockets del host.
- PostgreSQL y Redis solo están en una red `internal` y usan volúmenes persistentes.
- Los límites de CPU/memoria están bajo `deploy.resources.limits`; validar que la versión de Docker Compose del host aplique esos límites. Ajustarlos mediante pruebas de carga y métricas antes de producción.
- Redis usa persistencia AOF y `noeviction`. Agregar capacidad de memoria y alertas para prevenir que el rate limiting o las sesiones fallen por agotamiento.
- El archivo de provisionamiento exige contraseñas distintas de al menos 32 caracteres para los roles runtime y migratorio; generarlas con el gestor de secretos.
- Usar tags de imagen revisados/digest inmutable, escaneo de vulnerabilidades, parches del host y ventanas de actualización. Este manifiesto deja tags de PostgreSQL/Redis declarados por versión mayor; producción debe fijar un digest probado en el inventario de releases.

## Salud y operación

`GET /health` es un probe de proceso, no una autorización para servir tráfico si una dependencia deja de estar sana. Compose espera healthchecks de PostgreSQL y Redis al iniciar la API. El balanceador debe usar readiness propia, con timeouts y retirada rápida de instancias cuando el proceso falle.

Las trazas HTTP exportan a OTLP/HTTP. Los logs estructurados salen por stdout con `trace_id`, método, estado y duración, sin URL, query, cuerpos ni credenciales. El runtime del host debe recoger stdout/stderr, restringir acceso y retención, y enviar logs a un sistema centralizado con redacción adicional. No hay un colector de telemetría incluido en este Compose.

La aplicación requiere varias instancias/host redundantes, copias externas de backups y un procedimiento de recuperación probado antes de considerar el servicio tolerante a fallos. Este manifiesto no reemplaza un diseño de alta disponibilidad ni un despliegue físico revisado.
