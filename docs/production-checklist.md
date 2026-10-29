# Checklist de preparación para producción

No desplegar públicamente hasta que los puntos aplicables estén marcados, revisados por un responsable y exista evidencia. Esta checklist no sustituye una auditoría de seguridad ni una revisión legal.

## Seguridad de la aplicación

- [ ] Rate limiting de autenticación centralizado en Redis; límites y alertas ensayados bajo carga.
- [ ] Trazas OpenTelemetry activas, exportadas a colector privado y correlacionadas con logs por trace ID.
- [ ] Logs centralizados con retención y acceso definidos; verificado que no registran contraseñas, tokens, cookies, secretos, cuerpos ni stack traces.
- [ ] HSTS, CSP, X-Frame-Options, MIME sniffing y CORS revisados con dominios reales de producción.
- [ ] Cookies OIDC/API configuradas con `Secure`, `HttpOnly`, `SameSite` y dominio/ruta mínimos.
- [ ] HTTPS de extremo a extremo en borde/proxy y política de host; cabeceras forwarded aceptadas solo desde proxies confiables.
- [ ] WAF/CDN obligatorio desplegado antes del servicio, con mitigación DDoS, reglas OWASP, límites y procedimiento de bypass/incidente.
- [ ] Proxy inverso Nginx/Caddy configura TLS, redirección HTTP→HTTPS, tamaño máximo, timeout y hosts permitidos.
- [ ] Escaneo actualizado de dependencias, imagen base, SBOM y artefacto de release; vulnerabilidades altas/críticas resueltas o aceptadas formalmente.
- [ ] CI bloquea merge por tests, lint y typecheck; build y análisis de dependencias se ejecutan en la release.
- [ ] Pruebas adversariales/seguridad y autorización multi-tenant se ejecutan contra datos de prueba aislados.
- [ ] Cuentas pendientes, suspendidas, deshabilitadas y MFA verificadas en flujos de login/OIDC.
- [ ] CORS no usa wildcard con credenciales; CSRF y orígenes se revisan para los clientes de producción.

## Identidad, claves y privacidad

- [ ] `OIDC_ISSUER` usa la URL HTTPS canónica y discovery/JWKS son accesibles desde consumidores previstos.
- [ ] `OIDC_CLIENTS` contiene solo clientes aprobados con redirect URIs exactas, PKCE obligatorio para clientes públicos y secretos separados por aplicación.
- [ ] Claves privadas OIDC/JWKS, claves cookie, `MFA_ENCRYPTION_KEY`, credenciales Google y credenciales de DB/Redis generadas, persistentes y cargadas desde secret manager.
- [ ] Existe backup cifrado/recuperable de claves y plan probado de rotación con solapamiento de `kid`.
- [ ] Se han probado emisión, rotación, validación y retiro de claves con cliente OIDC de prueba.
- [ ] Acceso a secretos auditado, limitado, rotado y ausente de repositorio, logs, image layers y CI artifacts.
- [ ] Flujos de borrado lógico, anonimización, borrado físico y exportación GDPR/CCPA tienen propietario, procedimiento y retención definidos.
- [ ] Política de correo y verificación está aprobada; proveedor de correo configurado deliberadamente, con secretos y callbacks adecuados.
- [ ] Notificaciones de cambios de identidad a servicios externos (webhooks/event bus) están implementadas o formalmente fuera de alcance con mitigación documentada. **Pendiente en el estado actual del proyecto.**

## Infraestructura y datos

- [ ] API corre como no-root y con filesystem de solo lectura; imagen identificada por digest y revisada.
- [ ] No hay puertos de aplicación, PostgreSQL o Redis publicados directamente en interfaces públicas.
- [ ] Proxy se conecta a la red edge; PostgreSQL/Redis solo se conectan a la red interna; colector OTLP en red de observabilidad privada.
- [ ] Límites CPU/memoria probados bajo carga, sizing ajustado y alertas de capacidad activas.
- [ ] PostgreSQL versión/digest aprobado, backups PITR/retención definidos y restauración ensayada con RPO/RTO aprobado.
- [ ] Redis persistencia, memoria, `noeviction`, expiración, respaldos y recuperación de estado operativo verificados.
- [ ] Base creada con rol runtime `identity_app` de mínimo privilegio; API nunca se conecta como `postgres` ni como rol migratorio.
- [ ] Rol `identity_migrator` separado, credenciales con rotación y sesión de migración manual auditable.
- [ ] Migraciones revisadas antes de ejecutar, checksum íntegro y backup previo; ningún arranque ejecuta migraciones automáticamente.
- [ ] Redes, volúmenes y copias de seguridad usan cifrado en reposo/en tránsito según el proveedor y política.
- [ ] Host Docker, kernel, runtime, certificados y dependencias tienen actualización y parcheo definidos.

## Operación y respuesta

- [ ] Dashboard y alertas para disponibilidad, latencias, 5xx, CPU/memoria, PostgreSQL, Redis, OTLP y expiración TLS.
- [ ] Logs WAF/proxy/API centralizados, redaccionados, con permisos y retención definidos.
- [ ] Prueba de backup y restore reciente adjunta con base restaurada aislada y validación de datos.
- [ ] Procedimiento de rotación y recuperación de claves OIDC/MFA probado por más de un operador autorizado.
- [ ] Runbook de incidentes, guardia/contactos, responsabilidades, comunicaciones y obligaciones regulatorias completados.
- [ ] Procedimientos de escalado horizontal, mantenimiento, drenaje de tráfico y rollback revisados.
- [ ] Se ha definido si el despliegue de un host es aceptable; de lo contrario hay redundancia de zona/host, base de datos administrada o replicada y failover probado.
- [ ] Evaluación de seguridad independiente, privacidad y aprobación de negocio completadas antes de aceptar usuarios reales.

## Estado actual de este repositorio

La Fase 13 prepara Compose, Dockerfile, telemetría de trazas, manuales y scripts de operación. No despliega servicios. El proxy/WAF, colector OTLP, gestor de secretos, imagen de release firmada, restauración de producción, alta disponibilidad, webhooks y aprobaciones organizacionales siguen siendo operaciones/controles por completar antes de un despliegue real.
