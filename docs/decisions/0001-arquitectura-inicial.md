# ADR 0001: Arquitectura inicial de Identity API

- **Estado:** Propuesta para revisión; no implica aprobación para Fase 1.
- **Fecha:** 2026-10-26.
- **Contexto:** Fase 0 de `LOGIN.md`. El directorio está inicialmente vacío salvo por el Documento Maestro.

## Decisiones propuestas

### Runtime y módulos

- Usar Node.js 24 LTS como runtime objetivo y fijar la versión mayor en la configuración del proyecto/CI. Node.js 20.20.2 está instalado en el entorno inspeccionado, pero la rama 20 ya figura EOL; no se debe usar para el desarrollo o despliegue nuevo.
- Usar TypeScript en modo estricto y módulos ESM (`"type": "module"`). La versión actual de `oidc-provider` es ESM y el código de ejemplo del proyecto usa importaciones ESM. Fijar las versiones efectivas en `package-lock.json` cuando se autorice Fase 1.
- Usar Express 5 con los tipos comunitarios `@types/express` 5, compatible con Node.js 18 o superior. Verificar compatibilidad de compilación con el `tsconfig` estricto durante Fase 1.

### OIDC y federación de Google

- Usar `oidc-provider` para el rol de OpenID Provider (OP); su versión observada en el registro es 9.13.0. Integrarlo en Express 5 por el callback HTTP documentado.
- No confundir el OP propio con el inicio de sesión de Google: para Google como proveedor externo, agregar `openid-client` como OpenID Relying Party (RP), también de Panva, y validar la versión y el flujo en Fase 1. No implementar OAuth/OIDC manualmente.
- Implementar nuestros propios flujos de interacción (pantallas/endpoints de login, consentimiento y errores) y `findAccount`; `oidc-provider` no proporciona esos flujos de producto listos para producción. Desactivar expresamente `devInteractions` antes de cualquier ejecución que no sea una prueba local aislada.
- Para Google se necesitarán proyecto y consentimiento OAuth configurados, credencial de tipo aplicación web, URI de callback exactamente coincidente, HTTPS fuera de localhost, scopes mínimos (`openid`, `email`, `profile` solo si se necesitan), y secretos fuera del repositorio. Validar `state`/nonce mediante biblioteca y no ampliar scopes sin necesidad. Aún no hay credenciales ni callback definidos.

### Persistencia, caché y migraciones

- Usar PostgreSQL 18 (rama vigente y soportada observada) para identidad, organizaciones, membresías, clientes registrados y datos de auditoría; usar `pg` con SQL parametrizado explícito, sin ORM.
- Usar Redis para el adaptador de almacenamiento del proveedor OIDC y los artefactos/sesiones efímeros con TTL, permitiendo múltiples instancias. La identidad de negocio y la configuración autoritativa de clientes permanecen en PostgreSQL; definir y probar la integración/caché del registro de clientes con el adaptador antes de cerrar Fase 1. No almacenar tokens ni secretos en logs.
- Definir migraciones SQL versionadas, revisables y transaccionales, aplicadas por una orden explícita y con rollback documentado cuando sea viable. No modificar esquema automáticamente al iniciar el servicio.
- PostgreSQL local se ejecutará mediante un servicio PostgreSQL fijado por versión en Docker Compose, con volumen local, healthcheck y credenciales solo desde `.env` local ignorado por Git. Redis tendrá un servicio Compose equivalente. No se iniciaron contenedores en Fase 0.

### Pruebas y calidad

- Usar Vitest para pruebas unitarias e integración; Supertest para HTTP. Los tests de integración usarán PostgreSQL/Redis locales de Compose con datos sintéticos, nunca datos reales.
- Separar pruebas unitarias deterministas de integración que requieren servicios. Las pruebas de seguridad cubrirán aislamiento entre organizaciones, expiración/revocación y redacción de secretos antes de considerar esas fases completas.
- Fase 1 debe incorporar lint, typecheck y tests reproducibles, además del pipeline CI requerido por el Documento Maestro. No se ejecutaron tests porque no existe aún proyecto ni código.

## Riesgos y decisiones pendientes

1. Confirmar mediante instalación y typecheck que la versión publicada de `oidc-provider`, Express 5, Node 24 y sus tipos seleccionados son compatibles; no se instalaron dependencias durante Fase 0.
2. Diseñar un adaptador compatible con el contrato vigente de `oidc-provider` y decidir la política de clientes estáticos/dinámicos, invalidación de caché y persistencia durable de grants. El adaptador es una pieza crítica y no viene resuelto por PostgreSQL `pg`.
3. Revisar las necesidades de almacenamiento de sesiones de usuario del BFF por separado de los artefactos internos OIDC, y definir estrategia de claves de firma/JWKS y rotación sin secretos fijos.
4. No hay servidor PostgreSQL activo, Redis local ni configuración de Google en el entorno. Compose existe, pero la ejecución de servicios y la integración quedan para fases posteriores.
5. El runtime local Node 20 está EOL. Antes de Fase 1 se debe disponer de Node 24 LTS en el entorno del proyecto.
6. El repositorio Git detectado está en `/home/university/RiderProjects` (directorio padre), no en `login`; hay cambios y archivos no relacionados en ese árbol. Limitar commits futuros y revisión de cambios a `login/` para evitar incluir material ajeno.

## Referencias consultadas

- Node.js Releases: https://nodejs.org/en/about/previous-releases
- Express 5 migration/requirements: https://expressjs.com/en/guide/migrating-5/
- `oidc-provider` API y requisitos de configuración: https://github.com/panva/node-oidc-provider/blob/main/docs/README.md
- Versión y formato de módulo de `oidc-provider`: https://github.com/panva/node-oidc-provider/blob/main/package.json
- `openid-client`: https://github.com/panva/openid-client
- Google OAuth 2.0 para aplicaciones web: https://developers.google.com/identity/protocols/oauth2/web-server
- Versionado y soporte de PostgreSQL: https://www.postgresql.org/support/versioning/
