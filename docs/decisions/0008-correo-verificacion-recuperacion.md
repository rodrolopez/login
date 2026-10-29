# ADR 0008: Correo, verificación y recuperación

- **Estado:** aceptada para Fase 9.
- **Fecha:** 2026-10-26.
- **Contexto:** las cuentas locales podían autenticarse mientras su correo seguía sin verificar. La aplicación necesita verificar la dirección y recuperar contraseñas sin revelar si una cuenta existe. El envío real queda desactivado.

## Decisiones

- El dominio depende de `EmailProvider`. `DisabledEmailProvider` es el adaptador por defecto: registra solo que se suprimió un envío y su propósito; descarta destinatario, token y contenido. `TestEmailProvider` captura mensajes simulados únicamente cuando se inyecta en pruebas.
- Los flujos son `POST /auth/email/verification/request`, `POST /auth/email/verification/confirm`, `POST /auth/password/recovery/request` y `POST /auth/password/recovery/confirm`. Las solicitudes responden siempre `202` con el mismo cuerpo para direcciones conocidas y desconocidas. Los errores de preparación también conservan esa respuesta genérica.
- Cada token contiene 256 bits aleatorios codificados en Base64URL. PostgreSQL guarda únicamente el SHA-256 hexadecimal, propósito, usuario, correo, expiración y fecha de consumo. El token vence a las 24 horas para verificación y a los 30 minutos para recuperación. Al emitir otro del mismo propósito se invalida el anterior.
- El consumo se realiza con bloqueo y actualización transaccional de una fila no consumida y no vencida. Verificación y recuperación aceptan propósitos distintos; los tokens vencidos, alterados, usados o de propósito incorrecto se rechazan.
- El registro deja la cuenta `pending`. Una verificación válida marca el correo como verificado y la cuenta como `active`. La autenticación local, la sesión API, las interacciones OIDC y la autorización de organizaciones requieren cuenta activa y correo primario verificado. Una identidad federada solo puede iniciar sesión si el proveedor confirmó el correo.
- La recuperación actualiza la contraseña con Argon2id y luego llama a `IdentitySessionRevocationService.revokeAccountSessions`, que destruye sesiones API, artefactos OIDC y grants persistidos. La revocación atraviesa PostgreSQL y Redis y no puede formar una transacción distribuida; el flujo falla cerrado si Redis no está disponible para las solicitudes de sesión.
- Las solicitudes de verificación y recuperación usan rate limiting de Redis. Los errores de confirmación son genéricos y no contienen estado interno.

## Consecuencias y límites

- En el entorno actual no se envían correos. El adaptador predeterminado descarta el token deliberadamente, así que la verificación manual end-to-end requiere un proveedor de correo configurado en una fase posterior. La suite usa el adaptador de pruebas y no realiza llamadas externas.
- La expiración se comprueba al consumir el token. La tabla conserva registros vencidos/consumidos para operar con trazabilidad mínima; una política futura de limpieza puede eliminarlos después de una ventana de retención.
- La respuesta genérica reduce la enumeración por contenido y código HTTP; no promete igualdad exacta de tiempos de respuesta.
