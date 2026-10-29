# ADR 0009: TOTP MFA y códigos de recuperación

**Estado:** Aceptada para la Fase 11  
**Fecha:** 2026-10-29

## Contexto

La API requiere MFA opcional basado en TOTP y códigos de recuperación de un solo uso. WebAuthn/passkeys queda fuera de esta fase. El segundo factor debe bloquear tanto el inicio de sesión de API como el cierre de la interacción de login de OIDC.

## Decisiones

- `otplib` implementa TOTP RFC 6238 con secretos aleatorios Base32 de 160 bits, códigos de seis dígitos y paso de 30 segundos. Se acepta una ventana de tolerancia de un paso para compensar relojes; el contador aceptado se persiste y no se vuelve a aceptar.
- Las semillas se cifran con AES-256-GCM antes de guardarse en PostgreSQL. La clave dedicada `MFA_ENCRYPTION_KEY` es hexadecimal de 32 bytes, se proporciona por configuración y no se incluye en el repositorio. El enrolamiento pendiente expira en 15 minutos.
- El enrolamiento exige una sesión API autenticada. La API devuelve la semilla y URI `otpauth://` para el QR; el primer TOTP válido activa MFA y emite diez códigos de recuperación aleatorios. Solo se devuelven una vez.
- Los códigos de recuperación se persisten con Argon2id y se consumen mediante una actualización condicional, por lo que una reutilización concurrente no puede autorizar más de una vez.
- Una contraseña válida o autenticación Google para una cuenta con MFA produce un challenge aleatorio de cinco minutos almacenado en Redis. Solo se guarda el digest del challenge como clave Redis. No se emite cookie de sesión ni se completa OIDC hasta validar TOTP o un código de recuperación. Al completar, el challenge se elimina atómicamente.
- El endpoint de verificación de segundo factor tiene un límite Redis separado. El contador TOTP también evita la repetición dentro del mismo período.

## Riesgos y límites

- Perder `MFA_ENCRYPTION_KEY` vuelve inaccesibles las semillas. Debe respaldarse de forma segura y mantenerse igual en todas las instancias; la rotación requiere un procedimiento futuro.
- No se implementan passkeys/WebAuthn, códigos por correo/SMS, administración de dispositivos, regeneración de códigos, ni un flujo de desactivación/recuperación administrativa de MFA.
- El TOTP depende de relojes razonablemente sincronizados. La tolerancia amplia aumenta la ventana de aceptación; se limita a ±30 segundos y cada contador solo se acepta una vez.
- Los códigos de recuperación se muestran una sola vez. La interfaz cliente debe advertir que se guarden antes de cerrar el diálogo de confirmación.

## Validación

Las pruebas de integración usan exclusivamente PostgreSQL y Redis del perfil aislado de testing. Deben cubrir el enrolamiento, el login API y OIDC con MFA, TOTP inválido, consumo/reuso de recuperación y rate limiting.
