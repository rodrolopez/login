# ADR 0006: autenticación federada con Google

## Estado

Aceptada para la Fase 7.

## Decisión

La API actúa como relying party OpenID Connect mediante `openid-client` 6.x y usa Authorization Code con PKCE S256. La configuración Google es opcional; sin las tres variables `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` y `GOOGLE_REDIRECT_URI`, las rutas federadas responden como no disponibles. El callback debe coincidir exactamente con el URI registrado en Google Cloud Console. Fuera de desarrollo local, solo se acepta HTTPS.

Cada inicio genera `state`, `nonce` y un PKCE code verifier criptográficamente aleatorios. El estado se guarda en Redis por cinco minutos y se consume con `GETDEL`, por lo que un callback puede procesarse una sola vez. También se enlaza al navegador con una cookie temporal HttpOnly, SameSite=Lax y Secure en producción; la cookie se compara en tiempo constante con el `state` de retorno y se elimina al llegar al callback. El host que inicia el flujo debe coincidir con el host del redirect URI para que el navegador envíe la cookie de estado. `openid-client` valida la respuesta OIDC, la firma y claims del ID Token, incluyendo `state`, `nonce` y PKCE. Los errores del proveedor no se devuelven al cliente ni se registran.

La identidad de Google se identifica por el issuer fijo `https://accounts.google.com` y su `sub`, nunca por el correo. Si ese par ya está vinculado, inicia sesión en la cuenta ya asociada, respetando su estado. Si todavía no existe y el correo reclamado ya pertenece a una cuenta local, el flujo se detiene y pide que el usuario inicie sesión con contraseña antes de vincular. Esta fase no agrega una operación de vinculación de cuentas autenticadas. Una cuenta Google nueva y su fila en `external_identities` se crean dentro de una transacción. La unicidad de correo e identidad externa evita duplicados concurrentes y el rollback evita cuentas parciales. `email_verified` se persiste desde el claim validado de Google; los estados de cuenta siguen las reglas existentes.

En caso de éxito se crea la misma sesión API aleatoria respaldada por Redis que usa el login local, y se emite la cookie HttpOnly de Fase 6. No se almacenan tokens del proveedor. Las pruebas usan un `GoogleOidcClient` inyectado que simula sus respuestas; no hacen llamadas de red a Google.

## Consecuencias y riesgos pendientes

- En la consola de Google se debe registrar exactamente el valor de `GOOGLE_REDIRECT_URI`.
- En producción, los tres valores se deben suministrar desde un gestor de secretos y el callback debe ser HTTPS.
- Las cuentas locales no se vinculan automáticamente, aunque el email de Google figure como verificado. El flujo explícito de vinculación requiere una fase futura con sesión local autenticada y protección CSRF.
- La protección frente a callbacks repetidos depende del Redis compartido y su comando atómico `GETDEL`.
