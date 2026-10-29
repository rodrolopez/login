import type { RequestHandler } from 'express';

export type Language = 'en' | 'es';

export const messages = {
  en: {
    validation: 'The request contains invalid data.',
    required: 'This field is required.',
    invalidEmail: 'Enter a valid email address.',
    passwordLength: 'Password must be between 12 and 128 characters.',
    invalidPassword: 'Password must be a valid string of at most 128 characters.',
    invalidCredentials: 'Invalid credentials.',
    emailAlreadyUsed: 'Unable to register with these details.',
    accountActionAccepted:
      'If the account is eligible, instructions will be sent to its email address.',
    emailVerificationComplete: 'Email address verified.',
    accountActionInvalid: 'The link is invalid, expired, or has already been used.',
    passwordRecoveryComplete: 'Password updated. Please sign in again.',
    googleLocalAccount:
      'This email already has a local account. Sign in with your password before linking Google.',
    googleFailure: 'Google authentication could not be completed. Please try again.',
    rateLimited: 'Too many attempts. Please try again later.',
    mfaRequired: 'Additional verification is required to finish signing in.',
    mfaInvalid: 'The verification code is invalid or expired.',
    mfaAlreadyEnabled: 'Multi-factor authentication is already enabled.',
    unavailable: 'Authentication is temporarily unavailable.',
    internal: 'An internal error occurred.',
    notFound: 'The requested resource was not found.',
    payloadTooLarge: 'The request body is too large.',
    crossOriginDenied: 'Cross-origin request denied.',
  },
  es: {
    validation: 'La solicitud contiene datos inválidos.',
    required: 'Este campo es obligatorio.',
    invalidEmail: 'Ingresá una dirección de correo válida.',
    passwordLength: 'La contraseña debe tener entre 12 y 128 caracteres.',
    invalidPassword: 'La contraseña debe ser texto de hasta 128 caracteres.',
    invalidCredentials: 'Credenciales inválidas.',
    emailAlreadyUsed: 'No se pudo completar el registro con esos datos.',
    accountActionAccepted:
      'Si la cuenta puede realizar esta operación, recibirá instrucciones por correo electrónico.',
    emailVerificationComplete: 'Correo electrónico verificado.',
    accountActionInvalid: 'El enlace no es válido, venció o ya fue utilizado.',
    passwordRecoveryComplete: 'Contraseña actualizada. Iniciá sesión nuevamente.',
    googleLocalAccount:
      'Este correo ya tiene una cuenta local. Iniciá sesión con contraseña antes de vincular Google.',
    googleFailure: 'No se pudo completar la autenticación con Google. Intentá de nuevo.',
    rateLimited: 'Demasiados intentos. Volvé a intentarlo más tarde.',
    mfaRequired: 'Se requiere una verificación adicional para completar el inicio de sesión.',
    mfaInvalid: 'El código de verificación no es válido o venció.',
    mfaAlreadyEnabled: 'La autenticación multifactor ya está activada.',
    unavailable: 'La autenticación no está disponible temporalmente.',
    internal: 'Ocurrió un error interno.',
    notFound: 'No se encontró el recurso solicitado.',
    payloadTooLarge: 'El cuerpo de la solicitud es demasiado grande.',
    crossOriginDenied: 'Solicitud de origen cruzado rechazada.',
  },
} as const;

export type MessageKey = keyof typeof messages.en;

function languageFromHeader(header: string | undefined): Language {
  if (!header) return 'es';

  const preferences = header
    .split(',')
    .map((range, index) => {
      const [tag = '', ...parameters] = range.trim().split(';');
      const qualityParameter = parameters.find((parameter) => parameter.trim().startsWith('q='));
      const quality = qualityParameter ? Number(qualityParameter.trim().slice(2)) : 1;
      return { tag: tag.toLowerCase().split('-')[0], quality, index };
    })
    .filter(({ tag, quality }) => (tag === 'en' || tag === 'es') && quality > 0 && quality <= 1)
    .sort((left, right) => right.quality - left.quality || left.index - right.index);

  return preferences[0]?.tag === 'en' ? 'en' : preferences[0]?.tag === 'es' ? 'es' : 'es';
}

export const languageMiddleware: RequestHandler = (request, response, next) => {
  response.locals.language = languageFromHeader(request.get('accept-language'));
  next();
};

export function requestLanguage(response: { locals: Record<string, unknown> }): Language {
  return response.locals.language === 'en' ? 'en' : 'es';
}
