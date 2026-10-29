import { Buffer } from 'node:buffer';
import { z } from 'zod';

const passwordSchema = z
  .string()
  .min(12, { error: 'passwordLength' })
  .max(128, { error: 'passwordLength' })
  .refine((password) => Buffer.byteLength(password, 'utf8') <= 256, { error: 'passwordLength' });

const loginPasswordSchema = z
  .string()
  .min(1, { error: 'required' })
  .max(128, { error: 'invalidPassword' })
  .refine((password) => Buffer.byteLength(password, 'utf8') <= 256, { error: 'invalidPassword' });

const emailSchema = z.string().trim().toLowerCase().email({ error: 'invalidEmail' }).max(320);

export const registerBodySchema = z
  .object({ email: emailSchema, password: passwordSchema })
  .strict();

export const loginBodySchema = z
  .object({
    email: emailSchema,
    password: loginPasswordSchema,
    interactionUid: z
      .string()
      .min(16)
      .max(128)
      .regex(/^[A-Za-z0-9_-]+$/)
      .optional(),
  })
  .strict();

const accountActionTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

export const emailActionRequestSchema = z.object({ email: emailSchema }).strict();

export const emailVerificationConfirmSchema = z
  .object({ token: accountActionTokenSchema })
  .strict();

export const passwordRecoveryConfirmSchema = z
  .object({ token: accountActionTokenSchema, password: passwordSchema })
  .strict();

export const totpConfirmSchema = z.object({ token: z.string().regex(/^\d{6}$/) }).strict();

export const mfaLoginVerifySchema = z
  .object({
    challengeId: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    token: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
    recoveryCode: z
      .string()
      .regex(/^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{8}-[A-Fa-f0-9]{8}$/)
      .optional(),
  })
  .strict()
  .refine(
    (body) => Number(body.token !== undefined) + Number(body.recoveryCode !== undefined) === 1,
  );

export type RegisterBody = z.infer<typeof registerBodySchema>;
export type LoginBody = z.infer<typeof loginBodySchema>;
