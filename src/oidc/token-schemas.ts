import { z } from 'zod';

export const tokenAuthorizationCodeBody = z.object({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  client_id: z.string().min(1),
  redirect_uri: z.string().optional(),
  code_verifier: z.string().optional(),
  referrer: z.string().optional(),
  client_secret: z.string().optional(),
});

export const tokenRefreshBody = z.object({
  grant_type: z.literal('refresh_token'),
  refresh_token: z.string().min(1),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
});

export const tokenBody = z.discriminatedUnion('grant_type', [
  tokenAuthorizationCodeBody,
  tokenRefreshBody,
]);

export type TokenBody = z.infer<typeof tokenBody>;
