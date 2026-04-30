export type Referrer = 'DEFAULT' | 'SANDBOX';

export interface TossSuccessEnvelope<T> {
  resultType: 'SUCCESS';
  success: T;
}

export interface TossFailEnvelope {
  resultType: 'FAIL';
  error: { reason: string; description?: string };
}

export type TossEnvelope<T> = TossSuccessEnvelope<T> | TossFailEnvelope;

export interface GenerateTokenSuccess {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  scope: string;
}

export interface RefreshTokenSuccess {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn: number;
  scope?: string;
}

export interface LoginMeSuccess {
  userKey: number;
  scope: string;
  agreedTerms: string[];
  name?: string;
  phone?: string;
  birthday?: string;
  ci?: string;
  gender?: string;
  nationality?: string;
}
