import * as oidc from 'openid-client';

export const GOOGLE_ISSUER = 'https://accounts.google.com';

export interface GoogleIdentityClaims {
  subject: string;
  email: string;
  emailVerified: boolean;
}

export interface GoogleOidcClient {
  authorizationUrl(input: { state: string; nonce: string; codeVerifier: string }): Promise<string>;
  completeAuthorization(input: {
    callbackUrl: URL;
    expectedState: string;
    expectedNonce: string;
    codeVerifier: string;
  }): Promise<GoogleIdentityClaims>;
}

export interface GoogleOidcConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export class OpenIdGoogleClient implements GoogleOidcClient {
  private configuration?: Promise<oidc.Configuration>;

  constructor(private readonly config: GoogleOidcConfig) {}

  async authorizationUrl(input: {
    state: string;
    nonce: string;
    codeVerifier: string;
  }): Promise<string> {
    const challenge = await oidc.calculatePKCECodeChallenge(input.codeVerifier);
    const url = oidc.buildAuthorizationUrl(await this.getConfiguration(), {
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      state: input.state,
      nonce: input.nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    return url.href;
  }

  async completeAuthorization(input: {
    callbackUrl: URL;
    expectedState: string;
    expectedNonce: string;
    codeVerifier: string;
  }): Promise<GoogleIdentityClaims> {
    const tokens = await oidc.authorizationCodeGrant(
      await this.getConfiguration(),
      input.callbackUrl,
      {
        expectedState: input.expectedState,
        expectedNonce: input.expectedNonce,
        pkceCodeVerifier: input.codeVerifier,
      },
    );
    const claims = tokens.claims();
    if (
      !claims ||
      typeof claims.sub !== 'string' ||
      typeof claims.email !== 'string' ||
      typeof claims.email_verified !== 'boolean'
    ) {
      throw new Error('Google identity response is incomplete');
    }
    return {
      subject: claims.sub,
      email: claims.email,
      emailVerified: claims.email_verified,
    };
  }

  private getConfiguration(): Promise<oidc.Configuration> {
    this.configuration ??= oidc.discovery(
      new URL(GOOGLE_ISSUER),
      this.config.clientId,
      { redirect_uris: [this.config.redirectUri], response_types: ['code'] },
      oidc.ClientSecretPost(this.config.clientSecret),
    );
    return this.configuration;
  }
}

export const googleFlowCrypto = {
  randomState: oidc.randomState,
  randomNonce: oidc.randomNonce,
  randomCodeVerifier: oidc.randomPKCECodeVerifier,
};
