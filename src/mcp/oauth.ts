import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload
} from 'jose';

export interface VerifiedAccessToken {
  token: string;
  subject: string;
  clientId: string;
  scopes: string[];
  expiresAt?: number;
  payload: JWTPayload;
}

export interface AccessTokenVerifier {
  verify(token: string): Promise<VerifiedAccessToken>;
}

function scopesFromPayload(payload: JWTPayload): string[] {
  const scope = payload.scope;
  if (typeof scope === 'string') {
    return scope.split(/\s+/).filter(Boolean);
  }

  const scopes = payload.scp;
  if (typeof scopes === 'string') {
    return scopes.split(/\s+/).filter(Boolean);
  }
  if (Array.isArray(scopes)) {
    return scopes.filter((value): value is string => typeof value === 'string');
  }

  return [];
}

export class JwksAccessTokenVerifier implements AccessTokenVerifier {
  private readonly jwks;

  constructor(
    jwksUri: string,
    private readonly issuer: string,
    private readonly audience: string,
    private readonly requiredScope: string
  ) {
    this.jwks = createRemoteJWKSet(new URL(jwksUri));
  }

  async verify(token: string): Promise<VerifiedAccessToken> {
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.issuer,
      audience: this.audience
    });

    const scopes = scopesFromPayload(payload);
    if (!scopes.includes(this.requiredScope)) {
      throw new Error('insufficient OAuth scope');
    }

    const subject =
      typeof payload.sub === 'string' && payload.sub.length > 0
        ? payload.sub
        : 'unknown';
    const clientId =
      typeof payload.client_id === 'string'
        ? payload.client_id
        : typeof payload.azp === 'string'
          ? payload.azp
          : subject;

    return {
      token,
      subject,
      clientId,
      scopes,
      ...(typeof payload.exp === 'number' ? { expiresAt: payload.exp } : {}),
      payload
    };
  }
}

export function oauthProtectedResourceMetadata(
  resource: string,
  issuer: string,
  scope: string
) {
  return {
    resource,
    authorization_servers: [issuer],
    scopes_supported: [scope]
  };
}

export function oauthChallenge(
  resource: string,
  scope: string,
  error?: string,
  description?: string
): string {
  const metadata = new URL(
    '/.well-known/oauth-protected-resource',
    resource
  ).toString();
  const parts = [
    `Bearer resource_metadata="${metadata}"`,
    `scope="${scope}"`
  ];
  if (error) parts.push(`error="${error.replace(/"/g, '')}"`);
  if (description) {
    parts.push(
      `error_description="${description.replace(/"/g, '')}"`
    );
  }
  return parts.join(', ');
}
