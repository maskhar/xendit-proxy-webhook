export type AppEnvironment = 'test' | 'live';

export type Scope =
  | 'payment:create'
  | 'payment:read'
  | 'payment:cancel'
  | 'session:create'
  | 'session:read'
  | 'refund:create'
  | 'refund:read';

export type TenantContext = {
  tenantId: string;
  tenantSlug: string;
  tenantCode: string;
  apiKeyId: string;
  scopes: ReadonlySet<Scope>;
};
