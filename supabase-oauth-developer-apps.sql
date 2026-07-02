create extension if not exists pgcrypto;

create table if not exists public.oauth_clients (
  id uuid primary key default gen_random_uuid(),
  client_id text not null unique,
  client_secret_hash text,
  name text not null,
  redirect_uris text[] not null default array[]::text[],
  allowed_scopes text[] not null default array['openid', 'profile', 'email']::text[],
  is_public boolean not null default false,
  is_active boolean not null default true,
  created_by uuid references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint oauth_clients_redirect_uris_not_empty check (array_length(redirect_uris, 1) > 0)
);

alter table public.oauth_clients add column if not exists client_secret_hash text;
alter table public.oauth_clients add column if not exists created_by uuid references auth.users(id) on delete cascade;
alter table public.oauth_clients add column if not exists updated_at timestamptz not null default now();

do $$
begin
  if exists (
    select 1
    from pg_constraint
    where conname = 'oauth_clients_public_only'
      and conrelid = 'public.oauth_clients'::regclass
  ) then
    alter table public.oauth_clients drop constraint oauth_clients_public_only;
  end if;
end $$;

create index if not exists oauth_clients_created_by_idx
  on public.oauth_clients (created_by);

create table if not exists public.oauth_authorization_codes (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  client_id text not null references public.oauth_clients(client_id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  redirect_uri text not null,
  scope text not null default 'openid',
  code_challenge text not null,
  code_challenge_method text not null default 'S256',
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.oauth_authorization_codes
  add column if not exists scope text not null default 'openid';

alter table public.oauth_authorization_codes
  alter column scopes set default array['openid']::text[];

create index if not exists oauth_authorization_codes_client_idx
  on public.oauth_authorization_codes (client_id);

create index if not exists oauth_authorization_codes_user_idx
  on public.oauth_authorization_codes (user_id);

create table if not exists public.oauth_tokens (
  id uuid primary key default gen_random_uuid(),
  token_hash text not null unique,
  client_id text not null references public.oauth_clients(client_id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  scope text not null default 'openid',
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.oauth_tokens
  add column if not exists token_hash text;

alter table public.oauth_tokens
  add column if not exists scope text not null default 'openid';

alter table public.oauth_tokens
  alter column token_jti_hash set default encode(gen_random_bytes(32), 'hex');

alter table public.oauth_tokens
  alter column scopes set default array['openid']::text[];

create unique index if not exists oauth_tokens_token_hash_uidx
  on public.oauth_tokens (token_hash)
  where token_hash is not null;

create index if not exists oauth_tokens_client_idx
  on public.oauth_tokens (client_id);

create index if not exists oauth_tokens_user_idx
  on public.oauth_tokens (user_id);

create table if not exists public.security_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null,
  action text not null,
  target text,
  metadata jsonb not null default '{}'::jsonb,
  ip_hash text,
  user_agent_hash text,
  created_at timestamptz not null default now()
);

alter table public.oauth_clients enable row level security;
alter table public.oauth_authorization_codes enable row level security;
alter table public.oauth_tokens enable row level security;
alter table public.security_events enable row level security;

revoke all on public.oauth_clients from anon, authenticated;
revoke all on public.oauth_authorization_codes from anon, authenticated;
revoke all on public.oauth_tokens from anon, authenticated;
revoke all on public.security_events from anon, authenticated;
