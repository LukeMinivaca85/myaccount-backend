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
alter table public.security_events enable row level security;

revoke all on public.oauth_clients from anon, authenticated;
revoke all on public.security_events from anon, authenticated;
