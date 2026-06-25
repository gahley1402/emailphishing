
-- Enum for roles
create type public.app_role as enum ('admin', 'user');

-- Profiles
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text,
  created_at timestamptz not null default now()
);
grant select, insert, update on public.profiles to authenticated;
grant all on public.profiles to service_role;
alter table public.profiles enable row level security;
create policy "Users read own profile" on public.profiles for select to authenticated using (auth.uid() = id);
create policy "Users update own profile" on public.profiles for update to authenticated using (auth.uid() = id);
create policy "Users insert own profile" on public.profiles for insert to authenticated with check (auth.uid() = id);

-- User roles
create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.app_role not null,
  created_at timestamptz not null default now(),
  unique(user_id, role)
);
grant select on public.user_roles to authenticated;
grant all on public.user_roles to service_role;
alter table public.user_roles enable row level security;
create policy "Users read own roles" on public.user_roles for select to authenticated using (auth.uid() = user_id);

create or replace function public.has_role(_user_id uuid, _role public.app_role)
returns boolean language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.user_roles where user_id = _user_id and role = _role)
$$;

create policy "Admins read all roles" on public.user_roles for select to authenticated using (public.has_role(auth.uid(), 'admin'));

-- Scan history
create table public.scan_history (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  subject text,
  sender text,
  classification text not null check (classification in ('safe','suspicious','phishing')),
  risk_score int not null,
  email_preview text,
  findings jsonb not null default '[]'::jsonb,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
grant select, insert, delete on public.scan_history to authenticated;
grant all on public.scan_history to service_role;
alter table public.scan_history enable row level security;
create policy "Users manage own scans" on public.scan_history for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "Admins read all scans" on public.scan_history for select to authenticated using (public.has_role(auth.uid(), 'admin'));

-- Blacklisted domains (admin-managed, all users read)
create table public.blacklisted_domains (
  id uuid primary key default gen_random_uuid(),
  domain text not null unique,
  reason text,
  created_at timestamptz not null default now()
);
grant select on public.blacklisted_domains to authenticated;
grant all on public.blacklisted_domains to service_role;
alter table public.blacklisted_domains enable row level security;
create policy "Authenticated read blacklist" on public.blacklisted_domains for select to authenticated using (true);
create policy "Admins manage blacklist" on public.blacklisted_domains for all to authenticated using (public.has_role(auth.uid(),'admin')) with check (public.has_role(auth.uid(),'admin'));

-- Suspicious keywords (admin-managed, all users read)
create table public.suspicious_keywords (
  id uuid primary key default gen_random_uuid(),
  keyword text not null unique,
  weight int not null default 10,
  created_at timestamptz not null default now()
);
grant select on public.suspicious_keywords to authenticated;
grant all on public.suspicious_keywords to service_role;
alter table public.suspicious_keywords enable row level security;
create policy "Authenticated read keywords" on public.suspicious_keywords for select to authenticated using (true);
create policy "Admins manage keywords" on public.suspicious_keywords for all to authenticated using (public.has_role(auth.uid(),'admin')) with check (public.has_role(auth.uid(),'admin'));

-- Trigger: auto-create profile + assign role (first user = admin)
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  user_count int;
  assigned public.app_role;
begin
  insert into public.profiles (id, email, display_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email,'@',1)));

  select count(*) into user_count from public.user_roles;
  if user_count = 0 then
    assigned := 'admin';
  else
    assigned := 'user';
  end if;
  insert into public.user_roles (user_id, role) values (new.id, assigned);
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Seed default keywords and blacklisted domains
insert into public.suspicious_keywords (keyword, weight) values
  ('urgent', 10), ('verify account', 10), ('login immediately', 10),
  ('password expired', 10), ('click here', 10), ('update payment', 10),
  ('account suspended', 10), ('confirm your identity', 10), ('wire transfer', 10),
  ('limited time', 10), ('act now', 10), ('unusual activity', 10),
  ('reset your password', 10), ('security alert', 10), ('bitcoin', 10);

insert into public.blacklisted_domains (domain, reason) values
  ('paypa1.com','PayPal typosquat'),
  ('microsoft-support.com','Microsoft impersonation'),
  ('secure-apple.com','Apple impersonation'),
  ('amaz0n-billing.com','Amazon typosquat'),
  ('faceb00k-security.com','Facebook typosquat'),
  ('g00gle-verify.com','Google typosquat'),
  ('bit.ly','URL shortener'),
  ('tinyurl.com','URL shortener'),
  ('t.co','URL shortener'),
  ('goo.gl','URL shortener');
