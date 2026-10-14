-- NEON EXCHANGE: server-side admin-code authentication scaffold
-- Review this file before running it in Supabase SQL Editor.
-- IMPORTANT: Replace CHANGE_THIS_WITH_YOUR_ADMIN_CODE with your admin code before running.
-- Never put the real admin code in index.html or any public JavaScript.

-- Ensure bcrypt hashing functions are available in Supabase's extensions schema.
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create schema if not exists private;

create table if not exists private.admin_config (
  id boolean primary key default true check (id),
  code_hash text not null
);

create table if not exists private.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  granted_at timestamptz not null default now()
);

create table if not exists private.admin_code_attempts (
  user_id uuid primary key references auth.users(id) on delete cascade,
  attempts integer not null default 0,
  window_started_at timestamptz not null default now(),
  locked_until timestamptz
);

revoke all on schema private from public, anon, authenticated;
revoke all on all tables in schema private from public, anon, authenticated;

-- Store only a bcrypt hash of the code. Run this setup once; change the placeholder first.
insert into private.admin_config (id, code_hash)
values (true, crypt('CHANGE_THIS_WITH_YOUR_ADMIN_CODE', gen_salt('bf')))
on conflict (id) do nothing;

create or replace function public.verify_admin_code(p_code text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_hash text;
  v_attempts integer;
  v_window timestamptz;
  v_locked timestamptz;
begin
  if v_user is null then
    raise exception 'ログインしてください';
  end if;

  if p_code is null or length(p_code) > 128 then
    return false;
  end if;

  insert into private.admin_code_attempts(user_id)
  values (v_user)
  on conflict (user_id) do nothing;

  select attempts, window_started_at, locked_until
    into v_attempts, v_window, v_locked
    from private.admin_code_attempts
    where user_id = v_user
    for update;

  if v_locked is not null and v_locked > pg_catalog.now() then
    raise exception '試行回数が多すぎます。しばらく待ってください';
  end if;

  if v_window < pg_catalog.now() - interval '15 minutes' then
    update private.admin_code_attempts
      set attempts = 0, window_started_at = pg_catalog.now(), locked_until = null
      where user_id = v_user;
    v_attempts := 0;
  end if;

  select code_hash into v_hash from private.admin_config where id = true;
  if v_hash is not null and extensions.crypt(p_code, v_hash) = v_hash then
    insert into private.admin_users(user_id) values (v_user)
    on conflict (user_id) do nothing;
    update private.admin_code_attempts
      set attempts = 0, window_started_at = pg_catalog.now(), locked_until = null
      where user_id = v_user;
    return true;
  end if;

  v_attempts := coalesce(v_attempts, 0) + 1;
  update private.admin_code_attempts
    set attempts = v_attempts,
        locked_until = case when v_attempts >= 5 then pg_catalog.now() + interval '15 minutes' else null end
    where user_id = v_user;
  return false;
end;
$$;

revoke all on function public.verify_admin_code(text) from public, anon;
grant execute on function public.verify_admin_code(text) to authenticated;

-- This function can be used by later admin actions to check server-side authorization.
create or replace function public.is_current_user_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from private.admin_users where user_id = auth.uid()
  );
$$;

revoke all on function public.is_current_user_admin() from public, anon;
grant execute on function public.is_current_user_admin() to authenticated;
