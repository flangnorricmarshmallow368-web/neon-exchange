-- NEON EXCHANGE: email-locked admin panel
-- Run this whole file in Supabase SQL Editor.
-- The stored MD5 is only an identifier, not a credential; the server still
-- requires the authenticated Supabase user's email to be confirmed.
-- This script installs all RPCs used by the admin panel and disables legacy
-- admin_adjust_coins overloads so they cannot be called around these checks.

create schema if not exists private;

create table if not exists private.neon_admin_settings (
  singleton boolean primary key default true check (singleton),
  admin_email_md5 text not null,
  updated_at timestamptz not null default pg_catalog.now()
);

revoke all on schema private from public, anon, authenticated;
revoke all on table private.neon_admin_settings from public, anon, authenticated;

do $admin_config$
declare
  v_admin_email_md5 text := '7f4e6fdc74537cb81002b5bd3d9a27f9';
begin
  if v_admin_email_md5 !~ '^[0-9a-f]{32}$' then
    raise exception '管理者メールの設定ハッシュが不正です。';
  end if;

  insert into private.neon_admin_settings(singleton, admin_email_md5)
  values (true, v_admin_email_md5)
  on conflict (singleton) do update
    set admin_email_md5 = excluded.admin_email_md5,
        updated_at = pg_catalog.now();
end;
$admin_config$;

create or replace function public.is_current_user_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from auth.users u
    cross join private.neon_admin_settings s
    where s.singleton
      and u.id = auth.uid()
      and u.email_confirmed_at is not null
      and pg_catalog.md5(pg_catalog.lower(coalesce(u.email, ''))) = s.admin_email_md5
  );
$$;

revoke all on function public.is_current_user_admin() from public, anon;
grant execute on function public.is_current_user_admin() to authenticated;

-- Create a unique user/item key needed for safe inventory grants.
do $inventory_guard$
begin
  if exists (
    select 1 from public.inventory
    group by user_id, item_id
    having count(*) > 1
  ) then
    raise exception 'inventory に同じプレイヤー・アイテムの重複行があります。先に重複を整理してください。';
  end if;
end;
$inventory_guard$;

create unique index if not exists admin_inventory_user_item_uidx
  on public.inventory(user_id, item_id);

create or replace function public.admin_list_players()
returns table(player_id uuid, player_name text, coins bigint)
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not public.is_current_user_admin() then
    raise exception '管理者権限がありません';
  end if;

  return query
  select p.id, p.player_name, w.coins
  from public.profiles p
  join public.wallets w on w.user_id = p.id
  order by p.player_name
  limit 1000;
end;
$$;

revoke all on function public.admin_list_players() from public, anon;
grant execute on function public.admin_list_players() to authenticated;

create or replace function public.admin_adjust_player_coins(
  p_target_user_id uuid,
  p_amount bigint,
  p_reason text default null
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_current bigint;
  v_reason text;
  v_next bigint;
begin
  if not public.is_current_user_admin() then
    raise exception '管理者権限がありません';
  end if;
  if p_target_user_id is null or p_amount is null or p_amount = 0
     or p_amount < -1000000000000::bigint or p_amount > 1000000000000::bigint then
    raise exception '対象プレイヤーまたはコイン数が正しくありません';
  end if;

  select w.coins into v_current
  from public.wallets w
  where w.user_id = p_target_user_id
  for update;

  if not found then
    raise exception '対象プレイヤーのウォレットが見つかりません';
  end if;
  if p_amount < 0 and v_current < -p_amount then
    raise exception '所持コインより大きい額は差し引けません';
  end if;
  if p_amount > 0 and v_current > 9223372036854775807::bigint - p_amount then
    raise exception 'コイン上限を超えます';
  end if;

  v_next := v_current + p_amount;
  update public.wallets set coins = v_next where user_id = p_target_user_id;

  v_reason := pg_catalog.left(coalesce(nullif(pg_catalog.btrim(p_reason), ''), '管理者によるコイン調整'), 160);
  insert into public.game_history(user_id, action, detail, amount)
  values (p_target_user_id, 'admin_coin_adjustment', v_reason, p_amount);

  return v_next;
end;
$$;

revoke all on function public.admin_adjust_player_coins(uuid, bigint, text) from public, anon;
grant execute on function public.admin_adjust_player_coins(uuid, bigint, text) to authenticated;

create or replace function public.admin_grant_item(
  p_target_user_id uuid,
  p_item_id text,
  p_quantity integer
)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_new_quantity integer;
begin
  if not public.is_current_user_admin() then
    raise exception '管理者権限がありません';
  end if;
  if p_target_user_id is null then
    raise exception '対象プレイヤーを選択してください';
  end if;
  if p_item_id not in ('neon', 'star', 'fox', 'dragon', 'crystal', 'crown') then
    raise exception 'そのアイテムは配布できません';
  end if;
  if p_quantity is null or p_quantity < 1 or p_quantity > 100000 then
    raise exception '配布数は1〜100,000で指定してください';
  end if;
  if not exists (select 1 from public.profiles p where p.id = p_target_user_id) then
    raise exception '対象プレイヤーが見つかりません';
  end if;

  insert into public.inventory(user_id, item_id, quantity)
  values (p_target_user_id, p_item_id, p_quantity)
  on conflict (user_id, item_id) do update
    set quantity = public.inventory.quantity + excluded.quantity
    where public.inventory.quantity <= 2147483647 - excluded.quantity
  returning quantity into v_new_quantity;

  if not found then
    raise exception 'アイテム個数の上限を超えます';
  end if;

  insert into public.game_history(user_id, action, detail, amount)
  values (p_target_user_id, 'admin_item_grant',
          '管理者による配布: ' || p_item_id || ' × ' || p_quantity::text, 0);

  return v_new_quantity;
end;
$$;

revoke all on function public.admin_grant_item(uuid, text, integer) from public, anon;
grant execute on function public.admin_grant_item(uuid, text, integer) to authenticated;

create or replace function public.admin_rename_player(
  p_target_user_id uuid,
  p_new_player_name text
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_new_name text := pg_catalog.btrim(coalesce(p_new_player_name, ''));
  v_old_name text;
begin
  if not public.is_current_user_admin() then
    raise exception '管理者権限がありません';
  end if;
  if p_target_user_id is null or pg_catalog.length(v_new_name) < 3
     or pg_catalog.length(v_new_name) > 20
     or v_new_name !~ '^[[:alnum:]_-]{3,20}$' then
    raise exception '新しいIDは3〜20文字の英数字・_・-で入力してください';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(pg_catalog.lower(v_new_name)));

  if exists (
    select 1 from public.profiles p
    where p.id <> p_target_user_id
      and pg_catalog.lower(p.player_name) = pg_catalog.lower(v_new_name)
  ) then
    raise exception 'そのIDはすでに使われています';
  end if;

  select p.player_name into v_old_name
  from public.profiles p
  where p.id = p_target_user_id
  for update;
  if not found then
    raise exception '対象プレイヤーが見つかりません';
  end if;

  update public.profiles set player_name = v_new_name where id = p_target_user_id;

  insert into public.game_history(user_id, action, detail, amount)
  values (p_target_user_id, 'admin_player_rename',
          '管理者によるID変更: ' || v_old_name || ' → ' || v_new_name, 0);

  return v_new_name;
end;
$$;

revoke all on function public.admin_rename_player(uuid, text) from public, anon;
grant execute on function public.admin_rename_player(uuid, text) to authenticated;

-- Disable the older RPC (all overloads) so it cannot bypass the new server checks.
do $disable_legacy_admin_rpc$
declare
  r record;
begin
  for r in
    select p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) as identity_args
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname = 'admin_adjust_coins'
  loop
    execute pg_catalog.format(
      'revoke all on function public.%I(%s) from public, anon, authenticated',
      r.proname, r.identity_args
    );
  end loop;
end;
$disable_legacy_admin_rpc$;

-- The former code-based enrollment function may not exist in every project.
-- Revoke it only when that exact signature is present, keeping this script re-runnable.
do $disable_legacy_code_rpc$
begin
  if pg_catalog.to_regprocedure('public.verify_admin_code(text)') is not null then
    execute 'revoke all on function public.verify_admin_code(text) from public, anon, authenticated';
  end if;
end;
$disable_legacy_code_rpc$;
