-- NEON EXCHANGE: read-only verification for the email-based admin setup
-- Run AFTER admin-email-management-setup.sql in Supabase SQL Editor.
-- Read-only: this script does not alter database objects or game data.
-- It never prints the configured administrator identifier.

-- 1) Check private admin configuration without exposing its value.
select
  case
    when exists (
      select 1 from private.neon_admin_settings
      where singleton
        and char_length(admin_email_md5) = 32
        and admin_email_md5 ~ '^[0-9a-f]{32}$'
    ) then 'CONFIGURED'
    else 'MISSING_OR_INVALID'
  end as admin_email_configuration;

-- 2) Are all RPC functions used by the web page installed?
with required(rpc_name, signature) as (
  values
    ('is_current_user_admin', 'public.is_current_user_admin()'),
    ('admin_list_players', 'public.admin_list_players()'),
    ('admin_adjust_player_coins', 'public.admin_adjust_player_coins(uuid,bigint,text)'),
    ('admin_grant_item', 'public.admin_grant_item(uuid,text,integer)'),
    ('admin_rename_player', 'public.admin_rename_player(uuid,text)')
)
select rpc_name, signature, pg_catalog.to_regprocedure(signature) is not null as installed
from required
order by rpc_name;

-- 3) Was the unique inventory key created for safe item grants?
select pg_catalog.to_regclass('public.admin_inventory_user_item_uidx') is not null
  as inventory_unique_index_installed;

-- 4) Audit SECURITY DEFINER and client execution permissions for admin RPCs.
with required(signature) as (
  values
    ('public.is_current_user_admin()'),
    ('public.admin_list_players()'),
    ('public.admin_adjust_player_coins(uuid,bigint,text)'),
    ('public.admin_grant_item(uuid,text,integer)'),
    ('public.admin_rename_player(uuid,text)')
)
select
  p.oid::regprocedure as function_signature,
  p.prosecdef as security_definer,
  coalesce(bool_or(coalesce(r.rolname, 'PUBLIC') = 'PUBLIC' and x.privilege_type = 'EXECUTE'), false)
    as public_can_execute,
  coalesce(bool_or(r.rolname = 'anon' and x.privilege_type = 'EXECUTE'), false)
    as anon_can_execute,
  coalesce(bool_or(r.rolname = 'authenticated' and x.privilege_type = 'EXECUTE'), false)
    as authenticated_can_execute
from required q
join pg_catalog.pg_proc p on p.oid = pg_catalog.to_regprocedure(q.signature)
cross join lateral pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) x
left join pg_catalog.pg_roles r on r.oid = x.grantee
group by p.oid, p.prosecdef
order by function_signature::text;

-- 5) Verify that legacy admin_adjust_coins overloads cannot be called by browser roles.
-- No rows means the legacy RPC does not exist.
select
  p.oid::regprocedure as function_signature,
  coalesce(bool_or(coalesce(r.rolname, 'PUBLIC') = 'PUBLIC' and x.privilege_type = 'EXECUTE'), false)
    as public_can_execute,
  coalesce(bool_or(r.rolname = 'anon' and x.privilege_type = 'EXECUTE'), false)
    as anon_can_execute,
  coalesce(bool_or(r.rolname = 'authenticated' and x.privilege_type = 'EXECUTE'), false)
    as authenticated_can_execute
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
cross join lateral pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) x
left join pg_catalog.pg_roles r on r.oid = x.grantee
where n.nspname = 'public'
  and p.proname = 'admin_adjust_coins'
group by p.oid
order by function_signature::text;
