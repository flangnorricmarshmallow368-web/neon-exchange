-- NEON EXCHANGE: inspect admin_adjust_coins before enabling admin coin changes
-- Run this in Supabase SQL Editor and review the results.
-- This file does NOT modify the database.

-- 1) Show the exact definition/signature of every public.admin_adjust_coins overload.
select
  p.oid::regprocedure as function_signature,
  pg_get_functiondef(p.oid) as function_definition,
  p.prosecdef as security_definer
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.proname = 'admin_adjust_coins';

-- 2) Show who is allowed to execute those functions.
select
  p.oid::regprocedure as function_signature,
  coalesce(r.rolname, 'PUBLIC') as grantee,
  x.privilege_type
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) x
left join pg_roles r on r.oid = x.grantee
where n.nspname = 'public'
  and p.proname = 'admin_adjust_coins'
order by function_signature::text, grantee;

-- IMPORTANT:
-- Do not assume the admin panel is secure just because the UI is hidden.
-- The function itself must check the authenticated user's server-side admin role
-- (for example, private.admin_users with auth.uid()) before changing any wallet.
-- Share the results of these two queries (remove any personal data) so the function
-- can be patched against its real signature instead of guessing.
