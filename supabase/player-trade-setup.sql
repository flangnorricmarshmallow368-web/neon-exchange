-- NEON EXCHANGE: online player trade system
-- Run this in Supabase SQL Editor after reviewing the schema assumptions:
-- profiles(id, player_name), wallets(user_id, coins), inventory(user_id, item_id, quantity),
-- game_history(user_id, action, detail, amount, created_at).
-- All asset movement occurs in one PostgreSQL transaction when a recipient accepts.

create table if not exists public.player_trade_requests (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  item_id text,
  item_quantity integer not null default 0 check (item_quantity >= 0),
  coins bigint not null default 0 check (coins >= 0),
  status text not null default 'pending' check (status in ('pending','accepted','declined')),
  created_at timestamptz not null default now(),
  responded_at timestamptz,
  constraint player_trade_not_self check (sender_id <> recipient_id),
  constraint player_trade_has_offer check (item_quantity > 0 or coins > 0),
  constraint player_trade_item_quantity check (
    (item_id is null and item_quantity = 0) or
    (item_id is not null and item_quantity > 0)
  )
);

-- The application stores one quantity row per player/item; verify this before transfers.
do $inventory_guard$
begin
  if exists (
    select 1 from public.inventory
    group by user_id, item_id
    having count(*) > 1
  ) then
    raise exception 'inventoryに同じプレイヤー・アイテムの重複行があります。取引機能を有効にする前に整理してください。';
  end if;
end;
$inventory_guard$;

create unique index if not exists player_trade_inventory_user_item_uidx
  on public.inventory(user_id, item_id);

alter table public.player_trade_requests enable row level security;
revoke all on table public.player_trade_requests from public, anon, authenticated;

create or replace function public.list_player_trade_requests()
returns setof public.player_trade_requests
language sql
stable
security definer
set search_path = ''
as $$
  select t.*
  from public.player_trade_requests t
  where auth.uid() = t.sender_id or auth.uid() = t.recipient_id
  order by t.created_at desc
  limit 100;
$$;

revoke all on function public.list_player_trade_requests() from public, anon;
grant execute on function public.list_player_trade_requests() to authenticated;

create or replace function public.create_player_trade_request(
  p_recipient_player_name text,
  p_item_id text default null,
  p_item_quantity integer default 0,
  p_coins bigint default 0
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_sender uuid := auth.uid();
  v_recipient uuid;
  v_match_count integer;
  v_sender_coins bigint;
  v_item_quantity integer;
  v_request_id uuid;
begin
  if v_sender is null then
    raise exception 'ログインしてください';
  end if;

  if p_recipient_player_name is null
     or length(pg_catalog.btrim(p_recipient_player_name)) < 3
     or length(pg_catalog.btrim(p_recipient_player_name)) > 20 then
    raise exception '相手のプレイヤーIDを確認してください';
  end if;

  if p_coins is null or p_coins < 0 then
    raise exception 'コイン数が正しくありません';
  end if;

  if p_item_id is null or pg_catalog.btrim(p_item_id) = '' then
    if coalesce(p_item_quantity, 0) <> 0 then
      raise exception 'アイテムが選択されていません';
    end if;
    p_item_id := null;
    p_item_quantity := 0;
  elsif p_item_quantity is null or p_item_quantity < 1 or p_item_quantity > 100000 then
    raise exception 'アイテム数を確認してください';
  end if;

  if coalesce(p_coins, 0) = 0 and coalesce(p_item_quantity, 0) = 0 then
    raise exception 'アイテムかコインを指定してください';
  end if;

  select count(*) into v_match_count
  from public.profiles
  where lower(player_name) = lower(pg_catalog.btrim(p_recipient_player_name));

  if v_match_count = 0 then
    raise exception 'そのプレイヤーIDは見つかりません';
  elsif v_match_count > 1 then
    raise exception '同じプレイヤーIDが複数あります。管理者に連絡してください';
  end if;

  select id into v_recipient
  from public.profiles
  where lower(player_name) = lower(pg_catalog.btrim(p_recipient_player_name))
  limit 1;

  if v_recipient = v_sender then
    raise exception '自分自身には取引申請できません';
  end if;

  select coins into v_sender_coins
  from public.wallets
  where user_id = v_sender
  for update;

  if not found then
    raise exception '所持コイン情報が見つかりません';
  end if;

  if v_sender_coins < p_coins then
    raise exception '所持コインが足りません';
  end if;

  if p_item_id is not null then
    select quantity into v_item_quantity
    from public.inventory
    where user_id = v_sender and item_id = p_item_id
    for update;

    if not found or v_item_quantity < p_item_quantity then
      raise exception '指定したアイテム数を所持していません';
    end if;
  end if;

  insert into public.player_trade_requests
    (sender_id, recipient_id, item_id, item_quantity, coins)
  values
    (v_sender, v_recipient, p_item_id, p_item_quantity, p_coins)
  returning id into v_request_id;

  return v_request_id;
end;
$$;

revoke all on function public.create_player_trade_request(text,text,integer,bigint) from public, anon;
grant execute on function public.create_player_trade_request(text,text,integer,bigint) to authenticated;

create or replace function public.respond_player_trade_request(
  p_request_id uuid,
  p_accept boolean
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_trade public.player_trade_requests%rowtype;
  v_sender_coins bigint;
  v_recipient_coins bigint;
  v_sender_item_quantity integer;
  v_recipient_item_quantity integer;
begin
  if v_user is null then
    raise exception 'ログインしてください';
  end if;

  if p_accept is null then
    raise exception '承認か辞退を選択してください';
  end if;

  select * into v_trade
  from public.player_trade_requests
  where id = p_request_id
  for update;

  if not found then
    raise exception '取引申請が見つかりません';
  end if;

  if v_trade.recipient_id <> v_user then
    raise exception 'この取引申請に応答する権限がありません';
  end if;

  if v_trade.status <> 'pending' then
    raise exception 'この取引申請はすでに処理されています';
  end if;

  if not p_accept then
    update public.player_trade_requests
    set status = 'declined', responded_at = pg_catalog.now()
    where id = v_trade.id;
    return true;
  end if;

  -- Lock both wallets in a stable order so concurrent trades serialize safely.
  perform 1
  from public.wallets
  where user_id in (v_trade.sender_id, v_trade.recipient_id)
  order by user_id
  for update;

  select coins into v_sender_coins from public.wallets where user_id = v_trade.sender_id;
  select coins into v_recipient_coins from public.wallets where user_id = v_trade.recipient_id;

  if v_sender_coins is null or v_recipient_coins is null then
    raise exception '取引に必要な所持コイン情報が見つかりません';
  end if;

  if v_sender_coins < v_trade.coins then
    raise exception '送信者のコイン残高が不足しているため、取引できません';
  end if;

  if v_recipient_coins > 9223372036854775807::bigint - v_trade.coins then
    raise exception '受取側のコイン上限を超えるため、取引できません';
  end if;

  if v_trade.item_id is not null then
    select quantity into v_sender_item_quantity
    from public.inventory
    where user_id = v_trade.sender_id and item_id = v_trade.item_id
    for update;

    if not found or v_sender_item_quantity < v_trade.item_quantity then
      raise exception '送信者のアイテム数が不足しているため、取引できません';
    end if;
  end if;

  update public.wallets
  set coins = coins - v_trade.coins
  where user_id = v_trade.sender_id;

  update public.wallets
  set coins = coins + v_trade.coins
  where user_id = v_trade.recipient_id;

  if v_trade.item_id is not null then
    update public.inventory
    set quantity = quantity - v_trade.item_quantity
    where user_id = v_trade.sender_id and item_id = v_trade.item_id;

    delete from public.inventory
    where user_id = v_trade.sender_id and item_id = v_trade.item_id and quantity <= 0;

    select quantity into v_recipient_item_quantity
    from public.inventory
    where user_id = v_trade.recipient_id and item_id = v_trade.item_id
    for update;

    if found then
      update public.inventory
      set quantity = quantity + v_trade.item_quantity
      where user_id = v_trade.recipient_id and item_id = v_trade.item_id;
    else
      insert into public.inventory(user_id, item_id, quantity)
      values (v_trade.recipient_id, v_trade.item_id, v_trade.item_quantity);
    end if;
  end if;

  insert into public.game_history(user_id, action, detail, amount)
  values
    (v_trade.sender_id, 'trade_sent',
     '取引で送付: ' || coalesce(v_trade.item_id, 'アイテムなし') || ' x' || v_trade.item_quantity::text,
     -v_trade.coins),
    (v_trade.recipient_id, 'trade_received',
     '取引で受取: ' || coalesce(v_trade.item_id, 'アイテムなし') || ' x' || v_trade.item_quantity::text,
     v_trade.coins);

  update public.player_trade_requests
  set status = 'accepted', responded_at = pg_catalog.now()
  where id = v_trade.id;

  return true;
end;
$$;

revoke all on function public.respond_player_trade_request(uuid,boolean) from public, anon;
grant execute on function public.respond_player_trade_request(uuid,boolean) to authenticated;
