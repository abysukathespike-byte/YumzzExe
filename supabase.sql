-- ============================================================
-- YUMZEXE — SETUP LENGKAP SUPABASE
-- Jalankan sekali di Supabase > SQL Editor. Aman diulang.
-- ============================================================

-- 1. USERS
create table if not exists users (
  id bigint generated always as identity primary key,
  email text,
  username text,
  avatar_url text,
  exp int not null default 0,
  banned boolean not null default false,
  created_at timestamptz default now()
);
alter table users add column if not exists email text;
alter table users add column if not exists username text;
alter table users add column if not exists avatar_url text;
alter table users add column if not exists exp int not null default 0;
alter table users add column if not exists banned boolean not null default false;
create unique index if not exists users_email_key on users (email);

alter table users enable row level security;
drop policy if exists "users read" on users;
drop policy if exists "users insert" on users;
drop policy if exists "users update" on users;
drop policy if exists "users delete" on users;
create policy "users read" on users for select using (true);
create policy "users insert" on users for insert with check (true);
create policy "users update" on users for update using (true) with check (true);
create policy "users delete" on users for delete using (true);

-- 2. ADMINS
create table if not exists admins (
  email text primary key,
  role text not null default 'admin' check (role in ('owner','admin')),
  created_at timestamptz default now()
);
insert into admins (email, role) values ('abysukathespike@gmail.com', 'owner')
on conflict (email) do nothing;

alter table admins enable row level security;
drop policy if exists "admins read" on admins;
drop policy if exists "admins write" on admins;
create policy "admins read" on admins for select using (true);
-- PERINGATAN: policy write terbuka. Siapa pun dengan anon key bisa menambah admin.
create policy "admins write" on admins for all using (true) with check (true);

-- 3. MUTES
create table if not exists mutes (
  email text primary key,
  until timestamptz not null,
  created_at timestamptz default now()
);
alter table mutes enable row level security;
drop policy if exists "mutes all" on mutes;
create policy "mutes all" on mutes for all using (true) with check (true);

-- 4. GLOBAL_CHAT
create table if not exists global_chat (
  id bigint generated always as identity primary key,
  user_email text not null,
  username text not null,
  message text not null check (char_length(message) between 1 and 300),
  created_at timestamptz not null default now()
);
create index if not exists global_chat_created_idx on global_chat (created_at);

alter table global_chat enable row level security;
drop policy if exists "chat read" on global_chat;
drop policy if exists "chat insert" on global_chat;
drop policy if exists "chat delete" on global_chat;
create policy "chat read" on global_chat for select using (true);
create policy "chat insert" on global_chat for insert with check (true);
create policy "chat delete" on global_chat for delete using (true);

-- Trigger: tolak kirim chat kalau user dimute atau dibanned (dicek di server)
create or replace function chat_guard() returns trigger language plpgsql as $$
begin
  if exists (select 1 from mutes where email = new.user_email and until > now()) then
    raise exception 'muted';
  end if;
  if exists (select 1 from users where email = new.user_email and banned = true) then
    raise exception 'banned';
  end if;
  return new;
end $$;

drop trigger if exists chat_guard_trg on global_chat;
create trigger chat_guard_trg before insert on global_chat
  for each row execute function chat_guard();

-- Realtime untuk chat (insert & delete)
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'global_chat'
  ) then
    alter publication supabase_realtime add table global_chat;
  end if;
end $$;

-- 5. ANNOUNCEMENTS
create table if not exists announcements (
  id bigint generated always as identity primary key,
  title text not null,
  body text not null,
  active boolean not null default true,
  created_at timestamptz default now()
);
alter table announcements enable row level security;
drop policy if exists "ann read" on announcements;
drop policy if exists "ann write" on announcements;
create policy "ann read" on announcements for select using (true);
create policy "ann write" on announcements for all using (true) with check (true);

-- 6. EXECUTORS
create table if not exists executors (
  id bigint generated always as identity primary key,
  name text not null,
  platform text,
  detail text,
  status text not null default 'working' check (status in ('working','patched')),
  tag text,
  icon text default 'fa-bolt',
  url text,
  warning boolean not null default false,
  sort_order int not null default 0,
  created_at timestamptz default now()
);
alter table executors enable row level security;
drop policy if exists "executor read" on executors;
drop policy if exists "executor write" on executors;
create policy "executor read" on executors for select using (true);
create policy "executor write" on executors for all using (true) with check (true);

insert into executors (name, platform, detail, status, tag, icon, url, warning, sort_order)
select * from (values
  ('Arceus X Neo',  'Android',       'Arceus Project', 'working', 'TOP', 'fa-crown', null::text, true,  1),
  ('Delta Executor','Android & iOS', null::text,       'working', 'NEW', 'fa-bolt',  'https://delta.filenetwork.vip/android.html', false, 2),
  ('VegaX Executor','Android & iOS', null::text,       'working', null,  'fa-star',  'https://www.vegax.gg/download.html', false, 3)
) as v(name, platform, detail, status, tag, icon, url, warning, sort_order)
where not exists (select 1 from executors);

-- 7. CEK HASIL
select 'users' as tabel, count(*) from users
union all select 'global_chat', count(*) from global_chat
union all select 'executors', count(*) from executors
union all select 'admins', count(*) from admins
union all select 'announcements', count(*) from announcements;
