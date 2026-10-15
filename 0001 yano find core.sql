-- YANO FIND — Phase 1 core schema, RLS, and EXP/return logic
-- Run in Supabase SQL editor or as supabase/migrations/0001_yano_find_core.sql

create extension if not exists pgcrypto;

create type user_role as enum ('student','moderator','admin');
create type account_status as enum ('pending','active','suspended');
create type item_type as enum ('lost','found');
create type item_status as enum ('active','under_review','matched','return_pending','returned','closed','rejected','archived');
create type claim_status as enum ('pending','under_review','more_info_requested','approved','rejected','cancelled','handover_pending','returned');
create type exp_type as enum ('VALID_POST_REWARD','VERIFIED_RETURN_BONUS','ADMIN_ADJUSTMENT','REWARD_REVERSAL');

-- ---------- Reference tables ----------
create table colleges (
  id serial primary key, code text unique not null, name text,
  is_active boolean default true, created_at timestamptz default now());
insert into colleges(code) values ('CTET'),('COE');

create table programs (
  id serial primary key, code text unique not null, display_name text not null,
  college_id int references colleges(id),           -- NULL until admin confirms mapping
  is_active boolean default true, created_at timestamptz default now(), updated_at timestamptz default now());
insert into programs(code, display_name) values
 ('BSABE','BSABE'),('BSIT','BSIT'),('BSED MATH','BSED MATH'),('BSED FIL','BSED FIL'),
 ('BSED ENG','BSED ENG'),('BSNED','BSNED'),('BECED','BECED'),('BTVTED','BTVTED'),('BEED','BEED');

create table item_categories (id serial primary key, name text unique not null, is_active boolean default true, created_at timestamptz default now());
insert into item_categories(name) values ('Identification Cards'),('Wallets and Purses'),('Phones and Electronics'),
 ('Bags and Backpacks'),('Keys'),('Clothing and Accessories'),('Books and School Supplies'),('Jewelry'),
 ('Water Bottles and Containers'),('Umbrellas'),('Other');

create table app_settings (key text primary key, value jsonb not null);
-- Admin must choose which post types earn +5 EXP. Empty = none until configured.
insert into app_settings values ('valid_post_exp_types','[]'), ('registration_enabled','false');

create table academic_years (
  id serial primary key, name text unique not null, start_date date not null, end_date date not null,
  leaderboard_closing_at timestamptz, is_finalized boolean default false,
  created_at timestamptz default now(), finalized_at timestamptz, finalized_by uuid,
  check (end_date > start_date));

-- ---------- Profiles ----------
create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null check (length(btrim(full_name)) > 0),
  year_level smallint not null check (year_level between 1 and 5),
  college_id int not null references colleges(id),
  program_id int not null references programs(id),
  role user_role not null default 'student',
  account_status account_status not null default 'active',
  email_verified_at timestamptz,
  created_at timestamptz default now(), updated_at timestamptz default now());

-- Validate college/program pairing server-side
create function check_program_college() returns trigger language plpgsql as $$
begin
  if not exists (select 1 from programs where id = new.program_id and college_id = new.college_id) then
    raise exception 'Program is not assigned to the selected college';
  end if;
  return new;
end $$;
create trigger trg_profile_program before insert or update of college_id, program_id on profiles
  for each row execute function check_program_college();

-- Role helpers
create function is_admin() returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from profiles where id = auth.uid() and role = 'admin' and account_status = 'active') $$;
create function is_staff() returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from profiles where id = auth.uid() and role in ('moderator','admin') and account_status = 'active') $$;
create function is_verified() returns boolean language sql stable security definer set search_path = public as
$$ select exists (select 1 from profiles p join auth.users u on u.id = p.id
   where p.id = auth.uid() and p.account_status = 'active' and u.email_confirmed_at is not null) $$;

-- Block self role/status escalation
create function protect_profile_fields() returns trigger language plpgsql as $$
begin
  if not is_admin() and (new.role <> old.role or new.account_status <> old.account_status) then
    raise exception 'Not allowed to change role or account status';
  end if;
  new.updated_at = now();
  return new;
end $$;
create trigger trg_protect_profile before update on profiles for each row execute function protect_profile_fields();

-- Create profile on signup; enforce USeP domain
create function handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
declare m jsonb := new.raw_user_meta_data;
begin
  if lower(new.email) not like '%@usep.edu.ph' then raise exception 'Only @usep.edu.ph emails are allowed'; end if;
  if (select value::text from app_settings where key='registration_enabled') <> 'true' then
    raise exception 'Registration is not yet enabled. Administrator setup is incomplete.'; end if;
  insert into profiles(id, full_name, year_level, college_id, program_id)
  values (new.id, btrim(m->>'full_name'), (m->>'year_level')::smallint, (m->>'college_id')::int, (m->>'program_id')::int);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

-- ---------- Items, claims, returns ----------
create table items (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null references profiles(id),
  item_type item_type not null,
  title text not null check (length(btrim(title)) between 3 and 120),
  description text not null,
  identifying_details text,                       -- private: never exposed in public view
  category_id int references item_categories(id),
  date_lost_or_found date not null,
  location_description text not null,
  image_path text,
  status item_status not null default 'under_review',
  moderation_status text not null default 'pending' check (moderation_status in ('pending','approved','rejected','hidden')),
  created_at timestamptz default now(), updated_at timestamptz default now(), returned_at timestamptz);
create index on items (status, item_type, created_at desc);
create index on items using gin (to_tsvector('english', title || ' ' || description));

create table claims (
  id uuid primary key default gen_random_uuid(),
  item_id uuid not null references items(id),
  claimant_id uuid not null references profiles(id),
  claim_details text not null, supporting_evidence_path text,
  status claim_status not null default 'pending',
  reviewed_by uuid references profiles(id), decision_reason text,
  created_at timestamptz default now(), updated_at timestamptz default now(), decided_at timestamptz);
-- one active claim per student per item
create unique index one_active_claim on claims(item_id, claimant_id)
  where status not in ('rejected','cancelled');

create table return_confirmations (
  id uuid primary key default gen_random_uuid(),
  item_id uuid not null references items(id), claim_id uuid not null references claims(id),
  confirmation_type text not null check (confirmation_type in ('finder_handover','claimant_receipt','admin_override')),
  confirmed_by uuid not null references profiles(id), confirmed_at timestamptz default now(),
  verification_status text not null default 'confirmed', reviewed_by uuid, review_reason text,
  unique (claim_id, confirmation_type));

-- ---------- EXP ledger ----------
create table exp_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id),
  transaction_type exp_type not null, amount int not null, reason text,
  item_id uuid references items(id), claim_id uuid references claims(id),
  idempotency_key text not null unique,           -- blocks duplicate awards
  created_by uuid, created_at timestamptz default now());

-- ---------- Badges, notifications, logs ----------
create table achievements (
  id serial primary key, name text unique not null, description text, icon text,
  criteria_type text, criteria_config jsonb default '{}', is_active boolean default true, created_at timestamptz default now());
insert into achievements(name, description) values
 ('First Find','First qualifying contribution'),('Helpful Agila','Meaningful verified assistance'),
 ('Community Guardian','Sustained, responsible contributions'),('Trusted Contributor','Meets verified-contribution criteria'),
 ('Campus Hero','Substantial verified community impact'),('YANO FIND Leader','Top contributor under configured rules');

create table user_achievements (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references profiles(id),
  achievement_id int not null references achievements(id), awarded_at timestamptz default now(),
  awarded_by uuid, reason text, unique (user_id, achievement_id));

create table notifications (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references profiles(id),
  title text not null, message text not null, related_item_id uuid, related_claim_id uuid,
  read_at timestamptz, created_at timestamptz default now());

create table audit_logs (
  id uuid primary key default gen_random_uuid(), actor_id uuid, action text not null,
  entity_type text, entity_id text, reason text, metadata jsonb, created_at timestamptz default now());

create table moderation_logs (
  id uuid primary key default gen_random_uuid(), moderator_id uuid not null, item_id uuid, claim_id uuid,
  action text not null, reason text, created_at timestamptz default now());

create table reports (
  id uuid primary key default gen_random_uuid(), reported_by uuid not null references profiles(id),
  item_id uuid references items(id), claim_id uuid references claims(id), reason text not null,
  status text default 'open', reviewed_by uuid, created_at timestamptz default now(), resolved_at timestamptz);

create table leaderboard_snapshots (
  id uuid primary key default gen_random_uuid(), academic_year_id int not null references academic_years(id),
  snapshot_data jsonb not null, created_at timestamptz default now(), created_by uuid, is_final boolean default false);

-- ---------- Privileged functions ----------
create function log_audit(a text, et text, eid text, r text, meta jsonb default null) returns void
language sql security definer set search_path = public as
$$ insert into audit_logs(actor_id, action, entity_type, entity_id, reason, metadata) values (auth.uid(), a, et, eid, r, meta) $$;

-- Staff approves a post; +5 EXP once, only if post type is enabled by admin
create function approve_item(p_item uuid, p_reason text) returns void
language plpgsql security definer set search_path = public as $$
declare it items;
begin
  if not is_staff() then raise exception 'Not authorized'; end if;
  update items set moderation_status='approved', status='active', updated_at=now()
    where id=p_item and moderation_status='pending' returning * into it;
  if not found then raise exception 'Item not pending'; end if;
  insert into moderation_logs(moderator_id,item_id,action,reason) values (auth.uid(),p_item,'approve',p_reason);
  if (select value from app_settings where key='valid_post_exp_types') ? it.item_type::text then
    insert into exp_transactions(user_id,transaction_type,amount,reason,item_id,idempotency_key,created_by)
    values (it.created_by,'VALID_POST_REWARD',5,'Approved valid post',p_item,'post:'||p_item,auth.uid())
    on conflict (idempotency_key) do nothing;
  end if;
  perform log_audit('approve_item','item',p_item::text,p_reason);
end $$;

-- Staff approves a claim → handover pending (NOT returned)
create function approve_claim(p_claim uuid, p_reason text) returns void
language plpgsql security definer set search_path = public as $$
declare c claims;
begin
  if not is_staff() then raise exception 'Not authorized'; end if;
  if length(btrim(coalesce(p_reason,''))) = 0 then raise exception 'Decision reason required'; end if;
  select * into c from claims where id=p_claim for update;
  if c.claimant_id = auth.uid() then raise exception 'Cannot approve your own claim'; end if;
  if c.status not in ('pending','under_review','more_info_requested') then raise exception 'Invalid claim state'; end if;
  update claims set status='handover_pending', reviewed_by=auth.uid(), decision_reason=p_reason, decided_at=now() where id=p_claim;
  update items set status='return_pending', updated_at=now() where id=c.item_id;
  perform log_audit('approve_claim','claim',p_claim::text,p_reason);
end $$;

-- Finder and claimant each confirm; when both exist → Returned + one-time +10 to finder
create function confirm_return(p_claim uuid) returns text
language plpgsql security definer set search_path = public as $$
declare c claims; it items; kind text;
begin
  select * into c from claims where id=p_claim for update;
  if c.status <> 'handover_pending' then raise exception 'Claim is not awaiting handover'; end if;
  select * into it from items where id=c.item_id for update;
  if auth.uid() = it.created_by and auth.uid() = c.claimant_id then
    raise exception 'Finder and claimant are the same account; admin verification required'; end if;
  if auth.uid() = it.created_by then kind := 'finder_handover';
  elsif auth.uid() = c.claimant_id then kind := 'claimant_receipt';
  else raise exception 'Not a party to this handover'; end if;
  insert into return_confirmations(item_id,claim_id,confirmation_type,confirmed_by)
    values (it.id,p_claim,kind,auth.uid()) on conflict do nothing;
  if (select count(*) from return_confirmations where claim_id=p_claim
        and confirmation_type in ('finder_handover','claimant_receipt')) = 2 then
    update claims set status='returned', updated_at=now() where id=p_claim;
    update items set status='returned', returned_at=now(), updated_at=now() where id=it.id;
    insert into exp_transactions(user_id,transaction_type,amount,reason,item_id,claim_id,idempotency_key)
      values (it.created_by,'VERIFIED_RETURN_BONUS',10,'Verified successful return',it.id,p_claim,'return:'||p_claim)
      on conflict (idempotency_key) do nothing;
    insert into notifications(user_id,title,message,related_item_id,related_claim_id)
      values (it.created_by,'Return verified','+10 EXP awarded for a verified return.',it.id,p_claim);
    perform log_audit('return_verified','claim',p_claim::text,null);
    return 'returned';
  end if;
  return 'awaiting_other_party';
end $$;

-- Admin-only EXP adjustment with mandatory reason
create function admin_adjust_exp(p_user uuid, p_amount int, p_reason text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Not authorized'; end if;
  if length(btrim(coalesce(p_reason,''))) = 0 then raise exception 'Reason required'; end if;
  insert into exp_transactions(user_id,transaction_type,amount,reason,idempotency_key,created_by)
    values (p_user,'ADMIN_ADJUSTMENT',p_amount,p_reason,'adj:'||gen_random_uuid(),auth.uid());
  perform log_audit('exp_adjustment','profile',p_user::text,p_reason,jsonb_build_object('amount',p_amount));
end $$;

-- ---------- Views ----------
create view public_items with (security_invoker = false) as
  select i.id,i.item_type,i.title,i.description,i.category_id,i.date_lost_or_found,i.location_description,
         i.image_path,i.status,i.created_at, p.full_name as contributor
  from items i join profiles p on p.id = i.created_by
  where i.moderation_status='approved' and i.status not in ('rejected','archived');

create view leaderboard_live with (security_invoker = false) as
  select p.id user_id, p.full_name, pr.code program, c.code college, ay.id academic_year_id,
         coalesce(sum(e.amount),0) exp,
         count(distinct e.id) filter (where e.transaction_type='VERIFIED_RETURN_BONUS') returns
  from profiles p
  join programs pr on pr.id=p.program_id join colleges c on c.id=p.college_id
  cross join academic_years ay
  left join exp_transactions e on e.user_id=p.id
       and e.created_at::date between ay.start_date and ay.end_date
  where p.account_status='active'
  group by p.id,p.full_name,pr.code,c.code,ay.id
  order by exp desc, returns desc;

-- ---------- Row Level Security ----------
alter table profiles enable row level security;
alter table programs enable row level security;
alter table colleges enable row level security;
alter table item_categories enable row level security;
alter table app_settings enable row level security;
alter table academic_years enable row level security;
alter table items enable row level security;
alter table claims enable row level security;
alter table return_confirmations enable row level security;
alter table exp_transactions enable row level security;
alter table achievements enable row level security;
alter table user_achievements enable row level security;
alter table notifications enable row level security;
alter table audit_logs enable row level security;
alter table moderation_logs enable row level security;
alter table reports enable row level security;
alter table leaderboard_snapshots enable row level security;

-- Reference data: public read, admin write
create policy ref_read on colleges for select using (true);
create policy ref_read on programs for select using (true);
create policy ref_read on item_categories for select using (true);
create policy ref_read on academic_years for select using (true);
create policy ref_read on achievements for select using (true);
create policy ref_read on leaderboard_snapshots for select using (is_final);
create policy ref_admin on programs for all using (is_admin()) with check (is_admin());
create policy ref_admin on colleges for all using (is_admin()) with check (is_admin());
create policy ref_admin on item_categories for all using (is_admin()) with check (is_admin());
create policy ref_admin on academic_years for all using (is_admin() and not is_finalized) with check (is_admin());
create policy ref_admin on achievements for all using (is_admin()) with check (is_admin());
create policy settings_admin on app_settings for all using (is_admin()) with check (is_admin());

-- Profiles
create policy prof_self on profiles for select using (id = auth.uid() or is_staff());
create policy prof_update on profiles for update using (id = auth.uid() or is_admin());

-- Items: owner + staff see all; everyone else uses public_items view
create policy items_read on items for select using (created_by = auth.uid() or is_staff());
create policy items_insert on items for insert with check (
  created_by = auth.uid() and is_verified() and status='under_review' and moderation_status='pending');
create policy items_update on items for update using (
  (created_by = auth.uid() and status in ('active','under_review')) or is_staff())
  with check (created_by = auth.uid() or is_staff());

-- Claims: private to claimant, item owner (own listing), and staff
create policy claims_read on claims for select using (
  claimant_id = auth.uid() or is_staff()
  or exists (select 1 from items i where i.id=item_id and i.created_by=auth.uid()));
create policy claims_insert on claims for insert with check (
  claimant_id = auth.uid() and is_verified() and status='pending'
  and not exists (select 1 from items i where i.id=item_id and i.created_by=auth.uid()));
create policy claims_cancel on claims for update using (claimant_id = auth.uid() and status in ('pending','more_info_requested'))
  with check (status in ('cancelled','pending'));
create policy claims_staff on claims for update using (is_staff());

-- Returns, EXP: read-only to clients (writes only via SECURITY DEFINER functions)
create policy rc_read on return_confirmations for select using (confirmed_by = auth.uid() or is_staff());
create policy exp_read on exp_transactions for select using (user_id = auth.uid() or is_admin());
create policy ua_read on user_achievements for select using (true);

-- Notifications
create policy notif_read on notifications for select using (user_id = auth.uid());
create policy notif_update on notifications for update using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Logs / reports
create policy audit_read on audit_logs for select using (is_admin());
create policy mod_read on moderation_logs for select using (is_staff());
create policy rep_insert on reports for insert with check (reported_by = auth.uid() and is_verified());
create policy rep_read on reports for select using (reported_by = auth.uid() or is_staff());
create policy rep_staff on reports for update using (is_staff());

-- Lock down direct writes to ledger-style tables
revoke insert, update, delete on exp_transactions, return_confirmations, user_achievements, audit_logs, moderation_logs from anon, authenticated;
revoke all on public_items, leaderboard_live from anon, authenticated;
grant select on public_items, leaderboard_live to anon, authenticated;
grant execute on function approve_item, approve_claim, confirm_return, admin_adjust_exp to authenticated;

-- ---------- Storage (create buckets in dashboard or here) ----------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('item-photos','item-photos',true,5242880,array['image/jpeg','image/png','image/webp']),
       ('claim-evidence','claim-evidence',false,5242880,array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;
create policy photos_upload on storage.objects for insert to authenticated
  with check (bucket_id='item-photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy evidence_upload on storage.objects for insert to authenticated
  with check (bucket_id='claim-evidence' and (storage.foldername(name))[1] = auth.uid()::text);
create policy evidence_read on storage.objects for select to authenticated
  using (bucket_id='claim-evidence' and ((storage.foldername(name))[1] = auth.uid()::text or is_staff()));
