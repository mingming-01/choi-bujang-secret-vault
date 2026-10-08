-- Supabase Dashboard > SQL Editor에서 검토 후 실행하세요.
-- 실제 자료 표: public.learning_notes(id bigint, owner_id uuid, title, content, created_at).
-- 사용자 CRUD API 표: public.user_notes(id uuid, owner_id uuid, title, content, created_at).
-- 두 표만 변경합니다. user_notes에는 authenticated CRUD, learning_notes에는
-- 현재 목록 API에 필요한 authenticated SELECT만 부여하고 두 표 모두 owner_id로 RLS를 제한합니다.

-- 적용 전 권한 확인: grants와 역할 membership에 따른 유효 권한을 확인합니다.
select table_name, grantee, privilege_type, is_grantable
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name in ('learning_notes', 'user_notes')
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by table_name, grantee, privilege_type;

select targets.table_name, roles.role_name,
       has_table_privilege(roles.role_name::name, format('public.%I', targets.table_name), 'SELECT') as can_select,
       has_table_privilege(roles.role_name::name, format('public.%I', targets.table_name), 'INSERT') as can_insert,
       has_table_privilege(roles.role_name::name, format('public.%I', targets.table_name), 'UPDATE') as can_update,
       has_table_privilege(roles.role_name::name, format('public.%I', targets.table_name), 'DELETE') as can_delete
from (values ('learning_notes'), ('user_notes')) as targets(table_name)
cross join (values ('anon'), ('authenticated')) as roles(role_name)
order by targets.table_name, roles.role_name;

select c.relname as table_name, c.relrowsecurity as rls_enabled
from pg_class as c
where c.oid in ('public.learning_notes'::regclass, 'public.user_notes'::regclass)
order by c.relname;

select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
  and tablename in ('learning_notes', 'user_notes')
order by tablename, policyname;

begin;

alter table public.learning_notes enable row level security;
alter table public.user_notes enable row level security;

revoke all privileges on table public.learning_notes
from PUBLIC, anon, authenticated;
revoke all privileges on table public.user_notes
from PUBLIC, anon, authenticated;

grant select on table public.learning_notes to authenticated;
grant select, insert, update, delete on table public.user_notes to authenticated;

-- 기존 정책은 permissive하게 합산되므로, 두 대상 표의 기존 정책만 모두 교체합니다.
do $policies$
declare
  existing_policy record;
begin
  for existing_policy in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('learning_notes', 'user_notes')
  loop
    execute format('drop policy %I on %I.%I',
      existing_policy.policyname, existing_policy.schemaname, existing_policy.tablename);
  end loop;
end
$policies$;

create policy learning_notes_select_owner
on public.learning_notes for select to authenticated
using (auth.uid() = owner_id);

create policy user_notes_select_owner
on public.user_notes for select to authenticated
using (auth.uid() = owner_id);
create policy user_notes_insert_owner
on public.user_notes for insert to authenticated
with check (auth.uid() = owner_id);
create policy user_notes_update_owner
on public.user_notes for update to authenticated
using (auth.uid() = owner_id)
with check (auth.uid() = owner_id);
create policy user_notes_delete_owner
on public.user_notes for delete to authenticated
using (auth.uid() = owner_id);

commit;

-- 적용 후 확인: anon에는 권한이 없고, authenticated에는
-- learning_notes SELECT만, user_notes CRUD 네 권한만 있어야 합니다.
select table_name, grantee, privilege_type, is_grantable
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name in ('learning_notes', 'user_notes')
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by table_name, grantee, privilege_type;

select targets.table_name, roles.role_name,
       has_table_privilege(roles.role_name::name, format('public.%I', targets.table_name), 'SELECT') as can_select,
       has_table_privilege(roles.role_name::name, format('public.%I', targets.table_name), 'INSERT') as can_insert,
       has_table_privilege(roles.role_name::name, format('public.%I', targets.table_name), 'UPDATE') as can_update,
       has_table_privilege(roles.role_name::name, format('public.%I', targets.table_name), 'DELETE') as can_delete
from (values ('learning_notes'), ('user_notes')) as targets(table_name)
cross join (values ('anon'), ('authenticated')) as roles(role_name)
order by targets.table_name, roles.role_name;

select c.relname as table_name, c.relrowsecurity as rls_enabled
from pg_class as c
where c.oid in ('public.learning_notes'::regclass, 'public.user_notes'::regclass)
order by c.relname;

select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
  and tablename in ('learning_notes', 'user_notes')
order by tablename, policyname;
