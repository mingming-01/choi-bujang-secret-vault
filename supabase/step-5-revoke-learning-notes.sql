-- 제안 SQL입니다. Supabase Dashboard > SQL Editor에서 검토 후 직접 실행하세요.
-- 이 파일은 public.learning_notes만 대상으로 합니다.

-- 적용 전 권한 확인: PUBLIC, anon, authenticated의 명시적 grants.
select table_name, grantee, privilege_type, is_grantable
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

-- 상속된 PUBLIC 권한도 포함해 anon/authenticated가 가진 실효 권한을 확인합니다.
select role_name,
       has_table_privilege(role_name, 'public.learning_notes', 'SELECT') as can_select,
       has_table_privilege(role_name, 'public.learning_notes', 'INSERT') as can_insert,
       has_table_privilege(role_name, 'public.learning_notes', 'UPDATE') as can_update,
       has_table_privilege(role_name, 'public.learning_notes', 'DELETE') as can_delete
from (values ('anon'), ('authenticated')) as roles(role_name);

-- 적용: 브라우저 역할의 직접 접근 권한을 전부 회수합니다.
revoke all on table public.learning_notes from PUBLIC, anon, authenticated;

-- 적용 후 같은 두 조회를 다시 실행해 grants와 실효 권한이 없는지 확인합니다.
select table_name, grantee, privilege_type, is_grantable
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

select role_name,
       has_table_privilege(role_name, 'public.learning_notes', 'SELECT') as can_select,
       has_table_privilege(role_name, 'public.learning_notes', 'INSERT') as can_insert,
       has_table_privilege(role_name, 'public.learning_notes', 'UPDATE') as can_update,
       has_table_privilege(role_name, 'public.learning_notes', 'DELETE') as can_delete
from (values ('anon'), ('authenticated')) as roles(role_name);
