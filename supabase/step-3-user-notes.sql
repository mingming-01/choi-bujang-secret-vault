-- Supabase Dashboard > SQL Editor에서 실행하세요.
-- 기존 public.learning_notes와 네 학습용 행은 변경하지 않습니다.
-- 사용자 생성 메모는 별도 테이블에 UUID ID로 저장합니다.

begin;

create table if not exists public.user_notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title text not null,
  content text not null,
  created_at timestamptz not null default now()
);

alter table public.user_notes enable row level security;

-- 브라우저 역할에는 접근 권한을 주지 않습니다. API 서버만 secret key로 접근합니다.
revoke all privileges on table public.user_notes from public, anon, authenticated;
grant usage on schema public to service_role;
grant select, insert, update, delete on table public.user_notes to service_role;

-- 2단계의 공개/로그인 사용자 권한 제한은 유지하고, 서버 역할의 기존 자료 읽기만 보장합니다.
grant select on table public.learning_notes to service_role;

commit;
