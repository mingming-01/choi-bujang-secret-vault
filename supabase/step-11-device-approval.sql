-- 11단계: 서버 측 기기 승인 및 일회용 요청 검증
-- 이 파일은 검토용 마이그레이션입니다. 자동으로 실행되지 않습니다.

create table if not exists public.device_credentials (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  credential_id text not null unique,
  public_key text not null,
  counter bigint not null default 0 check (counter >= 0),
  transports text[] not null default '{}',
  device_label text not null default 'BYTE BACK 기기'
    check (char_length(device_label) between 1 and 80),
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected')),
  created_at timestamptz not null default now(),
  approved_at timestamptz,
  approved_by uuid references auth.users(id) on delete set null
);

create index if not exists device_credentials_user_status_idx
  on public.device_credentials (user_id, status);

create table if not exists public.device_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  purpose text not null
    check (purpose in ('registration', 'request')),
  challenge text not null unique,
  request_method text,
  request_path text,
  request_body_sha256 text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz,
  check (
    (
      purpose = 'registration'
      and request_method is null
      and request_path is null
      and request_body_sha256 is null
    )
    or
    (
      purpose = 'request'
      and request_method in ('GET', 'POST', 'PUT', 'DELETE')
      and request_path is not null
      and request_body_sha256 ~ '^[A-Za-z0-9_-]{43}$'
    )
  )
);

create index if not exists device_challenges_user_expiry_idx
  on public.device_challenges (user_id, expires_at);

alter table public.device_credentials enable row level security;
alter table public.device_challenges enable row level security;

-- 브라우저의 anon/authenticated 역할에서는 직접 조회·수정하지 못하게 합니다.
-- 서버의 SUPABASE_SECRET_KEY를 사용하는 API만 데이터에 접근합니다.
revoke all on table public.device_credentials from public, anon, authenticated;
revoke all on table public.device_challenges from public, anon, authenticated;
grant all on table public.device_credentials to service_role;
grant all on table public.device_challenges to service_role;
