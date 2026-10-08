-- Supabase Dashboard > SQL Editor에서 검토 후 실행하세요. 이 파일은 API 권한/RLS를 변경하지 않습니다.
-- 현재 스키마: public.learning_notes(id bigint, owner_id uuid, title, content, created_at).
-- 기존 미할당 가상 메모 4건만 A에 연결하고, 공개 가능한 가상 시험 메모 1건을 B 소유로 추가합니다.
-- user_notes는 API CRUD 테이블이며 이 준비 작업은 기존 learning_notes를 유지합니다.

begin;

do $seed$
declare
  a_user_id uuid;
  b_user_id uuid;
  unassigned_count bigint;
  already_assigned_count bigint;
  sample_title constant text := 'ALEPH 4단계 소유권 시험 메모 (B)';
  sample_content constant text := '공개 가능한 가상 시험 자료입니다. 비밀이나 개인정보는 포함하지 않습니다.';
begin
  select id into strict a_user_id
  from auth.users
  where lower(email) = lower('gjals0318@gmail.com');

  select id into strict b_user_id
  from auth.users
  where lower(email) = lower('example@gmail.com');

  if a_user_id = b_user_id then
    raise exception 'A와 B는 서로 다른 Supabase Auth 사용자여야 합니다.';
  end if;

  select count(*) into unassigned_count
  from public.learning_notes
  where owner_id is null;

  if unassigned_count = 4 then
    update public.learning_notes
    set owner_id = a_user_id
    where owner_id is null;
  elsif unassigned_count = 0 then
    select count(*) into already_assigned_count
    from public.learning_notes
    where owner_id = a_user_id;

    if already_assigned_count < 4 then
      raise exception '기존 네 메모를 안전하게 확인할 수 없습니다. 변경 없이 중단합니다.';
    end if;
  else
    raise exception '미할당 메모가 4건이 아닙니다. 데이터 확인 후 실행하세요.';
  end if;

  if exists (
    select 1
    from public.learning_notes
    where title = sample_title
      and content = sample_content
      and owner_id is distinct from b_user_id
  ) then
    raise exception '시험 메모와 같은 제목/본문의 다른 행이 있습니다. 중복 여부를 확인하세요.';
  end if;

  if not exists (
    select 1
    from public.learning_notes
    where title = sample_title
      and content = sample_content
      and owner_id = b_user_id
  ) then
    insert into public.learning_notes (owner_id, title, content)
    values (b_user_id, sample_title, sample_content);
  end if;
end
$seed$;

commit;
