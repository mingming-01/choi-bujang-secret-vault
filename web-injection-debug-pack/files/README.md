# BYTE BACK 방어전 시작 틀 R5

이 자료실은 1~3단계의 로그인과 메모 기능을 유지하면서 4단계에서 사용자별 소유권 검사를 추가합니다. 실제 개인정보나 비밀 키를 코드·Git·로그에 넣지 마세요.

## 1~3단계 보존 사항

- 기존 `public.learning_notes` 테이블과 네 건의 학습용 가상 메모를 보존합니다.
- `/data.json`은 2단계 이후 정적 배포에서 제외됩니다.
- `/aleph.json`은 배포 빌드에서 계속 생성됩니다.
- Supabase 서버 전용 `SUPABASE_SECRET_KEY`는 Vercel 함수에서만 사용합니다. 브라우저 코드나 응답에 넣지 마세요.
- `vercel.json`의 홈페이지 `X-Content-Type-Options: nosniff` 헤더를 유지합니다.
- Supabase Auth 이메일·비밀번호 로그인/로그아웃, 토큰 검증 및 사용자 메모 CRUD가 있습니다.

## 4단계: 로그인해도 내 자료만 보이게 하기

`api/notes.js`와 `api/notes/[id].js`는 계속 `src/verify-login.mjs`로 Bearer 토큰을 검증하고, 검증된 학생의 `userId`만 소유자 판정에 사용합니다. URL의 ID는 메모를 식별할 뿐 사용자 ID로 신뢰하지 않습니다. 요청 본문의 `owner_id`는 무시하며, 생성은 서버 검증 사용자 ID로 저장합니다.

- 목록 GET은 `user_notes`와 기존 `learning_notes` 모두 `owner_id = 검증된 사용자 ID` 조건으로 읽습니다.
- 단건 GET·PUT·DELETE는 메모 ID와 함께 검증 사용자 ID를 DB 소유자 조건으로 사용합니다. 타인 소유 또는 없는 ID는 `404 NOTE_NOT_FOUND`로 거부합니다.
- PUT은 기존 행의 소유자 조건을 확인하고 `owner_id`를 검증된 사용자 ID로 고정해 업데이트합니다. 본문에 소유자 변경값을 보내도 반영되지 않습니다.
- POST는 `owner_id` 요청값을 쓰지 않고 검증된 사용자 ID를 저장합니다.
- 한 건 GET 및 PUT 응답은 `{ "id": "…", "title": "…", "body": "…" }`, 생성 요청은 `{ "id": "UUID(선택)", "title": "제목", "body": "본문" }`, 수정 요청은 `{ "title": "제목", "body": "본문" }` 형식입니다.
- 허용 경로는 `GET, POST /api/notes` 및 `GET, PUT, DELETE /api/notes/:id`입니다.

서버는 Supabase secret key를 사용하므로 DB RLS는 서버 요청에서 우회될 수 있습니다. 따라서 API 소유자 필터는 필수이며, 브라우저에서 직접 접근할 수 있도록 별도로 authenticated RLS 정책도 적용합니다. `supabase/step-4-owned-notes-seed.sql`은 Auth 이메일로 A/B 계정 UUID를 조회해 기존 `learning_notes` 네 건을 A에 연결하고, 공개 가능한 가상 시험 메모 한 건을 B 소유로 추가합니다. `supabase/step-4-user-notes-rls.sql`은 기존 `learning_notes` 및 `user_notes` 두 테이블만 대상으로 anon 권한을 회수하고, authenticated CRUD와 `auth.uid() = owner_id` RLS 정책을 설정합니다. **두 SQL 모두 직접 실행하지 않았습니다.** 검토 후 Supabase Dashboard → SQL Editor에서 순서대로 실행하세요. RLS SQL은 기존 두 테이블의 정책을 교체하므로, 필요한 정책을 확인하고 실행하세요.

## 설정 및 확인

1. Supabase Auth에 A (`gjals0318@gmail.com`)와 B (`example@gmail.com`) 계정이 존재하고 서로 다른 사용자 ID인지 확인합니다. 실제 비밀번호는 코드나 대화에 쓰지 않습니다.
2. 먼저 `supabase/step-4-owned-notes-seed.sql`을 검토·실행해 학습용 행의 소유자를 준비합니다. 이어 `supabase/step-4-user-notes-rls.sql`을 검토·실행하고 적용 후 grants, RLS 및 정책 조회 결과를 확인합니다.
3. 로그인 후 A는 기존 네 메모를, B는 B의 시험 메모를 목록의 학습 자료 영역에서 확인해야 합니다. `user_notes` CRUD 메모는 목록의 내 메모 영역에 표시됩니다.
4. A와 B 각 계정에서 메모 추가·조회·수정·삭제를 시험합니다. 반대 계정 메모 ID로 단건 조회·수정·삭제를 시도하면 `404 NOTE_NOT_FOUND`여야 합니다. 생성 본문에 다른 `owner_id`를 넣어도 저장 소유자는 로그인 사용자여야 하며, PUT의 `owner_id` 변경은 적용되지 않아야 합니다.
5. 로그아웃/로그인 동작을 확인합니다. 로그아웃 상태의 메모 API는 HTTP 401과 JSON 오류를 반환해야 합니다. 기존 3단계의 `/data.json` 차단, 배포용 `/aleph.json`, 홈페이지의 `X-Content-Type-Options: nosniff`를 유지합니다.

로컬 시험은 `npm run test:r5`입니다. 이 테스트는 실제 Supabase 계정, SQL 정책이나 Vercel 배포를 검증하지 않습니다. 배포에서 `/aleph.json`, `/data.json`, 응답 헤더와 사용자 간 소유권 거부를 직접 확인해야 합니다. `npm run build`/`npm run bundle`은 이번 단계 요청에 따라 실행하지 않았습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 실제 운영 엔진이나 심판 판정이 아닙니다. 제출 묶음은 실제 저장소 및 배포와 일치하는지 확인해 생성하세요.
