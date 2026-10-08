# BYTE BACK 방어전 시작 틀 R5

이 자료실은 1~2단계의 가상 메모 자료를 유지하면서, 3단계에서 Supabase Auth 로그인과 인증된 사용자 메모 CRUD를 추가합니다. 실제 개인정보나 비밀 키를 코드·Git·로그에 넣지 마세요.

## 1~2단계 보존 사항

- 기존 `public.learning_notes` 테이블과 네 건의 학습용 가상 메모를 보존합니다.
- `/data.json`은 2단계 이후 정적 배포에서 제외됩니다.
- `/aleph.json`은 배포 빌드에서 계속 생성됩니다.
- Supabase 서버 전용 `SUPABASE_SECRET_KEY`는 Vercel 함수에서만 사용합니다. 브라우저 코드나 응답에 넣지 마세요.
- `vercel.json`의 홈페이지 `X-Content-Type-Options: nosniff` 헤더를 유지합니다.

## 3단계: 진짜 로그인과 메모 CRUD

화면은 Supabase 공식 `@supabase/supabase-js` SDK의 이메일·비밀번호 로그인 및 로그아웃 흐름을 사용합니다. Project URL과 publishable key는 공개 가능한 브라우저 설정입니다. 비밀번호를 직접 처리해 토큰을 만들지 않습니다. 로그인 실패 사유는 화면에 표시하고, 인증 상태에 따라 화면을 갱신합니다.

자료 함수는 `src/verify-login.mjs`를 통해 `Authorization: Bearer …` 토큰을 검증합니다. 발급자, audience 및 공개 JWKS 주소는 `aleph.config.json`의 `identityProvider`에 적혀 있으며, 비밀 키는 설정 파일에 없습니다. userId/role을 요청 본문에서 신뢰하지 않습니다. 인증 누락이나 검증 실패는 자료를 반환하지 않고 JSON 오류와 HTTP 401로 거부합니다.

로그인 후:

- `GET /api/notes`는 사용자 본인의 메모 목록과 기존 네 가상 학습 메모를 반환합니다.
- `POST /api/notes`는 `{ "id": "UUID(선택)", "title": "제목", "body": "본문" }`을 받고, ID가 없으면 서버가 UUID를 만듭니다. `owner_id`는 반드시 검증된 세션 사용자 ID로 기록합니다. 응답은 `{ "id": "…" }`입니다.
- `GET /api/notes/:id`는 `{ "id": "…", "title": "…", "body": "…" }`을 반환하고, 없는 ID는 404입니다.
- `PUT /api/notes/:id`는 제목과 본문을 수정합니다.
- `DELETE /api/notes/:id`는 삭제하고, 삭제 뒤 같은 GET은 404입니다.

`supabase/step-3-user-notes.sql`은 기존 테이블을 재생성하지 않고 사용자 메모용 `public.user_notes` 테이블을 별도로 준비합니다. Supabase Dashboard의 SQL Editor에서 실행한 뒤 Vercel 서버 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`가 이미 올바르게 설정되어 있는지 확인하세요. 실제 secret key를 저장소나 브라우저에 복사하지 마세요. SQL은 브라우저 역할 권한을 부여하지 않고, 서버 키로 쓰는 `service_role`에 한정해 새 테이블 CRUD 권한과 기존 샘플 테이블 SELECT 권한을 부여합니다.

### 의도적으로 남긴 3단계 허점

이번 단계는 인증(Authentication)을 붙였지만, 타인의 메모인지 비교하는 소유권 검사(Authorization)는 완성하지 않습니다. 따라서 로그인한 B가 A의 UUID를 알고 있으면 A의 메모를 조회·수정·삭제할 수 있는 허점이 남아 있습니다. 요청된 실습 조건이며 4단계에서 소유권 검사를 추가할 예정입니다. 비로그인 요청은 거부되지만, 로그인만으로 타인 자료 접근이 차단되는 것은 아닙니다.

## 설정 및 확인

1. Supabase Auth에서 이메일·비밀번호 로그인을 사용할 수 있게 하고 A/B 실습 계정을 준비합니다. Project URL과 publishable key는 `public/index.html`의 공개 클라이언트 초기화에 설정되어 있습니다. 해당 키는 공개용이며 secret key를 브라우저에 넣지 마세요.
2. Supabase Dashboard의 SQL Editor에서 `supabase/step-3-user-notes.sql`을 실행합니다. 이 SQL은 기존 `learning_notes` 테이블이나 네 메모를 삭제·재생성하지 않습니다. Vercel의 기존 서버 전용 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`를 수정하거나 출력하지 않습니다.
3. 로그인하지 않은 브라우저에서 `GET /api/notes`는 HTTP 401과 JSON 오류여야 합니다. A 로그인 후 목록, 추가, 한 건 조회, 수정, 삭제가 동작하고 삭제 후 조회는 404여야 합니다.
4. A 메모 UUID를 이용한 B의 조회·수정 가능 여부는 4단계 전까지 허용되는 의도된 허점입니다. 이 단계에서는 `owner_id`를 조회·수정·삭제 조건으로 쓰지 않습니다. 새 메모의 `owner_id` 값만 서버가 검증한 사용자 ID로 저장합니다.
5. 배포 후 `/aleph.json`이 계속 열리고, `/` 응답에 `X-Content-Type-Options: nosniff`가 있는지 확인합니다. `/data.json`은 다시 만들지 않습니다.

로컬 점검 명령은 `npm run build`와 `npm run bundle`입니다. 빌드는 정적 배포 파일을 준비하며 실제 Auth·DB·Vercel 응답은 실제 배포에서 별도로 확인해야 합니다. `npm run bundle`은 깨끗한 저장소의 커밋을 기준으로 제출 자료를 만들기 때문에, 실행 전 3단계 저장점 커밋이 필요합니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 실제 운영 엔진이나 심판 판정이 아닙니다. 제출 묶음은 실제 저장소 및 배포와 일치하는지 확인해 생성하세요.
