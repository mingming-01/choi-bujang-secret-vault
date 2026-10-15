# BYTE BACK 방어전 시작 틀 R5

이 자료실은 1~3단계의 로그인과 메모 기능을 유지하면서 4단계에서 사용자별 소유권 검사를 추가합니다. 실제 개인정보나 비밀 키를 코드·Git·로그에 넣지 마세요.

--
## 1~3단계 보존 사항

- 기존 `public.learning_notes` 테이블과 네 건의 학습용 가상 메모를 보존합니다.
- `/data.json`은 2단계 이후 정적 배포에서 제외됩니다.
- `/aleph.json`은 배포 빌드에서 계속 생성됩니다.
- Supabase 서버 전용 `SUPABASE_SECRET_KEY`는 Vercel 함수에서만 사용합니다. 브라우저 코드나 응답에 넣지 마세요.
- `vercel.json`의 홈페이지 `X-Content-Type-Options: nosniff` 헤더를 유지합니다.
- Supabase Auth 이메일·비밀번호 로그인/로그아웃, 토큰 검증 및 사용자 메모 CRUD가 있습니다.

--
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

## 6단계: 등록한 기기만 자료실에 들어옵니다

`src/decider.mjs`의 판정기는 요청 최상위 필드 `deviceRegistered`가 정확히 `true`인 경우에만 등록 기기로 판단해 `decision: 'allow'`와 `reasonCode: 'approved'`를 반환합니다. 값이 `false`이거나 필드가 누락되면 `decision: 'deny'`, `reasonCode: 'device_not_registered'`를 반환합니다. 두 경우 모두 응답의 `ruleIds`는 `['device_registered']`입니다.

로컬 가상 요청 검증은 다음 명령으로 실행합니다.

```sh
npm run decider:test
```

로컬 터미널에서 보고된 최근 결과는 등록 기기의 정상 요청, 미등록 기기의 가상 요청, 등록 여부가 누락된 요청 모두 **통과**입니다. 이 테스트는 가상 요청에 대한 로컬 판정기 연습이며, 공식 심판 통과의 증거가 아닙니다. 실제 API 접근통제나 운영 엔진의 동작도 이 결과로 검증된 것은 아니므로 별도로 확인해야 합니다.

6단계 기록 시 `aleph.config.json`의 `step`은 `6`입니다. `npm run bundle`, Git 명령, 실제 ZTNA 정책 적용은 이번 문서·설정 갱신에서 수행하지 않았습니다.

--
## 7단계: 평소와 다른 접속은 다시 확인합니다

`src/decider.mjs`는 6단계의 기기 규칙을 유지하면서 규칙 `step_up_required` 하나를 더합니다. 등록 기기의 요청에서 아래 세 가지가 **모두** 있을 때만 `decision: 'step_up'`, `reasonCode: 'step_up_required'`를 반환합니다.

- `signals.hour`가 0~5시 (평소와 다른 시각)
- `signals.network`가 `'unusual'` (평소와 다른 네트워크)
- `recentEvents`에 `kind: 'risk_signal'`이고 `ageSeconds` 600 이하, `count` 20 이상인 사건 (짧은 시간의 다량 읽기)

한두 가지만 있거나 `signals.region`만 다른 요청은 `allow`입니다. 지역 하나만으로 차단하지 않습니다. `signals.source`가 `'judge_fixture'`가 아니면 그 신호를 근거로 쓰지 않으며, 빠진 값을 정상값으로 채우지 않습니다. 복합 이상 요청이라도 `stepUp.verified`가 `true`이고 `authAgeSeconds`가 0~900이면 `allow`입니다. 미등록 기기는 신호와 관계없이 `deny`이고, 형식이 깨진 입력은 예외 없이 `deny`로 응답합니다.

0~5시, 20건, 600초 기준은 공식 계약이 정하지 않은 값이며 제공 연습 요청(`scripts/fixture-7.mjs`)에 맞춘 가정입니다.

로컬 가상 요청 확인은 `npm run decider:test`와 `npm run fixture:7`입니다. 최근 결과는 모두 통과(정상 `allow`, 복합 이상 `step_up`)이며, 이는 로컬 연습이지 심판 판정이 아닙니다. 실제 재로그인 전 자료 차단과 새 로그인 뒤 재판정은 구현하거나 시험하지 않았습니다(미실행).

7단계 기록 시 `aleph.config.json`의 `step`은 `7`입니다.

--
## 8단계: 자료마다 갈 수 있는 구역을 나눕니다

### 자원 정책

- `src/resources.mjs`에서 자원 ID와 경로 모양을 구분합니다.
- 메모 단건 경로는 GET, PUT, DELETE를 허용하고 메모 전체 목록과 생성 경로는 거부합니다.
- 반 공지 경로는 GET만 허용하고 POST, PUT, PATCH, DELETE는 거부합니다.
- 알 수 없는 경로와 `export` 기능 경로는 거부합니다.
- 판정기는 기존 `device_registered`, `step_up_required` 규칙을 유지하고 `resource_zone_access` 규칙을 추가합니다.

### 자료 API 보호

- 학생 인증을 검증하고 검증된 사용자 ID와 저장된 `owner_id`를 비교합니다.
- 다른 사용자의 메모는 조회·수정·삭제할 수 없습니다.
- 인증 실패와 메모 미발견 사유를 간단히 기록합니다.
- 로그에는 토큰이나 메모 본문을 기록하지 않습니다.

### 검증 명령

- `npm run decider:test`
- `npm run test:r5`

두 명령은 로컬 테스트이며 공식 심판 통과를 의미하지 않습니다.

### 구현 범위와 한계

- 공식 판정 요청 계약에서 확인된 메모 경로는 `GET /notes/:id`입니다.
- 반 공지 서비스와 경로는 현재 XDR 자료를 근거로 한 가정이며, 실제 공지 API가 구현되어 있거나 심판 요청과 일치한다고 확인된 것은 아닙니다.
- 자원 정책의 거부 응답은 기존 `device_not_registered` 사유 코드를 재사용하므로, 자원 거부 원인과 사유 코드의 의미가 완전히 일치하지 않습니다.

--
## 9단계: 비정상 조회를 탐지하고 회수 제안을 반환합니다

`src/detect.mjs`는 가상 사건에서 `at`, `method`, `identity.sub` 필드만 사용합니다. 동일한 `identity.sub`의 GET 요청이 연속된 10분 구간에서 120건을 초과하면 비정상 조회로 판단합니다. 따라서 정확히 120건은 정상이며, 사용자는 서로 구분해 집계하므로 다른 사용자의 요청을 합산하지 않습니다. GET이 아닌 요청은 탐지 대상에 포함되지 않습니다.

탐지된 요청은 다음 객체를 반환합니다.

```json
{ "action": "propose_revocation", "reasonCode": "burst_read", "subject": "<해당 identity.sub>" }
```

나머지 입력은 다음 객체를 반환합니다.

```json
{ "action": "observe" }
```

이는 가상 사건에 대한 회수 제안일 뿐, 실제 권한 회수나 접속 차단을 수행하지 않습니다.

가상 사건 탐지 테스트 실행 명령:

```sh
npm run detect:test
```

테스트는 가상 사건 연습이며, 실제 접속 회수나 공식 심판 통과의 증거가 아닙니다.

9단계 기록에서 `aleph.config.json`의 `step`은 `9`입니다.
