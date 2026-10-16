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

--
## 10단계: 백업에서 시험 메모 한 건 복구합니다

### 복구 경로와 범위

`aleph.config.json`에서 `restoreRoute`는 `/api/restore`이고 `allowedRoutes`에도 `POST /api/restore`가 등록되어 있습니다. 구현은 `api/restore.js`의 실제 POST 처리기입니다. 이 경로는 `public.learning_notes`의 지정된 한 행만 대상으로 하며 운영 정책이나 다른 서비스 규칙을 수정하지 않습니다. 일반 학생은 백업에 기록된 소유자 본인만 복구할 수 있고, 심판 토큰은 시험 계정 B(`identity: "b"`)만 허용합니다. 다른 사람의 ID나 소유자를 요청 본문으로 지정할 수 없습니다.

이 경로는 사전 구성된 비공개 Supabase Storage 백업만 사용합니다. 배포 환경의 서버 전용 설정은 다음과 같습니다. 값을 저장소, README, 브라우저 또는 로그에 넣지 마세요.

- `RESTORE_BACKUP_URL`: 같은 Supabase 프로젝트의 비공개 Storage 객체 URL (`/storage/v1/object/...`). 공개 URL, 다른 호스트, HTTP, redirect는 허용되지 않습니다.
- `RESTORE_BACKUP_SHA256`: 백업 JSON **원시 바이트 전체**의 신뢰된 SHA-256 64자리 16진수. 백업을 취득·승인할 때 기록한 값을 제한된 배포 설정으로 관리합니다.
- 기존 서버 전용 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`: 함수에서만 사용하며 클라이언트에 노출하지 않습니다.

백업 객체는 다음 구조의 JSON이어야 합니다. `contentSha256`는 `content` 문자열의 UTF-8 SHA-256입니다. 실복구 때는 사고 전에 확보하고 소유자·대상 ID를 확인한 B 메모 백업을 사용합니다. 저장소의 `test/fixtures/recovery/` 파일은 로컬 훈련 fixture일 뿐이며 운영 백업이 아닙니다.

```json
{
  "schema": "aleph.note-backup.v1",
  "environment": "production-backup",
  "revision": "승인된 백업 버전",
  "id": "learning_notes의 숫자 ID 문자열",
  "ownerId": "B 소유자의 UUID",
  "title": "백업 제목",
  "content": "백업 본문",
  "contentSha256": "본문의 SHA-256"
}
```

### 순서: 사본 검증, 미리보기, 한 건 복원

1. 운영자가 비공개 버킷의 승인된 사고 전 사본과 기록된 전체 파일 SHA-256을 다시 확인하고, `RESTORE_BACKUP_URL` 및 `RESTORE_BACKUP_SHA256`을 제한된 배포 설정에 넣습니다. 값이 없거나 사본을 다시 읽을 수 없으면 멈춥니다. **전체 바이트 해시가 맞지 않거나 JSON/schema/ID/소유자/본문 해시 검증 중 하나라도 실패하면 어떤 복원도 하지 않고 중단합니다.** 각 POST는 백업을 다시 GET하고 전체 바이트 해시 및 내용 해시를 검증합니다.
2. 시험 계정 B로 로그인해 사본의 `id`, `ownerId`, `contentSha256`를 POST 본문으로 보내고 `confirmation`은 생략합니다. 실제 요청 예:

   ```http
   POST /api/restore
   Authorization: Bearer <시험 계정 B 토큰>
   Content-Type: application/json

   {"id":"<백업의 숫자 ID>","ownerId":"<백업의 B UUID>","contentSha256":"<백업 본문 SHA-256>"}
   ```

3. 서버가 반환한 `preview`에서 `revision`, 대상 ID·소유자·내용 해시, `changedFields`를 읽고 복구 전 현재 한 건의 상태를 확인합니다. 이것이 실제 실행 전에 볼 버전과 변경 범위입니다. 응답의 `confirmation` 값을 확인하지 않고 진행하지 않습니다. 현재 행의 소유자가 백업과 다르거나 대상이 모호하면 서버는 충돌로 중단합니다.
4. 검증한 사본과 변경 범위가 기대와 정확히 맞을 때만 같은 요청을 다시 POST하고 미리보기에서 받은 `confirmation`을 추가합니다. 커밋 POST도 사본을 다시 읽고 검증한 뒤 현재 상태와 확인 문자열을 재대조합니다. 확인이 없거나 오래된 값이면 거부합니다. 지정한 행만 갱신(행이 삭제된 경우 같은 ID·소유자로 삽입)하고, 읽어 다시 대조한 ID·소유자·본문 해시가 사본과 일치할 때 성공으로 응답합니다. 다른 메모는 쓰지 않으며 감사 이력 테이블과 정책은 수정하지 않습니다.
5. 백업이 없거나 읽기·검증·소유권·동시성·복구 후 대조 중 실패하면 중단합니다. 실패를 성공으로 기록하거나 다른 메모/정책을 되돌려 맞추지 않습니다. 감사 기록과 변경 없는 다른 자료의 보존을 별도로 확인합니다.

이 경로는 기존 행을 업데이트하거나 삭제된 한 행을 다시 넣는 기능입니다. 실제 백업 설정, DB 스키마/권한, Storage 접근 및 배포를 여기서 검증한 것은 아닙니다. 실제 계정의 메모를 대상으로 실행하지 않았습니다(미실행).

### 복구 뒤 1~9단계 재시험 체크리스트

아래는 실행 순서와 기대 결과입니다. 각 요청은 정상 입력은 허용되고 공격 입력은 거부·추가확인되는지 확인하며, 복원 한 건 외의 데이터/감사 기록도 비교합니다. **이 변경에서 아래 재시험은 실행하지 않았습니다. 모든 결과는 미실행입니다.** 실행 뒤에만 관측 결과로 갱신하세요.

| 순서 | 정상 요청 | 금지·위험 요청 | 결과 |
|---|---|---|---|
| 1~3 | 정상 로그인 후 본인 자료실 이용, 허용된 정적 설정 확인 | 로그아웃/잘못된 토큰의 메모 요청, `/data.json` 원본 노출, 클라이언트의 서버 비밀 키 노출 시도 | 미실행 |
| 4 | A는 A 소유 자료, B는 B 소유 시험 메모만 조회 | B의 메모 ID로 A가 GET/PUT/DELETE하거나 요청 `owner_id`를 바꾸는 시도 | 미실행 |
| 5 | 서버 API가 의도한 Supabase 서비스로 동작 | 직접 DB/API의 비인가 접근, 서버 비밀값 응답·로그 노출 시도 | 미실행 |
| 6 | 등록 기기의 자료 요청 | 미등록 기기의 자료 요청 | 미실행 |
| 7 | 평소 신호의 정상 요청은 허용 | 제공 가상 fixture의 복합 이상 신호는 추가 확인(`step_up`); 확인 전 접근 금지 | 미실행 |
| 8 | 허용된 메모 단건 GET/PUT/DELETE와 공지 GET | 메모 목록/생성의 자원 정책 우회, 공지 변경 메서드, 미등록·export 경로 | 미실행 |
| 9 | 기준 이하의 정상 조회 | 같은 주체의 10분 구간 120건 초과 조회는 회수 제안이 발생하는지 확인(제안 자체를 실제 권한 회수로 오인하지 않음) | 미실행 |

각 시험은 시험 계정과 가상 데이터로만 수행합니다. 정상 요청을 허용하고 금지 요청을 예상한 거부/추가 확인으로 관측했을 때만 실제 결과를 기록합니다. 운영 정책을 변경하거나 실제 사용자의 자료로 공격 시험을 하지 않습니다.

10단계 기록의 `aleph.config.json` `step` 값은 `10`입니다. 로컬 패키지 테스트 3개, R5 테스트 11개, 복구 API 입력 검증 테스트 4개는 통과했습니다. 실제 Supabase 백업 설정과 DB 복원, 복구 후 데이터·감사 기록 보존, 1~9단계 재시험, 공식 심판 통과, Git 커밋 및 `npm run bundle`은 아직 확인하지 않았습니다. 이 문서의 기대 결과는 실행 결과가 아닙니다.

--
## 11단계: 나만의 접속 앱을 완성합니다

### 구현 내용

- 웹 앱 매니페스트와 앱 아이콘을 추가해 설치 가능한 웹 앱의 기본 구성을 마련했습니다.
- WebAuthn을 이용한 기기 등록 및 승인 상태 조회 기능을 추가했습니다.
- 새로 등록한 기기는 `pending` 상태로 저장하며, 승인된 기기만 보호 API 요청에 사용할 수 있도록 구성했습니다.
- 보호 API에서 기기 서명과 요청 경로, 요청 본문 해시를 확인하도록 구성했습니다.
- 요청 챌린지의 만료 시간과 사용 여부를 확인하고, 검증이 완료된 챌린지의 재사용을 방지하도록 구성했습니다.
- 기기 승인 및 요청 챌린지에 필요한 데이터베이스 구조를 `supabase/step-11-device-approval.sql`에 작성했습니다.
- 기기 승인 관련 서버 로직은 `src/device-approval.mjs`에 구현했습니다.

### 로컬 테스트

다음 명령어로 기존 테스트와 11단계 기기 서명 검증 테스트를 실행할 수 있습니다.

    npm run test:package
    npm run test:r5
    node --test test/device-approval.test.mjs

### 기기 서명 검증 항목

- **서명 누락:** 기기 서명 헤더가 없는 보호 요청을 거부합니다.
- **경로 변조:** 서명 시 지정한 요청 경로와 실제 요청 경로가 다르면 거부합니다.
- **본문 변조:** 서명 시 지정한 본문 해시와 실제 요청 본문의 해시가 다르면 거부합니다.

### 확인하지 않은 항목 및 한계

- `supabase/step-11-device-approval.sql`은 데이터베이스 구조를 정의한 파일이며, 실제 Supabase 환경에 적용했는지는 별도로 확인해야 합니다.
- 배포 환경에서의 기기 등록, 관리자 승인 및 정상적인 서명 요청 성공 여부는 별도 검증이 필요합니다.
- 로컬 테스트 결과만으로 실제 배포 환경의 동작이나 공식 심판 통과를 확정할 수 없습니다.
- `aleph.config.json`의 `step` 값은 11단계로 설정합니다. 설정 변경 후 실제 파일 값을 확인해야 합니다.
- Git 커밋 및 `npm run bundle` 실행 결과는 별도로 확인해야 합니다.


--
## 12단계: 탈환 작전실을 완성합니다

### 엔진 출처와 학생 구현의 범위

- 공식 판정·총공세 심판은 교육과정에서 제공하는 **ALEPH SDP 엔진**을 사용합니다. 이 저장소는 제공 엔진의 내부 구현을 자체 엔진인 것처럼 재현하지 않습니다.
- 학생 작업으로 관리하는 코드는 `src/decider.mjs`의 요청 판정 규칙, `src/detect.mjs`의 가상 사건 탐지, `src/device-approval.mjs`의 WebAuthn 기기 승인 검증, 메모 API 소유권 검사, 복구 API, `api/war-room.js` 및 `public/war-room-evidence.js`의 요약·실제 응답 기록 화면입니다.
- `npm run decider:test`와 `npm run detect:test`는 로컬 가상 입력 시험입니다. 이 결과를 ALEPH SDP 공식 판정이나 운영 환경에서 실제 차단·회수가 실행됐다는 증거로 간주하지 않습니다.
- `api/threat-intel.js`는 아직 `501 THREAT_INTEL_NOT_IMPLEMENTED`를 반환하는 미구현 경로입니다. 공식 침해 정보 조회가 구현된 것으로 표시하지 않습니다.
- 탈환 작전실의 조회 불가·미연결·미실행은 성공이나 0건을 뜻하지 않습니다. 화면의 실제 요청 기록은 실행한 HTTP 요청에 한해서만 일치·불일치·미검증으로 구분합니다. 가상 메모 본문, 토큰, 개인 키는 기록하거나 내보내지 않습니다.
- 41종 총공세는 이 문서만으로 실행 완료가 되지 않습니다. 각 시험의 실제 요청·응답 근거를 확인한 뒤에만 결과를 기록합니다.

### 새 환경 설치

필수 런타임은 Node.js 22 이상입니다. 저장소를 새 작업 폴더에 복제한 후 의존성을 설치합니다.

```sh
git clone https://github.com/mingming-01/choi-bujang-secret-vault.git
cd choi-bujang-secret-vault
npm install
```

비밀값은 Git, README, 스크린샷 또는 제출 JSON에 기록하지 않습니다. Supabase 및 WebAuthn 설정은 승인된 관리 경로를 통해 배포 환경의 서버 전용 환경변수로 구성합니다. 값은 문서에 복사하지 않습니다.

### 로컬 확인 및 실행

다음 명령은 구현된 로컬 테스트를 실행합니다.

```sh
npm run test:package
npm run test:r5
npm run decider:test
npm run detect:test
node --test test/device-approval.test.mjs test/war-room.test.mjs test/war-room-evidence.test.mjs
```

`npm run build -- --local`은 로컬 빌드 확인용입니다. 일반 `npm run build`는 Vercel이 제공하는 저장소·커밋·배포 식별 환경변수를 사용해 `public/aleph.json`을 생성하므로, 해당 환경변수가 없는 일반 로컬 셸에서는 실패할 수 있습니다. `npm run build`는 HTTP 서버를 시작하지 않습니다.

이 프로젝트의 `package.json`에는 `start` 또는 `dev` 스크립트가 없습니다. API 함수까지 포함한 로컬 앱은 Vercel CLI가 설치된 환경에서 프로젝트 루트의 `vercel dev`로 실행합니다. 종료하려면 해당 터미널에서 `Ctrl+C`를 누릅니다. 앱을 열어 보는 것만으로 실제 Supabase 설정, 관리자 기기 승인 또는 공식 심판 결과가 검증되는 것은 아닙니다.

### 배포와 중지

1. 공개 GitHub 저장소를 Vercel 프로젝트에 연결하고, `vercel.json`의 빌드 명령 `npm run build`와 출력 폴더 `public`을 유지합니다.
2. Vercel의 시스템 환경변수 및 승인된 서버 전용 변수 구성을 확인합니다. 필요한 변수 이름에는 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `WEBAUTHN_ORIGIN`, `WEBAUTHN_RP_ID`, `RESTORE_BACKUP_URL`, `RESTORE_BACKUP_SHA256` 등이 포함될 수 있습니다. 각 기능에 필요한 이름과 용도만 확인하고, 실제 값은 저장소나 화면 공유에 노출하지 않습니다.
3. `supabase/step-11-device-approval.sql`은 파일이 존재한다고 데이터베이스에 자동 적용되는 것이 아닙니다. 기기 승인이 필요한 환경에서는 권한 있는 운영자가 검토·적용 여부를 확인하고, 적용 전에는 운영 기기 등록이 동작한다고 주장하지 않습니다.
4. 배포를 일시 중지하거나 이전 정상 배포로 돌아가려면 Vercel 프로젝트의 Deployments 화면에서 대상 배포를 확인하고, 플랫폼이 제공하는 중지·롤백 절차를 사용합니다. 로컬 서버는 실행 터미널에서 `Ctrl+C`로 중지합니다.

### 자료 복구와 되돌리기

- `/api/restore`는 사전 구성된 비공개 백업을 다시 읽어 전체 파일 SHA-256 및 JSON·소유권·본문 해시를 검증하고, 확인 절차를 거쳐 지정된 `learning_notes` 한 건만 복구하도록 설계되었습니다. 운영자가 승인한 백업과 서버 전용 `RESTORE_BACKUP_URL`, `RESTORE_BACKUP_SHA256` 설정을 확인할 수 없으면 복구 요청을 실행하지 않습니다.
- 복구 미리보기의 백업 버전, 대상, 소유자 및 변경 범위를 검토하기 전에는 확인 문자열을 이용한 확정 요청을 보내지 않습니다. 테스트 fixture는 운영 백업이 아닙니다. 복구 뒤에는 대상 행의 소유자·본문 해시와 관계없는 자료 및 감사 기록의 보존을 별도로 확인합니다.
- 코드 배포를 되돌릴 때는 Git에서 변경 파일과 작업 상태를 먼저 확인하고, 기존 작업을 보존하면서 수정 커밋을 `git revert <문제가 된 커밋>`으로 되돌리는 방식을 우선합니다. `git reset --hard`로 작업 트리나 다른 변경을 지우지 않습니다.

### 현재 검증 범위와 미실행 항목

- 제작 1의 요약 API 로컬 테스트와 제작 2의 실제 응답 기록 모듈 테스트는 로컬에서 실행했을 때의 결과만 증명합니다.
- 브라우저에서 API 점검 버튼을 누른 결과가 없는 시험은 미실행입니다. 서버 응답을 받지 못한 요청은 미검증으로 남기며, 서버 로그나 HTTP 결과가 없으면 요청 성공을 추정하지 않습니다.
- 1~11단계의 전체 회귀 시험, 배포 환경의 정상 사용자 요청과 거부 요청, 41종 총공세, 관리자 기기 승인, 실제 백업 복구 및 공식 심판 통과는 실제로 수행하고 근거를 확보하기 전까지 미확인입니다.
- 저장점 생성 전 `aleph.config.json`의 `step`이 `12`인지 확인합니다. README 기록, 커밋 및 제출 JSON의 커밋 해시는 실제 생성 결과로 대조합니다.

--
## 보너스 XDR-02: 웹 주입 경보

- `xdr/web-injection/read-alerts.mjs`는 확인용 요약만 출력하고, `decide.mjs`는 요청 인자 패턴만 판정합니다.
- 실행기는 주소가 같은 서로 다른 유효 경보 ID의 명확한 단일 주입들을 반복 근거로 묶습니다. 패턴이 겹치는 경보는 이 근거 집계에서 제외합니다.
- `respond.mjs`는 차단 후보와 만료 시각을 기록하고 `xdr/alerts.log`에 결과를 남깁니다. 후보 규칙은 기존 ZTNA 규칙에 적용되지 않습니다.
- 확인 및 결과 갱신: `npm run xdr:run -- web-injection`. 상세 경보별 결과는 `xdr/web-injection/result.json`에서 확인합니다.
