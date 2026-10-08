# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계 자료실을 학습용 Supabase 테이블에 연결하는 2단계 실습입니다. SQL 시드의 네 메모는 모두 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 저장소에 넣지 마세요.

## 2단계: Supabase 자료를 서버 함수로 읽기

`supabase/step-2-learning-notes.sql`을 Supabase Dashboard의 **SQL Editor**에서 실행합니다. 이 스크립트는 `public.learning_notes` 테이블을 만들고 네 건의 가상 메모를 한 번만 추가합니다. `owner_id`는 이후 연결을 위한 nullable `uuid` 칸이며 `auth.users` 외래키는 없습니다. RLS를 켜고 `anon` 및 `authenticated`의 테이블 권한을 회수하며 읽기 정책을 만들지 않습니다. 실행 뒤 Table Editor에서 `owner_id`가 `uuid`인지, Database → Policies에서 RLS가 켜져 있고 읽기 정책이 없는지 확인하세요.

화면은 `/api/notes`를 호출하고, Vercel 서버 함수가 환경변수 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 사용해 `learning_notes`에서 자료를 읽습니다. Supabase Dashboard의 **Project Settings → API Keys**에서 프로젝트 URL과 secret key를 확인하고, Vercel의 **Project → Settings → Environment Variables**에 두 변수를 서버 환경변수로 직접 설정한 뒤 재배포하세요. 키 값을 코드, `public` 파일, 브라우저 응답, 로그, Git에 넣지 말고 `NEXT_PUBLIC_` 같은 공개 접두사도 붙이지 마세요. Dashboard 입력란에 키를 넣으면 되므로 답변이나 저장소에 키를 적을 필요는 없습니다.

### 중요한 약점: 자료 함수는 공개 주소입니다

`/api/notes`는 현재 로그인·사용자 권한 확인 없이 누구나 호출할 수 있습니다. Supabase secret key가 브라우저로 전달되지는 않지만, 서버 함수가 그 키로 RLS를 우회해 조회한 **메모 네 건은 API 응답으로 누구에게나 공개됩니다**. 이 단계는 공개 API를 서버 경유로 옮긴 것이며, 자료의 기밀성이나 접근 통제를 구현한 것이 아닙니다. 실제 비밀·개인 자료를 시드하거나 공개하지 마세요.

2단계 이후 빌드는 공개 `data.json`을 복사하지 않고 기존 `public/data.json`도 배포 결과에서 제거합니다. 따라서 배포의 `/data.json`에는 메모가 없으며, 화면은 `/api/notes`에서만 자료를 읽습니다. `public/aleph.json`은 이전처럼 Vercel 배포 식별 정보로 계속 생성됩니다. `aleph.config.json`의 단계는 `2`입니다. 시작 틀용 1단계 번들 명령은 이 작업에 필요하지 않습니다.

## 확인 방법

1. Supabase SQL Editor에서 시드 SQL을 실행하고 Table Editor에서 네 행을 확인합니다.
2. Vercel 환경변수에 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`를 설정한 뒤 새 배포를 만듭니다.
3. 배포된 `/`에서 네 카드가 보이는지, `/api/notes` 응답에 네 메모가 있는지, `/data.json`에 메모가 없는지 확인합니다. `/aleph.json`도 계속 제공되어야 합니다.
4. 정상: 화면/API에서 네 가상 메모가 보이고 `/data.json`은 404 또는 메모가 없는 응답입니다. 거부/실패: GET 이외의 API 요청은 405, 환경변수 누락 시 일반 오류만 반환하며 비밀값이나 Supabase 오류 상세는 응답·로그에 나오지 않아야 합니다.
5. 기존에 공개했던 네 메모 문장을 검증합니다. GitHub의 최신 파일과 배포된 최신 파일에서 각 메모 문장을 검색해 새 정적 파일이나 최신 배포 결과에 남아 있지 않은지 확인합니다. 이전 단계에서 이미 공개된 Git 커밋이나 과거 배포 기록에 메모가 남아 있을 수 있으므로, 이번 단계에서 최신 파일에서 제거되었다고 해서 과거 공개 기록까지 삭제되었다고 판단하지 않습니다.

로컬 정적 빌드 점검은 `npm run build -- --local`입니다. 이 로컬 빌드는 배포 식별 파일을 새로 만들지 않고, Vercel API 함수와 배포 응답 확인은 실제 Vercel 배포에서 해야 합니다. 이 환경에서는 Supabase SQL 실행, Vercel 환경변수 설정, 브라우저 및 배포 결과를 확인하지 않았습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 로그인, 허용 경로, 원본 API 주소, 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 해당 단계에서 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
