// 자원(resource) 구분표입니다. 판정기(src/decider.mjs)와 자료 API가 같은 이름으로 자원을 구별하도록 한곳에 둡니다.
// 요청의 service, method, path, route만 읽습니다. 사용자·역할·기기 값은 읽지 않습니다.
//
// 공식 계약(docs/DECIDER_REQUEST.md)과 연습 요청(scripts/fixture-7.mjs)이 확인해 주는 값은
//   service 'notes', route 'GET /notes/:id' 하나뿐입니다.
// 'notices'(반 공지)는 XDR 연습 사건 파일의 /api/notices 에서 따온 가정이며, 공식 값이 아닙니다.
// 이 표에 없는 서비스와 경로(강사 자료 포함)는 자원으로 인식하지 않습니다.

export const RESOURCE_KINDS = Object.freeze({
  NOTE: 'note',
  CLASS_NOTICE: 'class_notice',
});

export const RESOURCES = Object.freeze([
  { resourceId: 'note.item', kind: RESOURCE_KINDS.NOTE, service: 'notes', pattern: '/notes/:id' },
  { resourceId: 'note.collection', kind: RESOURCE_KINDS.NOTE, service: 'notes', pattern: '/notes' },
  { resourceId: 'notice.item', kind: RESOURCE_KINDS.CLASS_NOTICE, service: 'notices', pattern: '/notices/:id' },
  { resourceId: 'notice.collection', kind: RESOURCE_KINDS.CLASS_NOTICE, service: 'notices', pattern: '/notices' },
].map(Object.freeze));

const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
// 자료 ID 자리는 형식을 좁히지 않습니다(UUID가 아닐 수 있음). 다만 한 칸짜리 안전한 문자열이어야 합니다.
const ID_SEGMENT = /^[^/?#\\\s]+$/u;
const RESERVED_FEATURE_SEGMENTS = new Set(['export']);

// 공개 주소의 /api 접두어는 있어도 없어도 같은 경로로 봅니다.
function stripApiPrefix(path) {
  return path.startsWith('/api/') ? path.slice(4) : path;
}

function matchesPattern(path, pattern) {
  const have = path.split('/');
  const want = pattern.split('/');
  if (have.length !== want.length) return false;
  return want.every((part, index) => (part === ':id'
    ? ID_SEGMENT.test(have[index]) && have[index] !== '.' && have[index] !== '..'
        && !RESERVED_FEATURE_SEGMENTS.has(have[index])
      : have[index] === part));
}

// 요청 하나가 어느 자원인지 돌려줍니다. 알 수 없으면 null이며, 호출한 쪽은 null을 거부로 처리합니다.
// route(경로 모양)와 path(실제 경로)가 서로 다른 자원을 가리키면 위조로 보고 null입니다.
export function resourceOf(request) {
  try {
    const { service, method, path, route } = request;
    if (typeof service !== 'string' || typeof method !== 'string' || !METHODS.has(method)
        || typeof path !== 'string' || typeof route !== 'string') return null;
    const [routeMethod, routePath, ...rest] = route.split(' ');
    if (rest.length || routeMethod !== method || typeof routePath !== 'string') return null;
    const shape = stripApiPrefix(routePath);
    const entry = RESOURCES.find(item => item.service === service && item.pattern === shape);
    if (!entry || !matchesPattern(stripApiPrefix(path), entry.pattern)) return null;
    return Object.freeze({ resourceId: entry.resourceId, kind: entry.kind, method });
  } catch {
    return null;
  }
}

/**
 * 자원별 경로 접근 정책입니다.
 * 자원 식별 실패, 목록 접근, 허용하지 않는 메서드는 거부합니다.
 * 실제 판정 응답과 reasonCode는 decider.mjs에서 처리합니다.
 */
export function resourceAccessAllowed(request) {
  const resource = resourceOf(request);
  if (!resource) return false;

  if (resource.kind === RESOURCE_KINDS.NOTE) {
    return resource.resourceId === 'note.item'
      && ['GET', 'PUT', 'DELETE'].includes(resource.method);
  }

  if (resource.kind === RESOURCE_KINDS.CLASS_NOTICE) {
    return resource.method === 'GET';
  }

  return false;
}