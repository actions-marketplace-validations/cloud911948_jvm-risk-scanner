# JVM 런타임 리스크 리포트

- 감지 JDK: 21 · 의존성: {spring-security=7.0.6, spring-graphql=2.0.4, jol=?, spring-boot=4.0.8, spring-framework=7.0.9, tomcat=11.0.24, netty=4.2.17.Final} · 이미지: [redis:8.2.7] · 플래그: 1개
- 규칙 버전 2026-09-17.v7 · OSV 미조회(--offline) · EOL 표 rules.json

### [CRITICAL] CVE-2026-59270 — spring-security 7.0.6: 내장 UnboundID LDAP 서버가 잘 알려진 관리자 DN 을 무조건 등록하고 모든 인터페이스에 바인드 (CVSS 9.4)
- 조건: spring-security-ldap 의 내장(UnboundID) LDAP 서버 사용 시 — 사용 흔적: src/main/java/app/LdapCfg.java
- 조치: 수정 버전 7.0.7, 7.1.1 — https://www.herodevs.com/blog-posts/cve-2026-59270-spring-security-embedded-ldap-admin-dn-exposure

### [CRITICAL] CVE-2026-59285 — spring-graphql 2.0.4: Spring for GraphQL 안전하지 않은 역직렬화 → RCE (Jackson 2.x + 페이지네이션 필드) (CVSS 9.2)
- 조건: Jackson 2.x 로 역직렬화하고 페이지네이션 GraphQL 필드 노출 시 — 사용 흔적: build.gradle.kts, src/main/java/app/Gql.java
- 조치: 수정 버전 2.0.5 — https://securityonline.info/spring-graphql-vulnerabilities/

### [CRITICAL] CVE-2026-65182 — tomcat (Boot BOM 관리) 11.0.24: Tomcat 보안 제약(security-constraint) 우회 — web.xml 에서 긴 경로 제약이 짧은 하위 경로의 더 엄격한 제약보다 먼저 선언될 때 미인증 접근 (CVSS 9.1)
- 조건: web.xml 에 <security-constraint> 를 직접 선언한 경우. Spring Security 만 쓰면 미발동 — 사용 흔적: src/main/webapp/WEB-INF/web.xml
- 조치: 수정 버전 11.0.25, 10.1.59, 9.0.121 — https://tomcat.apache.org/security-11.html

### [HIGH] JDK27-COH-UNSAFE — sun.misc.Unsafe / jdk.internal.misc.Unsafe 직접 사용 — 압축 객체 헤더와 충돌 위험
- Unsafe 사용 파일: src/main/java/app/Fast.java
- 조치: Unsafe 사용처를 VarHandle/MemorySegment 로 이전하거나, 해당 라이브러리의 JDK 25+ 호환 버전 확인.

### [HIGH] CVE-2026-41707 — spring-security 7.0.6: DPoPProofJwtDecoderFactory DPoP proof 재사용(캐시 축출로 리플레이) (CVSS -)
- 조건: OAuth2 리소스 서버에서 DPoP 사용 시 — 사용 흔적: src/main/java/app/LdapCfg.java
- 조치: 수정 버전 7.0.7, 7.1.1 — https://spring.io/security/cve-2026-41707

### [HIGH] CVE-2026-47841 — spring-security 7.0.6: WebAuthn userVerification=REQUIRED 가 분산 세션 역직렬화 후 우회됨 (CVSS -)
- 조건: WebAuthn + 분산 세션 저장소(Redis/JDBC/Hazelcast) — 사용 흔적: src/main/java/app/LdapCfg.java
- 조치: 수정 버전 7.0.7, 7.1.1 — https://spring.io/security/cve-2026-47841

### [HIGH] CVE-2026-47877 — spring-security 7.0.6: Authorization Server 기본 동의 페이지 XSS (CVSS -)
- 조건: Authorization Server 기본 동의 페이지 사용 시(커스텀 페이지는 무관) — 사용 흔적: src/main/java/app/Gql.java
- 조치: 수정 버전 7.0.7, 7.1.1 — https://spring.io/security/cve-2026-47877

### [HIGH] CVE-2026-81934 — redis 8.2.7: TLS pending-data 처리 use-after-free → 인증된 공격자 RCE (초기 NVD 9.8, Redis 재평가 7.5) (CVSS 7.5)
- 조건: Redis 서버가 TLS 활성화 시 — 사용 흔적: docker-compose.yml
- 조치: 수정 버전 8.2.9, 8.4.6, 8.6.6, 8.8.2, 8.10.1 — https://redis.io/blog/security-advisory-cve-2026-81934/

### [MEDIUM] JDK27-GC-DEFAULT — JDK 27 부터 모든 환경에서 G1 이 기본 GC (JEP 523)
- GC 플래그 없음. 현재 JDK 21 → 27 이행 시 소형 컨테이너(1 CPU / <1792MB)에서 Serial→G1 로 바뀜.
- 조치: 스테이징에서 GC 로그(-Xlog:gc*) 비교. 소형 컨테이너에서 Serial 이 더 낫다면 -XX:+UseSerialGC 를 명시.

### [MEDIUM] JDK27-COH-DEFAULT — JDK 27 부터 압축 객체 헤더가 기본 (JEP 534) — 힙 10~22% 감소, 객체 레이아웃 변경
- 옵트아웃 플래그 없음(정상 — 기본값을 받아들이되 아래 충돌 항목 확인).
- 조치: 아래 JDK27-COH-* 규칙에 걸리는 항목이 있으면 스테이징에서 먼저 검증. 문제 시 -XX:-UseCompactObjectHeaders 로 이전 레이아웃 유지(비권장, 임시).

### [MEDIUM] JDK27-COH-LAYOUT-TOOLS — 객체 레이아웃 의존 도구 감지 (JOL, lincheck)
- 감지: jol
- 조치: 도구 최신 버전이 압축 헤더를 지원하는지 확인. 테스트 전용이면 -XX:-UseCompactObjectHeaders 로 테스트 JVM 만 분리.

### [MEDIUM] JDK27-COH-AGENT — -javaagent / -agentpath 사용 — 네이티브·JVMTI 에이전트의 압축 헤더 호환 확인
- 에이전트: -javaagent:/opt/apm/agent.jar",
- 조치: 에이전트 벤더의 'JDK 25/26/27 compact object headers' 지원 문서 확인. 미확인이면 스테이징에서 에이전트 켠 채로 부하 테스트.

### [MEDIUM] EOL-SOON — spring-boot 4.0.8 — 119일 후 지원 종료 (2026-12-31)
- 조치: 업그레이드 계획 수립

### [LOW] JDK27-JFR-REDACT — JFR 민감정보 자동 마스킹 (JEP 536, JDK 27)
- JFR 사용 흔적 있음
- 조치: JFR 파서·대시보드가 마스킹된 필드에 의존하는지 확인.

