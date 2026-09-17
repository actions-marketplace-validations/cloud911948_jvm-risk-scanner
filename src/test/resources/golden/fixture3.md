# JVM 런타임 리스크 리포트

- 감지 JDK: 17 · 의존성: {spring-boot=3.5.13, spring-security=6.5.9, spring-framework=6.2.17, spring-graphql=1.4.5, tomcat=10.1.52} · 이미지: 없음 · 플래그: 0개
- 규칙 버전 2026-09-17.v7 · OSV 미조회(--offline) · EOL 표 rules.json

### [HIGH] EOL-PAST — spring-boot 3.5.13 — 지원 종료됨 (2026-06-30)
- 조치: 지원 중인 라인으로 업그레이드 (최신 3.5.16)

### [HIGH] EOL-PAST — spring-framework (BOM) 6.2.17 — 지원 종료됨 (2026-06-30)
- 조치: 지원 중인 라인으로 업그레이드 (최신 6.2.19)

### [HIGH] EOL-PAST — spring-security (BOM) 6.5.9 — 지원 종료됨 (2026-06-30)
- Boot 3.5 관리 라인. 2026-08-20 CVE OSS 수정 없음
- 조치: 지원 중인 라인으로 업그레이드 (최신 6.5.11)

### [MEDIUM] JDK27-GC-DEFAULT — JDK 27 부터 모든 환경에서 G1 이 기본 GC (JEP 523)
- GC 플래그 없음. 현재 JDK 17 → 27 이행 시 소형 컨테이너(1 CPU / <1792MB)에서 Serial→G1 로 바뀜.
- 조치: 스테이징에서 GC 로그(-Xlog:gc*) 비교. 소형 컨테이너에서 Serial 이 더 낫다면 -XX:+UseSerialGC 를 명시.

### [MEDIUM] JDK27-COH-DEFAULT — JDK 27 부터 압축 객체 헤더가 기본 (JEP 534) — 힙 10~22% 감소, 객체 레이아웃 변경
- 옵트아웃 플래그 없음(정상 — 기본값을 받아들이되 아래 충돌 항목 확인).
- 조치: 아래 JDK27-COH-* 규칙에 걸리는 항목이 있으면 스테이징에서 먼저 검증. 문제 시 -XX:-UseCompactObjectHeaders 로 이전 레이아웃 유지(비권장, 임시).

### [MEDIUM] EOL-SOON — JDK 17 — 27일 후 지원 종료 (2026-09-30)
- Oracle Premier 종료 기준(Extended 는 2029-09). 배포판별 상이 — Temurin 17 은 2027-10 예정
- 조치: 업그레이드 계획 수립

### [INFO] CVE-2026-59270 — spring-security (Boot BOM 추정) 6.5.9: 취약 버전이나 사용 흔적 없음 — 내장 UnboundID LDAP 서버가 잘 알려진 관리자 DN 을 무조건 등록하고 모든 인터페이스에 바인드
- 조건: spring-security-ldap 의 내장(UnboundID) LDAP 서버 사용 시 — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: UnboundIdContainer | spring-security-ldap | unboundid | ldap\.embedded | LdapServer
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 7.0.7, 7.1.1

### [INFO] CVE-2026-41707 — spring-security (Boot BOM 추정) 6.5.9: 취약 버전이나 사용 흔적 없음 — DPoPProofJwtDecoderFactory DPoP proof 재사용(캐시 축출로 리플레이)
- 조건: OAuth2 리소스 서버에서 DPoP 사용 시 — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: DPoPProofJwtDecoderFactory | \.dpop\( | DPoP
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 7.0.7, 7.1.1

### [INFO] CVE-2026-47841 — spring-security (Boot BOM 추정) 6.5.9: 취약 버전이나 사용 흔적 없음 — WebAuthn userVerification=REQUIRED 가 분산 세션 역직렬화 후 우회됨
- 조건: WebAuthn + 분산 세션 저장소(Redis/JDBC/Hazelcast) — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: springframework\.security\.web\.webauthn | \.webAuthn\( | WebAuthnConfigurer | spring-security-webauthn
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 7.0.7, 7.1.1

### [INFO] CVE-2026-65182 — tomcat (Boot BOM 추정) 10.1.52: 취약 버전이나 사용 흔적 없음 — Tomcat 보안 제약(security-constraint) 우회 — web.xml 에서 긴 경로 제약이 짧은 하위 경로의 더 엄격한 제약보다 먼저 선언될 때 미인증 접근
- 조건: web.xml 에 <security-constraint> 를 직접 선언한 경우. Spring Security 만 쓰면 미발동 — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: <security-constraint> | <auth-constraint>
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 11.0.25, 10.1.59, 9.0.121

### [INFO] DEP-ESTIMATED — 일부 버전은 Boot BOM 표의 인접 패치로 추정
- spring-security=6.5.9, spring-framework=6.2.17, spring-graphql=1.4.5, tomcat=10.1.52
- 조치: 정확한 값은 ./gradlew dependencies 또는 mvn dependency:tree

