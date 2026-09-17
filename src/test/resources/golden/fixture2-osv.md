# JVM 런타임 리스크 리포트

- 감지 JDK: 25 · 의존성: {spring-boot=4.0.7, spring-security=7.0.6, spring-framework=7.0.8, spring-graphql=2.0.4, tomcat=11.0.22, netty=4.2.15.Final} · 이미지: 없음 · 플래그: 0개
- 규칙 버전 2026-09-17.v7 · OSV 미조회(--offline) · EOL 표 rules.json

### [MEDIUM] JDK27-GC-DEFAULT — JDK 27 부터 모든 환경에서 G1 이 기본 GC (JEP 523)
- GC 플래그 없음. 현재 JDK 25 → 27 이행 시 소형 컨테이너(1 CPU / <1792MB)에서 Serial→G1 로 바뀜.
- 조치: 스테이징에서 GC 로그(-Xlog:gc*) 비교. 소형 컨테이너에서 Serial 이 더 낫다면 -XX:+UseSerialGC 를 명시.

### [MEDIUM] JDK27-COH-DEFAULT — JDK 27 부터 압축 객체 헤더가 기본 (JEP 534) — 힙 10~22% 감소, 객체 레이아웃 변경
- 옵트아웃 플래그 없음(정상 — 기본값을 받아들이되 아래 충돌 항목 확인).
- 조치: 아래 JDK27-COH-* 규칙에 걸리는 항목이 있으면 스테이징에서 먼저 검증. 문제 시 -XX:-UseCompactObjectHeaders 로 이전 레이아웃 유지(비권장, 임시).

### [MEDIUM] EOL-SOON — spring-boot 4.0.7 — 119일 후 지원 종료 (2026-12-31)
- 조치: 업그레이드 계획 수립

### [MEDIUM] OSV-NETTY — netty (Boot BOM 관리) 4.2.15.Final: OSV 등재 취약점 1건 (MEDIUM 1) — 흔적 규칙 미정의
- 버전만으로 판정(사용 조건 미확인): CVE-2026-75596(M)
- 조치: 같은 라인 최신 4.2.17.Final 이상으로 올리면 일괄 해소. 낱개 확인은 https://osv.dev/list?ecosystem=Maven&q=io.netty:netty-handler

### [INFO] CVE-2026-59270 — spring-security (Boot BOM 관리) 7.0.6: 취약 버전이나 사용 흔적 없음 — 내장 UnboundID LDAP 서버가 잘 알려진 관리자 DN 을 무조건 등록하고 모든 인터페이스에 바인드
- 조건: spring-security-ldap 의 내장(UnboundID) LDAP 서버 사용 시 — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: UnboundIdContainer | spring-security-ldap | unboundid | ldap\.embedded | LdapServer
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 7.0.7, 7.1.1

### [INFO] CVE-2026-41707 — spring-security (Boot BOM 관리) 7.0.6: 취약 버전이나 사용 흔적 없음 — DPoPProofJwtDecoderFactory DPoP proof 재사용(캐시 축출로 리플레이)
- 조건: OAuth2 리소스 서버에서 DPoP 사용 시 — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: DPoPProofJwtDecoderFactory | \.dpop\( | DPoP
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 7.0.7, 7.1.1

### [INFO] CVE-2026-47841 — spring-security (Boot BOM 관리) 7.0.6: 취약 버전이나 사용 흔적 없음 — WebAuthn userVerification=REQUIRED 가 분산 세션 역직렬화 후 우회됨
- 조건: WebAuthn + 분산 세션 저장소(Redis/JDBC/Hazelcast) — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: springframework\.security\.web\.webauthn | \.webAuthn\( | WebAuthnConfigurer | spring-security-webauthn
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 7.0.7, 7.1.1

### [INFO] CVE-2026-47877 — spring-security (Boot BOM 관리) 7.0.6: 취약 버전이나 사용 흔적 없음 — Authorization Server 기본 동의 페이지 XSS
- 조건: Authorization Server 기본 동의 페이지 사용 시(커스텀 페이지는 무관) — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: spring-security-oauth2-authorization-server | OAuth2AuthorizationServerConfigurer | authorization-server
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 7.0.7, 7.1.1

### [INFO] CVE-2026-59285 — spring-graphql (Boot BOM 관리) 2.0.4: 취약 버전이나 사용 흔적 없음 — Spring for GraphQL 안전하지 않은 역직렬화 → RCE (Jackson 2.x + 페이지네이션 필드)
- 조건: Jackson 2.x 로 역직렬화하고 페이지네이션 GraphQL 필드 노출 시 — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: spring-graphql | spring-boot-starter-graphql | @SchemaMapping | ScrollSubrange | Window<
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 2.0.5

### [INFO] CVE-2026-75595 — netty (Boot BOM 관리) 4.2.15.Final: 취약 버전이나 사용 흔적 없음 — Netty SslClientHelloHandler 가 단편화된 ClientHello 의 SNI 를 잘못 읽어 SNI 별 mTLS(clientAuth=REQUIRE) 우회
- 조건: Netty 기반 게이트웨이(Spring Cloud Gateway·Reactor Netty·gRPC)에서 SNI 별 SslContext 로 mTLS 를 나눠 강제하고, 기본/폴백 SslContext 가 clientAuth=NONE/OPTIONAL 일 때 — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: SniHandler | SslClientHelloHandler | ClientAuth\.REQUIRE | clientAuth\s*[=(]\s*["']?REQUIRE
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 4.2.17.Final, 4.1.137.Final

### [INFO] CVE-2026-65182 — tomcat (Boot BOM 관리) 11.0.22: 취약 버전이나 사용 흔적 없음 — Tomcat 보안 제약(security-constraint) 우회 — web.xml 에서 긴 경로 제약이 짧은 하위 경로의 더 엄격한 제약보다 먼저 선언될 때 미인증 접근
- 조건: web.xml 에 <security-constraint> 를 직접 선언한 경우. Spring Security 만 쓰면 미발동 — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정). 찾은 흔적 문자열: <security-constraint> | <auth-constraint>
- 조치: 버전 자체는 취약 범위. 업그레이드 시 함께 해소: 11.0.25, 10.1.59, 9.0.121

