# jvm-risk-scanner

**A GitHub Action that reads a repository and tells you what will bite you before moving to JDK 27.** It looks where dependency scanners do not: JVM flags, agents, `sun.misc.Unsafe` and JFR usage that JDK 27 defaults (JEP 523 G1 everywhere, JEP 534 compact object headers) actually touch; end of support for JDK, Spring Boot, Spring Framework, Spring Security, Tomcat and Redis lines (endoflife.date at scan time); and recent high-severity CVEs. CVEs are judged in two steps: vulnerable version ranges come from OSV.dev at scan time, and a CVE whose *usage evidence* strings are absent from source, build and config is downgraded to INFO instead of shouting CRITICAL for a feature you never use. Suggested fix versions are checked against Maven Central before they are printed. Report text is in Korean.

```yaml
- uses: cloud911948/jvm-risk-scanner@v0
  with:
    deps-file: deps.txt   # optional: gradle dependencies / mvn dependency:tree output
    sarif: "true"         # optional: also write jvm-risk.sarif for code scanning
    fail-on: high         # optional: exit 1 at this severity or above (UNKNOWN also fails)
```

Runs on JDK 21+. The single runnable jar is attached to each [release](https://github.com/cloud911948/jvm-risk-scanner/releases). Full documentation below is in Korean.

---

JDK 27로 올리기 전에 저장소만 보고 걸리는 것을 PR 코멘트로 남기는 GitHub Action입니다.

Dependabot이나 Snyk는 의존성 버전을 봅니다. 이 도구는 그 옆의 빈자리를 봅니다. JVM 플래그, 에이전트, `sun.misc.Unsafe` 사용처처럼 JDK 27 기본값 변화(JEP 523 G1 기본화, JEP 534 압축 객체 헤더)에 실제로 영향을 받는 지점과, 런타임·프레임워크 라인의 지원 종료, 그리고 최근 고위험 CVE 중 이 저장소가 실제로 취약 경로를 쓰는지까지 한 번에 확인합니다.

```
### [CRITICAL] CVE-2026-59270 — spring-security (Boot BOM 관리) 7.0.6: 내장 UnboundID LDAP 서버가 … (CVSS 9.4)
- 조건: spring-security-ldap 의 내장(UnboundID) LDAP 서버 사용 시 — 사용 흔적: src/main/java/app/LdapCfg.java
### [HIGH] JDK27-COH-UNSAFE — sun.misc.Unsafe 직접 사용 — 압축 객체 헤더와 충돌 위험
### [MEDIUM] JDK27-GC-DEFAULT — JDK 27 부터 모든 환경에서 G1 이 기본 GC (JEP 523)
- GC 플래그 없음. 현재 JDK 21 → 27 이행 시 소형 컨테이너(1 CPU / <1792MB)에서 Serial→G1 로 바뀜.
```

## 사용

`.github/workflows/jvm-risk.yml`

```yaml
name: jvm-risk
on: [pull_request]
permissions: { contents: read, pull-requests: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cloud911948/jvm-risk-scanner@v0
```

`@v0` 은 0.x 최신 릴리스를 따라갑니다. 고정하려면 `@v0.1.0`. Action 은 릴리스에 첨부된 jar 를 내려받아 실행하고, 못 받으면 소스에서 빌드합니다(리포트 끝에 어느 쪽인지 남습니다).

로컬에서는 JDK 21 이상이면 됩니다.

```
# 릴리스 페이지의 jvm-risk-scanner.jar 를 받거나 ./gradlew -q fatJar
java -jar build/libs/jvm-risk-scanner.jar /path/to/repo                     # 마크다운 리포트
java -jar build/libs/jvm-risk-scanner.jar /path/to/repo --json              # 감지 사실 + 지적 사항
java -jar build/libs/jvm-risk-scanner.jar /path/to/repo --sarif             # GitHub code scanning 용
java -jar build/libs/jvm-risk-scanner.jar /path/to/repo --deps deps.txt     # 의존성 해석 출력으로 실제 버전·전이 의존성까지
java -jar build/libs/jvm-risk-scanner.jar /path/to/repo --suggest           # OSV 에만 있는 항목을 규칙 뼈대로 출력
java -jar build/libs/jvm-risk-scanner.jar /path/to/repo --rules my-rules.json
java -jar build/libs/jvm-risk-scanner.jar /path/to/repo --offline           # 네트워크 조회 없이 규칙 스냅샷만
```

### 빌드 파일만 볼 때와 해석 결과를 줄 때

빌드 파일에는 보통 Boot 버전만 적혀 있고 Security·Tomcat 은 BOM 이 정합니다. 그래서 기본 모드는 규칙 파일의 BOM 표로 추정합니다. `./gradlew dependencies --configuration runtimeClasspath > deps.txt` 또는 `mvn dependency:tree -DoutputFile=deps.txt` 로 뽑은 출력을 `--deps` 로 주면 추정이 아니라 실제 해석 버전을 쓰고, 전이 의존성 전체를 OSV 에 물어 `OSV-TRANSITIVE` 한 항목으로 냅니다. CI 에서는 [example/jvm-risk.yml](example/jvm-risk.yml) 처럼 트리를 먼저 뽑아 넘기면 됩니다.

### 검토 끝난 항목 숨기기

저장소 루트에 `.jvmrisk-ignore` 를 두면 다음 PR 부터 그 항목이 사라지고 리포트 끝에 억제 건수만 남습니다. 한 줄에 하나이고 **만료일과 사유가 없으면 무효**입니다. 한 번 검토하고 영구히 안 보는 목록이 되지 않도록, 만료되면 다시 리포트에 나옵니다.

```
CVE-2026-59270 until=2026-12-31           # 내장 LDAP 안 씀, 4.0.8 이행 때 재확인
EOL-PAST spring-boot until=2026-11-30     # 4분기 라인 이동 착수 예정
```

### 빌드를 깰지는 워크플로가 정합니다

기본 종료 코드는 0 이고 리포트만 남깁니다. `--fail-on high` 처럼 주면 그 심각도 이상이 하나라도 있을 때 1 로 끝납니다. Action 입력 `fail-on` 도 같고, Action 은 한 번의 실행에서 리포트·SARIF·판정을 같이 내므로 세 결과가 같은 조회를 봅니다.

### 판정 결과와 판정 불능은 다릅니다

OSV·endoflife.date·Maven Central 조회가 실패하면 그 사실을 `SCAN-UNKNOWN` 항목(심각도 `unknown`, HIGH 바로 아래)으로 리포트에 남깁니다. 네트워크 오류로 응답이 비었는데 "취약점 0건"으로 읽히는 것이 조용한 오류 중 최악이기 때문입니다. `--fail-on` 은 어떤 기준이든 UNKNOWN 을 실패로 봅니다.

다만 OSV 의 일시 장애가 모든 PR 을 깨지 않도록 마지막 성공 조회를 `~/.cache/jvm-risk-scanner/osv-last.json` 에 보관합니다. 조회가 실패하면 7일 이내의 캐시로 판정하고 리포트 머리에 "N일 전 캐시 기준"이라고 적으며, 그보다 오래됐을 때만 UNKNOWN 입니다. CI 에서는 [example/jvm-risk.yml](example/jvm-risk.yml) 처럼 `actions/cache` 로 그 디렉터리를 유지하십시오. 스냅샷만으로 보려면 `--offline` 입니다. PR 이 없는 휴면 저장소는 스캐너가 돌지 않습니다. 그 저장소 자신에 `schedule:` 을 걸어도 GitHub 은 공개 저장소에서 60일 무활동이면 스케줄을 자동으로 끄므로, [example/jvm-risk.yml](example/jvm-risk.yml) 의 `dormant` 잡처럼 활동 있는 저장소의 크론에서 체크아웃해 같이 스캔하십시오.

## 무엇을 보나

| 영역 | 판정 | 근거 |
|---|---|---|
| JDK 27 기본값 | GC 플래그가 없으면 소형 컨테이너에서 Serial→G1 전환을 경고. 압축 객체 헤더 기본화에 대해 `Unsafe`·JOL·lincheck·`-javaagent` 를 충돌 후보로 표시. JFR 사용 시 자동 마스킹 안내 | [JEP 523](https://openjdk.org/jeps/523), [JEP 534](https://openjdk.org/jeps/534) |
| EOL | JDK·Spring Boot·Spring Framework·Spring Security·Redis·Tomcat 라인의 지원 종료가 지났거나 120일 이내 | Spring·Tomcat·Redis 는 스캔 시점에 endoflife.date 를 조회해 규칙 표를 덮습니다. JDK 는 배포판별로 날짜가 달라 규칙 표를 유지하고 `note` 에 차이를 적었습니다 |
| CVE | Spring Security 2026-08-20 권고(CVSS 9.4 내장 LDAP, DPoP, WebAuthn, XSS), Spring for GraphQL RCE(9.2), Redis TLS UAF | 규칙마다 출처 URL |

### 버전만 보고 CRITICAL 을 찍지 않습니다

취약 버전 범위에 있어도 소스·빌드·설정 어디에도 그 기능을 쓰는 흔적(예: 내장 LDAP 이면 `UnboundIdContainer`, `spring-security-ldap`)이 없으면 심각도를 INFO 로 내리고 "취약 버전이나 사용 흔적 없음"으로 적습니다. 흔적이 있으면 원래 심각도에 발견 파일을 붙입니다. 세 저장소에서 실측했을 때 버전만으로는 셋 다 CRITICAL 이었고 실제로는 셋 다 해당 기능을 쓰지 않았습니다. 그 결과를 그대로 내보내면 운영자가 도구를 믿지 않게 됩니다.

### Boot 버전만 있는 프로젝트

`spring-boot-dependencies` POM 에서 뽑은 관리 버전 표(`rules.json` 의 `boot_bom`)로 Security·Framework·GraphQL 버전을 채웁니다. 표에 없는 패치 버전은 같은 minor 의 가장 가까운 아래 패치로 채우고 `DEP-ESTIMATED` 로 따로 표시합니다. 멀티모듈에서 Boot 버전이 섞여 있으면 가장 오래된 버전을 기준으로 대조하고 `BOOT-MIXED` 로 알립니다.

### 취약 버전 범위는 OSV 에서, 사용 조건은 규칙 파일에서

스캔할 때마다 감지한 의존성으로 [OSV.dev](https://osv.dev) 를 조회합니다. Spring Security 처럼 모듈별로 CVE 가 등재되는 제품은 core·web·config·ldap·oauth2 를 함께 묻고, `--deps` 가 있으면 해석된 아티팩트 중 제품 그룹(`org.springframework` 등)에 속한 것은 그 제품 라인으로 보내고, 나머지만 전이 의존성으로 한 번의 배치 조회로 묻습니다. 이름 목록으로 걸면 spring-expression 같은 것이 전이 쪽으로 새어 이중 계상됩니다. 그래서 규칙 파일을 갱신하지 않아도 새 CVE 의 버전 범위와 수정 버전은 최신입니다. 네트워크가 막히면 규칙 파일의 스냅샷만 쓰고 리포트 머리에 그 사실을 적습니다. `--offline` 으로 조회를 끌 수 있습니다.

OSV 에는 있지만 규칙 파일에 사용 흔적 정의가 없는 CVE 는 **제품당 한 줄로 묶어 MEDIUM** 으로 냅니다. Boot 2.7 라인의 Tomcat 9.0.65 는 OSV 등재 취약점이 40건인데, 낱개로 찍으면 리포트가 읽히지 않고 답은 어차피 라인 업그레이드 하나이기 때문입니다. 낱개 판정이 필요한 건은 규칙 파일에 흔적을 정의하면 위의 흔적 판정 경로로 올라옵니다.

권고하는 수정 버전은 찍기 전에 Maven Central 메타데이터로 존재를 확인합니다. 규칙 파일에 프로젝트 권고문 기준 수정 버전이 있으면 그것을 쓰고, OSV 값만 있는데 Central 에 없으면 같은 라인의 다음 버전을 "추정"으로 적습니다. 예: `10.1.59 (추정: OSV 는 10.1.58 표기, Central 미존재 → 같은 라인 다음 버전)`. 번호가 건너뛴 릴리스와 OSV 의 수정 버전 자체가 틀린 경우를 도구가 구분하지 못하므로 추정 표시를 뗄 수 없습니다. 존재하지 않는 버전을 올리라고 하는 리포트는 신뢰를 한 번에 깎기 때문입니다.

흔적이 없어 INFO 로 내릴 때는 무엇을 찾았는지도 같이 적습니다. 리플렉션이나 프로퍼티로 켜지는 기능은 문자열 흔적 없이 활성화될 수 있어서, 이 판정의 오류는 조용한 미탐 쪽으로 납니다. 찾은 문자열 목록을 보면 검토자가 흔적 정의의 빈틈을 알 수 있습니다.

OSV 가 다 아는 것은 아닙니다. Spring 이 2026-08-20 에 공개한 Security·GraphQL 권고는 9월 중순까지 OSV 에 등재되지 않았고, Tomcat 10.1 의 수정 버전을 OSV 는 10.1.58 로 적고 있지만 Maven Central 에 그 버전은 없습니다(10.1.59 가 실제). 그래서 규칙 파일 스냅샷과 합집합으로 봅니다.

## 규칙은 데이터

판정 기준은 [`rules.json`](rules.json) 에 있고 코드는 대조만 합니다. CVE 항목은 권고문 URL(`source`), 발동 조건(`condition`), 사용 흔적(`evidence`)이 비어 있으면 로딩 시점에 거부됩니다. 흔적 정의는 이 도구에서 유일하게 사람의 판단이 들어가는 곳이라, 다른 사람이 근거를 보고 검증·수정할 수 있어야 합니다. 규칙 파일이 담는 것은 세 가지입니다. JDK 27 기본값 변화(순수 수동), EOL 표, 그리고 CVE 마다 "이 기능을 실제로 쓰는가"를 가리는 사용 흔적 문자열입니다. 버전 범위는 OSV 가 대신하므로 규칙 파일은 판단이 들어간 부분만 얇게 유지합니다. `--rules` 로 자체 규칙 파일을 바꿔 끼울 수 있습니다. PR 은 출처 URL 을 붙여 주십시오.

## 한계

- 빌드 파일을 정규식으로 읽습니다. Gradle·Maven 파서를 쓰지 않는 것은 의도입니다. DSL 변형마다 파서가 깨지는 것보다 못 찾으면 "미확인"으로 남기는 쪽이 운영에서 덜 위험했습니다.
- JEP 534 는 깨지는 도구 목록을 제공하지 않습니다. `Unsafe`·JOL·lincheck·javaagent 항목은 "확인 필요" 신호이지 확정 판정이 아닙니다.
- `--deps` 없이 돌리면 전이 의존성은 보지 않습니다. 빌드 파일에 이름이 나오는 것만 봅니다.
- 취약점 데이터 소스가 사실상 OSV 하나입니다. GHSA 는 OSV 의 주 공급원이라 두 번째 소스가 되지 못하고, 독립성이 있는 건 벤더 권고문(Spring·Tomcat 보안 페이지·NVD)입니다. 규칙 파일이 그 역할을 손으로 하고 있고, 구조적 수집은 다음 버전 항목입니다.
- 빌드 파일 정규식은 부류의 문제입니다. `ext['tomcat.version']` 을 고쳐도 Kotlin DSL 의 `extra[...]`, 버전 카탈로그, `resolutionStrategy.force` 같은 변형이 남습니다. 방향은 정규식을 늘리는 게 아니라 SBOM(CycloneDX) 입력으로 옮기는 것이고, 다음 버전 항목입니다.
- 멀티모듈에서 "저장소당 대표 버전" 은 배포되지 않는 모듈의 낡은 버전이 리포트를 오염시킬 수 있습니다. 판정 단위를 배포 아티팩트의 classpath 로 바꾸는 것도 다음 버전 항목입니다.
- 사용 흔적 검색은 문자열 매칭입니다. 서드파티 라이브러리가 같은 이름을 쓰면 오탐이 납니다. WebAuthn 규칙이 Yubico 구현을 잡았던 사례가 있어 Spring Security 전용 심볼로 좁혔습니다.
- Windows 의 WSL 마운트(`/mnt/c`)에서는 파일 I/O 가 느립니다. 자바 파일 1,700개짜리 저장소가 35초 걸렸습니다. CI 러너에서는 문제가 되지 않습니다.

## 개발

```
./gradlew test                          # fixture/ fixture2/ fixture3/ 회귀 + 골든 파일 대조
./gradlew test -Dgolden.update=true     # 판정 변경이 의도한 것이면 골든 파일 갱신 후 diff 를 커밋에 포함
./gradlew fatJar                        # build/libs/jvm-risk-scanner.jar
```

픽스처별 오프라인 리포트 전체를 `src/test/resources/golden/` 에 고정합니다. 온라인 경로는 녹화해 둔 OSV 응답(`src/test/resources/osv/`)을 스텁으로 넣어 따로 고정합니다. 골든 파일이 실시간 OSV 를 보면 새 CVE 등재마다 코드 변경 없이 깨져 신호 가치가 죽습니다. 정규식이나 흔적 정의를 고쳤을 때 다른 판정이 움직이면 diff 로 드러납니다. 낱개 픽스처를 흔적 정의마다 늘리는 것보다 유지비가 쌉니다.

구조는 `Collector`(사실 수집, `DepTree` 가 해석 출력 파싱) → `Osv`·`Eol`·`Central`(온라인 조회) → `Evaluator`(규칙·OSV 대조) → `Ignore`(억제) → `Report`(마크다운·JSON·SARIF)이고, `Rules` 가 JSON 을 타입으로 읽습니다. 수집기는 판단하지 않고 평가기는 파일도 네트워크도 만지지 않습니다.

## 라이선스

MIT
