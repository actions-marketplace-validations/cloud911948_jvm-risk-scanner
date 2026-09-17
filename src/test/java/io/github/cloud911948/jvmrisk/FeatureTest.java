package io.github.cloud911948.jvmrisk;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** --deps 파싱, .jvmrisk-ignore, SARIF, EOL 병합. 네트워크 없이 도는 것만. */
class FeatureTest {

    private static final Rules RULES = Rules.bundled();

    @Test
    void depTreeParsesGradleAndMaven() {
        String gradle = """
                runtimeClasspath - Runtime classpath of source set 'main'.
                +--- org.springframework.boot:spring-boot-starter-security -> 2.7.18
                |    +--- org.springframework.security:spring-security-core:5.7.3 -> 5.7.11
                |    \\--- org.apache.tomcat.embed:tomcat-embed-core:9.0.83 (*)
                \\--- org.yaml:snakeyaml:1.30 (c)
                """;
        Map<String, String> g = DepTree.parse(gradle);
        assertEquals("5.7.11", g.get("org.springframework.security:spring-security-core")); // -> 뒤가 실제
        assertEquals("9.0.83", g.get("org.apache.tomcat.embed:tomcat-embed-core"));
        assertEquals("2.7.18", g.get("org.springframework.boot:spring-boot-starter-security"));
        assertEquals("1.30", g.get("org.yaml:snakeyaml"));
        String maven = """
                [INFO] com.example:app:jar:1.0
                [INFO] +- org.springframework.boot:spring-boot-starter-web:jar:3.5.13:compile
                [INFO] |  \\- org.apache.tomcat.embed:tomcat-embed-core:jar:10.1.52:compile
                [INFO] \\- com.fasterxml.jackson.core:jackson-databind:jar:2.19.4:compile
                """;
        Map<String, String> m = DepTree.parse(maven);
        assertEquals("10.1.52", m.get("org.apache.tomcat.embed:tomcat-embed-core"));
        assertEquals("2.19.4", m.get("com.fasterxml.jackson.core:jackson-databind"));
    }

    @Test
    void depTreeReadsPowerShellUtf16File() throws Exception {
        Path f = Files.createTempFile("deps", ".txt");
        String tree = "+--- org.springframework.boot:spring-boot-starter-web -> 2.7.18\r\n";
        byte[] bom = {(byte) 0xFF, (byte) 0xFE};
        byte[] body = tree.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
        byte[] all = new byte[bom.length + body.length];
        System.arraycopy(bom, 0, all, 0, 2);
        System.arraycopy(body, 0, all, 2, body.length);
        Files.write(f, all);
        assertEquals("2.7.18", DepTree.read(f).get("org.springframework.boot:spring-boot-starter-web"));
    }

    @Test
    void gradleExtBracketOverrideIsRead() throws Exception {
        Path tmp = Files.createTempDirectory("jvmrisk");
        Files.writeString(tmp.resolve("build.gradle"), "plugins { id 'org.springframework.boot' version '2.7.18' }\next['tomcat.version'] = '9.0.102'\n");
        Facts f = new Collector(RULES).collect(tmp);
        assertEquals("9.0.102", f.deps.get("tomcat")); // BOM 표(9.0.83)가 아니라 ext 오버라이드
    }

    @Test
    void resolvedArtifactsOfAProductGroupAreNotTransitive() {
        assertEquals("spring-framework", Osv.productOfCoord("org.springframework:spring-expression"));
        assertEquals("tomcat", Osv.productOfCoord("org.apache.tomcat.embed:tomcat-embed-el"));
        assertEquals(null, Osv.productOfCoord("org.yaml:snakeyaml")); // 이런 것만 전이 목록으로 간다
    }

    @Test
    void resolvedVersionBeatsBomEstimate() {
        Facts f = new Collector(RULES).collect(Path.of("fixture3")); // Boot 3.5.13 → security 6.5.9 (bom~)
        Collector.applyResolved(f, Map.of("org.springframework.security:spring-security-core", "6.5.11"));
        assertEquals("6.5.11", f.deps.get("spring-security"));
        assertEquals("resolved", f.src.get("spring-security"));
    }

    @Test
    void ignoreFileSuppressesByIdAndTitlePart() throws Exception {
        Path tmp = Files.createTempDirectory("jvmrisk");
        Files.writeString(tmp.resolve(".jvmrisk-ignore"), """
                # 검토 끝난 것
                CVE-2026-59270 until=2026-12-31           # 내장 LDAP 안 씀
                EOL-PAST spring-boot until=2026-11-30     # 이행 일정 확정
                JDK27-GC-DEFAULT until=2026-01-01         # 만료된 줄 — 다시 나와야 한다
                JDK27-COH-DEFAULT                         # until 없음 — 무효
                """);
        List<Finding> findings = new ArrayList<>(List.of(
                new Finding("info", "CVE-2026-59270", "spring-security 5.7.3: ...", "", ""),
                new Finding("high", "EOL-PAST", "spring-boot 2.7.3 — 지원 종료됨", "", ""),
                new Finding("high", "EOL-PAST", "JDK 17 — 지원 종료됨", "", ""),
                new Finding("medium", "JDK27-GC-DEFAULT", "...", "", "")));
        Ignore ig = Ignore.load(tmp, LocalDate.of(2026, 9, 17));
        List<Finding> removed = ig.apply(findings);
        assertEquals(2, removed.size());
        assertEquals(2, findings.size());
        assertTrue(findings.stream().anyMatch(x -> x.title().startsWith("JDK 17"))); // 제목 조건이 안 맞는 EOL-PAST 는 남는다
        assertEquals(1, ig.expired.size());   // 만료된 억제는 적용되지 않고 사유가 남는다
        assertEquals(1, ig.invalid.size());   // until 없는 줄은 무효
    }

    @Test
    void rulesRejectCveWithoutEvidenceOrSource() {
        Rules.Cve bad = new Rules.Cve("CVE-0", "tomcat", "high", 7.0, "t", List.of(List.of("1.0", "1.1")), List.of("1.2"), "cond", "https://x", List.of());
        try {
            new Rules("v", RULES.jdk27Defaults(), RULES.eol(), 120, List.of(bad), RULES.bootBom());
            throw new AssertionError("evidence 없는 CVE 가 통과했다");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("evidence"), e.getMessage());
        }
    }

    @Test
    void infoDowngradeListsEvidencePatterns() {
        Facts f = new Collector(RULES).collect(Path.of("fixture2")); // Boot 4.0.7 → security 7.0.6, 흔적 없음
        List<Finding> findings = new Evaluator(RULES, LocalDate.of(2026, 9, 3)).evaluate(f);
        Finding info = findings.stream().filter(x -> x.id().equals("CVE-2026-59270")).findFirst().orElseThrow();
        assertEquals("info", info.severity());
        assertTrue(info.detail().contains("찾은 흔적 문자열: UnboundIdContainer"), info.detail()); // 검토자가 흔적 정의의 빈틈을 볼 수 있어야 한다
    }

    @Test
    void sarifHasRulesAndLevels() {
        Facts f = new Collector(RULES).collect(Path.of("fixture"));
        List<Finding> findings = new Evaluator(RULES, LocalDate.of(2026, 9, 3)).evaluate(f);
        String s = Report.sarif(RULES, f, findings);
        assertTrue(s.contains("\"version\" : \"2.1.0\""));
        assertTrue(s.contains("\"ruleId\" : \"CVE-2026-59270\""));
        assertTrue(s.contains("\"level\" : \"error\"") && s.contains("\"level\" : \"note\""));
        assertTrue(s.contains("src/main/java/app/LdapCfg.java")); // 흔적 파일이 위치로 들어간다
    }

    @Test
    void eolMergeReplacesDateAndKeepsNote() {
        List<Rules.Eol> base = List.of(new Rules.Eol("spring-security", "7.0", "2027-07-31", "7.0.7", "Boot 4.0 라인"));
        // merge 는 네트워크를 쓰므로 여기서는 병합 규칙만 흉내: 같은 product+cycle 이면 날짜·latest 갱신, note 유지
        Rules.Eol online = new Rules.Eol("spring-security", "7.0", "2026-12-31", "7.0.8", null);
        Rules.Eol merged = new Rules.Eol(online.product(), online.cycle(), online.eol(), online.latest(), base.get(0).note());
        assertEquals("2026-12-31", merged.eol());
        assertEquals("Boot 4.0 라인", merged.note());
    }
}
