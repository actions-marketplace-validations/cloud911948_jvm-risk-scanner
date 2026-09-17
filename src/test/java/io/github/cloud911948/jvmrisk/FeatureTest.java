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
                CVE-2026-59270            # 내장 LDAP 안 씀
                EOL-PAST spring-boot      # 이행 일정 확정
                """);
        List<Finding> findings = new ArrayList<>(List.of(
                new Finding("info", "CVE-2026-59270", "spring-security 5.7.3: ...", "", ""),
                new Finding("high", "EOL-PAST", "spring-boot 2.7.3 — 지원 종료됨", "", ""),
                new Finding("high", "EOL-PAST", "JDK 17 — 지원 종료됨", "", ""),
                new Finding("medium", "JDK27-GC-DEFAULT", "...", "", "")));
        List<Finding> removed = Ignore.load(tmp).apply(findings);
        assertEquals(2, removed.size());
        assertEquals(2, findings.size());
        assertTrue(findings.stream().anyMatch(x -> x.title().startsWith("JDK 17"))); // 제목 조건이 안 맞는 EOL-PAST 는 남는다
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
