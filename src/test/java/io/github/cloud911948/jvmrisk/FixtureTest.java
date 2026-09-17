package io.github.cloud911948.jvmrisk;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * fixture/ 세 개로 규칙 회귀를 잡는다. 날짜를 2026-09-03 으로 고정하는 이유는 EOL 잔여일이 결과 제목에 들어가기 때문이다.
 */
class FixtureTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 3);
    private static final Rules RULES = Rules.bundled(); // jar 에 들어갈 것과 같은 파일

    private static Facts collect(String dir) {
        return new Collector(RULES).collect(Path.of(dir));
    }

    private static List<Finding> evaluate(Facts f) {
        return new Evaluator(RULES, TODAY).evaluate(f);
    }

    private static Set<String> ids(List<Finding> findings) {
        return findings.stream().map(Finding::id).collect(Collectors.toSet());
    }

    @Test
    void gradleKtsWithEverything() {
        Facts f = collect("fixture");
        List<Finding> findings = evaluate(f);
        Set<String> ids = ids(findings);
        String titles = findings.stream().map(Finding::title).collect(Collectors.joining(" | "));

        assertEquals(Set.of("21"), f.jdk);
        assertEquals("4.0.8", f.deps.get("spring-boot"));
        assertEquals("7.0.6", f.deps.get("spring-security"));
        assertEquals("2.0.4", f.deps.get("spring-graphql"));
        assertTrue(f.images.contains(new Facts.Image("redis", "8.2.7")));
        for (String must : List.of("JDK27-GC-DEFAULT", "JDK27-COH-DEFAULT", "JDK27-COH-UNSAFE", "JDK27-COH-LAYOUT-TOOLS",
                "JDK27-COH-AGENT", "JDK27-JFR-REDACT", "EOL-SOON", "CVE-2026-59270", "CVE-2026-59285", "CVE-2026-41707",
                "CVE-2026-47841", "CVE-2026-47877", "CVE-2026-81934", "CVE-2026-65182")) {
            assertTrue(ids.contains(must), must + " 누락: " + ids);
        }
        assertTrue(titles.contains("spring-boot 4.0.8") && titles.contains("119일"), titles); // 4.0 라인 EOL 2026-12-31
        assertFalse(ids.contains("JDK27-GC-EXPLICIT"));
        // Boot 4.0.8 BOM → Tomcat 11.0.24, web.xml 에 security-constraint 가 있으니 흔적 있음 → 원래 심각도
        assertEquals("11.0.24", f.deps.get("tomcat"));
        assertEquals("critical", findings.stream().filter(x -> x.id().equals("CVE-2026-65182")).findFirst().orElseThrow().severity());
    }

    @Test
    void versionCatalogAliasResolvesThroughBom() {
        Facts f = collect("fixture2");
        Set<String> ids = ids(evaluate(f));
        assertEquals("4.0.7", f.deps.get("spring-boot"));
        assertEquals("7.0.6", f.deps.get("spring-security"));
        assertEquals("bom", f.src.get("spring-security"));
        assertTrue(ids.contains("CVE-2026-59270"), ids.toString());
        assertFalse(ids.contains("DEP-ESTIMATED"));
        // Boot 4.0.7 BOM → netty 4.2.15(취약)지만 SNI mTLS 흔적 없음 → info
        assertEquals("4.2.15.Final", f.deps.get("netty"));
        assertEquals("info", evaluate(f).stream().filter(x -> x.id().equals("CVE-2026-75595")).findFirst().orElseThrow().severity());
    }

    @Test
    void mavenBomImportFallsBackToNearestPatch() {
        Facts f = collect("fixture3");
        Set<String> ids = ids(evaluate(f));
        assertEquals("3.5.13", f.deps.get("spring-boot"));
        assertEquals("6.5.9", f.deps.get("spring-security"));
        assertEquals("bom~", f.src.get("spring-security"));
        assertTrue(ids.containsAll(List.of("DEP-ESTIMATED", "EOL-PAST", "EOL-SOON", "CVE-2026-59270")), ids.toString());
    }

    @Test
    void extensionlessScriptNamedLikeSkipDirIsStillRead() throws Exception {
        Path tmp = java.nio.file.Files.createTempDirectory("jvmrisk");
        java.nio.file.Files.createDirectories(tmp.resolve("bin"));
        java.nio.file.Files.writeString(tmp.resolve("bin/build"), "java -XX:+UseSerialGC -javaagent:apm.jar -jar app.jar");
        java.nio.file.Files.createDirectories(tmp.resolve("build"));
        java.nio.file.Files.writeString(tmp.resolve("build/generated.gradle"), "sourceCompatibility = JavaVersion.VERSION_17");
        java.nio.file.Files.writeString(tmp.resolve("build.gradle"), "sourceCompatibility = JavaVersion.VERSION_1_8");
        Facts f = new Collector(RULES).collect(tmp);
        assertTrue(f.flags.contains("-XX:+UseSerialGC"), f.flags.toString());
        assertEquals(1, f.agents.size());
        assertEquals(Set.of("8"), f.jdk); // build/ 디렉터리는 건너뛰고, bin/build 파일은 읽고, VERSION_1_8 은 8
    }

    @Test
    void osvOnlyVulnIsMediumAndKnownCveIsNotDuplicated() {
        Facts f = collect("fixture2"); // Boot 4.0.7 → netty 4.2.15
        java.util.Map<String, List<Osv.Vuln>> osv = java.util.Map.of("netty", List.of(
                new Osv.Vuln("GHSA-c4c3-7fpv-j4q5", List.of("CVE-2026-75595"), "critical", "SNI bypass", List.of("4.2.17.Final"), "u1", List.of()),
                new Osv.Vuln("GHSA-fccg-mwvh-qqg4", List.of("CVE-2026-75596"), "medium", "quadratic DoS", List.of("4.2.17.Final"), "u2", List.of())));
        List<Finding> findings = new Evaluator(RULES, TODAY, osv).evaluate(f);
        long n75595 = findings.stream().filter(x -> x.id().equals("CVE-2026-75595")).count();
        Finding grouped = findings.stream().filter(x -> x.id().equals("OSV-NETTY")).findFirst().orElseThrow();
        assertEquals(1, n75595);                                   // rules.json 이 아는 CVE 는 OSV 로 중복 생성하지 않는다
        assertEquals("medium", grouped.severity());               // 흔적 규칙 없는 OSV 항목은 제품당 한 줄, MEDIUM
        assertTrue(grouped.title().contains("1건") && grouped.detail().contains("CVE-2026-75596(M)"), grouped.detail());
        assertTrue(grouped.action().contains("4.2.17.Final"), grouped.action());
    }

    @Test
    void everyQueriedProductIsEvaluated() {
        Facts f = collect("fixture3"); // Boot 3.5.13 → framework 6.2.17(bom~)
        java.util.Map<String, List<Osv.Vuln>> osv = java.util.Map.of("spring-framework", List.of(
                new Osv.Vuln("GHSA-fw", List.of("CVE-2099-1"), "critical", "framework only", List.of("6.2.99"), "u", List.of())));
        List<Finding> findings = new Evaluator(RULES, TODAY, osv).evaluate(f);
        assertTrue(findings.stream().anyMatch(x -> x.id().equals("OSV-SPRING-FRAMEWORK")), "조회한 제품이 판정에서 빠지면 CVE 가 어디에도 안 나온다");
    }

    @Test
    void osvParseReadsAliasesFixedAndSeverity() {
        String json = "{\"vulns\":[{\"id\":\"GHSA-x\",\"aliases\":[\"CVE-1\"],\"summary\":\"s\",\"database_specific\":{\"severity\":\"MODERATE\"},"
                + "\"affected\":[{\"ranges\":[{\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"1.2\"}]}]}]}]}";
        Osv.Vuln v = Osv.parse(json).get(0);
        assertEquals("CVE-1", v.cveId());
        assertEquals(List.of("1.2"), v.fixed());
        assertEquals("medium", v.severity());
    }

    @Test
    void versionCompareIgnoresQualifier() {
        assertTrue(Version.inRange("3.5.13-SNAPSHOT", "3.5.0", "3.5.13"));
        assertFalse(Version.inRange("7.0.7", "7.0.0", "7.0.6"));
        assertEquals("3.5", Version.line("3.5.13"));
    }
}
