package io.github.cloud911948.jvmrisk;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/** 수집한 사실을 규칙과 대조한다. 확신 없는 항목은 심각도를 올리지 않고 info 로 두고 이유를 적는다. */
public final class Evaluator {

    private static final Pattern GC_FLAG = Pattern.compile("-XX:\\+Use(Serial|Parallel|Z|Shenandoah|G1)GC");

    private final Rules rules;
    private final LocalDate today;
    /** product → OSV 취약점. 오프라인이거나 조회 실패면 비어 있고, 그때는 rules.json 스냅샷만 본다. */
    private final Map<String, List<Osv.Vuln>> osv;

    public Evaluator(Rules rules, LocalDate today) {
        this(rules, today, Map.of());
    }

    public Evaluator(Rules rules, LocalDate today, Map<String, List<Osv.Vuln>> osv) {
        this.rules = rules;
        this.today = today;
        this.osv = osv;
    }

    public List<Finding> evaluate(Facts f) {
        List<Finding> out = new ArrayList<>();
        jdk27(f, out);
        eol(f, out);
        cve(f, out);
        transitive(f, out);
        misc(f, out);
        out.sort(Finding.BY_SEVERITY);
        return out;
    }

    private void jdk27(Facts f, List<Finding> out) {
        List<String> gc = f.flags.stream().filter(x -> GC_FLAG.matcher(x).lookingAt()).sorted().toList();
        String jdkMax = f.jdk.stream().map(Integer::parseInt).max(Integer::compare).map(String::valueOf).orElse("미확인");
        if (gc.isEmpty()) {
            add(out, rules.defaultRule("JDK27-GC-DEFAULT"),
                    "GC 플래그 없음. 현재 JDK " + jdkMax + " → 27 이행 시 소형 컨테이너(1 CPU / <1792MB)에서 Serial→G1 로 바뀜.");
        } else {
            add(out, rules.defaultRule("JDK27-GC-EXPLICIT"), "명시 플래그: " + String.join(", ", gc));
        }
        if (!f.flags.contains("-XX:-UseCompactObjectHeaders")) {
            add(out, rules.defaultRule("JDK27-COH-DEFAULT"), "옵트아웃 플래그 없음(정상 — 기본값을 받아들이되 아래 충돌 항목 확인).");
        }
        if (!f.unsafe.isEmpty()) {
            add(out, rules.defaultRule("JDK27-COH-UNSAFE"), "Unsafe 사용 파일: " + String.join(", ", f.unsafe.subList(0, Math.min(5, f.unsafe.size()))));
        }
        List<String> tools = List.of("jol", "lincheck").stream().filter(f.deps::containsKey).toList();
        if (!tools.isEmpty()) add(out, rules.defaultRule("JDK27-COH-LAYOUT-TOOLS"), "감지: " + String.join(", ", tools));
        if (!f.agents.isEmpty()) add(out, rules.defaultRule("JDK27-COH-AGENT"), "에이전트: " + String.join(", ", f.agents));
        if (f.jfr) add(out, rules.defaultRule("JDK27-JFR-REDACT"), "JFR 사용 흔적 있음");
    }

    private void eol(Facts f, List<Finding> out) {
        for (String v : f.jdk) eolCheck(out, "jdk", v, "JDK");
        for (String k : List.of("spring-boot", "spring-framework", "spring-security")) {
            String t = f.src.get(k);
            eolCheck(out, k, f.deps.get(k), k + (t == null ? "" : "resolved".equals(t) ? " (해석 결과)" : " (BOM)"));
        }
        for (Facts.Image img : f.images) eolCheck(out, img.name(), img.version(), img.name());
    }

    private void eolCheck(List<Finding> out, String product, String version, String label) {
        if (version == null) return;
        String cycle = product.equals("jdk") ? version.split("\\.")[0] : Version.line(version);
        for (Rules.Eol e : rules.eol()) {
            if (!e.product().equals(product) || !e.cycle().equals(cycle) || e.eol() == null) continue;
            LocalDate d = LocalDate.parse(e.eol());
            long days = ChronoUnit.DAYS.between(today, d);
            String note = e.note() == null ? "" : e.note();
            if (d.isBefore(today)) {
                out.add(new Finding("high", "EOL-PAST", label + " " + version + " — 지원 종료됨 (" + e.eol() + ")", note,
                        "지원 중인 라인으로 업그레이드 (최신 " + (e.latest() == null ? "?" : e.latest()) + ")"));
            } else if (days <= rules.eolWarnDays()) {
                out.add(new Finding("medium", "EOL-SOON", label + " " + version + " — " + days + "일 후 지원 종료 (" + e.eol() + ")", note, "업그레이드 계획 수립"));
            }
            return;
        }
        out.add(new Finding("info", "EOL-UNKNOWN", label + " " + version + " — EOL 표에 없음", "", "rules.json eol 에 추가"));
    }

    private void cve(Facts f, List<Finding> out) {
        cveCheck(out, f, "spring-security", f.deps.get("spring-security"), "spring-security");
        cveCheck(out, f, "spring-graphql", f.deps.get("spring-graphql"), "spring-graphql");
        cveCheck(out, f, "netty", f.deps.get("netty"), "netty");
        cveCheck(out, f, "tomcat", f.deps.get("tomcat"), "tomcat");
        for (Facts.Image img : f.images) {
            if (img.name().equals("redis")) cveCheck(out, f, "redis-server", img.version(), "redis");
            if (img.name().equals("tomcat") && !f.deps.containsKey("tomcat")) cveCheck(out, f, "tomcat", img.version(), "tomcat(image)");
        }
    }

    private void cveCheck(List<Finding> out, Facts f, String product, String version, String label) {
        if (version == null || version.equals("?")) return;
        String tag = f.src.get(product);
        if ("bom".equals(tag)) label += " (Boot BOM 관리)";
        else if ("bom~".equals(tag)) label += " (Boot BOM 추정)";
        else if ("resolved".equals(tag)) label += " (해석 결과)";
        java.util.Set<String> known = new java.util.HashSet<>();
        for (Rules.Cve c : rules.cves()) {
            if (!c.product().equals(product)) continue;
            boolean affected = c.affected().stream().anyMatch(r -> Version.inRange(version, r.get(0), r.get(1)));
            if (!affected) continue;
            known.add(c.id());
            List<String> ev = f.evidence.getOrDefault(c.id(), List.of());
            String fixed = String.join(", ", c.fixed());
            if (!ev.isEmpty()) {
                out.add(new Finding(c.severity(), c.id(),
                        label + " " + version + ": " + c.title() + " (CVSS " + (c.cvss() == null ? "-" : c.cvss()) + ")",
                        "조건: " + c.condition() + " — 사용 흔적: " + String.join(", ", ev),
                        "수정 버전 " + fixed + " — " + c.source()));
            } else {
                // 버전은 취약 범위지만 취약 경로를 쓰는 흔적이 없다. 버전만 보고 CRITICAL 을 찍으면 운영자가 도구를 안 믿게 된다.
                out.add(new Finding("info", c.id(),
                        label + " " + version + ": 취약 버전이나 사용 흔적 없음 — " + c.title(),
                        "조건: " + c.condition() + " — 소스·빌드·설정에서 관련 문자열 미발견(조건 미충족 추정)",
                        "버전 자체는 취약 범위. 업그레이드 시 함께 해소: " + fixed));
            }
        }
        osvOnly(out, product, version, label, known);
    }

    /**
     * OSV 에만 있는 항목(버전은 취약 범위, 흔적 규칙 없음)은 제품당 한 줄로 묶는다.
     * 오래된 라인은 누적 CVE 가 수십 건이라 낱개로 찍으면 리포트가 읽히지 않고, 답은 어차피 "라인 업그레이드" 하나다.
     * 버전만으로 CRITICAL 을 찍지 않고 MEDIUM 으로 "확인 필요"만 남긴다. 낱개 조건이 필요한 건은 rules.json 에 evidence 를 추가하면 위 경로로 올라온다.
     */
    private void osvOnly(List<Finding> out, String product, String version, String label, java.util.Set<String> known) {
        List<Osv.Vuln> rest = osv.getOrDefault(product, List.of()).stream()
                .filter(v -> !known.contains(v.cveId()) && v.aliases().stream().noneMatch(known::contains)).toList();
        if (rest.isEmpty()) return;
        Map<String, Long> bySev = rest.stream().collect(Collectors.groupingBy(Osv.Vuln::severity, java.util.LinkedHashMap::new, Collectors.counting()));
        String counts = List.of("critical", "high", "medium", "low").stream().filter(bySev::containsKey)
                .map(s -> s.toUpperCase() + " " + bySev.get(s)).collect(Collectors.joining(" · "));
        String ids = rest.stream().map(v -> v.cveId() + "(" + v.severity().substring(0, 1).toUpperCase() + ")").collect(Collectors.joining(", "));
        String line = Version.line(version);
        String fix = rest.stream().flatMap(v -> v.fixed().stream()).filter(x -> Version.line(x).equals(line)).max(Version.ORDER)
                .orElseGet(() -> rest.stream().flatMap(v -> v.fixed().stream()).max(Version.ORDER).orElse("미기재"));
        out.add(new Finding("medium", "OSV-" + product.toUpperCase(),
                label + " " + version + ": OSV 등재 취약점 " + rest.size() + "건 (" + counts + ") — 흔적 규칙 미정의",
                "버전만으로 판정(사용 조건 미확인): " + ids,
                "같은 라인 최신 " + fix + " 이상으로 올리면 일괄 해소. 낱개 확인은 https://osv.dev/list?ecosystem=Maven&q=" + Osv.COORDS.get(product)));
    }

    /** --deps 로 받은 전이 의존성 중 OSV 에 걸린 것. 아티팩트당 한 줄이 아니라 전체를 한 항목으로, 세부는 detail 에. */
    private void transitive(Facts f, List<Finding> out) {
        if (f.transitive.isEmpty()) return;
        int total = f.transitive.values().stream().mapToInt(List::size).sum();
        long crit = f.transitive.values().stream().flatMap(List::stream).filter(v -> v.severity().equals("critical")).count();
        String lines = f.transitive.entrySet().stream().map(e -> e.getKey() + ":" + f.resolved.get(e.getKey()) + " " + e.getValue().size() + "건"
                + (e.getValue().stream().anyMatch(v -> v.severity().equals("critical")) ? "(C)" : "")).collect(Collectors.joining("; "));
        out.add(new Finding(crit > 0 ? "high" : "medium", "OSV-TRANSITIVE",
                "전이 의존성 " + f.transitive.size() + "개 아티팩트에 OSV 등재 취약점 " + total + "건 (CRITICAL " + crit + ")",
                lines, "./gradlew dependencyInsight --dependency <artifact> 로 끌어오는 경로 확인 후 버전 강제 또는 상위 라이브러리 업그레이드"));
    }

    private void misc(Facts f, List<Finding> out) {
        String boot = f.deps.get("spring-boot");
        if (boot != null && !f.deps.containsKey("spring-security")) {
            out.add(new Finding("info", "DEP-UNRESOLVED", "spring-security 버전 미확인 — Boot " + boot + " 은 BOM 표에 없음",
                    "rules.json boot_bom 에 행 추가 필요", "./gradlew dependencies 로 실제 버전 확인"));
        }
        if (f.bootAll.size() > 1) {
            out.add(new Finding("info", "BOOT-MIXED", "모듈별 Spring Boot 버전이 섞여 있음: " + String.join(", ", f.bootAll),
                    "가장 오래된 " + boot + " 기준으로 EOL·CVE 대조", "모듈별 버전 통일 여부 검토"));
        }
        String estimated = f.src.entrySet().stream().filter(e -> e.getValue().equals("bom~"))
                .map(e -> e.getKey() + "=" + f.deps.get(e.getKey())).collect(Collectors.joining(", "));
        if (!estimated.isEmpty()) {
            out.add(new Finding("info", "DEP-ESTIMATED", "일부 버전은 Boot BOM 표의 인접 패치로 추정", estimated,
                    "정확한 값은 ./gradlew dependencies 또는 mvn dependency:tree"));
        }
    }

    private static void add(List<Finding> out, Rules.DefaultRule r, String detail) {
        out.add(new Finding(r.severity(), r.id(), r.title(), detail, r.action()));
    }
}
