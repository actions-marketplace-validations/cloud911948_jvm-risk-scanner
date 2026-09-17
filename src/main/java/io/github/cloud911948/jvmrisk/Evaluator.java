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

    public Evaluator(Rules rules, LocalDate today) {
        this.rules = rules;
        this.today = today;
    }

    public List<Finding> evaluate(Facts f) {
        List<Finding> out = new ArrayList<>();
        jdk27(f, out);
        eol(f, out);
        cve(f, out);
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
            eolCheck(out, k, f.deps.get(k), k + (f.src.containsKey(k) ? " (BOM)" : ""));
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
        for (Rules.Cve c : rules.cves()) {
            if (!c.product().equals(product)) continue;
            boolean affected = c.affected().stream().anyMatch(r -> Version.inRange(version, r.get(0), r.get(1)));
            if (!affected) continue;
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
