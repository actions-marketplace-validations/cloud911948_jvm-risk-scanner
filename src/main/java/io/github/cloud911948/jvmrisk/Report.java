package io.github.cloud911948.jvmrisk;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 마크다운은 PR 코멘트와 Step Summary 용, JSON 은 다른 도구에 물릴 때 쓴다. */
public final class Report {

    private Report() {}

    public static String markdown(Rules rules, Facts f, List<Finding> findings) {
        StringBuilder sb = new StringBuilder("# JVM 런타임 리스크 리포트\n\n");
        sb.append("- 감지 JDK: ").append(f.jdk.isEmpty() ? "미확인" : String.join(", ", f.jdk))
                .append(" · 의존성: ").append(f.deps.isEmpty() ? "없음" : f.deps)
                .append(" · 이미지: ").append(f.images.isEmpty() ? "없음" : f.images)
                .append(" · 플래그: ").append(f.flags.size()).append("개\n");
        sb.append("- 규칙 버전 ").append(rules.version()).append(" · OSV ").append(f.osv).append(" · EOL 표 ").append(f.eolSrc)
                .append(f.resolved.isEmpty() ? "" : " · 의존성 해석 결과 " + f.resolved.size() + "개 좌표").append("\n\n");
        for (Finding x : findings) {
            sb.append("### [").append(x.severity().toUpperCase()).append("] ").append(x.id()).append(" — ").append(x.title()).append('\n');
            if (x.detail() != null && !x.detail().isEmpty()) sb.append("- ").append(x.detail()).append('\n');
            sb.append("- 조치: ").append(x.action()).append("\n\n");
        }
        if (!f.suppressed.isEmpty() || !f.ignoreNotes.isEmpty()) {
            sb.append("---\n");
            if (!f.suppressed.isEmpty()) sb.append("억제 ").append(f.suppressed.size()).append("건 (.jvmrisk-ignore): ")
                    .append(f.suppressed.stream().map(Finding::id).distinct().collect(java.util.stream.Collectors.joining(", "))).append('\n');
            for (String n : f.ignoreNotes) sb.append("- ").append(n).append('\n');
        }
        return sb.toString();
    }

    /** SARIF 2.1.0 최소형. GitHub code scanning 에 올리면 Security 탭과 PR 파일 뷰에 표시된다. */
    public static String sarif(Rules rules, Facts f, List<Finding> findings) {
        List<Map<String, Object>> ruleDefs = new java.util.ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<Map<String, Object>> results = new java.util.ArrayList<>();
        for (Finding x : findings) {
            if (seen.add(x.id())) ruleDefs.add(Map.of("id", x.id(), "shortDescription", Map.of("text", x.id()),
                    "help", Map.of("text", x.action())));
            String level = switch (x.severity()) { case "critical", "high" -> "error"; case "medium" -> "warning"; default -> "note"; };
            String file = firstFile(x.detail());
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("ruleId", x.id());
            r.put("level", level);
            r.put("message", Map.of("text", x.title() + (x.detail().isEmpty() ? "" : " — " + x.detail()) + " — 조치: " + x.action()));
            r.put("locations", List.of(Map.of("physicalLocation", Map.of("artifactLocation", Map.of("uri", file)))));
            results.add(r);
        }
        Map<String, Object> run = Map.of(
                "tool", Map.of("driver", Map.of("name", "jvm-risk-scanner", "version", rules.version(),
                        "informationUri", "https://github.com/cloud911948/jvm-risk-scanner", "rules", ruleDefs)),
                "results", results);
        try {
            return new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(Map.of(
                    "$schema", "https://json.schemastore.org/sarif-2.1.0.json", "version", "2.1.0", "runs", List.of(run)));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** detail 의 "사용 흔적: a, b" 나 "Unsafe 사용 파일: a" 에서 첫 파일. 없으면 빌드 파일 자리. */
    private static String firstFile(String detail) {
        int i = detail.indexOf("흔적: ");
        if (i < 0) i = detail.indexOf("파일: ");
        if (i < 0) return "build.gradle";
        String rest = detail.substring(i + 4);
        int end = rest.indexOf(',');
        return (end < 0 ? rest : rest.substring(0, end)).strip();
    }

    /** OSV 에만 있는 항목을 rules.json cves 항목 뼈대로. evidence 는 비워 두고 references 를 붙여 사람이 권고문을 읽고 채운다. */
    public static String suggest(Rules rules, Map<String, List<Osv.Vuln>> vulns) {
        java.util.Set<String> known = new java.util.HashSet<>();
        rules.cves().forEach(c -> known.add(c.id()));
        List<Map<String, Object>> items = new java.util.ArrayList<>();
        vulns.forEach((product, vs) -> {
            for (Osv.Vuln v : vs) {
                if (known.contains(v.cveId()) || v.aliases().stream().anyMatch(known::contains)) continue;
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", v.cveId());
                m.put("product", product);
                m.put("severity", v.severity());
                m.put("title", v.summary());
                m.put("fixed", v.fixed());
                m.put("condition", "TODO: 권고문에서 발동 조건을 한 줄로");
                m.put("evidence", List.of());
                m.put("source", v.url());
                m.put("references", v.references());
                items.add(m);
            }
        });
        try {
            return new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(items);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String json(Facts f, List<Finding> findings) {
        try {
            return new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(Map.of("facts", f, "findings", findings));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
