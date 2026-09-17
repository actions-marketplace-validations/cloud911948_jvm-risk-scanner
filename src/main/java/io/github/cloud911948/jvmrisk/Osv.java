package io.github.cloud911948.jvmrisk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * OSV.dev 조회. 취약 버전 범위·수정 버전은 공개 데이터이므로 스캔 시점에 가져오고,
 * "실제로 그 기능을 쓰는가"(evidence)만 rules.json 에 남긴다.
 * 좌표 목록을 querybatch 한 번으로 묻고(응답은 id 만), id 별 상세를 병렬로 받는다.
 * 네트워크가 막히면 빈 결과를 돌려주고 {@link #failed()} 로 알린다. 그때는 rules.json 스냅샷만으로 판정한다.
 */
public final class Osv {

    public record Vuln(String id, List<String> aliases, String severity, String summary, List<String> fixed, String url, List<String> references) {
        /** rules.json 은 CVE id 를 쓰므로 CVE 별칭이 있으면 그것을 대표 id 로 삼는다. */
        public String cveId() {
            return aliases.stream().filter(a -> a.startsWith("CVE-")).findFirst().orElse(id);
        }
    }

    /** 제품 → 물어볼 아티팩트들. Spring Security 처럼 모듈별로 CVE 가 등재되는 제품은 여러 개를 묻는다. */
    static final Map<String, List<String>> COORDS = Map.of(
            "spring-boot", List.of("org.springframework.boot:spring-boot"),
            "spring-framework", List.of("org.springframework:spring-core", "org.springframework:spring-web", "org.springframework:spring-webmvc"),
            "spring-security", List.of("org.springframework.security:spring-security-core", "org.springframework.security:spring-security-web",
                    "org.springframework.security:spring-security-config", "org.springframework.security:spring-security-ldap",
                    "org.springframework.security:spring-security-oauth2-resource-server", "org.springframework.security:spring-security-oauth2-authorization-server"),
            "spring-graphql", List.of("org.springframework.graphql:spring-graphql"),
            "tomcat", List.of("org.apache.tomcat.embed:tomcat-embed-core"),
            "netty", List.of("io.netty:netty-handler", "io.netty:netty-codec-http2"));

    private static final int MAX_COORDS = 400;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final List<String> failed = new ArrayList<>();

    /** product → version. 제품별 대표 아티팩트들로 묻고 제품 단위로 합친다(중복 id 제거). */
    public Map<String, List<Vuln>> queryProducts(Map<String, String> productVersions) {
        Map<String, String> coords = new LinkedHashMap<>();
        productVersions.forEach((product, version) -> {
            if (version == null || version.equals("?")) return;
            for (String c : COORDS.getOrDefault(product, List.of())) coords.put(c, version);
        });
        Map<String, List<Vuln>> byCoord = queryCoords(coords);
        Map<String, List<Vuln>> out = new LinkedHashMap<>();
        productVersions.forEach((product, version) -> {
            Set<String> seen = new LinkedHashSet<>();
            List<Vuln> merged = new ArrayList<>();
            for (String c : COORDS.getOrDefault(product, List.of())) {
                for (Vuln v : byCoord.getOrDefault(c, List.of())) if (seen.add(v.id())) merged.add(v);
            }
            if (!merged.isEmpty()) out.put(product, merged);
        });
        return out;
    }

    /** group:artifact → version 을 받아 group:artifact → 취약점 목록. 실패하면 빈 맵 + failed 에 사유. */
    public Map<String, List<Vuln>> queryCoords(Map<String, String> coords) {
        Map<String, List<Vuln>> out = new LinkedHashMap<>();
        if (coords.isEmpty()) return out;
        List<Map.Entry<String, String>> entries = new ArrayList<>(coords.entrySet());
        if (entries.size() > MAX_COORDS) {
            failed.add("좌표 " + entries.size() + "개 중 앞 " + MAX_COORDS + "개만 조회");
            entries = entries.subList(0, MAX_COORDS);
        }
        StringBuilder body = new StringBuilder("{\"queries\":[");
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) body.append(',');
            body.append("{\"package\":{\"name\":\"").append(entries.get(i).getKey()).append("\",\"ecosystem\":\"Maven\"},\"version\":\"").append(entries.get(i).getValue()).append("\"}");
        }
        body.append("]}");
        JsonNode results;
        try {
            HttpResponse<String> r = http.send(post("https://api.osv.dev/v1/querybatch", body.toString()), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) throw new IllegalStateException("HTTP " + r.statusCode());
            results = MAPPER.readTree(r.body()).path("results");
        } catch (Exception e) {
            failed.add("OSV querybatch 실패: " + e.getMessage());
            return out;
        }
        // id → 상세. 같은 id 가 여러 좌표에 걸리므로 한 번만 받는다.
        Map<String, CompletableFuture<Vuln>> details = new LinkedHashMap<>();
        Map<String, List<String>> idsByCoord = new LinkedHashMap<>();
        for (int i = 0; i < entries.size() && i < results.size(); i++) {
            List<String> ids = new ArrayList<>();
            for (JsonNode v : results.get(i).path("vulns")) {
                String id = v.path("id").asText();
                ids.add(id);
                details.computeIfAbsent(id, k -> http.sendAsync(
                        HttpRequest.newBuilder(URI.create("https://api.osv.dev/v1/vulns/" + k)).timeout(Duration.ofSeconds(8)).GET().build(),
                        HttpResponse.BodyHandlers.ofString()).thenApply(resp -> resp.statusCode() == 200 ? parseOne(MAPPER_READ(resp.body())) : null));
            }
            idsByCoord.put(entries.get(i).getKey(), ids);
        }
        Map<String, Vuln> got = new LinkedHashMap<>();
        details.forEach((id, f) -> {
            try {
                Vuln v = f.get();
                if (v != null) got.put(id, v); else failed.add(id);
            } catch (Exception e) {
                failed.add(id);
            }
        });
        idsByCoord.forEach((coord, ids) -> {
            List<Vuln> vs = ids.stream().map(got::get).filter(v -> v != null).toList();
            if (!vs.isEmpty()) out.put(coord, vs);
        });
        return out;
    }

    public List<String> failed() {
        return failed;
    }

    private static HttpRequest post(String url, String body) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                .header("content-type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private static JsonNode MAPPER_READ(String s) {
        try {
            return MAPPER.readTree(s);
        } catch (Exception e) {
            return null;
        }
    }

    /** /v1/query 응답(vulns 배열) 파싱. 테스트용으로 남겨 둔다. */
    static List<Vuln> parse(String json) {
        List<Vuln> out = new ArrayList<>();
        JsonNode root = MAPPER_READ(json);
        if (root == null) return null;
        for (JsonNode v : root.path("vulns")) out.add(parseOne(v));
        return out;
    }

    static Vuln parseOne(JsonNode v) {
        if (v == null) return null;
        List<String> aliases = new ArrayList<>();
        v.path("aliases").forEach(a -> aliases.add(a.asText()));
        List<String> fixed = new ArrayList<>();
        for (JsonNode a : v.path("affected")) for (JsonNode r : a.path("ranges")) for (JsonNode e : r.path("events")) {
            if (e.has("fixed") && !fixed.contains(e.get("fixed").asText())) fixed.add(e.get("fixed").asText());
        }
        List<String> refs = new ArrayList<>();
        for (JsonNode ref : v.path("references")) if (refs.size() < 5) refs.add(ref.path("url").asText());
        String sev = v.path("database_specific").path("severity").asText("").toLowerCase();
        if (sev.equals("moderate")) sev = "medium";
        return new Vuln(v.path("id").asText(), aliases, sev.isEmpty() ? "medium" : sev,
                v.path("summary").asText(""), fixed, "https://osv.dev/vulnerability/" + v.path("id").asText(), refs);
    }
}
