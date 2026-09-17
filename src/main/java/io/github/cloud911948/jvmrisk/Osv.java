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
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * OSV.dev 조회. 취약 버전 범위·수정 버전은 공개 데이터이므로 스캔 시점에 가져오고,
 * "실제로 그 기능을 쓰는가"(evidence)만 rules.json 에 남긴다.
 * 네트워크가 막히면 조용히 빈 결과를 돌려주고 {@link #failed} 로 알린다. 그때는 rules.json 스냅샷만으로 판정한다.
 * ponytail: 제품당 대표 아티팩트 1개만 묻는다. 모듈별로 등재된 CVE 를 놓칠 수 있고, 그건 rules.json 이 메운다.
 */
public final class Osv {

    public record Vuln(String id, List<String> aliases, String severity, String summary, List<String> fixed, String url) {
        /** rules.json 은 CVE id 를 쓰므로 CVE 별칭이 있으면 그것을 대표 id 로 삼는다. */
        public String cveId() {
            return aliases.stream().filter(a -> a.startsWith("CVE-")).findFirst().orElse(id);
        }
    }

    static final Map<String, String> COORDS = Map.of(
            "spring-boot", "org.springframework.boot:spring-boot",
            "spring-framework", "org.springframework:spring-core",
            "spring-security", "org.springframework.security:spring-security-core",
            "spring-graphql", "org.springframework.graphql:spring-graphql",
            "tomcat", "org.apache.tomcat.embed:tomcat-embed-core",
            "netty", "io.netty:netty-handler");

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final List<String> failed = new ArrayList<>();

    /** product → version 을 받아 product → 취약점 목록. 조회 실패한 제품은 결과에서 빠지고 failed() 에 남는다. */
    public Map<String, List<Vuln>> query(Map<String, String> productVersions) {
        Map<String, CompletableFuture<List<Vuln>>> pending = new LinkedHashMap<>();
        productVersions.forEach((product, version) -> {
            String coord = COORDS.get(product);
            if (coord == null || version == null || version.equals("?")) return;
            pending.put(product, http.sendAsync(request(coord, version), HttpResponse.BodyHandlers.ofString())
                    .thenApply(r -> r.statusCode() == 200 ? parse(r.body()) : null));
        });
        Map<String, List<Vuln>> out = new LinkedHashMap<>();
        pending.forEach((product, f) -> {
            List<Vuln> v;
            try {
                v = f.get();
            } catch (Exception e) {
                v = null;
            }
            if (v == null) failed.add(product); else out.put(product, v);
        });
        return out;
    }

    public List<String> failed() {
        return failed;
    }

    private static HttpRequest request(String coord, String version) {
        String body = "{\"package\":{\"name\":\"" + coord + "\",\"ecosystem\":\"Maven\"},\"version\":\"" + version + "\"}";
        return HttpRequest.newBuilder(URI.create("https://api.osv.dev/v1/query"))
                .timeout(Duration.ofSeconds(8))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    static List<Vuln> parse(String json) {
        List<Vuln> out = new ArrayList<>();
        try {
            for (JsonNode v : MAPPER.readTree(json).path("vulns")) {
                List<String> aliases = new ArrayList<>();
                v.path("aliases").forEach(a -> aliases.add(a.asText()));
                List<String> fixed = new ArrayList<>();
                for (JsonNode a : v.path("affected")) for (JsonNode r : a.path("ranges")) for (JsonNode e : r.path("events")) {
                    if (e.has("fixed") && !fixed.contains(e.get("fixed").asText())) fixed.add(e.get("fixed").asText());
                }
                String sev = v.path("database_specific").path("severity").asText("").toLowerCase();
                if (sev.equals("moderate")) sev = "medium";
                out.add(new Vuln(v.path("id").asText(), aliases, sev.isEmpty() ? "medium" : sev,
                        v.path("summary").asText(""), fixed, "https://osv.dev/vulnerability/" + v.path("id").asText()));
            }
        } catch (Exception e) {
            return null;
        }
        return out;
    }
}
