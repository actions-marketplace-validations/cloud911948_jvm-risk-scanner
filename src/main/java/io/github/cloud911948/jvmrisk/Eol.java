package io.github.cloud911948.jvmrisk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * endoflife.date 에서 라인별 지원 종료일·최신 패치를 받아 rules.json 의 eol 표를 덮는다.
 * JDK 는 배포판마다 날짜가 달라(Oracle/Temurin/Corretto) 표를 그대로 두고, 여기서는 Spring·Tomcat·Redis 만 받는다.
 * 실패하면 rules.json 값이 남는다.
 */
public final class Eol {

    static final Map<String, String> PRODUCTS = Map.of(
            "spring-boot", "spring-boot", "spring-framework", "spring-framework", "spring-security", "spring-security",
            "tomcat", "tomcat", "redis", "redis");

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final List<String> failed = new ArrayList<>();

    /** 온라인 행으로 덮은 새 표. 같은 product+cycle 이 있으면 eol·latest 만 갱신, 없으면 추가. rules 의 note 는 유지. */
    public List<Rules.Eol> merge(List<Rules.Eol> base) {
        Map<String, CompletableFuture<JsonNode>> pending = new java.util.LinkedHashMap<>();
        PRODUCTS.forEach((product, slug) -> pending.put(product, http.sendAsync(
                HttpRequest.newBuilder(URI.create("https://endoflife.date/api/" + slug + ".json")).timeout(Duration.ofSeconds(8)).GET().build(),
                HttpResponse.BodyHandlers.ofString()).thenApply(r -> r.statusCode() == 200 ? read(r.body()) : null)));
        List<Rules.Eol> out = new ArrayList<>(base);
        pending.forEach((product, f) -> {
            JsonNode cycles;
            try {
                cycles = f.get(15, java.util.concurrent.TimeUnit.SECONDS); // request timeout 은 헤더까지만 보장한다
            } catch (Exception e) {
                cycles = null;
            }
            if (cycles == null) {
                failed.add(product);
                return;
            }
            for (JsonNode c : cycles) {
                String cycle = c.path("cycle").asText();
                JsonNode eolNode = c.path("eol");
                // endoflife.date 의 eol 은 날짜 | false(미종료) | true(종료됐으나 날짜 미상). true 를 null 로 바꾸면 EOL-PAST 가 조용히 사라진다.
                String eol = eolNode.isTextual() ? eolNode.asText() : null;
                boolean endedNoDate = eolNode.isBoolean() && eolNode.asBoolean();
                String latest = c.path("latest").asText(null);
                int idx = -1;
                for (int i = 0; i < out.size(); i++) if (out.get(i).product().equals(product) && out.get(i).cycle().equals(cycle)) idx = i;
                if (idx >= 0) {
                    Rules.Eol o = out.get(idx);
                    String date = eol != null ? eol : endedNoDate ? (o.eol() != null ? o.eol() : java.time.LocalDate.now().toString()) : null;
                    out.set(idx, new Rules.Eol(product, cycle, date, latest != null ? latest : o.latest(), o.note()));
                } else {
                    out.add(new Rules.Eol(product, cycle, eol != null ? eol : endedNoDate ? java.time.LocalDate.now().toString() : null, latest, "endoflife.date"));
                }
            }
        });
        return out;
    }

    public List<String> failed() {
        return failed;
    }

    private static JsonNode read(String body) {
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            return null;
        }
    }
}
