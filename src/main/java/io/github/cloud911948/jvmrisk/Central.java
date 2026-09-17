package io.github.cloud911948.jvmrisk;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maven Central 에 그 버전이 실제로 있는지 본다. OSV 가 Tomcat 10.1 수정 버전을 10.1.58 로 적었지만 Central 에는 없었다(실제 10.1.59).
 * 존재하지 않는 버전을 "올려라"고 권고하는 리포트는 신뢰를 한 번에 깎으므로, 권고 버전을 찍기 전에 한 번 확인한다.
 * 조회 실패 시 null(미확인) — 권고문은 그대로 두고 "(Central 미확인)" 만 붙인다.
 */
public final class Central {

    private static final Pattern VERSION = Pattern.compile("<version>([^<]+)</version>");
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final Map<String, List<String>> cache = new HashMap<>();

    /** group:artifact 의 전체 버전 목록. 실패면 null. */
    public List<String> versions(String coord) {
        if (cache.containsKey(coord)) return cache.get(coord);
        List<String> out = null;
        try {
            String[] ga = coord.split(":");
            String url = "https://repo1.maven.org/maven2/" + ga[0].replace('.', '/') + "/" + ga[1] + "/maven-metadata.xml";
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(8)).GET().build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() == 200) {
                Matcher m = VERSION.matcher(r.body());
                out = new java.util.ArrayList<>();
                while (m.find()) out.add(m.group(1));
            }
        } catch (Exception e) {
            out = null;
        }
        cache.put(coord, out);
        return out;
    }

    /**
     * 권고 버전 검증 문구. 존재하면 그대로, 없으면 같은 라인에서 그 다음으로 존재하는 버전을 대신 권고하며 사유를 남긴다.
     * 예) "10.1.58" → "10.1.59 (OSV 는 10.1.58 표기, Central 미존재)"
     */
    public String verify(String coord, String version) {
        List<String> all = versions(coord);
        if (all == null) return version + " (Central 미확인)";
        if (all.contains(version)) return version;
        String line = Version.line(version);
        Version want = Version.parse(version);
        return all.stream().filter(v -> Version.line(v).equals(line) && Version.parse(v).compareTo(want) > 0)
                .min(Version.ORDER)
                .map(v -> v + " (OSV 는 " + version + " 표기, Central 미존재)")
                .orElse(version + " (Central 미존재, 같은 라인 후속 없음)");
    }
}
