package io.github.cloud911948.jvmrisk;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * `gradle dependencies` / `mvn dependency:tree` 출력에서 해석된 좌표를 읽는다.
 * 빌드 파일 정규식은 "적힌 버전"만 보지만, 이 출력은 BOM 과 충돌 해결을 거친 "실제 버전"이고 전이 의존성까지 들어 있다.
 * 있으면 이쪽이 이기고, 없으면 기존 정규식+BOM 표로 간다.
 */
public final class DepTree {

    /** Gradle: `+--- group:artifact:1.0 -> 1.2 (*)` / `\--- group:artifact -> 1.2` / `group:artifact:1.0 (c)` */
    private static final Pattern GRADLE = Pattern.compile("[+\\\\|\\s]*-{3}\\s+([\\w.\\-]+:[\\w.\\-]+)(?::([\\w.\\-]+))?(?:\\s+->\\s+([\\w.\\-]+))?");
    /** Maven: `[INFO] |  \- group:artifact:jar:1.0:compile` (classifier 가 끼면 필드가 하나 더) */
    private static final Pattern MAVEN = Pattern.compile("[|+\\\\\\s-]*([\\w.\\-]+):([\\w.\\-]+):(?:jar|war|pom|bundle|test-jar|ejb)(?::[\\w.\\-]+)?:([\\d][\\w.\\-]*):(?:compile|runtime|provided|test|system)");

    private DepTree() {}

    /** group:artifact → version. 같은 좌표가 여러 번 나오면 마지막(보통 같은 값) 유지. */
    public static Map<String, String> parse(String text) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String line : text.split("\\R")) {
            Matcher m = MAVEN.matcher(line.startsWith("[INFO]") ? line.substring(6) : line);
            if (m.find()) {
                out.put(m.group(1) + ":" + m.group(2), m.group(3));
                continue;
            }
            m = GRADLE.matcher(line);
            if (m.find()) {
                String v = m.group(3) != null ? m.group(3) : m.group(2); // `->` 뒤가 최종 해석 버전
                if (v != null && Character.isDigit(v.charAt(0))) out.put(m.group(1), v);
            }
        }
        return out;
    }

    /** 대표 아티팩트 좌표 → 제품 이름. Facts.deps 를 실제 버전으로 덮는 데 쓴다. */
    static final Map<String, String> PRODUCT_OF = Map.of(
            "org.springframework.boot:spring-boot", "spring-boot",
            "org.springframework:spring-core", "spring-framework",
            "org.springframework.security:spring-security-core", "spring-security",
            "org.springframework.graphql:spring-graphql", "spring-graphql",
            "org.apache.tomcat.embed:tomcat-embed-core", "tomcat",
            "io.netty:netty-handler", "netty");
}
