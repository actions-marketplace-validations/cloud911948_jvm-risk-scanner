package io.github.cloud911948.jvmrisk;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** 저장소에서 긁어낸 사실. 판단은 하지 않는다. 판단은 {@link Evaluator} 가 한다. */
public final class Facts {
    @JsonIgnore
    public final Path root;
    public final TreeSet<String> jdk = new TreeSet<>();
    public final TreeSet<String> flags = new TreeSet<>();
    /** product → version. 예: spring-boot=4.0.8, spring-security=7.0.6, jol=? */
    public final Map<String, String> deps = new LinkedHashMap<>();
    /** product → "bom" | "bom~". 명시 버전이 아니라 Boot BOM 표로 채운 항목의 출처 표시. */
    public final Map<String, String> src = new LinkedHashMap<>();
    public final TreeSet<Image> images = new TreeSet<>();
    public final List<String> unsafe = new ArrayList<>();
    public final TreeSet<String> agents = new TreeSet<>();
    /** 멀티모듈에서 발견된 모든 Boot 버전. deps 의 spring-boot 는 이 중 가장 오래된 것. */
    public final TreeSet<String> bootAll = new TreeSet<>(Version.ORDER);
    /** CVE id → 사용 흔적이 발견된 파일(상대 경로, 최대 3개). */
    public final Map<String, List<String>> evidence = new LinkedHashMap<>();
    public boolean jfr;
    /** 리포트 머리에 찍는 OSV 조회 상태. 판정엔 쓰지 않는다. */
    public String osv = "미조회(--offline)";
    /** --deps 로 읽은 해석 결과(group:artifact → 실제 버전). 비어 있으면 빌드 파일 정규식+BOM 표로 간다. */
    public final Map<String, String> resolved = new LinkedHashMap<>();
    /** 전이 의존성 OSV 결과(group:artifact → 취약점). 대표 제품 좌표는 제외. */
    public final Map<String, List<Osv.Vuln>> transitive = new LinkedHashMap<>();
    public String eolSrc = "rules.json";
    public List<Finding> suppressed = new ArrayList<>();

    public Facts(Path root) {
        this.root = root;
    }

    public record Image(String name, String version) implements Comparable<Image> {
        @Override
        public int compareTo(Image o) {
            int c = name.compareTo(o.name);
            return c != 0 ? c : Version.ORDER.compare(version, o.version);
        }

        @Override
        public String toString() {
            return name + ":" + version;
        }
    }
}
