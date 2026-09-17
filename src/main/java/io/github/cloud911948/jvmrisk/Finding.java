package io.github.cloud911948.jvmrisk;

import java.util.Comparator;
import java.util.List;

public record Finding(String severity, String id, String title, String detail, String action) {

    /** unknown 은 "판정 불능"이다. 조회가 실패해 안전한지 모르는 상태를 취약점 0건과 구분하려고 high 바로 아래에 둔다. */
    public static final List<String> SEVERITIES = List.of("critical", "high", "unknown", "medium", "low", "info");

    public static final Comparator<Finding> BY_SEVERITY = Comparator.comparingInt(f -> SEVERITIES.indexOf(f.severity()));
}
