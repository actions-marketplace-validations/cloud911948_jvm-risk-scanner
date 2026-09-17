package io.github.cloud911948.jvmrisk;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

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
        sb.append("- 규칙 버전 ").append(rules.version()).append(" · OSV ").append(f.osv).append("\n\n");
        for (Finding x : findings) {
            sb.append("### [").append(x.severity().toUpperCase()).append("] ").append(x.id()).append(" — ").append(x.title()).append('\n');
            if (x.detail() != null && !x.detail().isEmpty()) sb.append("- ").append(x.detail()).append('\n');
            sb.append("- 조치: ").append(x.action()).append("\n\n");
        }
        return sb.toString();
    }

    public static String json(Facts f, List<Finding> findings) {
        try {
            return new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(Map.of("facts", f, "findings", findings));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
