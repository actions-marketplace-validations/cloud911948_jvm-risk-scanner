package io.github.cloud911948.jvmrisk;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 저장소 루트의 `.jvmrisk-ignore`. 검토가 끝난 항목을 다음 PR 부터 숨긴다.
 * 한 줄에 하나: `<finding id>` 또는 `<finding id> <제목에 포함될 문자열>`. `#` 뒤는 주석.
 * 예) `CVE-2026-59270  # 내장 LDAP 안 씀, 2026-09 검토`
 *     `EOL-PAST spring-boot 2.7   # 4.0.8 이행 일정 확정, 2026-11`
 */
public final class Ignore {

    record Rule(String id, String titlePart) {
        boolean matches(Finding f) {
            return f.id().equals(id) && (titlePart.isEmpty() || f.title().contains(titlePart));
        }
    }

    private final List<Rule> rules = new ArrayList<>();

    public static Ignore load(Path root) {
        Ignore ig = new Ignore();
        Path file = root.resolve(".jvmrisk-ignore");
        if (!Files.isRegularFile(file)) return ig;
        try {
            for (String raw : Files.readAllLines(file)) {
                String line = raw.contains("#") ? raw.substring(0, raw.indexOf('#')) : raw;
                line = line.strip();
                if (line.isEmpty()) continue;
                int sp = line.indexOf(' ');
                ig.rules.add(sp < 0 ? new Rule(line, "") : new Rule(line.substring(0, sp), line.substring(sp + 1).strip()));
            }
        } catch (IOException e) {
            // 읽기 실패는 무시 = 억제 없음. 억제가 조용히 사라지는 쪽이 조용히 숨기는 쪽보다 안전하다.
        }
        return ig;
    }

    public boolean isEmpty() {
        return rules.isEmpty();
    }

    /** 억제된 항목을 제거하고 제거된 목록을 돌려준다(리포트 꼬리에 건수 표시용). */
    public List<Finding> apply(List<Finding> findings) {
        List<Finding> removed = new ArrayList<>();
        findings.removeIf(f -> {
            boolean hit = rules.stream().anyMatch(r -> r.matches(f));
            if (hit) removed.add(f);
            return hit;
        });
        return removed;
    }
}
