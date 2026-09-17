package io.github.cloud911948.jvmrisk;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 저장소 루트의 `.jvmrisk-ignore`. 검토가 끝난 항목을 다음 PR 부터 숨긴다.
 * 한 줄에 하나: `<finding id> [제목에 포함될 문자열] until=YYYY-MM-DD  # 사유`.
 * until 과 사유(주석)가 없으면 무효 — "한 번 검토하고 영구히 안 보는" 목록이 되는 걸 막는다. 만료되면 다시 리포트에 나온다.
 * 예) `CVE-2026-59270 until=2026-12-31  # 내장 LDAP 안 씀, 4.0.8 이행 때 재확인`
 *     `EOL-PAST spring-boot until=2026-11-30  # 4분기 라인 이동 착수 예정`
 */
public final class Ignore {

    record Rule(String id, String titlePart, java.time.LocalDate until, String reason) {
        boolean matches(Finding f) {
            return f.id().equals(id) && (titlePart.isEmpty() || f.title().contains(titlePart));
        }
    }

    private final List<Rule> rules = new ArrayList<>();
    /** 형식이 틀려 무시된 줄. 리포트 꼬리에 찍어 사용자가 고치게 한다. */
    public final List<String> invalid = new ArrayList<>();
    public final List<String> expired = new ArrayList<>();

    public static Ignore load(Path root) {
        return load(root, java.time.LocalDate.now());
    }

    static Ignore load(Path root, java.time.LocalDate today) {
        Ignore ig = new Ignore();
        Path file = root.resolve(".jvmrisk-ignore");
        if (!Files.isRegularFile(file)) return ig;
        try {
            for (String raw : Files.readAllLines(file)) {
                String reason = raw.contains("#") ? raw.substring(raw.indexOf('#') + 1).strip() : "";
                String line = (raw.contains("#") ? raw.substring(0, raw.indexOf('#')) : raw).strip();
                if (line.isEmpty()) continue;
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\s*until=(\\d{4}-\\d{2}-\\d{2})\\s*$").matcher(line);
                if (!m.find() || reason.isEmpty()) {
                    ig.invalid.add(raw.strip() + "  ← until=YYYY-MM-DD 와 # 사유 가 모두 필요");
                    continue;
                }
                java.time.LocalDate until = java.time.LocalDate.parse(m.group(1));
                String head = line.substring(0, m.start()).strip();
                int sp = head.indexOf(' ');
                Rule r = sp < 0 ? new Rule(head, "", until, reason) : new Rule(head.substring(0, sp), head.substring(sp + 1).strip(), until, reason);
                if (until.isBefore(today)) ig.expired.add(r.id() + " (" + until + " 만료, " + reason + ")");
                else ig.rules.add(r);
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
