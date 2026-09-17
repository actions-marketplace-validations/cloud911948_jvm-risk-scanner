package io.github.cloud911948.jvmrisk;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 픽스처별 오프라인 리포트 전체를 고정한다. 정규식이나 흔적 정의를 고쳤을 때 다른 판정이 움직이면 diff 로 바로 드러난다.
 * 의도한 변경이면 `./gradlew test -Dgolden.update=true` 로 갱신하고 diff 를 커밋에 포함한다.
 */
class GoldenTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 3);
    private static final Rules RULES = Rules.bundled();

    @Test
    void reportsMatchGoldenFiles() throws Exception {
        for (String name : List.of("fixture", "fixture2", "fixture3")) {
            Facts f = new Collector(RULES).collect(Path.of(name));
            List<Finding> findings = new Evaluator(RULES, TODAY).evaluate(f);
            String actual = Report.markdown(RULES, f, findings);
            Path golden = Path.of("src/test/resources/golden", name + ".md");
            if (Boolean.getBoolean("golden.update") || !Files.exists(golden)) {
                Files.writeString(golden, actual);
                continue;
            }
            assertEquals(Files.readString(golden), actual, name + " 리포트가 골든 파일과 다릅니다. 의도한 변경이면 -Dgolden.update=true");
        }
    }
}
