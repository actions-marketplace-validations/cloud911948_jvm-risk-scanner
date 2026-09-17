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

    /** 온라인 경로도 고정한다. 녹화해 둔 OSV 응답(src/test/resources/osv)을 스텁으로 넣는다. 외부 세계의 불변이 아니라 "고정 입력 → 고정 판정"을 검증하는 것이다. */
    @Test
    void onlinePathMatchesGoldenWithRecordedOsv() throws Exception {
        Facts f = new Collector(RULES).collect(Path.of("fixture2")); // Boot 4.0.7 → netty 4.2.15.Final
        List<Osv.Vuln> netty = Osv.parse(Files.readString(Path.of("src/test/resources/osv/netty-handler-4.2.15.json")));
        List<Finding> findings = new Evaluator(RULES, TODAY, java.util.Map.of("netty", netty)).evaluate(f);
        check("fixture2-osv", Report.markdown(RULES, f, findings));
    }

    private static void check(String name, String actual) throws Exception {
        Path golden = Path.of("src/test/resources/golden", name + ".md");
        if (Boolean.getBoolean("golden.update") || !Files.exists(golden)) {
            Files.writeString(golden, actual);
            return;
        }
        assertEquals(Files.readString(golden), actual, name + " 리포트가 골든 파일과 다릅니다. 의도한 변경이면 -Dgolden.update=true");
    }

    @Test
    void reportsMatchGoldenFiles() throws Exception {
        for (String name : List.of("fixture", "fixture2", "fixture3")) {
            Facts f = new Collector(RULES).collect(Path.of(name));
            List<Finding> findings = new Evaluator(RULES, TODAY).evaluate(f);
            check(name, Report.markdown(RULES, f, findings));
        }
    }
}
