package io.github.cloud911948.jvmrisk;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

/**
 * 사용: java -jar jvm-risk-scanner.jar [디렉터리] [--json] [--rules 경로] [--offline]
 * 기본은 OSV.dev 를 조회해 취약 버전 범위를 최신으로 가져온다. --offline 이면 rules.json 스냅샷만 쓴다.
 * 종료 코드는 항상 0 이다. PR 을 막는 게 아니라 리포트를 남기는 도구이고, 막을지는 워크플로에서 정한다.
 */
public final class Main {

    public static void main(String[] args) {
        // 리포트는 마크다운(UTF-8)이다. Windows 콘솔은 stdout 을 MS949 로 잡아 한글이 깨지므로 출력 인코딩을 고정한다.
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8));
        Path root = Path.of(".");
        Path rulesFile = null;
        boolean json = false;
        boolean offline = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--json" -> json = true;
                case "--offline" -> offline = true;
                case "--rules" -> {
                    if (i + 1 >= args.length) usage("--rules 뒤에 규칙 파일 경로가 필요합니다");
                    rulesFile = Path.of(args[++i]);
                }
                default -> root = Path.of(args[i]);
            }
        }
        if (!Files.isDirectory(root)) usage("디렉터리가 아닙니다: " + root);
        Rules rules = rulesFile != null ? Rules.load(rulesFile) : Rules.bundled();
        Facts facts = new Collector(rules).collect(root);
        Map<String, List<Osv.Vuln>> vulns = Map.of();
        if (!offline) {
            Osv osv = new Osv();
            vulns = osv.query(facts.deps);
            facts.osv = "조회 " + vulns.size() + "개 제품" + (osv.failed().isEmpty() ? "" : ", 실패 " + osv.failed() + " → 스냅샷") ;
        }
        List<Finding> findings = new Evaluator(rules, LocalDate.now(), vulns).evaluate(facts);
        System.out.print(json ? Report.json(facts, findings) : Report.markdown(rules, facts, findings));
    }

    private static void usage(String reason) {
        System.err.println(reason);
        System.err.println("사용: java -jar jvm-risk-scanner.jar [디렉터리] [--json] [--rules 경로] [--offline]");
        System.exit(2);
    }
}
