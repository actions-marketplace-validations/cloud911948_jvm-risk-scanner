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
 * 사용: java -jar jvm-risk-scanner.jar [디렉터리] [--json | --sarif] [--rules 경로] [--deps 해석출력] [--offline] [--suggest] [--fail-on critical|high|medium]
 * 기본은 OSV.dev(취약 범위)·endoflife.date(EOL)를 조회한다. --offline 이면 rules.json 스냅샷만 쓴다.
 * --deps 는 `gradle dependencies` / `mvn dependency:tree` 출력 파일. 있으면 실제 해석 버전과 전이 의존성까지 본다.
 * --suggest 는 OSV 에만 있는 항목을 rules.json 항목 뼈대(evidence 비움)로 찍어 사람이 채우게 한다.
 * 종료 코드는 기본 0 이다(리포트만). --fail-on 을 주면 그 심각도 이상이 하나라도 있을 때 1 로 끝나 PR 을 막을 수 있다.
 */
public final class Main {

    public static void main(String[] args) {
        // 리포트는 마크다운(UTF-8)이다. Windows 콘솔은 stdout 을 MS949 로 잡아 한글이 깨지므로 출력 인코딩을 고정한다.
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8));
        Path root = Path.of(".");
        Path rulesFile = null;
        boolean json = false;
        boolean sarif = false;
        boolean offline = false;
        boolean suggest = false;
        Path depsFile = null;
        String failOn = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--json" -> json = true;
                case "--offline" -> offline = true;
                case "--sarif" -> sarif = true;
                case "--suggest" -> suggest = true;
                case "--fail-on" -> {
                    if (i + 1 >= args.length || !List.of("critical", "high", "medium", "low").contains(args[i + 1])) usage("--fail-on 뒤에 critical|high|medium|low 가 필요합니다");
                    failOn = args[++i];
                }
                case "--deps" -> {
                    if (i + 1 >= args.length) usage("--deps 뒤에 의존성 해석 출력 파일 경로가 필요합니다");
                    depsFile = Path.of(args[++i]);
                }
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
        if (depsFile != null) {
            try {
                Collector.applyResolved(facts, DepTree.read(depsFile));
            } catch (java.io.IOException e) {
                usage("의존성 해석 출력을 읽을 수 없습니다: " + depsFile + " (" + e.getMessage() + ")");
            }
        }
        Map<String, List<Osv.Vuln>> vulns = Map.of();
        Central central = null;
        if (!offline) {
            central = new Central();
            Osv osv = new Osv();
            vulns = osv.queryProducts(facts.deps);
            if (!facts.resolved.isEmpty()) {
                java.util.Set<String> productCoords = new java.util.HashSet<>(DepTree.PRODUCT_OF.keySet());
                Map<String, String> others = new java.util.LinkedHashMap<>();
                facts.resolved.forEach((k, v) -> { if (!productCoords.contains(k) && !k.startsWith("org.springframework.security:")) others.put(k, v); });
                facts.transitive.putAll(osv.queryCoords(others));
            }
            facts.osv = "조회 " + vulns.size() + "개 제품" + (facts.resolved.isEmpty() ? "" : " + 전이 " + facts.transitive.size() + "개 아티팩트")
                    + (osv.failed().isEmpty() ? "" : ", 실패 " + osv.failed().size() + "건 → 스냅샷");
            Eol eol = new Eol();
            rules = new Rules(rules.version(), rules.jdk27Defaults(), eol.merge(rules.eol()), rules.eolWarnDays(), rules.cves(), rules.bootBom());
            facts.eolSrc = "endoflife.date" + (eol.failed().isEmpty() ? "" : "(실패 " + eol.failed() + " 는 rules.json)");
        }
        List<Finding> findings = new java.util.ArrayList<>(new Evaluator(rules, LocalDate.now(), vulns, central).evaluate(facts));
        Ignore ignore = Ignore.load(root);
        facts.suppressed = ignore.apply(findings);
        ignore.invalid.forEach(x -> facts.ignoreNotes.add("무효한 억제 줄: " + x));
        ignore.expired.forEach(x -> facts.ignoreNotes.add("억제 만료로 재등장: " + x));
        if (suggest) {
            System.out.print(Report.suggest(rules, vulns));
            return;
        }
        System.out.print(sarif ? Report.sarif(rules, facts, findings) : json ? Report.json(facts, findings) : Report.markdown(rules, facts, findings));
        if (failOn != null) {
            List<String> order = List.of("critical", "high", "medium", "low", "info");
            int limit = order.indexOf(failOn);
            boolean hit = findings.stream().anyMatch(x -> order.indexOf(x.severity()) <= limit);
            if (hit) {
                System.err.println("--fail-on " + failOn + ": 해당 심각도 이상 항목이 있어 종료 코드 1");
                System.exit(1);
            }
        }
    }

    private static void usage(String reason) {
        System.err.println(reason);
        System.err.println("사용: java -jar jvm-risk-scanner.jar [디렉터리] [--json | --sarif] [--rules 경로] [--deps 해석출력] [--offline] [--suggest] [--fail-on 심각도]");
        System.exit(2);
    }
}
