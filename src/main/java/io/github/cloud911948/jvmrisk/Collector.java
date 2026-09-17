package io.github.cloud911948.jvmrisk;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 빌드 파일·Dockerfile·설정에서 JDK 버전, JVM 플래그, Spring 의존성 버전, 컨테이너 이미지를 정규식으로 긁는다.
 * Gradle/Maven 파서를 쓰지 않는 건 의도다. 파서를 물리면 DSL 변형마다 깨지고, 정규식은 못 찾으면 "미확인"으로 남는다.
 * 오탐보다 미탐을 택한다.
 */
public final class Collector {

    static final Set<String> SKIP_DIRS = Set.of(".git", "node_modules", "build", "target", ".gradle", ".idea", "out", "logs", "log", "dist", ".next");
    private static final Set<String> BUILD_EXT = Set.of("gradle", "kts", "xml", "toml", "properties", "yml", "yaml", "sh", "env", "conf");
    private static final Set<String> SOURCE_EXT = Set.of("java", "kt");
    private static final long MAX_BYTES = 2_000_000;

    private static final Pattern JDK_TOOLCHAIN = Pattern.compile("languageVersion\\s*(?:=|\\.set\\()?\\s*(?:JavaLanguageVersion\\.of\\()?\\s*\\(?\\s*(\\d{1,2})");
    private static final Pattern JDK_COMPAT = Pattern.compile("(?:sourceCompatibility|targetCompatibility|maven\\.compiler\\.(?:release|source|target)|java\\.version)\\s*[=>:]*\\s*['\"]?(?:JavaVersion\\.VERSION_)?(?:1[._])?(\\d{1,2})");
    private static final Pattern JDK_IMAGE = Pattern.compile("FROM\\s+\\S*(?:temurin|openjdk|corretto|zulu|liberica|jdk|jre)[:\\-](\\d{1,2})", Pattern.CASE_INSENSITIVE);
    private static final Pattern XX_FLAG = Pattern.compile("-XX:[+\\-]\\w+(?:=\\w+)?");
    private static final Pattern AGENT = Pattern.compile("-(javaagent|agentpath|agentlib):(\\S+)");
    private static final Pattern JFR = Pattern.compile("StartFlightRecording|\\.jfc\\b|jcmd\\s+\\S+\\s+JFR");
    private static final Pattern BOOT_PLUGIN = Pattern.compile("id\\s*\\(?\\s*['\"]org\\.springframework\\.boot['\"]\\s*\\)?\\s*version\\s*\\(?\\s*['\"]([\\d.]+)");
    private static final Pattern BOOT_PROPERTY = Pattern.compile("springBootVersion\\s*=\\s*['\"]?([\\d.]+)");
    /** 그룹 prefix 를 반드시 요구한다. p6spy-spring-boot-starter 같은 서드파티가 Boot 버전으로 잡혔던 오탐 때문이다. */
    private static final Pattern BOOT_COORD = Pattern.compile("org\\.springframework\\.boot:spring-boot-(?:gradle-plugin|starter[\\w\\-]*|dependencies):([\\d.]+)");
    private static final Pattern BOOT_MVN_BOM = Pattern.compile("<dependencyManagement>.*?spring-boot-dependencies.*?<version>([\\d.]+)", Pattern.DOTALL);
    private static final Pattern BOOT_MVN_PROP = Pattern.compile("<(?:spring-boot|springboot)\\.version>([\\d.]+)");
    private static final Pattern BOOT_MVN_PARENT = Pattern.compile("<parent>.*?spring-boot-starter-parent.*?<version>([\\d.]+)", Pattern.DOTALL);
    private static final Pattern SECURITY = Pattern.compile("org\\.springframework\\.security[:\"'\\s]+spring-security-[\\w\\-]+[:\"'\\s]+([\\d.]+)");
    private static final Pattern SECURITY_PROP = Pattern.compile("spring-security\\.version\\s*[=>]+\\s*['\"]?([\\d.]+)|<spring-security\\.version>([\\d.]+)");
    private static final Pattern GRAPHQL = Pattern.compile("spring-graphql[:\"'\\s]+([\\d.]+)|<spring-graphql\\.version>([\\d.]+)");
    private static final Pattern FRAMEWORK = Pattern.compile("org\\.springframework[:\"'\\s]+spring-(?:core|context|web)[:\"'\\s]+([\\d.]+)");
    /** ext['tomcat.version'] = '9.0.102' 같은 Gradle ext 대괄호 꼴도 읽는다. 실측 저장소에서 이 한 줄을 놓쳐 9.0.65 로 추정했었다. */
    private static final Pattern NETTY = Pattern.compile("io\\.netty[:\"'\\s]+netty-(?:handler|all|codec-http2?|transport)[:\"'\\s]+([\\d.]+(?:\\.Final)?)|<netty\\.version>([\\d.]+(?:\\.Final)?)|netty\\.version['\"\\]]*\\s*[=:]\\s*['\"]?([\\d.]+(?:\\.Final)?)");
    private static final Pattern TOMCAT = Pattern.compile("org\\.apache\\.tomcat(?:\\.embed)?[:\"'\\s]+tomcat-[\\w\\-]+[:\"'\\s]+([\\d.]+)|<tomcat\\.version>([\\d.]+)|tomcat\\.version['\"\\]]*\\s*[=:]\\s*['\"]?([\\d.]+)");
    private static final Pattern IMAGE = Pattern.compile("(?:image:|FROM)\\s+(redis|tomcat)[:\\s]+v?([\\d.]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern UNSAFE = Pattern.compile("sun\\.misc\\.Unsafe|jdk\\.internal\\.misc\\.Unsafe");

    private final Rules rules;

    public Collector(Rules rules) {
        this.rules = rules;
    }

    public Facts collect(Path root) {
        Facts f = new Facts(root);
        Map<String, Pattern> evidence = new LinkedHashMap<>();
        for (Rules.Cve c : rules.cves()) {
            if (c.evidence() != null && !c.evidence().isEmpty()) evidence.put(c.id(), Pattern.compile(String.join("|", c.evidence())));
        }
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    // 디렉터리 이름만 본다. `bin/build` 같은 확장자 없는 스크립트 파일은 걸러지면 안 된다.
                    return !dir.equals(root) && SKIP_DIRS.contains(dir.getFileName().toString()) ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path p, BasicFileAttributes attrs) {
                    if (attrs.isRegularFile()) scanFile(f, root, p, evidence);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path p, IOException e) {
                    return FileVisitResult.CONTINUE; // 못 읽는 파일 하나 때문에 스캔 전체를 버리지 않는다
                }
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        if (!f.bootAll.isEmpty()) f.deps.put("spring-boot", f.bootAll.first()); // 멀티모듈에서 버전이 섞이면 가장 오래된 쪽이 위험 기준
        fillFromBom(f);
        return f;
    }

    /** 의존성 해석 출력이 있으면 대표 제품 버전을 실제 값으로 덮는다. BOM 추정보다 항상 우선. */
    public static void applyResolved(Facts f, Map<String, String> resolved) {
        if (resolved.isEmpty()) return;
        f.resolved.putAll(resolved);
        DepTree.PRODUCT_OF.forEach((coord, product) -> {
            String v = resolved.get(coord);
            if (v != null) {
                f.deps.put(product, v);
                f.src.put(product, "resolved");
            }
        });
    }

    private void scanFile(Facts f, Path root, Path p, Map<String, Pattern> evidence) {
        String name = p.getFileName().toString();
        String ext = ext(name);
        boolean build = BUILD_EXT.contains(ext) || ext.isEmpty() || name.startsWith("Dockerfile") || name.startsWith("docker-compose");
        boolean source = SOURCE_EXT.contains(ext);
        if (!build && !source) return;
        String text = read(p);
        if (text == null) return;
        String rel = root.relativize(p).toString().replace('\\', '/');
        // 소스 파일도 같은 정규식을 돌린다. ProcessBuilder 인자에 박힌 -XX 플래그나 테스트의 lincheck import 는 빌드 파일에 없다.
        scanText(f, name, text);
        if (source && UNSAFE.matcher(text).find()) f.unsafe.add(rel);
        // CVE 사용 흔적은 소스·빌드·설정을 가리지 않는다. 파일당 한 번 읽고 모든 CVE 패턴을 돌린다.
        evidence.forEach((id, pat) -> {
            if (!pat.matcher(text).find()) return;
            List<String> hits = f.evidence.computeIfAbsent(id, k -> new ArrayList<>());
            if (hits.size() < 3) hits.add(rel);
        });
    }

    private void scanText(Facts f, String name, String text) {
        find(JDK_TOOLCHAIN, text, m -> f.jdk.add(m.group(1)));
        find(JDK_COMPAT, text, m -> f.jdk.add(m.group(1)));
        find(JDK_IMAGE, text, m -> f.jdk.add(m.group(1)));
        find(XX_FLAG, text, m -> f.flags.add(m.group()));
        find(AGENT, text, m -> f.agents.add(m.group().length() > 80 ? m.group().substring(0, 80) : m.group()));
        if (JFR.matcher(text).find()) f.jfr = true;
        if (name.equals("libs.versions.toml")) Catalog.scan(text, f);
        find(BOOT_PLUGIN, text, m -> f.bootAll.add(m.group(1)));
        find(BOOT_PROPERTY, text, m -> f.bootAll.add(m.group(1)));
        find(BOOT_COORD, text, m -> f.bootAll.add(m.group(1)));
        find(BOOT_MVN_BOM, text, m -> f.bootAll.add(m.group(1)));
        find(BOOT_MVN_PROP, text, m -> f.bootAll.add(m.group(1)));
        find(BOOT_MVN_PARENT, text, m -> f.bootAll.add(m.group(1)));
        find(SECURITY, text, m -> f.deps.put("spring-security", m.group(1)));
        find(SECURITY_PROP, text, m -> f.deps.put("spring-security", first(m)));
        find(GRAPHQL, text, m -> f.deps.put("spring-graphql", first(m)));
        find(FRAMEWORK, text, m -> f.deps.put("spring-framework", m.group(1)));
        find(NETTY, text, m -> f.deps.put("netty", first(m)));
        find(TOMCAT, text, m -> f.deps.put("tomcat", first(m)));
        if (text.contains("org.openjdk.jol")) f.deps.put("jol", "?");
        if (text.contains("lincheck")) f.deps.put("lincheck", "?");
        find(IMAGE, text, m -> f.images.add(new Facts.Image(m.group(1).toLowerCase(), m.group(2))));
    }

    /** Boot 버전만 있고 Security/Framework/GraphQL 이 명시되지 않았으면 spring-boot-dependencies 표로 채운다. */
    private void fillFromBom(Facts f) {
        String boot = f.deps.get("spring-boot");
        if (boot == null) return;
        Map<String, String> row = rules.bootBom().get(boot);
        String tag = "bom";
        if (row == null) {
            // 표에 없는 패치면 같은 minor 에서 가장 가까운 아래 패치로 추정하고 bom~ 로 표시한다. 추측을 숨기지 않는다.
            String line = Version.line(boot);
            String nearest = rules.bootBom().keySet().stream()
                    .filter(v -> Version.line(v).equals(line) && Version.parse(v).compareTo(Version.parse(boot)) <= 0)
                    .max(Version.ORDER).orElse(null);
            if (nearest == null) return;
            row = rules.bootBom().get(nearest);
            tag = "bom~";
        }
        for (String k : List.of("spring-security", "spring-framework", "spring-graphql", "tomcat", "netty")) {
            if (!f.deps.containsKey(k) && row.get(k) != null) {
                f.deps.put(k, row.get(k));
                f.src.put(k, tag);
            }
        }
    }

    private static String read(Path p) {
        try {
            if (Files.size(p) >= MAX_BYTES) return null;
            return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private static String ext(String name) {
        int i = name.lastIndexOf('.');
        return i < 0 ? "" : name.substring(i + 1);
    }

    private static String first(Matcher m) {
        for (int i = 1; i <= m.groupCount(); i++) if (m.group(i) != null) return m.group(i);
        return null;
    }

    private static void find(Pattern p, String text, Consumer<Matcher> each) {
        Matcher m = p.matcher(text);
        while (m.find()) each.accept(m);
    }
}
