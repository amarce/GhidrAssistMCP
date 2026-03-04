package ghidrassistmcp.tools;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Execute inline Ghidra scripts (python/java) through Ghidra's script infrastructure.
 */
public class RunScriptTool implements McpTool {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final long DEFAULT_TIMEOUT_MS = 30000L;
    private static final long MIN_TIMEOUT_MS = 1000L;
    private static final long MAX_TIMEOUT_MS = 300000L;
    private static final int MAX_OUTPUT_CHARS = 16000;
    private static final Set<String> MUTATION_HINTS = Set.of(
        "starttransaction", "endtransaction", "set", "create", "delete", "remove", "rename",
        "disassemble", "addfunction", "clearlisting", "write", "save", "commit", "apply"
    );

    @Override
    public String getName() {
        return "run_script";
    }

    @Override
    public String getDescription() {
        return "⚠️ HIGH RISK: Executes inline Python/Java Ghidra scripts against the current program context";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean supportsAsync() {
        return true;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "code", Map.of(
                    "type", "string",
                    "description", "Inline Ghidra script source code (required). Local script paths are not accepted."
                ),
                "language", Map.of(
                    "type", "string",
                    "enum", List.of("python", "java"),
                    "default", "python",
                    "description", "Script language"
                ),
                "timeout_ms", Map.of(
                    "type", "integer",
                    "description", "Optional script timeout in milliseconds"
                ),
                "mode", Map.of(
                    "type", "string",
                    "enum", List.of("read_only", "full"),
                    "default", "read_only",
                    "description", "Execution mode. read_only blocks likely mutating scripts; full allows mutating scripts when destructive execution is confirmed."
                ),
                "capture_stdout", Map.of(
                    "type", "boolean",
                    "description", "Capture script stdout/stderr into tool result"
                )
            ),
            List.of("code"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return errorResult("No program currently loaded");
        }

        String code = asString(arguments.get("code"));
        if (code == null || code.isBlank()) {
            return errorResult("code is required and must contain inline script source");
        }

        if (containsPathLikeArguments(arguments)) {
            return errorResult("run_script accepts inline code only; do not provide script path arguments");
        }

        String language = normalizeLanguage(asString(arguments.get("language")));
        if (!Objects.equals(language, "python") && !Objects.equals(language, "java")) {
            return errorResult("language must be one of: python, java");
        }

        String mode = normalizeMode(asString(arguments.get("mode")));
        if (!Objects.equals(mode, "read_only") && !Objects.equals(mode, "full")) {
            return errorResult("mode must be one of: read_only, full");
        }

        if (!isDestructiveAllowed(arguments, backend)) {
            return errorResult("run_script requires confirm_destructive=true unless allow_destructive_tools is enabled in plugin configuration");
        }

        if ("read_only".equals(mode) && appearsMutatingScript(code, language)) {
            return errorResult("Script appears to use mutating/transaction APIs and is blocked in read_only mode. Use mode=full when mutation is intended.");
        }

        long timeoutMs = clampTimeout(asLong(arguments.get("timeout_ms"), DEFAULT_TIMEOUT_MS));
        boolean captureStdout = asBoolean(arguments.get("capture_stdout"), true);
        long startedAt = System.currentTimeMillis();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", getName());
        response.put("program", currentProgram.getName());
        response.put("language", language);
        response.put("mode", mode);
        response.put("timeout_ms", timeoutMs);
        response.put("source", "inline_code");
        response.put("task_cancellable", isTaskManagedExecution(backend));

        File scriptFile = null;
        try {
            scriptFile = writeTempScript(code, language);
            final File executableScriptFile = scriptFile;
            ScriptExecutionResult execution = executeWithTimeout(
                () -> runScriptWithGhidraInfrastructure(executableScriptFile, currentProgram, backend, captureStdout),
                timeoutMs);

            response.put("status", execution.status);
            if (captureStdout) {
                response.put("stdout", trimOutput(execution.stdout));
                response.put("stderr", trimOutput(execution.stderr));
            }
            response.put("result", trimOutput(safeStringify(execution.resultObject)));
            response.put("duration_ms", System.currentTimeMillis() - startedAt);
            logAudit(currentProgram.getName(), mode, timeoutMs, System.currentTimeMillis() - startedAt, "completed");
            return McpSchema.CallToolResult.builder().addTextContent(toJson(response)).build();
        } catch (TimeoutException e) {
            response.put("status", "timeout");
            response.put("error", "Script execution exceeded timeout");
            response.put("duration_ms", System.currentTimeMillis() - startedAt);
            logAudit(currentProgram.getName(), mode, timeoutMs, System.currentTimeMillis() - startedAt, "timeout");
            return McpSchema.CallToolResult.builder().addTextContent(toJson(response)).build();
        } catch (InterruptedException | CancellationException e) {
            Thread.currentThread().interrupt();
            response.put("status", "cancelled");
            response.put("error", "Script execution was cancelled");
            response.put("duration_ms", System.currentTimeMillis() - startedAt);
            logAudit(currentProgram.getName(), mode, timeoutMs, System.currentTimeMillis() - startedAt, "cancelled");
            return McpSchema.CallToolResult.builder().addTextContent(toJson(response)).build();
        } catch (Exception e) {
            response.put("status", "error");
            response.put("error", sanitizeExceptionMessage(e));
            response.put("duration_ms", System.currentTimeMillis() - startedAt);
            logAudit(currentProgram.getName(), mode, timeoutMs, System.currentTimeMillis() - startedAt, "error");
            return McpSchema.CallToolResult.builder().addTextContent(toJson(response)).build();
        } finally {
            if (scriptFile != null) {
                scriptFile.delete();
            }
        }
    }

    private ScriptExecutionResult runScriptWithGhidraInfrastructure(File scriptFile, Program currentProgram,
            GhidrAssistMCPBackend backend, boolean captureStdout) throws Exception {
        StringWriter stdoutSw = new StringWriter();
        StringWriter stderrSw = new StringWriter();
        PrintWriter stdoutPw = captureStdout ? new PrintWriter(stdoutSw, true) : null;
        PrintWriter stderrPw = captureStdout ? new PrintWriter(stderrSw, true) : null;

        Object taskMonitor = getDummyTaskMonitor();
        Object ghidraState = createGhidraState(currentProgram, backend);
        Object scriptResult = invokeViaScriptUtil(scriptFile, ghidraState, taskMonitor, stdoutPw, stderrPw);

        if (captureStdout) {
            stdoutPw.flush();
            stderrPw.flush();
        }

        return new ScriptExecutionResult(
            "completed",
            captureStdout ? stdoutSw.toString() : null,
            captureStdout ? stderrSw.toString() : null,
            scriptResult);
    }

    private Object invokeViaScriptUtil(File scriptFile, Object ghidraState, Object taskMonitor,
            PrintWriter stdoutPw, PrintWriter stderrPw) throws Exception {
        Class<?> utilClass = Class.forName("ghidra.app.script.GhidraScriptUtil");
        return invokeViaScriptUtil(scriptFile, ghidraState, taskMonitor, stdoutPw, stderrPw, utilClass);
    }

    Object invokeViaScriptUtil(File scriptFile, Object ghidraState, Object taskMonitor,
            PrintWriter stdoutPw, PrintWriter stderrPw, Class<?> utilClass) throws Exception {
        List<Method> discoveredRunScriptMethods = discoverRunScriptMethods(utilClass);
        List<MethodInvocationPlan> supportedPlans = discoverSupportedRunScriptPlans(discoveredRunScriptMethods);
        if (supportedPlans.isEmpty()) {
            throw new IllegalStateException("Unable to execute script with GhidraScriptUtil: no supported runScript signatures were found. " +
                "Discovered runScript signatures: " + formatMethodSignatures(discoveredRunScriptMethods));
        }

        List<String> failures = new ArrayList<>();
        Throwable lastFailure = null;
        for (MethodInvocationPlan plan : supportedPlans) {
            try {
                Object[] args = buildInvocationArgs(plan, scriptFile, ghidraState, taskMonitor, stdoutPw, stderrPw);
                return plan.method.invoke(null, args);
            } catch (Exception e) {
                Throwable rootCause = rootCause(e);
                String signature = formatMethodSignature(plan.method);
                Msg.warn(RunScriptTool.class,
                    "run_script invocation failed for signature " + signature + ": " + rootCause.getClass().getName() +
                        ": " + (rootCause.getMessage() == null ? "<no-message>" : rootCause.getMessage()));
                failures.add(signature + " -> " + rootCause.getClass().getSimpleName() +
                    (rootCause.getMessage() == null ? "" : (": " + rootCause.getMessage())));
                lastFailure = rootCause;
            }
        }

        String message = "Unable to execute script with supported GhidraScriptUtil.runScript signatures. " +
            "Attempted signatures: " + failures;
        if (lastFailure instanceof Exception ex) {
            throw new IllegalStateException(message, ex);
        }
        throw new IllegalStateException(message);
    }

    private List<Method> discoverRunScriptMethods(Class<?> utilClass) {
        List<Method> methods = new ArrayList<>();
        collectRunScriptMethods(methods, utilClass.getMethods());
        collectRunScriptMethods(methods, utilClass.getDeclaredMethods());
        return methods;
    }

    private static void collectRunScriptMethods(List<Method> out, Method[] candidates) {
        for (Method method : candidates) {
            if (!Modifier.isStatic(method.getModifiers())) {
                continue;
            }
            String name = method.getName();
            if (!name.equals("runScript") && !name.startsWith("runScript")) {
                continue;
            }
            if (!out.contains(method)) {
                try {
                    method.setAccessible(true);
                } catch (Exception ignored) {
                    // best effort
                }
                out.add(method);
            }
        }
    }

    private List<MethodInvocationPlan> discoverSupportedRunScriptPlans(List<Method> runScriptMethods) {
        List<MethodInvocationPlan> plans = new ArrayList<>();
        for (Method method : runScriptMethods) {
            MethodInvocationPlan plan = createInvocationPlan(method);
            if (plan != null) {
                plans.add(plan);
            }
        }
        plans.sort((a, b) -> Integer.compare(b.parameterKinds.size(), a.parameterKinds.size()));
        return plans;
    }

    private MethodInvocationPlan createInvocationPlan(Method method) {
        Class<?>[] parameterTypes = method.getParameterTypes();
        List<InvocationArgKind> kinds = new ArrayList<>();
        boolean stdoutAssigned = false;
        boolean stderrAssigned = false;

        for (int i = 0; i < parameterTypes.length; i++) {
            Class<?> type = parameterTypes[i];
            if (i == 0 && (type == String.class || File.class.isAssignableFrom(type) || isResourceFileType(type))) {
                kinds.add(InvocationArgKind.SCRIPT_SOURCE);
            } else if (isTaskMonitorType(type)) {
                kinds.add(InvocationArgKind.TASK_MONITOR);
            } else if (isGhidraStateType(type)) {
                kinds.add(InvocationArgKind.GHIDRA_STATE);
            } else if (isScriptInfoType(type)) {
                kinds.add(InvocationArgKind.SCRIPT_INFO);
            } else if (isGhidraScriptType(type)) {
                kinds.add(InvocationArgKind.GHIDRA_SCRIPT);
            } else if (PrintWriter.class.isAssignableFrom(type)) {
                if (!stdoutAssigned) {
                    kinds.add(InvocationArgKind.STDOUT);
                    stdoutAssigned = true;
                } else if (!stderrAssigned) {
                    kinds.add(InvocationArgKind.STDERR);
                    stderrAssigned = true;
                } else {
                    return null;
                }
            } else {
                return null;
            }
        }

        if (!kinds.contains(InvocationArgKind.SCRIPT_SOURCE)) {
            return null;
        }
        return new MethodInvocationPlan(method, kinds);
    }

    private Object[] buildInvocationArgs(MethodInvocationPlan plan, File scriptFile, Object ghidraState,
            Object taskMonitor, PrintWriter stdoutPw, PrintWriter stderrPw) {
        Class<?>[] parameterTypes = plan.method.getParameterTypes();
        Object[] args = new Object[parameterTypes.length];
        for (int i = 0; i < parameterTypes.length; i++) {
            Class<?> type = parameterTypes[i];
            InvocationArgKind kind = plan.parameterKinds.get(i);
            args[i] = switch (kind) {
                case SCRIPT_SOURCE -> mapScriptSource(type, scriptFile);
                case GHIDRA_STATE -> ghidraState;
                case TASK_MONITOR -> taskMonitor;
                case STDOUT -> stdoutPw;
                case STDERR -> stderrPw;
                case SCRIPT_INFO -> createScriptInfo(scriptFile);
                case GHIDRA_SCRIPT -> createScriptInstance(scriptFile, stdoutPw);
            };

            if (args[i] == null && parameterTypes[i].isPrimitive()) {
                return null;
            }
        }
        return args;
    }

    private static Object mapScriptSource(Class<?> type, File scriptFile) {
        if (type == String.class) {
            return scriptFile.getAbsolutePath();
        }
        if (File.class.isAssignableFrom(type)) {
            return scriptFile;
        }
        if (isResourceFileType(type)) {
            return createResourceFile(scriptFile, type);
        }
        return null;
    }

    private static boolean isTaskMonitorType(Class<?> type) {
        return type.getName().equals("ghidra.util.task.TaskMonitor");
    }

    private static boolean isGhidraStateType(Class<?> type) {
        return type.getName().equals("ghidra.app.script.GhidraState");
    }

    private static boolean isScriptInfoType(Class<?> type) {
        return type.getName().equals("ghidra.app.script.ScriptInfo");
    }

    private static boolean isGhidraScriptType(Class<?> type) {
        return type.getName().equals("ghidra.app.script.GhidraScript");
    }

    private Object createScriptInfo(File scriptFile) {
        try {
            Class<?> utilClass = Class.forName("ghidra.app.script.GhidraScriptUtil");
            Object resourceFile = createResourceFile(scriptFile, Class.forName("generic.jar.ResourceFile"));
            if (resourceFile == null) {
                return null;
            }

            for (Method method : utilClass.getMethods()) {
                if (!Modifier.isStatic(method.getModifiers()) || !method.getName().equals("getScriptInfo")) {
                    continue;
                }
                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length != 1 || !parameterTypes[0].isInstance(resourceFile)) {
                    continue;
                }
                return method.invoke(null, resourceFile);
            }
        } catch (Exception ignored) {
            // best effort
        }
        return null;
    }

    private Object createScriptInstance(File scriptFile, PrintWriter writer) {
        try {
            Object scriptInfo = createScriptInfo(scriptFile);
            if (scriptInfo == null) {
                return null;
            }
            Method getProvider = scriptInfo.getClass().getMethod("getProvider");
            Object provider = getProvider.invoke(scriptInfo);
            if (provider == null) {
                return null;
            }

            for (Method method : provider.getClass().getMethods()) {
                if (!method.getName().equals("getScriptInstance")) {
                    continue;
                }
                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length == 2 && isScriptInfoType(parameterTypes[0]) && PrintWriter.class.isAssignableFrom(parameterTypes[1])) {
                    return method.invoke(provider, scriptInfo, writer);
                }
                if (parameterTypes.length == 1 && isScriptInfoType(parameterTypes[0])) {
                    return method.invoke(provider, scriptInfo);
                }
            }
        } catch (Exception ignored) {
            // best effort
        }
        return null;
    }

    private static Throwable rootCause(Exception exception) {
        Throwable current = exception;
        if (current instanceof InvocationTargetException ite && ite.getCause() != null) {
            current = ite.getCause();
        }
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }

    private static String formatMethodSignatures(List<Method> methods) {
        if (methods.isEmpty()) {
            return "<none>";
        }
        List<String> signatures = new ArrayList<>();
        for (Method method : methods) {
            signatures.add(formatMethodSignature(method));
        }
        return signatures.toString();
    }

    private static String formatMethodSignature(Method method) {
        StringBuilder sb = new StringBuilder(method.getName()).append('(');
        Class<?>[] parameterTypes = method.getParameterTypes();
        for (int i = 0; i < parameterTypes.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(parameterTypes[i].getTypeName());
        }
        return sb.append(')').toString();
    }

    private static class MethodInvocationPlan {
        private final Method method;
        private final List<InvocationArgKind> parameterKinds;

        MethodInvocationPlan(Method method, List<InvocationArgKind> parameterKinds) {
            this.method = method;
            this.parameterKinds = parameterKinds;
        }
    }

    private enum InvocationArgKind {
        SCRIPT_SOURCE,
        GHIDRA_STATE,
        TASK_MONITOR,
        STDOUT,
        STDERR,
        SCRIPT_INFO,
        GHIDRA_SCRIPT
    }

    private Object createGhidraState(Program currentProgram, GhidrAssistMCPBackend backend) {
        try {
            Class<?> stateClass = Class.forName("ghidra.app.script.GhidraState");
            Object pluginTool = null;
            if (backend != null) {
                GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
                pluginTool = getPluginTool(plugin);
            }

            for (Constructor<?> ctor : stateClass.getConstructors()) {
                Object[] values = tryBuildStateCtorArgs(ctor.getParameterTypes(), pluginTool, currentProgram);
                if (values != null) {
                    return ctor.newInstance(values);
                }
            }

            Object state = stateClass.getDeclaredConstructor().newInstance();
            tryInvokeNoThrow(state, "setCurrentProgram", currentProgram);
            return state;
        } catch (Exception ignored) {
            return null;
        }
    }

    private Object[] tryBuildStateCtorArgs(Class<?>[] parameterTypes, Object pluginTool, Program currentProgram) {
        Object[] args = new Object[parameterTypes.length];
        for (int i = 0; i < parameterTypes.length; i++) {
            Class<?> type = parameterTypes[i];
            if (pluginTool != null && type.isInstance(pluginTool)) {
                args[i] = pluginTool;
            } else if (Program.class.isAssignableFrom(type)) {
                args[i] = currentProgram;
            } else if (type.isPrimitive()) {
                return null;
            } else {
                args[i] = null;
            }
        }
        return args;
    }

    private Object getPluginTool(GhidrAssistMCPPlugin plugin) {
        if (plugin == null) {
            return null;
        }
        Class<?> cls = plugin.getClass();
        while (cls != null) {
            try {
                Field toolField = cls.getDeclaredField("tool");
                toolField.setAccessible(true);
                return toolField.get(plugin);
            } catch (Exception ignored) {
                cls = cls.getSuperclass();
            }
        }
        return null;
    }

    private Object getDummyTaskMonitor() {
        try {
            Class<?> monitorClass = Class.forName("ghidra.util.task.TaskMonitor");
            Field dummyField = monitorClass.getField("DUMMY");
            return dummyField.get(null);
        } catch (Exception e) {
            return null;
        }
    }

    private static <T> T executeWithTimeout(Callable<T> callable, long timeoutMs) throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<T> future = executor.submit(callable);
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw e;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception ex) {
                throw ex;
            }
            throw new RuntimeException(cause);
        } finally {
            executor.shutdownNow();
        }
    }

    private static File writeTempScript(String code, String language) throws Exception {
        String extension = "python".equals(language) ? ".py" : ".java";
        File file = File.createTempFile("ghidrassist_inline_", extension);
        Files.writeString(file.toPath(), code, StandardCharsets.UTF_8);
        return file;
    }

    private static boolean isResourceFileType(Class<?> type) {
        return type.getName().equals("generic.jar.ResourceFile");
    }

    private static Object createResourceFile(File file, Class<?> resourceFileType) {
        try {
            Constructor<?> ctor = resourceFileType.getConstructor(File.class);
            return ctor.newInstance(file);
        } catch (Exception ignored) {
            try {
                Constructor<?> ctor = resourceFileType.getConstructor(String.class);
                return ctor.newInstance(file.getAbsolutePath());
            } catch (Exception e) {
                return null;
            }
        }
    }

    private static void tryInvokeNoThrow(Object target, String methodName, Object argument) {
        if (target == null) {
            return;
        }
        try {
            Method method = target.getClass().getMethod(methodName, argument.getClass());
            method.invoke(target, argument);
        } catch (Exception ignored) {
            // best effort
        }
    }


    private static boolean containsPathLikeArguments(Map<String, Object> arguments) {
        return arguments.containsKey("path") || arguments.containsKey("script_path") || arguments.containsKey("file");
    }

    private static String asString(Object value) {
        return value instanceof String ? (String) value : null;
    }

    private static boolean asBoolean(Object value, boolean defaultValue) {
        if (value instanceof Boolean b) {
            return b;
        }
        return defaultValue;
    }

    private static long asLong(Object value, long defaultValue) {
        if (value instanceof Number n) {
            return n.longValue();
        }
        return defaultValue;
    }

    private static String normalizeLanguage(String language) {
        return (language == null || language.isBlank()) ? "python" : language.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeMode(String mode) {
        return (mode == null || mode.isBlank()) ? "read_only" : mode.trim().toLowerCase(Locale.ROOT);
    }

    private static long clampTimeout(long timeoutMs) {
        if (timeoutMs < MIN_TIMEOUT_MS) {
            return MIN_TIMEOUT_MS;
        }
        if (timeoutMs > MAX_TIMEOUT_MS) {
            return MAX_TIMEOUT_MS;
        }
        return timeoutMs;
    }

    private static String trimOutput(String text) {
        if (text == null || text.length() <= MAX_OUTPUT_CHARS) {
            return text;
        }
        return text.substring(0, MAX_OUTPUT_CHARS) + "\n...[truncated]";
    }

    private static String sanitizeExceptionMessage(Exception e) {
        String message = e.getMessage();
        if (message == null || message.isBlank()) {
            return "Script execution failed";
        }
        String redacted = message
            .replaceAll("(?i)(token|password|secret|apikey|api_key)\\s*[=:]\\s*[^\\s,;]+", "$1=<redacted>")
            .replaceAll("(/[A-Za-z0-9._-]+)+", "<path>");
        return trimOutput(redacted);
    }

    private static boolean appearsMutatingScript(String code, String language) {
        if (code == null) {
            return false;
        }
        String normalized = code.toLowerCase(Locale.ROOT);
        if ("python".equals(language) || "java".equals(language)) {
            for (String hint : MUTATION_HINTS) {
                if (normalized.contains(hint)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isDestructiveAllowed(Map<String, Object> arguments, GhidrAssistMCPBackend backend) {
        boolean globallyAllowed = backend != null && backend.isAllowDestructiveTools();
        return globallyAllowed || asBoolean(arguments.get("confirm_destructive"), false);
    }

    private static boolean isTaskManagedExecution(GhidrAssistMCPBackend backend) {
        if (backend == null || backend.getTaskManager() == null) {
            return false;
        }
        return Thread.currentThread().getName().startsWith("MCP-Task-");
    }

    private static void logAudit(String program, String mode, long timeoutMs, long durationMs, String outcome) {
        Msg.info(RunScriptTool.class,
            "tool=run_script program=" + program + " mode=" + mode +
            " duration_ms=" + durationMs + " timeout_ms=" + timeoutMs + " outcome=" + outcome);
    }

    private static String safeStringify(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return value.toString();
        } catch (Exception e) {
            return "<unprintable: " + value.getClass().getName() + ">";
        }
    }

    private static String toJson(Map<String, Object> map) {
        try {
            return OBJECT_MAPPER.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            return map.toString();
        }
    }

    private static McpSchema.CallToolResult errorResult(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "error");
        body.put("error", message);
        return McpSchema.CallToolResult.builder().addTextContent(toJson(body)).build();
    }

    private static class ScriptExecutionResult {
        private final String status;
        private final String stdout;
        private final String stderr;
        private final Object resultObject;

        ScriptExecutionResult(String status, String stdout, String stderr, Object resultObject) {
            this.status = status;
            this.stdout = stdout;
            this.stderr = stderr;
            this.resultObject = resultObject;
        }
    }
}
