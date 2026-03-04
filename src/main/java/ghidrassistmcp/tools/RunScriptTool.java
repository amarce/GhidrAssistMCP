package ghidrassistmcp.tools;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
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
        List<Throwable> failures = new ArrayList<>();

        for (Method method : utilClass.getMethods()) {
            if (!Modifier.isStatic(method.getModifiers())) {
                continue;
            }
            if (!method.getName().toLowerCase(Locale.ROOT).contains("runscript")) {
                continue;
            }
            try {
                Object[] args = buildInvocationArgs(method.getParameterTypes(), scriptFile, ghidraState, taskMonitor,
                    stdoutPw, stderrPw);
                if (args == null) {
                    continue;
                }
                return method.invoke(null, args);
            } catch (Exception e) {
                failures.add(e);
            }
        }

        throw new IllegalStateException("Unable to execute script with GhidraScriptUtil runScript overloads. " +
            "Attempted overload failures: " + failures.size());
    }

    private Object[] buildInvocationArgs(Class<?>[] parameterTypes, File scriptFile, Object ghidraState,
            Object taskMonitor, PrintWriter stdoutPw, PrintWriter stderrPw) {
        Object[] args = new Object[parameterTypes.length];
        for (int i = 0; i < parameterTypes.length; i++) {
            Class<?> type = parameterTypes[i];
            Object value;

            if (type == String.class) {
                value = scriptFile.getAbsolutePath();
            } else if (File.class.isAssignableFrom(type)) {
                value = scriptFile;
            } else if (PrintWriter.class.isAssignableFrom(type)) {
                value = (i == 0 || stdoutPw == null) ? stdoutPw : stderrPw;
            } else if (taskMonitor != null && type.isInstance(taskMonitor)) {
                value = taskMonitor;
            } else if (ghidraState != null && type.isInstance(ghidraState)) {
                value = ghidraState;
            } else if (isResourceFileType(type)) {
                value = createResourceFile(scriptFile, type);
            } else if (type == boolean.class || type == Boolean.class) {
                value = Boolean.FALSE;
            } else if (type == int.class || type == Integer.class) {
                value = Integer.valueOf(0);
            } else if (!type.isPrimitive()) {
                value = null;
            } else {
                return null;
            }
            args[i] = value;
        }
        return args;
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
