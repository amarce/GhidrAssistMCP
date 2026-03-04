package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;

import ghidra.app.script.GhidraState;
import ghidra.util.task.TaskMonitor;

class RunScriptToolTest {

    @Test
    void invokeViaScriptUtil_mapsPythonStringSignatureAndWriters() throws Exception {
        RunScriptTool tool = new RunScriptTool();
        File script = File.createTempFile("test_script", ".py");
        Files.writeString(script.toPath(), "print('hello')");

        StringWriter stdoutBuffer = new StringWriter();
        StringWriter stderrBuffer = new StringWriter();
        Object result = tool.invokeViaScriptUtil(
            script,
            new GhidraState(),
            new TaskMonitor(),
            new PrintWriter(stdoutBuffer, true),
            new PrintWriter(stderrBuffer, true),
            PythonRunScriptUtil.class);

        assertEquals("python-path", result);
        assertTrue(stdoutBuffer.toString().contains("stdout-ok"));
        assertTrue(stderrBuffer.toString().contains("stderr-ok"));
    }

    @Test
    void invokeViaScriptUtil_fallsBackToFileSignatureForJava() throws Exception {
        RunScriptTool tool = new RunScriptTool();
        File script = File.createTempFile("test_script", ".java");
        Files.writeString(script.toPath(), "class Test {}\n");

        Object result = tool.invokeViaScriptUtil(
            script,
            new GhidraState(),
            new TaskMonitor(),
            null,
            null,
            JavaRunScriptUtil.class);

        assertEquals("java-file", result);
    }

    @Test
    void invokeViaScriptUtil_reportsDiscoveredSignaturesWhenUnsupported() throws Exception {
        RunScriptTool tool = new RunScriptTool();
        File script = File.createTempFile("test_script", ".py");
        Files.writeString(script.toPath(), "print('hello')");

        try {
            tool.invokeViaScriptUtil(
                script,
                new GhidraState(),
                new TaskMonitor(),
                null,
                null,
                UnsupportedRunScriptUtil.class);
        } catch (IllegalStateException e) {
            assertNotNull(e.getMessage());
            assertTrue(e.getMessage().contains("Discovered runScript signatures"));
            assertTrue(e.getMessage().contains("runScript(java.lang.String, java.lang.String, java.lang.String)"));
            return;
        }

        throw new AssertionError("Expected IllegalStateException for unsupported signatures");
    }

    public static class PythonRunScriptUtil {
        public static Object runScript(String path, GhidraState state, TaskMonitor monitor, PrintWriter stdout,
                PrintWriter stderr) {
            if (stdout != null) {
                stdout.write("stdout-ok:" + path);
            }
            if (stderr != null) {
                stderr.write("stderr-ok:" + path);
            }
            return path.endsWith(".py") ? "python-path" : "wrong-script";
        }

        public static Object runScript(String a, String b, TaskMonitor monitor) {
            return "unsupported";
        }
    }

    public static class JavaRunScriptUtil {
        public static Object runScript(String path, GhidraState state, TaskMonitor monitor) {
            throw new IllegalStateException("string-overload failure");
        }

        public static Object runScript(File path, GhidraState state, TaskMonitor monitor) {
            return path.getName().endsWith(".java") ? "java-file" : "wrong-extension";
        }
    }

    public static class UnsupportedRunScriptUtil {
        public static Object runScript(String a, String b, String c) {
            return "nope";
        }
    }
}
