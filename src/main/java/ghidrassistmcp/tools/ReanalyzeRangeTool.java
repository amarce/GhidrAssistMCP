package ghidrassistmcp.tools;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class ReanalyzeRangeTool implements McpTool {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isDestructive() { return true; }

    @Override
    public boolean supportsAsync() { return true; }

    @Override
    public String getName() { return "reanalyze_range"; }

    @Override
    public String getDescription() { return "Run analysis passes on a specified range and refresh analysis/decompiler state"; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "start", Map.of("type", "string", "description", "Range start address"),
            "end", Map.of("type", "string", "description", "Range end address (inclusive)")
        ), List.of("start", "end"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        ObjectNode response = objectMapper.createObjectNode();
        response.put("tool", getName());

        if (currentProgram == null) {
            response.put("success", false);
            response.put("error", "No program currently loaded");
            return result(response);
        }

        String startStr = getString(arguments, "start");
        String endStr = getString(arguments, "end");
        if (startStr == null || endStr == null) {
            response.put("success", false);
            response.put("error", "start and end are required");
            return result(response);
        }

        Address start = currentProgram.getAddressFactory().getAddress(startStr);
        Address end = currentProgram.getAddressFactory().getAddress(endStr);
        if (start == null || end == null || start.compareTo(end) > 0) {
            response.put("success", false);
            response.put("error", "Invalid start/end range");
            return result(response);
        }

        try {
            AddressSet set = new AddressSet(start, end);
            runRangeAnalysis(currentProgram, set);
            response.put("success", true);
            response.put("program", currentProgram.getName());
            response.put("start", start.toString());
            response.put("end", end.toString());
            response.put("status", "analysis_completed");
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", "Range analysis failed: " + e.getMessage());
        }

        return result(response);
    }

    private static void runRangeAnalysis(Program program, AddressSet set) throws Exception {
        Class<?> aamClass = Class.forName("ghidra.app.plugin.core.analysis.AutoAnalysisManager");
        Method getAnalysisManager = aamClass.getMethod("getAnalysisManager", Program.class);
        Object manager = getAnalysisManager.invoke(null, program);

        boolean invoked = false;

        for (String methodName : List.of("reAnalyzeAll", "scheduleOneTimeAnalysis", "startAnalysis")) {
            for (Method method : manager.getClass().getMethods()) {
                if (!method.getName().equals(methodName)) {
                    continue;
                }
                Class<?>[] paramTypes = method.getParameterTypes();
                if (paramTypes.length == 1 && paramTypes[0].isAssignableFrom(set.getClass())) {
                    method.invoke(manager, set);
                    invoked = true;
                }
            }
        }

        Object monitor = getDummyTaskMonitor();
        for (Method method : manager.getClass().getMethods()) {
            if (!method.getName().equals("startAnalysis")) {
                continue;
            }
            Class<?>[] paramTypes = method.getParameterTypes();
            if (paramTypes.length == 1 && monitor != null && paramTypes[0].isInstance(monitor)) {
                method.invoke(manager, monitor);
                invoked = true;
            }
        }

        if (!invoked) {
            throw new IllegalStateException("No compatible AutoAnalysisManager method available for range analysis");
        }
    }

    private static Object getDummyTaskMonitor() {
        try {
            Class<?> taskMonitorClass = Class.forName("ghidra.util.task.TaskMonitor");
            Field dummy = taskMonitorClass.getField("DUMMY");
            return dummy.get(null);
        } catch (Exception e) {
            return null;
        }
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof String ? (String) value : null;
    }

    private McpSchema.CallToolResult result(ObjectNode response) {
        return McpSchema.CallToolResult.builder().addTextContent(response.toPrettyString()).build();
    }
}
