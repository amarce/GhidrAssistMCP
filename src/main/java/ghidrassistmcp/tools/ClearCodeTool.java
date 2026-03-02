package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class ClearCodeTool implements McpTool {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isDestructive() { return true; }

    @Override
    public String getName() { return "clear_code"; }

    @Override
    public String getDescription() { return "Clear code units/instructions in a range so re-disassembly is possible"; }

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
        if (start == null || end == null) {
            response.put("success", false);
            response.put("error", "Invalid start/end address");
            return result(response);
        }
        if (start.compareTo(end) > 0) {
            response.put("success", false);
            response.put("error", "start must be <= end");
            return result(response);
        }

        int tx = currentProgram.startTransaction("Clear code range");
        boolean commit = false;
        try {
            currentProgram.getListing().clearCodeUnits(start, end, false);
            commit = true;
            response.put("success", true);
            response.put("program", currentProgram.getName());
            response.put("start", start.toString());
            response.put("end", end.toString());
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", "Failed clearing code units: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, commit);
        }

        return result(response);
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof String ? (String) value : null;
    }

    private McpSchema.CallToolResult result(ObjectNode response) {
        return McpSchema.CallToolResult.builder().addTextContent(response.toPrettyString()).build();
    }
}
