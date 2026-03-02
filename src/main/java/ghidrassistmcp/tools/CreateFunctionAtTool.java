package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class CreateFunctionAtTool implements McpTool {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isDestructive() { return true; }

    @Override
    public String getName() { return "create_function_at"; }

    @Override
    public String getDescription() { return "Create a function at an entry address and return resulting function range"; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "entry", Map.of("type", "string", "description", "Function entry address"),
            "name", Map.of("type", "string", "description", "Optional function name")
        ), List.of("entry"), null, null, null);
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

        String entryStr = getString(arguments, "entry");
        String name = getString(arguments, "name");
        if (entryStr == null) {
            response.put("success", false);
            response.put("error", "entry is required");
            return result(response);
        }

        Address entry = currentProgram.getAddressFactory().getAddress(entryStr);
        if (entry == null) {
            response.put("success", false);
            response.put("error", "Invalid entry address: " + entryStr);
            return result(response);
        }

        int tx = currentProgram.startTransaction("Create function at address");
        boolean commit = false;
        try {
            Function existing = currentProgram.getFunctionManager().getFunctionAt(entry);
            Function function;
            if (existing != null) {
                function = existing;
                if (name != null && !name.isBlank()) {
                    function.setName(name, SourceType.USER_DEFINED);
                    commit = true;
                }
            } else {
                function = currentProgram.getListing().createFunction(name, entry, new AddressSet(entry), SourceType.USER_DEFINED);
                commit = function != null;
            }

            if (function == null) {
                response.put("success", false);
                response.put("error", "Unable to create function at entry");
            } else {
                response.put("success", true);
                response.put("program", currentProgram.getName());
                response.put("entry", function.getEntryPoint().toString());
                response.put("name", function.getName());
                response.put("range", function.getBody().toString());
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", "Failed creating function: " + e.getMessage());
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
