package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class GetBytesTool implements McpTool {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getName() {
        return "get_bytes";
    }

    @Override
    public String getDescription() {
        return "Read raw bytes at an address for deterministic verification";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "address", Map.of("type", "string", "description", "Start address"),
            "len", Map.of("type", "integer", "description", "Number of bytes to read")
        ), List.of("address", "len"), null, null, null);
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

        String addressStr = getString(arguments, "address");
        Number lenNumber = getNumber(arguments, "len");
        if (addressStr == null || lenNumber == null) {
            response.put("success", false);
            response.put("error", "address and len are required");
            return result(response);
        }

        int len = lenNumber.intValue();
        if (len < 0) {
            response.put("success", false);
            response.put("error", "len must be >= 0");
            return result(response);
        }

        Address address = currentProgram.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            response.put("success", false);
            response.put("error", "Invalid address: " + addressStr);
            return result(response);
        }

        byte[] bytes = new byte[len];
        try {
            currentProgram.getMemory().getBytes(address, bytes);
        } catch (MemoryAccessException e) {
            response.put("success", false);
            response.put("error", "Unable to read bytes: " + e.getMessage());
            return result(response);
        }

        response.put("success", true);
        response.put("program", currentProgram.getName());
        response.put("address", address.toString());
        response.put("len", len);
        response.put("bytes_hex", toHex(bytes));
        return result(response);
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof String ? (String) value : null;
    }

    private static Number getNumber(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof Number ? (Number) value : null;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }

    private McpSchema.CallToolResult result(ObjectNode response) {
        return McpSchema.CallToolResult.builder().addTextContent(response.toPrettyString()).build();
    }
}
