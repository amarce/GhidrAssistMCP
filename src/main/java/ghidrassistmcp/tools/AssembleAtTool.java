package ghidrassistmcp.tools;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class AssembleAtTool implements McpTool {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public boolean isDestructive() { return true; }

    @Override
    public String getName() { return "assemble_at"; }

    @Override
    public String getDescription() { return "Assemble instructions at address, patch bytes, and report emitted bytes with diagnostics"; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "address", Map.of("type", "string", "description", "Start address for emitted code"),
            "asm_lines", Map.of("type", "array", "items", Map.of("type", "string"), "description", "Assembly instructions")
        ), List.of("address", "asm_lines"), null, null, null);
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
        List<String> asmLines = getStringList(arguments.get("asm_lines"));
        if (addressStr == null || asmLines == null) {
            response.put("success", false);
            response.put("error", "address and asm_lines are required");
            return result(response);
        }

        Address current = currentProgram.getAddressFactory().getAddress(addressStr);
        if (current == null) {
            response.put("success", false);
            response.put("error", "Invalid address: " + addressStr);
            return result(response);
        }

        ArrayNode emitted = objectMapper.createArrayNode();
        ArrayNode failures = objectMapper.createArrayNode();
        StringBuilder totalHex = new StringBuilder();
        int tx = currentProgram.startTransaction("Assemble at address");
        boolean commit = false;

        try {
            Object assembler = getAssembler(currentProgram);
            Memory memory = currentProgram.getMemory();
            for (int i = 0; i < asmLines.size(); i++) {
                String line = asmLines.get(i);
                ObjectNode lineNode = objectMapper.createObjectNode();
                lineNode.put("index", i);
                lineNode.put("line", line);
                lineNode.put("address", current.toString());

                if (line == null || line.isBlank()) {
                    ObjectNode fail = lineNode.deepCopy();
                    fail.put("error", "Empty assembly line");
                    failures.add(fail);
                    continue;
                }

                try {
                    byte[] bytes = assembleLine(assembler, current, line);
                    if (bytes.length == 0) {
                        ObjectNode fail = lineNode.deepCopy();
                        fail.put("error", "Assembler emitted zero bytes");
                        failures.add(fail);
                        continue;
                    }

                    byte[] before = new byte[bytes.length];
                    memory.getBytes(current, before);
                    memory.setBytes(current, bytes);

                    lineNode.put("emitted_bytes", toHex(bytes));
                    lineNode.put("before_bytes", toHex(before));
                    lineNode.put("length", bytes.length);
                    emitted.add(lineNode);

                    if (totalHex.length() > 0) {
                        totalHex.append(' ');
                    }
                    totalHex.append(toHex(bytes));
                    current = current.add(bytes.length);
                } catch (Exception lineErr) {
                    ObjectNode fail = lineNode.deepCopy();
                    fail.put("error", lineErr.getMessage());
                    failures.add(fail);
                }
            }

            commit = emitted.size() > 0;
            response.put("success", failures.size() == 0 && emitted.size() > 0);
            response.put("program", currentProgram.getName());
            response.put("start_address", addressStr);
            response.put("emitted_bytes", totalHex.toString());
            response.set("line_map", emitted);
            response.set("failures", failures);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", "Assembly failed: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, commit);
        }

        return result(response);
    }

    private static Object getAssembler(Program program) throws Exception {
        Class<?> assemblersClass = Class.forName("ghidra.app.plugin.assembler.Assemblers");
        Method getAssembler = assemblersClass.getMethod("getAssembler", Program.class);
        return getAssembler.invoke(null, program);
    }

    private static byte[] assembleLine(Object assembler, Address at, String line) throws Exception {
        Method method = assembler.getClass().getMethod("assembleLine", Address.class, String.class);
        Object result = method.invoke(assembler, at, line);
        return (byte[]) result;
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof String ? (String) value : null;
    }

    @SuppressWarnings("unchecked")
    private static List<String> getStringList(Object value) {
        if (!(value instanceof List<?>)) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (Object item : (List<Object>) value) {
            if (!(item instanceof String)) {
                return null;
            }
            out.add((String) item);
        }
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i] & 0xff));
            if (i < bytes.length - 1) {
                sb.append(' ');
            }
        }
        return sb.toString();
    }

    private McpSchema.CallToolResult result(ObjectNode response) {
        return McpSchema.CallToolResult.builder().addTextContent(response.toPrettyString()).build();
    }
}
