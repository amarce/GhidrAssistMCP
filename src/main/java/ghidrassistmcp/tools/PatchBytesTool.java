package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Patch bytes in memory using either hex input or explicit integer byte values.
 */
public class PatchBytesTool implements McpTool {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public String getName() {
        return "patch_bytes";
    }

    @Override
    public String getDescription() {
        return "Patch program bytes at an address, with optional expected-byte verification and dry-run";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", Map.of(
                    "type", "string",
                    "description", "Target address for patch"
                ),
                "bytes", Map.of(
                    "type", "string",
                    "description", "Patch bytes as hex string (e.g. '90 90 C3' or '9090C3')"
                ),
                "byte_values", Map.of(
                    "type", "array",
                    "items", Map.of("type", "integer"),
                    "description", "Patch bytes as integer array (0-255)"
                ),
                "expected_original_bytes", Map.of(
                    "type", "string",
                    "description", "Optional expected bytes at target before patch (hex string)"
                ),
                "dry_run", Map.of(
                    "type", "boolean",
                    "description", "If true, validate and preview only without writing"
                )
            ),
            List.of("address"), null, null, null);
    }

    @Override
    @SuppressWarnings("unchecked")
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        ObjectNode response = objectMapper.createObjectNode();
        response.put("tool", getName());

        if (currentProgram == null) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "No program currently loaded");
            return result(response);
        }
        response.put("program", currentProgram.getName());

        String addressStr = getString(arguments, "address");
        if (addressStr == null) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "address is required");
            return result(response);
        }

        Address address = currentProgram.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Invalid address: " + addressStr);
            return result(response);
        }
        response.put("address", address.toString());

        byte[] patchBytes;
        try {
            patchBytes = resolvePatchBytes(arguments);
        } catch (IllegalArgumentException e) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", e.getMessage());
            return result(response);
        }

        if (patchBytes.length == 0) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Patch payload is empty");
            return result(response);
        }

        boolean dryRun = Boolean.TRUE.equals(arguments.get("dry_run"));
        response.put("dry_run", dryRun);

        Memory memory = currentProgram.getMemory();
        MemoryBlock block = memory.getBlock(address);
        if (block == null) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "No memory block contains the target address");
            return result(response);
        }

        if (!block.isWrite()) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Target memory block is not writable");
            return result(response);
        }

        if (!fitsInBlock(address, patchBytes.length, block)) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Patch range exceeds memory block bounds");
            return result(response);
        }

        byte[] before = new byte[patchBytes.length];
        try {
            memory.getBytes(address, before);
        } catch (MemoryAccessException e) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Unable to read target bytes: " + e.getMessage());
            return result(response);
        }

        String expectedOriginal = getString(arguments, "expected_original_bytes");
        if (expectedOriginal != null) {
            byte[] expected;
            try {
                expected = parseHexBytes(expectedOriginal);
            } catch (IllegalArgumentException e) {
                response.put("success", false);
                response.put("status", "error");
                response.put("error", "Invalid expected_original_bytes: " + e.getMessage());
                return result(response);
            }

            if (expected.length != before.length) {
                response.put("success", false);
                response.put("status", "error");
                response.put("error", "expected_original_bytes length must equal patch length");
                response.put("expected_length", expected.length);
                response.put("patch_length", before.length);
                return result(response);
            }

            if (!equalsBytes(expected, before)) {
                response.put("success", false);
                response.put("status", "mismatch");
                response.put("error", "Current bytes do not match expected_original_bytes");
                response.put("before_bytes", toHex(before));
                response.put("expected_original_bytes", toHex(expected));
                return result(response);
            }
        }

        response.put("length", patchBytes.length);
        response.put("before_bytes", toHex(before));
        response.put("after_bytes", toHex(patchBytes));

        if (dryRun) {
            response.put("success", true);
            response.put("status", "dry_run_ok");
            return result(response);
        }

        int tx = currentProgram.startTransaction("Patch bytes");
        boolean commit = false;
        try {
            memory.setBytes(address, patchBytes);
            commit = true;
            response.put("success", true);
            response.put("status", "patched");
        } catch (MemoryAccessException e) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Failed to patch bytes: " + e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, commit);
        }

        return result(response);
    }

    private byte[] resolvePatchBytes(Map<String, Object> arguments) {
        String bytesHex = getString(arguments, "bytes");
        Object valuesObj = arguments.get("byte_values");

        if (bytesHex != null && valuesObj != null) {
            throw new IllegalArgumentException("Provide only one patch payload: bytes or byte_values");
        }

        if (bytesHex != null) {
            return parseHexBytes(bytesHex);
        }

        if (valuesObj instanceof List<?>) {
            List<?> values = (List<?>) valuesObj;
            List<Byte> out = new ArrayList<>(values.size());
            for (Object value : values) {
                if (!(value instanceof Number)) {
                    throw new IllegalArgumentException("byte_values must contain integers only");
                }
                int intValue = ((Number) value).intValue();
                if (intValue < 0 || intValue > 255) {
                    throw new IllegalArgumentException("byte_values entries must be in range 0..255");
                }
                out.add((byte) intValue);
            }
            byte[] bytes = new byte[out.size()];
            for (int i = 0; i < out.size(); i++) {
                bytes[i] = out.get(i);
            }
            return bytes;
        }

        throw new IllegalArgumentException("Patch payload required: provide bytes or byte_values");
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof String ? (String) value : null;
    }

    private static byte[] parseHexBytes(String hexInput) {
        String normalized = hexInput.replaceAll("0x", "")
            .replaceAll("[^0-9A-Fa-f]", "");

        if (normalized.isEmpty()) {
            return new byte[0];
        }
        if ((normalized.length() % 2) != 0) {
            throw new IllegalArgumentException("Hex payload must contain an even number of nibbles");
        }

        byte[] out = new byte[normalized.length() / 2];
        for (int i = 0; i < normalized.length(); i += 2) {
            out[i / 2] = (byte) Integer.parseInt(normalized.substring(i, i + 2), 16);
        }
        return out;
    }

    private static boolean fitsInBlock(Address start, int length, MemoryBlock block) {
        if (length <= 0) {
            return true;
        }
        try {
            Address end = start.addNoWrap(length - 1);
            return block.contains(start) && block.contains(end);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean equalsBytes(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
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
        return McpSchema.CallToolResult.builder()
            .addTextContent(response.toPrettyString())
            .build();
    }
}
