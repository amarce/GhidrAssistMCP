package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Create, delete, or redefine functions by entry address and optional body range.
 */
public class FunctionLifecycleTool implements McpTool {

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
        return "function_lifecycle";
    }

    @Override
    public String getDescription() {
        return "Create, delete, or redefine functions using entry addresses and optional body ranges";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "action", Map.of(
                    "type", "string",
                    "enum", List.of("create", "delete", "redefine"),
                    "description", "Lifecycle action to perform"
                ),
                "entry_address", Map.of(
                    "type", "string",
                    "description", "Function entry address"
                ),
                "name", Map.of(
                    "type", "string",
                    "description", "Optional function name used for create/redefine"
                ),
                "body_start", Map.of(
                    "type", "string",
                    "description", "Optional start address for function body range"
                ),
                "body_end", Map.of(
                    "type", "string",
                    "description", "Optional inclusive end address for function body range"
                ),
                "range_start", Map.of(
                    "type", "string",
                    "description", "Alias for body_start"
                ),
                "range_end", Map.of(
                    "type", "string",
                    "description", "Alias for body_end"
                )
            ),
            List.of("action", "entry_address"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        ObjectNode response = objectMapper.createObjectNode();
        response.put("tool", getName());

        if (currentProgram == null) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "No program currently loaded");
            return textResult(response);
        }

        String action = getString(arguments, "action");
        String entryAddressStr = getString(arguments, "entry_address");

        response.put("program", currentProgram.getName());
        if (action != null) {
            response.put("action", action);
        }
        if (entryAddressStr != null) {
            response.put("entry_address", entryAddressStr);
        }

        if (action == null || entryAddressStr == null) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "action and entry_address are required");
            return textResult(response);
        }

        Address entry = currentProgram.getAddressFactory().getAddress(entryAddressStr);
        if (entry == null) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Invalid entry_address: " + entryAddressStr);
            return textResult(response);
        }

        AddressSetView body = resolveBodyRange(arguments, currentProgram, entry, response);
        if (body == null && (hasArg(arguments, "body_start") || hasArg(arguments, "body_end") ||
            hasArg(arguments, "range_start") || hasArg(arguments, "range_end"))) {
            return textResult(response);
        }

        int tx = currentProgram.startTransaction("Function lifecycle");
        boolean commit = false;
        try {
            FunctionManager functionManager = currentProgram.getFunctionManager();
            Function existing = functionManager.getFunctionAt(entry);
            String normalizedAction = action.toLowerCase();

            switch (normalizedAction) {
                case "create": {
                    if (existing != null) {
                        response.put("success", false);
                        response.put("status", "error");
                        response.put("error", "Function already exists at entry_address");
                        break;
                    }

                    AddressSetView createBody = body != null ? body : new AddressSet(entry, entry);
                    String name = getString(arguments, "name");
                    Function created = currentProgram.getListing().createFunction(
                        name, entry, createBody, SourceType.USER_DEFINED);

                    response.put("success", created != null);
                    response.put("status", created != null ? "created" : "error");
                    if (created != null) {
                        response.put("function_name", created.getName());
                        response.put("body", created.getBody().toString());
                        commit = true;
                    } else {
                        response.put("error", "Failed to create function");
                    }
                    break;
                }
                case "delete": {
                    if (existing == null) {
                        response.put("success", false);
                        response.put("status", "error");
                        response.put("error", "No function exists at entry_address");
                        break;
                    }

                    String oldName = existing.getName();
                    boolean removed = functionManager.removeFunction(entry);
                    response.put("success", removed);
                    response.put("status", removed ? "deleted" : "error");
                    response.put("function_name", oldName);
                    if (removed) {
                        commit = true;
                    } else {
                        response.put("error", "Failed to delete function");
                    }
                    break;
                }
                case "redefine": {
                    if (existing == null) {
                        response.put("success", false);
                        response.put("status", "error");
                        response.put("error", "No function exists at entry_address to redefine");
                        break;
                    }

                    AddressSetView redefineBody = body != null ? body : existing.getBody();
                    String name = getString(arguments, "name");
                    String finalName = (name == null || name.isBlank()) ? existing.getName() : name;

                    boolean removed = functionManager.removeFunction(entry);
                    if (!removed) {
                        response.put("success", false);
                        response.put("status", "error");
                        response.put("error", "Failed to remove existing function before redefine");
                        break;
                    }

                    Function redefined = currentProgram.getListing().createFunction(
                        finalName, entry, redefineBody, SourceType.USER_DEFINED);
                    if (redefined == null) {
                        response.put("success", false);
                        response.put("status", "error");
                        response.put("error", "Failed to recreate function during redefine");
                        break;
                    }

                    response.put("success", true);
                    response.put("status", "redefined");
                    response.put("function_name", redefined.getName());
                    response.put("body", redefined.getBody().toString());
                    commit = true;
                    break;
                }
                default:
                    response.put("success", false);
                    response.put("status", "error");
                    response.put("error", "Invalid action. Use create, delete, or redefine");
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, commit);
        }

        return textResult(response);
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof String ? (String) value : null;
    }

    private static boolean hasArg(Map<String, Object> arguments, String key) {
        return arguments.containsKey(key) && arguments.get(key) != null;
    }

    private AddressSetView resolveBodyRange(Map<String, Object> arguments, Program program,
                                            Address entry, ObjectNode response) {
        String bodyStartStr = firstNonNull(
            getString(arguments, "body_start"),
            getString(arguments, "range_start"));
        String bodyEndStr = firstNonNull(
            getString(arguments, "body_end"),
            getString(arguments, "range_end"));

        if (bodyStartStr == null && bodyEndStr == null) {
            return null;
        }

        Address bodyStart = bodyStartStr == null ? entry : program.getAddressFactory().getAddress(bodyStartStr);
        Address bodyEnd = bodyEndStr == null ? entry : program.getAddressFactory().getAddress(bodyEndStr);

        if (bodyStart == null || bodyEnd == null) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Invalid body/range address values");
            return null;
        }

        if (bodyStart.compareTo(bodyEnd) > 0) {
            response.put("success", false);
            response.put("status", "error");
            response.put("error", "Body start address must be <= body end address");
            return null;
        }

        return new AddressSet(bodyStart, bodyEnd);
    }

    private static String firstNonNull(String a, String b) {
        return a != null ? a : b;
    }

    private McpSchema.CallToolResult textResult(ObjectNode node) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(node.toPrettyString())
            .build();
    }
}
