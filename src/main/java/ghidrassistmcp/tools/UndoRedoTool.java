/*
 * MCP tool for undo/redo operations.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that performs undo or redo on the current program.
 */
public class UndoRedoTool implements McpTool {

    @Override
    public String getName() {
        return "undo_redo";
    }

    @Override
    public String getDescription() {
        return "Undo or redo the last operation on a program. " +
               "Specify action: 'undo' or 'redo'. Optionally specify 'count' to undo/redo multiple steps.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "action", Map.of("type", "string",
                    "description", "Action to perform: 'undo' or 'redo'"),
                "count", Map.of("type", "integer",
                    "description", "Number of steps to undo/redo (default: 1)")
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: No program currently loaded")
                .build();
        }

        String action = (String) arguments.get("action");
        if (action == null || action.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: 'action' is required ('undo' or 'redo')")
                .build();
        }

        int count = 1;
        if (arguments.containsKey("count")) {
            Object countObj = arguments.get("count");
            if (countObj instanceof Number) {
                count = ((Number) countObj).intValue();
            }
        }
        count = Math.max(1, Math.min(count, 100)); // Clamp to 1-100

        boolean isUndo = action.equalsIgnoreCase("undo");
        boolean isRedo = action.equalsIgnoreCase("redo");

        if (!isUndo && !isRedo) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Invalid action '" + action + "'. Use 'undo' or 'redo'.")
                .build();
        }

        try {
            int performed = 0;
            for (int i = 0; i < count; i++) {
                if (isUndo && currentProgram.canUndo()) {
                    currentProgram.undo();
                    performed++;
                } else if (isRedo && currentProgram.canRedo()) {
                    currentProgram.redo();
                    performed++;
                } else {
                    break;
                }
            }

            String actionName = isUndo ? "Undo" : "Redo";
            StringBuilder result = new StringBuilder();
            result.append(actionName).append(": ").append(performed).append(" step(s) performed");
            if (performed < count) {
                result.append(" (requested ").append(count).append(", no more ").append(action).append(" available)");
            }
            result.append("\nCan undo: ").append(currentProgram.canUndo());
            result.append("\nCan redo: ").append(currentProgram.canRedo());

            return McpSchema.CallToolResult.builder()
                .addTextContent(result.toString())
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error performing " + action + ": " + e.getMessage())
                .build();
        }
    }
}
