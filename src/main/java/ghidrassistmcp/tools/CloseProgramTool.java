/*
 * MCP tool for closing an open program in Ghidra.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that closes an open program in Ghidra.
 * Safety: refuses to close the last open program since that would disable MCP.
 */
public class CloseProgramTool implements McpTool {

    @Override
    public String getName() {
        return "close_program";
    }

    @Override
    public String getDescription() {
        return "Close an open program in Ghidra. " +
               "Specify 'program_name' to identify which program to close. " +
               "IMPORTANT: Cannot close the last remaining open program — at least one must stay " +
               "open for the headless MCP server to keep a program context.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "program_name", Map.of("type", "string",
                    "description", "Name of the program to close")
            ),
            List.of("program_name"), null, null, null);
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        String programName = (String) arguments.get("program_name");
        if (programName == null || programName.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: 'program_name' is required")
                .build();
        }

        List<Program> openPrograms = backend.getAllOpenPrograms();

        // Safety: refuse to close the last open program
        if (openPrograms.size() <= 1) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Cannot close the last open program.\n" +
                    "At least one program must remain open for the MCP server to maintain " +
                    "a program context. Open another program first before closing this one.")
                .build();
        }

        // Find the program to close
        Program toClose = null;
        for (Program p : openPrograms) {
            if (p.getName().equals(programName)) {
                toClose = p;
                break;
            }
        }
        if (toClose == null) {
            // Try case-insensitive
            for (Program p : openPrograms) {
                if (p.getName().equalsIgnoreCase(programName)) {
                    toClose = p;
                    break;
                }
            }
        }
        if (toClose == null) {
            // Try partial match
            for (Program p : openPrograms) {
                if (p.getName().toLowerCase().contains(programName.toLowerCase())) {
                    toClose = p;
                    break;
                }
            }
        }

        if (toClose == null) {
            StringBuilder available = new StringBuilder("Error: Program not found: " + programName + "\n");
            available.append("Open programs:\n");
            for (Program p : openPrograms) {
                available.append("  - ").append(p.getName()).append("\n");
            }
            return McpSchema.CallToolResult.builder()
                .addTextContent(available.toString())
                .build();
        }

        String closedName = toClose.getName();

        // Close via ProgramManager in GUI mode, or remove from headless list
        PluginTool pluginTool = backend.getPluginTool();
        if (pluginTool != null) {
            ProgramManager pm = pluginTool.getService(ProgramManager.class);
            if (pm != null) {
                pm.closeProgram(toClose, false);
            }
        } else {
            backend.removeHeadlessProgram(toClose);
            toClose.release(this);
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent("Closed program: " + closedName + "\n" +
                "Remaining open programs: " + (openPrograms.size() - 1))
            .build();
    }
}
