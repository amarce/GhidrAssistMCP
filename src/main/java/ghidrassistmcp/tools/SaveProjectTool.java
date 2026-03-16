/*
 * MCP tool for saving programs and the project.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that saves programs in the current project.
 * Can save a specific program or all open programs.
 */
public class SaveProjectTool implements McpTool {

    @Override
    public String getName() {
        return "save_project";
    }

    @Override
    public String getDescription() {
        return "Save program changes in the current Ghidra project. " +
               "Specify 'program_name' to save a specific program, or omit to save all open programs.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "program_name", Map.of("type", "string",
                    "description", "Name of the program to save (omit to save all)")
            ),
            List.of(), null, null, null);
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
        List<Program> openPrograms = backend.getAllOpenPrograms();

        if (openPrograms.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No programs are currently open to save.")
                .build();
        }

        StringBuilder result = new StringBuilder();

        if (programName != null && !programName.trim().isEmpty()) {
            // Save specific program
            Program toSave = null;
            for (Program p : openPrograms) {
                if (p.getName().equalsIgnoreCase(programName)) {
                    toSave = p;
                    break;
                }
            }
            if (toSave == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error: Program not found: " + programName)
                    .build();
            }

            try {
                DomainFile df = toSave.getDomainFile();
                df.save(ghidra.util.task.TaskMonitor.DUMMY);
                result.append("Saved: ").append(toSave.getName());
            } catch (Exception e) {
                result.append("Error saving ").append(toSave.getName()).append(": ").append(e.getMessage());
            }
        } else {
            // Save all open programs
            int saved = 0;
            int errors = 0;
            for (Program p : openPrograms) {
                try {
                    DomainFile df = p.getDomainFile();
                    if (df != null) {
                        df.save(ghidra.util.task.TaskMonitor.DUMMY);
                        result.append("Saved: ").append(p.getName()).append("\n");
                        saved++;
                    }
                } catch (Exception e) {
                    result.append("Error saving ").append(p.getName()).append(": ").append(e.getMessage()).append("\n");
                    errors++;
                }
            }
            result.append("\n---\nSaved ").append(saved).append(" program(s)");
            if (errors > 0) {
                result.append(", ").append(errors).append(" error(s)");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }
}
