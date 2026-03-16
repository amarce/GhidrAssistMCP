/*
 * MCP tool for running auto-analysis on a program.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that triggers auto-analysis on a program.
 */
public class AnalyzeProgramTool implements McpTool {

    @Override
    public String getName() {
        return "analyze_program";
    }

    @Override
    public String getDescription() {
        return "Run Ghidra auto-analysis on a program. " +
               "This performs all default analysis passes (disassembly, decompilation, type propagation, etc.). " +
               "Optionally specify 'program_name' to target a specific program.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "program_name", Map.of("type", "string",
                    "description", "Name of the program to analyze (default: active program)")
            ),
            List.of(), null, null, null);
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public boolean supportsAsync() {
        return true;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        // Resolve target program
        String programName = (String) arguments.get("program_name");
        Program target = currentProgram;
        if (programName != null && !programName.trim().isEmpty()) {
            target = null;
            for (Program p : backend.getAllOpenPrograms()) {
                if (p.getName().equalsIgnoreCase(programName)) {
                    target = p;
                    break;
                }
            }
        }

        if (target == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: No program found" +
                    (programName != null ? ": " + programName : ". Open a program first."))
                .build();
        }

        try {
            AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(target);
            analysisManager.reAnalyzeAll(target.getMemory());
            analysisManager.startAnalysis(TaskMonitor.DUMMY);

            return McpSchema.CallToolResult.builder()
                .addTextContent("Auto-analysis started on: " + target.getName() + "\n" +
                    "Analysis runs in the background. Use 'analysis_tasks' to check progress.")
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error starting analysis: " + e.getMessage())
                .build();
        }
    }
}
