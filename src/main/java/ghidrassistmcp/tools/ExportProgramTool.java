/*
 * MCP tool for exporting a program to a file on disk.
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;
import java.util.Map;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.CppExporter;
import ghidra.app.util.exporter.IntelHexExporter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that exports a program to a file on disk.
 * Supports multiple output formats: binary, c/c++ header, intel hex.
 */
public class ExportProgramTool implements McpTool {

    @Override
    public String getName() {
        return "export_program";
    }

    @Override
    public String getDescription() {
        return "Export a program to a file on disk. " +
               "Supported formats: 'binary' (raw bytes), 'c' (C/C++ header), 'intel_hex'. " +
               "Specify 'output_path' (absolute path) and optionally 'format' (default: 'binary').";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "output_path", Map.of("type", "string",
                    "description", "Absolute path for the output file"),
                "format", Map.of("type", "string",
                    "description", "Export format: 'binary', 'c', 'intel_hex' (default: 'binary')")
            ),
            List.of("output_path"), null, null, null);
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: No program currently loaded")
                .build();
        }

        String outputPath = (String) arguments.get("output_path");
        if (outputPath == null || outputPath.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: 'output_path' is required")
                .build();
        }

        String format = arguments.containsKey("format")
            ? (String) arguments.get("format") : "binary";

        File outputFile = new File(outputPath);

        // Ensure parent directory exists
        File parentDir = outputFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        try {
            Exporter exporter;
            switch (format.toLowerCase()) {
                case "c":
                case "cpp":
                case "c_header":
                    exporter = new CppExporter();
                    break;
                case "intel_hex":
                case "hex":
                    exporter = new IntelHexExporter();
                    break;
                case "binary":
                case "bin":
                case "raw":
                default:
                    exporter = new BinaryExporter();
                    break;
            }

            boolean success = exporter.export(outputFile, currentProgram,
                currentProgram.getMemory(), TaskMonitor.DUMMY);

            if (success) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Exported " + currentProgram.getName() + " to " + outputPath +
                        "\nFormat: " + format +
                        "\nSize: " + outputFile.length() + " bytes")
                    .build();
            } else {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Export failed for " + currentProgram.getName())
                    .build();
            }

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error exporting program: " + e.getMessage())
                .build();
        }
    }
}
