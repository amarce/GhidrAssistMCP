/*
 * MCP tool for importing files into the Ghidra project.
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that imports a binary file from disk into the Ghidra project.
 */
public class ImportFileTool implements McpTool {

    @Override
    public String getName() {
        return "import_file";
    }

    @Override
    public String getDescription() {
        return "Import a binary file from disk into the current Ghidra project. " +
               "Specify 'file_path' (absolute path on disk) and optionally 'folder_path' " +
               "(project folder to import into, default: '/').";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "file_path", Map.of("type", "string",
                    "description", "Absolute path to the file on disk to import"),
                "folder_path", Map.of("type", "string",
                    "description", "Project folder to import into (default: '/')")
            ),
            List.of("file_path"), null, null, null);
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
        PluginTool pluginTool = backend.getPluginTool();
        if (pluginTool == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: No active Ghidra tool available")
                .build();
        }

        Project project = pluginTool.getProject();
        if (project == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: No project is currently open")
                .build();
        }

        String filePath = (String) arguments.get("file_path");
        if (filePath == null || filePath.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: 'file_path' is required")
                .build();
        }

        File file = new File(filePath);
        if (!file.exists()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: File not found: " + filePath)
                .build();
        }
        if (!file.isFile()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Path is not a file: " + filePath)
                .build();
        }

        String folderPath = arguments.containsKey("folder_path")
            ? (String) arguments.get("folder_path") : "/";

        ProjectData projectData = project.getProjectData();
        DomainFolder folder = projectData.getFolder(folderPath);
        if (folder == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Project folder not found: " + folderPath)
                .build();
        }

        try {
            MessageLog messageLog = new MessageLog();
            LoadResults<? extends DomainObject> results = AutoImporter.importByUsingBestGuess(
                file, project, folderPath, this, messageLog, TaskMonitor.DUMMY);

            if (results == null) {
                String logMsg = messageLog.toString();
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Import failed: No suitable loader found for " + file.getName() +
                        (logMsg.isEmpty() ? "" : "\nDetails: " + logMsg))
                    .build();
            }

            StringBuilder result = new StringBuilder();
            result.append("Successfully imported: ").append(file.getName()).append("\n");
            result.append("Into project folder: ").append(folderPath).append("\n");

            DomainObject primary = results.getPrimaryDomainObject();
            if (primary != null) {
                result.append("Program name: ").append(primary.getName()).append("\n");
                if (primary instanceof Program) {
                    Program prog = (Program) primary;
                    result.append("Language: ").append(prog.getLanguageID()).append("\n");
                    result.append("Format: ").append(prog.getExecutableFormat()).append("\n");
                }
            }

            String logMsg = messageLog.toString();
            if (!logMsg.isEmpty()) {
                result.append("\nImport log:\n").append(logMsg);
            }

            results.release(this);

            return McpSchema.CallToolResult.builder()
                .addTextContent(result.toString())
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error importing file: " + e.getMessage())
                .build();
        }
    }
}
