/*
 * MCP tool for importing files into the Ghidra project.
 */
package ghidrassistmcp.tools;

import java.io.File;
import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.framework.model.DomainFolder;
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
 * Uses the ProgramLoader builder API (Ghidra 12+).
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
               "(project folder to import into, default: '/'). " +
               "For raw binary files (firmware dumps, .bin), you MUST specify 'language_id' " +
               "(e.g., 'tricore:LE:32:default' for Bosch MED17 ECUs). " +
               "Use 'list_languages' to see all available language IDs.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "file_path", Map.of("type", "string",
                    "description", "Absolute path to the file on disk to import"),
                "folder_path", Map.of("type", "string",
                    "description", "Project folder to import into (default: '/')"),
                "language_id", Map.of("type", "string",
                    "description", "Language/CPU ID for raw binary imports (e.g., 'tricore:LE:32:default', 'ARM:LE:32:v8'). Use list_languages to discover available IDs."),
                "compiler_id", Map.of("type", "string",
                    "description", "Compiler spec ID (default: 'default'). Only needed with language_id."),
                "name", Map.of("type", "string",
                    "description", "Override the imported program name (default: filename)")
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
        Project project = backend.getProject();
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

        String languageId = arguments.containsKey("language_id")
            ? (String) arguments.get("language_id") : null;
        String compilerId = arguments.containsKey("compiler_id")
            ? (String) arguments.get("compiler_id") : null;
        String nameOverride = arguments.containsKey("name")
            ? (String) arguments.get("name") : null;

        try {
            MessageLog messageLog = new MessageLog();

            var builder = ProgramLoader.builder()
                .source(file)
                .project(project)
                .projectFolderPath(folderPath)
                .log(messageLog)
                .monitor(TaskMonitor.DUMMY);

            if (languageId != null && !languageId.trim().isEmpty()) {
                builder.language(languageId.trim());
            }
            if (compilerId != null && !compilerId.trim().isEmpty()) {
                builder.compiler(compilerId.trim());
            }
            if (nameOverride != null && !nameOverride.trim().isEmpty()) {
                builder.name(nameOverride.trim());
            }

            LoadResults<Program> results = builder.load();

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

            try {
                Loaded<Program> primary = results.getPrimary();
                if (primary != null) {
                    Program prog = primary.getDomainObject(this);
                    result.append("Program name: ").append(prog.getName()).append("\n");
                    result.append("Language: ").append(prog.getLanguageID()).append("\n");
                    result.append("Format: ").append(prog.getExecutableFormat()).append("\n");
                    primary.save(TaskMonitor.DUMMY);
                    // Register in headless mode
                    backend.addHeadlessProgram(prog);
                }
            } finally {
                results.close();
            }

            String logMsg = messageLog.toString();
            if (!logMsg.isEmpty()) {
                result.append("\nImport log:\n").append(logMsg);
            }

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
