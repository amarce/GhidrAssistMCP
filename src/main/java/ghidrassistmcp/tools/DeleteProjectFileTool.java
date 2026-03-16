/*
 * MCP tool for deleting files from the Ghidra project.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that deletes a file from the Ghidra project.
 */
public class DeleteProjectFileTool implements McpTool {

    @Override
    public String getName() {
        return "delete_project_file";
    }

    @Override
    public String getDescription() {
        return "Delete a file from the current Ghidra project. " +
               "Specify 'file_path' as the full project path (e.g., '/folder/binary.exe'). " +
               "WARNING: This permanently removes the file from the project.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "file_path", Map.of("type", "string",
                    "description", "Full project path to the file to delete (e.g., '/folder/binary.exe')")
            ),
            List.of("file_path"), null, null, null);
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
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

        ProjectData projectData = project.getProjectData();

        // Parse folder path and file name from the full path
        int lastSlash = filePath.lastIndexOf('/');
        String folderPath;
        String fileName;
        if (lastSlash <= 0) {
            folderPath = "/";
            fileName = lastSlash == 0 ? filePath.substring(1) : filePath;
        } else {
            folderPath = filePath.substring(0, lastSlash);
            fileName = filePath.substring(lastSlash + 1);
        }

        DomainFolder folder = projectData.getFolder(folderPath);
        if (folder == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Folder not found: " + folderPath)
                .build();
        }

        DomainFile domainFile = folder.getFile(fileName);
        if (domainFile == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: File not found: " + filePath)
                .build();
        }

        if (domainFile.isReadOnly()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: File is read-only: " + filePath)
                .build();
        }

        try {
            String name = domainFile.getName();
            domainFile.delete();
            return McpSchema.CallToolResult.builder()
                .addTextContent("Deleted file: " + filePath + " (" + name + ")")
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error deleting file: " + e.getMessage())
                .build();
        }
    }
}
