/*
 * MCP tool for moving files between folders in the Ghidra project.
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
 * MCP tool that moves a file to a different folder in the Ghidra project.
 */
public class MoveProjectFileTool implements McpTool {

    @Override
    public String getName() {
        return "move_project_file";
    }

    @Override
    public String getDescription() {
        return "Move a file to a different folder in the current Ghidra project. " +
               "Specify 'file_path' (current path) and 'destination_folder' (target folder path).";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "file_path", Map.of("type", "string",
                    "description", "Current project path of the file to move"),
                "destination_folder", Map.of("type", "string",
                    "description", "Target folder path in the project")
            ),
            List.of("file_path", "destination_folder"), null, null, null);
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
        Project project = backend.getProject();
        if (project == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: No project is currently open")
                .build();
        }

        String filePath = (String) arguments.get("file_path");
        String destFolderPath = (String) arguments.get("destination_folder");

        ProjectData projectData = project.getProjectData();

        // Parse source file
        int lastSlash = filePath.lastIndexOf('/');
        String srcFolderPath = lastSlash <= 0 ? "/" : filePath.substring(0, lastSlash);
        String fileName = lastSlash == 0 ? filePath.substring(1) : (lastSlash > 0 ? filePath.substring(lastSlash + 1) : filePath);

        DomainFolder srcFolder = projectData.getFolder(srcFolderPath);
        if (srcFolder == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Source folder not found: " + srcFolderPath)
                .build();
        }

        DomainFile file = srcFolder.getFile(fileName);
        if (file == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: File not found: " + filePath)
                .build();
        }

        DomainFolder destFolder = projectData.getFolder(destFolderPath);
        if (destFolder == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Destination folder not found: " + destFolderPath)
                .build();
        }

        try {
            file.moveTo(destFolder);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Moved '" + fileName + "' from '" + srcFolderPath + "' to '" + destFolderPath + "'")
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error moving file: " + e.getMessage())
                .build();
        }
    }
}
