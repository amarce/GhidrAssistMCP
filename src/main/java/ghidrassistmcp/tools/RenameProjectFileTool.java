/*
 * MCP tool for renaming files and folders in the Ghidra project.
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
 * MCP tool that renames a file or folder in the Ghidra project.
 */
public class RenameProjectFileTool implements McpTool {

    @Override
    public String getName() {
        return "rename_project_item";
    }

    @Override
    public String getDescription() {
        return "Rename a file or folder in the current Ghidra project. " +
               "Specify 'path' (current project path) and 'new_name' (new name).";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "path", Map.of("type", "string",
                    "description", "Current project path of the item to rename (e.g., '/folder/old_name')"),
                "new_name", Map.of("type", "string",
                    "description", "New name for the item")
            ),
            List.of("path", "new_name"), null, null, null);
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

        String path = (String) arguments.get("path");
        String newName = (String) arguments.get("new_name");

        if (path == null || path.trim().isEmpty() || newName == null || newName.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Both 'path' and 'new_name' are required")
                .build();
        }

        ProjectData projectData = project.getProjectData();

        // Try as folder first
        DomainFolder folder = projectData.getFolder(path);
        if (folder != null) {
            try {
                String oldName = folder.getName();
                folder.setName(newName);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Renamed folder '" + oldName + "' to '" + newName + "'")
                    .build();
            } catch (Exception e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error renaming folder: " + e.getMessage())
                    .build();
            }
        }

        // Try as file
        int lastSlash = path.lastIndexOf('/');
        String folderPath = lastSlash <= 0 ? "/" : path.substring(0, lastSlash);
        String fileName = lastSlash == 0 ? path.substring(1) : (lastSlash > 0 ? path.substring(lastSlash + 1) : path);

        DomainFolder parentFolder = projectData.getFolder(folderPath);
        if (parentFolder == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Path not found: " + path)
                .build();
        }

        DomainFile file = parentFolder.getFile(fileName);
        if (file == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: File or folder not found: " + path)
                .build();
        }

        try {
            String oldName = file.getName();
            file.setName(newName);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Renamed file '" + oldName + "' to '" + newName + "'")
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error renaming file: " + e.getMessage())
                .build();
        }
    }
}
