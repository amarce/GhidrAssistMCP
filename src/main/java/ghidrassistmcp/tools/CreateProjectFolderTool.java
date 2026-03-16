/*
 * MCP tool for creating folders in the Ghidra project.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that creates new folders in the Ghidra project.
 */
public class CreateProjectFolderTool implements McpTool {

    @Override
    public String getName() {
        return "create_project_folder";
    }

    @Override
    public String getDescription() {
        return "Create a new folder in the current Ghidra project. " +
               "Specify 'parent_path' for the parent folder (default: '/') and 'folder_name' for the new folder name.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "parent_path", Map.of("type", "string",
                    "description", "Parent folder path (default: '/')"),
                "folder_name", Map.of("type", "string",
                    "description", "Name of the new folder to create")
            ),
            List.of("folder_name"), null, null, null);
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

        String folderName = (String) arguments.get("folder_name");
        if (folderName == null || folderName.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: 'folder_name' is required")
                .build();
        }

        String parentPath = arguments.containsKey("parent_path")
            ? (String) arguments.get("parent_path") : "/";

        ProjectData projectData = project.getProjectData();
        DomainFolder parentFolder = projectData.getFolder(parentPath);
        if (parentFolder == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Parent folder not found: " + parentPath)
                .build();
        }

        try {
            DomainFolder newFolder = parentFolder.createFolder(folderName);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Created folder: " + newFolder.getPathname())
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error creating folder: " + e.getMessage())
                .build();
        }
    }
}
