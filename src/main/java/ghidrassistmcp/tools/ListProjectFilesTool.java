/*
 * MCP tool for browsing the Ghidra project tree.
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
 * MCP tool that lists files and folders in the current Ghidra project.
 * Allows browsing the project tree to discover available binaries.
 */
public class ListProjectFilesTool implements McpTool {

    @Override
    public String getName() {
        return "list_project_files";
    }

    @Override
    public String getDescription() {
        return "List files and folders in the current Ghidra project. " +
               "Use 'folder_path' to browse subdirectories (default: root '/').";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "folder_path", Map.of("type", "string",
                    "description", "Project folder path to list (default: '/')")
            ),
            List.of(), null, null, null);
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

        ProjectData projectData = project.getProjectData();
        String folderPath = arguments.containsKey("folder_path")
            ? (String) arguments.get("folder_path") : "/";

        DomainFolder folder = projectData.getFolder(folderPath);
        if (folder == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: Folder not found: " + folderPath)
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Project: ").append(project.getName()).append("\n");
        result.append("Path: ").append(folder.getPathname()).append("\n\n");

        // List subfolders
        DomainFolder[] subfolders = folder.getFolders();
        if (subfolders.length > 0) {
            result.append("Folders:\n");
            for (DomainFolder sub : subfolders) {
                result.append("  [DIR] ").append(sub.getName()).append("/\n");
            }
            result.append("\n");
        }

        // List files
        DomainFile[] files = folder.getFiles();
        if (files.length > 0) {
            result.append("Files:\n");
            for (DomainFile file : files) {
                result.append("  ").append(file.getName());
                result.append("  (").append(file.getContentType()).append(")");
                if (file.isReadOnly()) {
                    result.append(" [READ-ONLY]");
                }
                result.append("\n");
            }
        }

        if (subfolders.length == 0 && files.length == 0) {
            result.append("(empty folder)\n");
        }

        result.append("\n---\n");
        result.append("Total: ").append(subfolders.length).append(" folder(s), ")
              .append(files.length).append(" file(s)");

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }
}
