/*
 * MCP tool for getting current Ghidra project information.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that returns information about the current Ghidra project.
 */
public class GetProjectInfoTool implements McpTool {

    @Override
    public String getName() {
        return "get_project_info";
    }

    @Override
    public String getDescription() {
        return "Get information about the current Ghidra project including name, location, " +
               "number of files, and open programs.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(), List.of(), null, null, null);
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
                .addTextContent("No project is currently open.\n" +
                    "Use 'create_project' to create a new project or 'open_project' to open an existing one.")
                .build();
        }

        ProjectLocator locator = project.getProjectLocator();
        ProjectData projectData = project.getProjectData();

        StringBuilder result = new StringBuilder();
        result.append("Project Information:\n\n");
        result.append("Name: ").append(project.getName()).append("\n");
        result.append("Location: ").append(locator.getProjectDir()).append("\n");

        // Count files recursively
        int[] counts = countFilesAndFolders(projectData.getRootFolder());
        result.append("Total files: ").append(counts[0]).append("\n");
        result.append("Total folders: ").append(counts[1]).append("\n");

        // Open programs
        List<Program> openPrograms = backend.getAllOpenPrograms();
        result.append("Open programs: ").append(openPrograms.size()).append("\n");
        if (!openPrograms.isEmpty()) {
            result.append("\nOpen programs:\n");
            for (Program p : openPrograms) {
                boolean isActive = (currentProgram != null && p.equals(currentProgram));
                result.append("  - ").append(p.getName());
                if (isActive) result.append(" [ACTIVE]");
                result.append(" (").append(p.getExecutableFormat()).append(")\n");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private int[] countFilesAndFolders(DomainFolder folder) {
        int files = folder.getFiles().length;
        int folders = 0;
        for (DomainFolder sub : folder.getFolders()) {
            folders++;
            int[] subCounts = countFilesAndFolders(sub);
            files += subCounts[0];
            folders += subCounts[1];
        }
        return new int[]{files, folders};
    }
}
