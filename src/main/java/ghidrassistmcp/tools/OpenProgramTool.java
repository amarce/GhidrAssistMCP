/*
 * MCP tool for opening a project file in Ghidra's CodeBrowser.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that opens a file from the Ghidra project in the CodeBrowser.
 */
public class OpenProgramTool implements McpTool {

    @Override
    public String getName() {
        return "open_program";
    }

    @Override
    public String getDescription() {
        return "Open a file from the Ghidra project in the CodeBrowser. " +
               "Specify 'file_path' as the full project path (e.g., '/folder/binary.exe').";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "file_path", Map.of("type", "string",
                    "description", "Full project path to the file to open (e.g., '/folder/binary.exe')")
            ),
            List.of("file_path"), null, null, null);
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

        String filePath = (String) arguments.get("file_path");
        if (filePath == null || filePath.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: 'file_path' is required")
                .build();
        }

        ProjectData projectData = project.getProjectData();

        // Parse folder path and file name
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
                .addTextContent("Error: File not found in project: " + filePath)
                .build();
        }

        // Check if the file is already open
        List<Program> openPrograms = backend.getAllOpenPrograms();
        for (Program p : openPrograms) {
            DomainFile df = p.getDomainFile();
            if (df != null && df.getPathname().equals(domainFile.getPathname())) {
                // Already open — just make it the active program
                ProgramManager pm = pluginTool.getService(ProgramManager.class);
                if (pm != null) {
                    pm.setCurrentProgram(p);
                }
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Program already open, set as active: " + p.getName())
                    .build();
            }
        }

        // Open the file using ProgramManager
        ProgramManager pm = pluginTool.getService(ProgramManager.class);
        if (pm == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: ProgramManager service not available")
                .build();
        }

        try {
            DomainObject obj = domainFile.getDomainObject(this, true, false, ghidra.util.task.TaskMonitor.DUMMY);
            if (!(obj instanceof Program)) {
                obj.release(this);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error: File is not a program: " + filePath +
                        " (type: " + domainFile.getContentType() + ")")
                    .build();
            }

            Program program = (Program) obj;
            pm.openProgram(program);
            program.release(this);

            return McpSchema.CallToolResult.builder()
                .addTextContent("Opened program: " + program.getName() + "\n" +
                    "Path: " + domainFile.getPathname() + "\n" +
                    "Language: " + program.getLanguageID() + "\n" +
                    "Format: " + program.getExecutableFormat())
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error opening file: " + e.getMessage())
                .build();
        }
    }
}
