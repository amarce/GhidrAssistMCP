/*
 * MCP tool for listing all installed processor/language definitions in Ghidra.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.util.DefaultLanguageService;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists all installed CPU/language definitions available in Ghidra.
 * Useful for discovering language IDs to use with import_file for raw binary imports.
 */
public class ListLanguagesTool implements McpTool {

    @Override
    public String getName() {
        return "list_languages";
    }

    @Override
    public String getDescription() {
        return "List all installed processor/language definitions in Ghidra. " +
               "Use the returned language IDs with import_file's 'language_id' parameter " +
               "to import raw binary files for specific CPU architectures.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "filter", Map.of("type", "string",
                    "description", "Optional filter string to match against processor name (case-insensitive)")
            ),
            List.of(), null, null, null);
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        try {
            LanguageService languageService = DefaultLanguageService.getLanguageService();
            List<LanguageDescription> descriptions = languageService.getLanguageDescriptions(true);

            String filter = arguments != null ? (String) arguments.get("filter") : null;
            String filterLower = (filter != null && !filter.trim().isEmpty())
                ? filter.trim().toLowerCase() : null;

            StringBuilder sb = new StringBuilder();
            int count = 0;

            for (LanguageDescription desc : descriptions) {
                String processor = desc.getProcessor().toString();

                if (filterLower != null && !processor.toLowerCase().contains(filterLower)) {
                    continue;
                }

                sb.append(String.format("%-40s  Processor: %-12s  Endian: %-8s  Size: %-4d  Variant: %-10s  %s\n",
                    desc.getLanguageID(),
                    processor,
                    desc.getEndian(),
                    desc.getSize(),
                    desc.getVariant(),
                    desc.getDescription()));
                count++;
            }

            if (count == 0) {
                String msg = filterLower != null
                    ? "No languages found matching filter: " + filter
                    : "No languages found";
                return McpSchema.CallToolResult.builder()
                    .addTextContent(msg)
                    .build();
            }

            String header = "Found " + count + " language(s)" +
                (filterLower != null ? " matching '" + filter + "'" : "") + ":\n\n";

            return McpSchema.CallToolResult.builder()
                .addTextContent(header + sb.toString())
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error listing languages: " + e.getMessage())
                .build();
        }
    }
}
