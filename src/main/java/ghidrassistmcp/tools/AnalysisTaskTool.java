package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Analysis orchestration tool for auto-analysis and custom memory-zone management.
 */
public class AnalysisTaskTool implements McpTool {

    @Override
    public String getName() {
        return "analysis_tasks";
    }

    @Override
    public String getDescription() {
        return "Run auto-analysis and manage custom memory zones used by analysis/decompilation tasks";
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
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "action", Map.of(
                    "type", "string",
                    "enum", List.of("auto_analyze", "set_memory_zones", "list_memory_zones", "clear_memory_zones"),
                    "description", "Operation to perform"
                ),
                "zones", Map.of(
                    "type", "array",
                    "description", "Required for set_memory_zones",
                    "items", Map.of(
                        "type", "object",
                        "properties", Map.of(
                            "start", Map.of("type", "string", "description", "Zone start address"),
                            "end", Map.of("type", "string", "description", "Zone end address (inclusive)"),
                            "label", Map.of("type", "string", "description", "Optional label")
                        ),
                        "required", List.of("start", "end")
                    )
                ),
                "reason", Map.of(
                    "type", "string",
                    "description", "Optional note stored in operation metadata"
                )
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder().addTextContent("Internal error: backend context required").build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addTextContent("No program currently loaded").build();
        }

        String action = asString(arguments.get("action"));
        if (action == null || action.isBlank()) {
            return McpSchema.CallToolResult.builder().addTextContent("action is required").build();
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("tool", getName());
        response.put("program", currentProgram.getName());
        response.put("action", action);

        switch (action.toLowerCase()) {
            case "auto_analyze": {
                String reason = asString(arguments.get("reason"));
                String status = backend.runAutoAnalysis(currentProgram, reason != null ? reason : "analysis_tasks:auto_analyze");
                response.put("status", "completed");
                response.put("auto_analyze", status);
                break;
            }
            case "set_memory_zones": {
                Object zonesObj = arguments.get("zones");
                if (!(zonesObj instanceof List<?> list)) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("zones must be provided as an array for set_memory_zones")
                        .build();
                }

                List<GhidrAssistMCPBackend.MemoryZone> zones = new ArrayList<>();
                int i = 0;
                for (Object item : list) {
                    if (!(item instanceof Map<?, ?> m)) {
                        return McpSchema.CallToolResult.builder().addTextContent("Invalid zone at index " + i).build();
                    }

                    String start = asString(m.get("start"));
                    String end = asString(m.get("end"));
                    String label = asString(m.get("label"));

                    if (start == null || end == null) {
                        return McpSchema.CallToolResult.builder().addTextContent("Zone requires start and end at index " + i).build();
                    }

                    Address startAddr = currentProgram.getAddressFactory().getAddress(start);
                    Address endAddr = currentProgram.getAddressFactory().getAddress(end);
                    if (startAddr == null || endAddr == null || startAddr.compareTo(endAddr) > 0) {
                        return McpSchema.CallToolResult.builder().addTextContent("Invalid address range at zone index " + i).build();
                    }

                    String zoneLabel = (label == null || label.isBlank()) ? "zone_" + i : label;
                    zones.add(new GhidrAssistMCPBackend.MemoryZone(startAddr.toString(), endAddr.toString(), zoneLabel));
                    i++;
                }

                backend.setCustomMemoryZones(currentProgram, zones);
                response.put("status", "updated");
                response.put("zone_count", zones.size());
                response.put("zones", zones);
                break;
            }
            case "list_memory_zones": {
                List<GhidrAssistMCPBackend.MemoryZone> zones = backend.getCustomMemoryZones(currentProgram);
                response.put("status", "ok");
                response.put("zone_count", zones.size());
                response.put("zones", zones);
                break;
            }
            case "clear_memory_zones": {
                backend.clearCustomMemoryZones(currentProgram);
                response.put("status", "cleared");
                break;
            }
            default:
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Unknown action: " + action + ". Supported: auto_analyze, set_memory_zones, list_memory_zones, clear_memory_zones")
                    .build();
        }

        return McpSchema.CallToolResult.builder().addTextContent(response.toString()).build();
    }

    private static String asString(Object value) {
        return value instanceof String ? (String) value : null;
    }
}
