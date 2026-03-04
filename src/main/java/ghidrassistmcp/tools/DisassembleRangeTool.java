package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that disassembles an arbitrary address range.
 */
public class DisassembleRangeTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "disassemble_range";
    }

    @Override
    public String getDescription() {
        return "Disassemble instructions between start and end addresses, even outside defined functions";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "start", Map.of("type", "string", "description", "Range start address"),
                "end", Map.of("type", "string", "description", "Range end address (inclusive)"),
                "max_instructions", Map.of("type", "integer", "description", "Optional cap (default 500)")
            ),
            List.of("start", "end"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addTextContent("No program currently loaded").build();
        }

        String startStr = arguments.get("start") instanceof String ? (String) arguments.get("start") : null;
        String endStr = arguments.get("end") instanceof String ? (String) arguments.get("end") : null;
        int maxInstructions = 500;
        if (arguments.get("max_instructions") instanceof Number) {
            maxInstructions = Math.max(1, ((Number) arguments.get("max_instructions")).intValue());
        }

        if (startStr == null || endStr == null) {
            return McpSchema.CallToolResult.builder().addTextContent("start and end are required").build();
        }

        Address start = currentProgram.getAddressFactory().getAddress(startStr);
        Address end = currentProgram.getAddressFactory().getAddress(endStr);
        if (start == null || end == null) {
            return McpSchema.CallToolResult.builder().addTextContent("Invalid start or end address").build();
        }
        if (start.compareTo(end) > 0) {
            return McpSchema.CallToolResult.builder().addTextContent("start must be <= end").build();
        }

        StringBuilder out = new StringBuilder();
        out.append("Disassembly range ").append(start).append(" - ").append(end).append("\n\n");

        InstructionIterator it = currentProgram.getListing().getInstructions(start, true);
        int count = 0;

        while (it.hasNext() && count < maxInstructions) {
            Instruction instr = it.next();
            Address instrAddr = instr.getAddress();
            if (instrAddr.compareTo(end) > 0) {
                break;
            }

            out.append(instrAddr)
               .append(": ")
               .append(instr.toString())
               .append("\n");
            count++;
        }

        if (count == 0) {
            out.append("No defined instructions found in the range. You may need to create/disassemble code first.");
        } else if (count >= maxInstructions) {
            out.append("\n... truncated at max_instructions=").append(maxInstructions);
        }

        return McpSchema.CallToolResult.builder().addTextContent(out.toString()).build();
    }
}
