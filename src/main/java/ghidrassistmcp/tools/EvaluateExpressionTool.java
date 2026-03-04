package ghidrassistmcp.tools;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.lang.Register;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Evaluate simple register expressions at a given address using linear pcode propagation.
 */
public class EvaluateExpressionTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "evaluate_expression";
    }

    @Override
    public String getDescription() {
        return "Evaluate a register/expression at an address using lightweight constant propagation";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", Map.of("type", "string", "description", "Address where the expression should be evaluated"),
                "expression", Map.of("type", "string", "description", "Expression to evaluate (currently register name or integer literal)"),
                "register", Map.of("type", "string", "description", "Convenience alias for expression when querying a register")
            ),
            List.of("address"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addTextContent("No program currently loaded").build();
        }

        String addressStr = getString(arguments, "address");
        String expression = getString(arguments, "expression");
        String register = getString(arguments, "register");
        if ((expression == null || expression.isBlank()) && register != null && !register.isBlank()) {
            expression = register;
        }

        if (addressStr == null || addressStr.isBlank()) {
            return McpSchema.CallToolResult.builder().addTextContent("address is required").build();
        }
        if (expression == null || expression.isBlank()) {
            return McpSchema.CallToolResult.builder().addTextContent("expression (or register) is required").build();
        }

        Address target = currentProgram.getAddressFactory().getAddress(addressStr);
        if (target == null) {
            return McpSchema.CallToolResult.builder().addTextContent("Invalid address: " + addressStr).build();
        }

        Function function = currentProgram.getFunctionManager().getFunctionContaining(target);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No containing function for " + target + ". Define a function first or use disassemble_range for raw code.")
                .build();
        }

        Map<String, Long> values = new HashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(function.getBody(), true);

        while (it.hasNext()) {
            Instruction instr = it.next();
            if (instr.getAddress().compareTo(target) >= 0) {
                break;
            }
            PcodeOp[] pcode = instr.getPcode();
            for (PcodeOp op : pcode) {
                applyOp(currentProgram, values, op);
            }
        }

        StringBuilder out = new StringBuilder();
        out.append("Evaluation at ").append(target)
           .append(" (function ").append(function.getName()).append(")\n");
        out.append("Expression: ").append(expression).append("\n");

        Long literal = parseLiteral(expression);
        if (literal != null) {
            out.append("Value: 0x").append(Long.toUnsignedString(literal, 16))
               .append(" (decimal ").append(Long.toUnsignedString(literal)).append(")\n")
               .append("Resolved: yes (literal)");
            return McpSchema.CallToolResult.builder().addTextContent(out.toString()).build();
        }

        String key = resolveRegisterExpressionKey(currentProgram, expression);
        if (key == null) {
            out.append("Value: unknown\nResolved: no\n");
            out.append("Note: register not recognized for this language profile.");
            return McpSchema.CallToolResult.builder().addTextContent(out.toString()).build();
        }

        Long value = values.get(key);
        if (value == null) {
            out.append("Value: unknown\nResolved: no\n");
            out.append("Note: register recognized, but value was not propagated to this location. ")
               .append("Evaluator currently handles linear constant propagation and may miss CFG-sensitive values.");
        } else {
            out.append("Value: 0x").append(Long.toUnsignedString(value, 16))
               .append(" (decimal ").append(Long.toUnsignedString(value)).append(")\nResolved: yes");
        }

        return McpSchema.CallToolResult.builder().addTextContent(out.toString()).build();
    }

    private void applyOp(Program program, Map<String, Long> values, PcodeOp op) {
        Varnode out = op.getOutput();
        if (out == null) {
            return;
        }

        Long result = switch (op.getOpcode()) {
            case PcodeOp.COPY -> readValue(program, values, op.getInput(0));
            case PcodeOp.INT_ADD -> bin(program, values, op, (a, b) -> a + b);
            case PcodeOp.INT_SUB -> bin(program, values, op, (a, b) -> a - b);
            case PcodeOp.INT_AND -> bin(program, values, op, (a, b) -> a & b);
            case PcodeOp.INT_OR -> bin(program, values, op, (a, b) -> a | b);
            case PcodeOp.INT_XOR -> bin(program, values, op, (a, b) -> a ^ b);
            case PcodeOp.INT_LEFT -> bin(program, values, op, (a, b) -> a << (b & 0x3f));
            case PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT -> bin(program, values, op, (a, b) -> a >> (b & 0x3f));
            case PcodeOp.INT_MULT -> bin(program, values, op, (a, b) -> a * b);
            default -> null;
        };

        String outKey = getRegisterKey(program, out);
        if (outKey == null) {
            return;
        }

        if (result == null) {
            values.remove(outKey);
        } else {
            values.put(outKey, result);
        }
    }

    private Long bin(Program program, Map<String, Long> values, PcodeOp op, LongBinOp fn) {
        Long a = readValue(program, values, op.getInput(0));
        Long b = readValue(program, values, op.getInput(1));
        return (a == null || b == null) ? null : fn.apply(a, b);
    }

    private Long readValue(Program program, Map<String, Long> values, Varnode node) {
        if (node == null) {
            return null;
        }
        if (node.isConstant()) {
            return node.getOffset();
        }

        String key = getRegisterKey(program, node);
        return key == null ? null : values.get(key);
    }

    String getRegisterKey(Program program, Varnode node) {
        if (node == null || !node.isRegister()) {
            return null;
        }
        Register register = program.getRegister(node.getAddress(), node.getSize());
        if (register != null) {
            return canonicalRegisterKey(register, node.getSize());
        }
        return null;
    }

    String resolveRegisterExpressionKey(Program program, String expression) {
        if (program == null || expression == null || expression.isBlank()) {
            return null;
        }

        String trimmed = expression.trim();
        Register register = program.getLanguage().getRegister(trimmed);
        if (register == null) {
            register = program.getRegister(trimmed);
        }
        if (register == null) {
            return null;
        }

        return canonicalRegisterKey(register, register.getNumBytes());
    }

    static String canonicalRegisterKey(Register register, int size) {
        if (register == null) {
            return null;
        }
        Register baseRegister = register.getBaseRegister();
        Register canonicalBase = baseRegister == null ? register : baseRegister;
        int baseOffset = canonicalBase.getOffset();
        int offset = Math.max(0, register.getOffset() - baseOffset);
        int normalizedSize = size > 0 ? size : register.getNumBytes();
        return normalizeRegisterKey(canonicalBase.getName()) + ":" + offset + ":" + normalizedSize;
    }

    private static String normalizeRegisterKey(String value) {
        return value == null ? null : value.trim().toLowerCase();
    }

    private static Long parseLiteral(String expression) {
        try {
            String trimmed = expression.trim().toLowerCase();
            if (trimmed.startsWith("0x")) {
                return Long.parseUnsignedLong(trimmed.substring(2), 16);
            }
            if (trimmed.matches("[0-9]+")) {
                return Long.parseUnsignedLong(trimmed, 10);
            }
            return null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String getString(Map<String, Object> arguments, String key) {
        Object value = arguments.get(key);
        return value instanceof String ? (String) value : null;
    }

    @FunctionalInterface
    private interface LongBinOp {
        long apply(long a, long b);
    }
}
