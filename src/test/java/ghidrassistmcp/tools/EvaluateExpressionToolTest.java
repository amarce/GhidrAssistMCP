package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;

class EvaluateExpressionToolTest {

    @Test
    void canonicalRegisterKey_usesBaseRegisterOffsetAndSize() {
        Register base = Mockito.mock(Register.class);
        Mockito.when(base.getName()).thenReturn("x10");
        Mockito.when(base.getOffset()).thenReturn(0);

        Register alias = Mockito.mock(Register.class);
        Mockito.when(alias.getBaseRegister()).thenReturn(base);
        Mockito.when(alias.getOffset()).thenReturn(0);
        Mockito.when(alias.getNumBytes()).thenReturn(8);

        String key = EvaluateExpressionTool.canonicalRegisterKey(alias, alias.getNumBytes());
        assertEquals("x10:0:8", key);
    }

    @Test
    void aliasRegisterPair_resolvesToSameCanonicalIdentity() {
        EvaluateExpressionTool tool = new EvaluateExpressionTool();

        Register base = Mockito.mock(Register.class);
        Mockito.when(base.getName()).thenReturn("x10");
        Mockito.when(base.getOffset()).thenReturn(0);

        Register a0 = Mockito.mock(Register.class);
        Mockito.when(a0.getBaseRegister()).thenReturn(base);
        Mockito.when(a0.getOffset()).thenReturn(0);
        Mockito.when(a0.getNumBytes()).thenReturn(8);

        Register x10 = Mockito.mock(Register.class);
        Mockito.when(x10.getBaseRegister()).thenReturn(base);
        Mockito.when(x10.getOffset()).thenReturn(0);
        Mockito.when(x10.getNumBytes()).thenReturn(8);

        Language language = Mockito.mock(Language.class);
        Mockito.when(language.getRegister("a0")).thenReturn(a0);

        Program program = Mockito.mock(Program.class);
        Mockito.when(program.getLanguage()).thenReturn(language);
        Mockito.when(program.getRegister("a0")).thenReturn(a0);

        Varnode node = Mockito.mock(Varnode.class);
        Address address = Mockito.mock(Address.class);
        Mockito.when(node.isRegister()).thenReturn(true);
        Mockito.when(node.getSize()).thenReturn(8);
        Mockito.when(node.getAddress()).thenReturn(address);
        Mockito.when(program.getRegister(address, 8)).thenReturn(x10);

        String fromVarnode = tool.getRegisterKey(program, node);
        String fromExpression = tool.resolveRegisterExpressionKey(program, "a0");

        assertNotNull(fromVarnode);
        assertEquals(fromVarnode, fromExpression);

        Map<String, Long> values = new HashMap<>();
        values.put(fromVarnode, 0x42L);
        assertEquals(0x42L, values.get(fromExpression));
    }

    @Test
    void resolveRegisterExpressionKey_returnsNullForUnknownRegister() {
        EvaluateExpressionTool tool = new EvaluateExpressionTool();

        Language language = Mockito.mock(Language.class);
        Program program = Mockito.mock(Program.class);
        Mockito.when(program.getLanguage()).thenReturn(language);
        Mockito.when(language.getRegister("not_a_reg")).thenReturn(null);
        Mockito.when(program.getRegister("not_a_reg")).thenReturn(null);

        assertNull(tool.resolveRegisterExpressionKey(program, "not_a_reg"));
    }
}
