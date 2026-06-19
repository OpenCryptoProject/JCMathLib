package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class IsZeroTest {
    @Test
    public void zero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 7, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0xffff, bn.ctIsZero());
    }

    @Test
    public void nonzero_0() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 5, memoryType, rm);

        byte[] data = {0x01, 0x00, 0x00, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0x00, bn.ctIsZero());
    }

    @Test
    public void nonzero_1() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 5, memoryType, rm);

        byte[] data = {0x00, 0x01, 0x00, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0x00, bn.ctIsZero());
    }

    @Test
    public void nonzero_2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 5, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x01, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0x00, bn.ctIsZero());
    }

    @Test
    public void nonzero_3() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 5, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x01};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0x00, bn.ctIsZero());
    }

    @Test
    public void nonzero_more() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 5, memoryType, rm);

        byte[] data = {0x01, 0x00, 0x01, 0x01};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0x00, bn.ctIsZero());
    }
}