package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class ShrinkTest {

    @Test
    public void shrink_toZero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctShrink();
        Assertions.assertEquals(0, bn.length());
    }

    @Test
    public void shrink_longer() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctShrink();
        Assertions.assertEquals(3, bn.length());
    }

    @Test
    public void shrink_sameLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctShrink();
        Assertions.assertEquals(3, bn.length());
    }

    @Test
    public void shrink_blindFalse() {
        ResourceManager rm = new ResourceManager((short) 10);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctShrink((short) 0);
        Assertions.assertEquals(3, bn.length());
    }

    @Test
    public void shrink_blindTrue() {
        ResourceManager rm = new ResourceManager((short) 10);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctShrink((short) 0xffff);
        Assertions.assertEquals(6, bn.length());
    }
}
