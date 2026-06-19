package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class IsOneTest {
    @Test
    public void one() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 7, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x01};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0xffff, bn.ctIsOne());
    }

    @Test
    public void zero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 7, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0x00, bn.ctIsOne());
    }

    @Test
    public void hex_0101() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 7, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x01, 0x01};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        Assertions.assertEquals((short) 0x00, bn.ctIsOne());
    }
}
