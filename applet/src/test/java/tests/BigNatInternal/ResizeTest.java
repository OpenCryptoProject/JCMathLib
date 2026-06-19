package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class ResizeTest {
    @Test
    public void resize_smallerLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03, 0x01, 0x05, 0x06};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        /* First resize to truncate */
        bn.ctResize((short) (data.length - 3));
        Assertions.assertEquals(data.length - 3, bn.length());

        /* Check that truncation ~ filling with zeroes */
        bn.ctResize((short) (data.length));
        Assertions.assertEquals(data.length, bn.length());
        byte[] expectedResult = {0, 0, 0, 0x01, 0x05, 0x06};
        byte[] actualResult = new byte[6];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void resize_biggerLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03, 0x01, 0x05, 0x06};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctResize((short) (data.length + 3));
        Assertions.assertEquals(data.length  + 3, bn.length());

        byte[] expectedResult = {0, 0, 0, 0x01, 0x02, 0x03, 0x01, 0x05, 0x06};
        byte[] actualResult = new byte[9];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void resize_sameSize() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctResize((short) data.length);
        Assertions.assertEquals(data.length, data.length);

        byte[] expectedResult = {0x01, 0x02, 0x03};
        byte[] actualResult = new byte[3];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void resize_empty() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) 3);
        bn.ctResize((short) 0);
        Assertions.assertEquals(0, bn.length());
        /* No exception */
        bn.copyToByteArray(new byte[] {}, (short) 0);
    }
}
