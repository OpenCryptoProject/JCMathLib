package tests.BigNatInternal;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class CloneTest {
    @Test
    public void clone_otherSizeSameAsThis() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctClone(bn2);

        byte[] actualResult = new byte[data2.length];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(data2, actualResult);
    }

    @Test
    public void clone_otherValueLengthBiggerThanThis() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 4, memoryType, rm);
        BigNat bn2 = new BigNat((short) 50, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctClone(bn2);

        byte[] actualResult = new byte[data2.length];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(data2, actualResult);
    }

    @Test
    public void clone_otherSizeBiggerThanThis_exception() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 4, memoryType, rm);
        BigNat bn2 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        Assertions.assertThrows(ISOException.class, () -> bn1.ctClone(bn2));
    }

    @Test
    public void clone_otherSizeSmallerThanThis() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 4, memoryType, rm);
        BigNat bn2 = new BigNat((short) 4, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctClone(bn2);

        byte[] actualResult = new byte[data2.length];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(data2, actualResult);
    }

    @Test
    public void clone_otherSizeZero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 4, memoryType, rm);
        BigNat bn2 = new BigNat((short) 4, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctClone(bn2);
        Assertions.assertEquals(bn1.length(), 0);
    }

    @Test
    public void clone_otherSizeSameAsThis_blindFalse() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctClone(bn2, (short) 0x00);

        byte[] actualResult = new byte[data2.length];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(data2, actualResult);
    }

    @Test
    public void clone_otherSizeSameAsThis_blindTrue() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctClone(bn2, (short) 0x00);

        byte[] actualResult = new byte[data2.length];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(data2, actualResult);
    }
}
