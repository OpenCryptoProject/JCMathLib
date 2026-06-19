package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class CopyToByteArrayTest {
    @Test
    public void copyToByteArray_shortDestination() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[3];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bn1.ctCopyToByteArray(actualDst, (short) 0));
    }

    @Test
    public void copyToByteArray_dstlonger_offset_0() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[10];
        bn1.ctCopyToByteArray(actualDst, (short) 0);

        byte[] expectedDst = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0, 0, 0, 0};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void copyToByteArray_dstlonger_offset_1() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[10];
        bn1.ctCopyToByteArray(actualDst, (short) 1);

        byte[] expectedDst = {0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0, 0, 0};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void copyToByteArray_dstlonger_offset_4() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[10];
        bn1.ctCopyToByteArray(actualDst, (short) 4);

        byte[] expectedDst = {0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void copyToByteArray_dstlonger_offset_5_exception() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[10];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bn1.ctCopyToByteArray(actualDst, (short) 5));

        byte[] expectedDst = new byte[10];
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void copyToByteArray_dstSameLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[6];
        bn1.ctCopyToByteArray(actualDst, (short) 0);

        byte[] expectedDst = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void copyToByteArray_dstSameLengt_offset_1_exception() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[6];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bn1.ctCopyToByteArray(actualDst, (short) 5));

        byte[] expectedDst = new byte[6];
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void copyToByteArray_dstSameLength_blindFalse() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[6];
        bn1.ctCopyToByteArray(actualDst, (short) 0, (short) 0);

        byte[] expectedDst = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void copyToByteArray_dstSameLength_blindTrue() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[6];
        bn1.ctCopyToByteArray(actualDst, (short) 0, (short) (0xffff));

        byte[] expectedDst = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }
}
