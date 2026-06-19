package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class FromByteArrayTest {

    @Test
    public void emptyArray() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {};
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bn1.ctFromByteArray(data1, (short) 0, (short) data1.length));
    }

    @Test
    public void tooLongSrcLength_outOfBounds() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bn1.ctFromByteArray(data1, (short) 0, (short) (data1.length + 1)));
    }

    @Test
    public void fromByteArray_shorter() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.ctFromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[10];
        bn1.copyToByteArray(actualDst, (short) 0);

        byte[] expectedDst = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0, 0, 0, 0};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void fromByteArray_empty() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {};
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> bn1.ctFromByteArray(data1, (short) 0, (short) data1.length));
    }

    @Test
    public void fromByteArray_equal() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 6, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.ctFromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[10];
        bn1.copyToByteArray(actualDst, (short) 0);

        byte[] expectedDst = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0, 0, 0, 0};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }

    @Test
    public void fromByteArray_longer() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 6, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        bn1.ctFromByteArray(data1, (short) 0, (short) data1.length);

        byte[] actualDst = new byte[10];
        bn1.copyToByteArray(actualDst, (short) 0);

        byte[] expectedDst = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0, 0, 0};
        Assertions.assertArrayEquals(expectedDst, actualDst);
    }
}
