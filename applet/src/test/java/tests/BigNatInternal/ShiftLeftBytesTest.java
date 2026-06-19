package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class ShiftLeftBytesTest {
    @Test
    public void zeroShift() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeftBytes((short) 0);

        byte[] expectedResult = {0x01, 0x02, 0x03};
        byte[] actualResult = new byte[3];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void oneShift() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 4, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeftBytes((short) 1);

        byte[] expectedResult = {0x01, 0x02, 0x03, 0x00};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void twoShift_noResizing() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 2, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeftBytes((short) 2);

        byte[] expectedResult = {0x03, 0x00, 0x00};
        byte[] actualResult = new byte[3];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void twoShift_resize() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeftBytes((short) 2);

        byte[] expectedResult = {0x02, 0x03, 0x00, 0x00};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void overflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 2, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeftBytes((short) 3);

        byte[] expectedResult = {0x00, 0x00, 0x00};
        byte[] actualResult = new byte[3];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
