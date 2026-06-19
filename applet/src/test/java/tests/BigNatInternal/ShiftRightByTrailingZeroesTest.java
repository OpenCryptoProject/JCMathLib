package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class ShiftRightByTrailingZeroesTest {
    @Test
    public void one() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 1, memoryType, rm);

        byte[] data1 = {0x00, 0x01};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn1.ctShiftRightByTrailingZeroes((short) 0);

        byte[] expectedResult = {0x00, 0x01};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void two() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 1, memoryType, rm);

        byte[] data1 = {0x00, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn1.ctShiftRightByTrailingZeroes((short) 0);

        byte[] expectedResult = {0x00, 0x01};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void twoBytes_oneBit() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 1, memoryType, rm);

        byte[] data1 = {0x01, 0x00};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn1.ctShiftRightByTrailingZeroes((short) 0);

        byte[] expectedResult = {0x00, 0x01};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void twoBytes() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 1, memoryType, rm);

        byte[] data1 = {(byte) 0x81, 0x29};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn1.ctShiftRightByTrailingZeroes((short) 0);

        byte[] expectedResult = {(byte) 0x81, 0x29};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void twoBytes_shift3() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 1, memoryType, rm);

        byte[] data1 = {(byte) 0x81, 0x28};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn1.ctShiftRightByTrailingZeroes((short) 0);

        byte[] expectedResult = {(byte) 0x10, 0x25};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
