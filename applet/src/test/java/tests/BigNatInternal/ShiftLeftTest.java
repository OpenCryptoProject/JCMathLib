package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class ShiftLeftTest {
    @Test
    public void shiftLeft_0() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x05, 0x08};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn1.ctShiftLeft((short) 0);

        byte[] expectedResult = {0x05, 0x08};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void shiftLeft_1() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x05, 0x08};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn1.ctShiftLeft((short) 1);

        byte[] expectedResult = {0x0A, (byte) 0x10};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void shiftLeft_7() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x00, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn1.ctShiftLeft((short) 7);

        byte[] expectedResult = {0x01, (byte) 0x00};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void shiftLeft_8() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeft((short) 8);

        byte[] expectedResult = {0x01, 0x02, 0x03, 0x00};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void shiftLeft_9_resize() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeft((short) 9);

        byte[] expectedResult = {0x02, 0x04, 0x06, 0x00};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void shiftLeft_9_noResize() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 2, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeft((short) 9);

        byte[] expectedResult = {0x04, 0x06, 0x00};
        byte[] actualResult = new byte[3];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void shiftLeft_12_noResize() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 2, memoryType, rm);

        byte[] data = {(byte) 0xab, (byte) 0xcd, (byte) 0xde};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeft((short) 12);

        byte[] expectedResult = {(byte) 0xDD, (byte) 0xE0, 0x00};
        byte[] actualResult = new byte[3];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void shiftLeft_12_resizePartially() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {(byte) 0xab, (byte) 0xcd, (byte) 0xde};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeft((short) 12);

        byte[] expectedResult = {(byte) 0xBC, (byte) 0xDD, (byte) 0xE0, 0x00};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void shiftLeft_16_noResize() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 2, memoryType, rm);

        byte[] data = {0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        bn.ctShiftLeft((short) 16);

        byte[] expectedResult = {0x03, 0x00, 0x00};
        byte[] actualResult = new byte[3];
        bn.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
