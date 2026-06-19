package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class SubtractShiftTest {
    @Test
    public void subtract_otherLonger() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x03, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x05, 0x01, 0x01};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        bn1.ctResize((short) (bn1.length() + 1));
        byte[] expectedResult = {0x00, 0x02, 0x01};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_otherLonger_underflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x03, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x05, 0x01, 0x03};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        bn1.ctResize((short) (bn1.length() + 1));
        byte[] expectedResult = {0x00, 0x01, (byte) 0xff};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_sameLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x03, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x01};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        bn1.ctResize((short) (bn1.length() + 1));
        byte[] expectedResult = {0x00, 0x02, 0x01};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_sameLength_underflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x03, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x03};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        byte[] expectedResult = {0x01, (byte) 0xff};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_sameLength_underflow2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x03, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        byte[] expectedResult = {0x00, (byte) 0xff};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_sameLength_underflow3() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x01};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        byte[] expectedResult = {(byte) 0xff, 0x01};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_sameLength_underflow4() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x01};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        byte[] expectedResult = {(byte) 0xfe, (byte) 0xff};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_thisBigger() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x03, 0x03, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x01};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        bn1.ctResize((short) (bn1.length() + 1));
        byte[] expectedResult = {0x00, 0x03, 0x02, 0x01};
        byte[] actualResult = new byte[4];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_thisBigger_underflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x03, 0x03, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x03, 0x03};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        byte[] expectedResult = {0x02, (byte) 0xff, (byte) 0xff};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_thisBiggerMemory() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        byte[] expectedResult = {0x01, 0x01, 0x01, 0x01, 0x01, 0x00};
        byte[] actualResult = new byte[6];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_thisBiggerMemory2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        byte[] expectedResult = {0x01, 0x01, 0x01, 0x01, 0x00, 0x02};
        byte[] actualResult = new byte[6];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_thisBiggerMemory3() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x01};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 1);

        byte[] expectedResult = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00};
        byte[] actualResult = new byte[6];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_noShift_multiplier() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x05, 0x08};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 0, (short) 2);

        byte[] expectedResult = {(byte) 0x03, (byte) 0x04};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_shift2_noMultiplier() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x05, 0x08};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 2, (short) 0);

        byte[] expectedResult = {0x05, 0x08};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_shift1_noMultiplier() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x05, 0x08};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 1, (short) 1);

        byte[] expectedResult = {0x03, 0x08};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void subtract_bigShift_noOverflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctSubtractShift(bn2, (byte) 7, (short) 1);

        byte[] expectedResult = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        byte[] actualResult = new byte[6];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
