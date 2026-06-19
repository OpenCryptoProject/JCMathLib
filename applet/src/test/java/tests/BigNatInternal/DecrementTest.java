package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class DecrementTest {
    @Test
    public void increment_firstByte() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {0x00, 0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctDecrement();

        byte[] expectedResult = {0x00, 0x01, 0x02, 0x02};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);

        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void increment_twoBytes() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {0x00, 0x01, 0x02, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctDecrement();

        byte[] expectedResult = {0x00, 0x01, 0x01, (byte) 0xff};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);

        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void increment_allBytes() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {0x01, 0x00, 0x00, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctDecrement();

        byte[] expectedResult = {0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);

        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void increment_overflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {0x00, 0x00, 0x00, 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctDecrement();

        byte[] expectedResult = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);

        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
