package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class IncrementTest {
    @Test
    public void increment_firstByte() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {0x00, 0x01, 0x02, 0x03};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctIncrement();

        byte[] expectedResult = {0x00, 0x01, 0x02, 0x04};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);

        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void increment_secondByte() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {0x00, 0x01, 0x02, (byte) 0xff};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctIncrement();

        byte[] expectedResult = {0x00, 0x01, 0x03, 0x00};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);

        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void increment_lastByte() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctIncrement();

        byte[] expectedResult = {0x01, 0x00, 0x00, 0x00};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);

        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void increment_overflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        bn.fromByteArray(data, (short) 0, (short) data.length);
        bn.ctIncrement();

        byte[] expectedResult = {0x00, 0x00, 0x00, 0x00};
        byte[] actualResult = new byte[4];
        bn.copyToByteArray(actualResult, (short) 0);

        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
