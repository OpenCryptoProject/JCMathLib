package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/**
 * @author Veronika Hanulikova
 */
public class PrependZeroesTest {
    // TODO: add test for blinding
    @Test
    public void toFullLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] outBuffer = new byte[10];
        Arrays.fill(outBuffer, (byte) 0xff);
        byte[] rBuffer = new byte[] {(byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03};

        bn1.ctPrependZeros((short) 8, outBuffer, (short) 2);
        Assertions.assertArrayEquals(rBuffer, outBuffer);
    }

    @Test
    public void oneMissing() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] outBuffer = new byte[10];
        Arrays.fill(outBuffer, (byte) 0xff);
        byte[] rBuffer = new byte[] {(byte) 0xff, (byte) 0xff, 0, 0, 0, 0, 0x01, 0x02, 0x03, (byte) 0xff};

        bn1.ctPrependZeros((short) 7, outBuffer, (short) 2);
        Assertions.assertArrayEquals(rBuffer, outBuffer);
    }

    @Test
    public void twoMissing() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] outBuffer = new byte[10];
        Arrays.fill(outBuffer, (byte) 0xff);
        byte[] rBuffer = new byte[] {(byte) 0xff, 0, 0, 0, 0, 0x01, 0x02, 0x03, (byte) 0xff, (byte) 0xff};

        bn1.ctPrependZeros((short) 7, outBuffer, (short) 1);
        Assertions.assertArrayEquals(rBuffer, outBuffer);
    }

    @Test
    public void atStart() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] outBuffer = new byte[10];
        Arrays.fill(outBuffer, (byte) 0xff);
        byte[] rBuffer = new byte[] {0, 0, 0, 0, 0x01, 0x02, 0x03, (byte) 0xff, (byte) 0xff, (byte) 0xff};

        bn1.ctPrependZeros((short) 7, outBuffer, (short) 0);
        Assertions.assertArrayEquals(rBuffer, outBuffer);
    }

    @Test
    public void atStartToFull() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] outBuffer = new byte[10];
        Arrays.fill(outBuffer, (byte) 0xff);
        byte[] rBuffer = new byte[] {0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03};

        bn1.ctPrependZeros((short) 10, outBuffer, (short) 0);
        Assertions.assertArrayEquals(rBuffer, outBuffer);
    }

    @Test
    public void atStartOneMissing() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);

        byte[] outBuffer = new byte[10];
        Arrays.fill(outBuffer, (byte) 0xff);
        byte[] rBuffer = new byte[] {0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, (byte) 0xff};

        bn1.ctPrependZeros((short) 9, outBuffer, (short) 0);
        Assertions.assertArrayEquals(rBuffer, outBuffer);
    }
}
