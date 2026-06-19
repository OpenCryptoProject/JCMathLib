package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.BigNatInternal;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class MultTest {
    @Test
    public void mult_oneByteOne() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {0x01, 0x02};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_oneByteFive() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {0x05, 0x0A};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_oneByteZero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {};
        byte[] actualResult = new byte[0];
        Assertions.assertEquals(0, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_severalBytesZero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00, 0x00, 0x00};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {};
        byte[] actualResult = new byte[0];
        Assertions.assertEquals(0, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_oneByteFF() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 3, memoryType, rm);
        BigNat bn2 = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {0x01, (byte) 0xfe};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_twoBytesFF() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 3, memoryType, rm);
        BigNat bn2 = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {(byte) 0xff};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, (byte) 0xff};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {(byte) 0xfe, (byte) 0xff, 0x01};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_thisLong() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {(byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc, (byte) 0xfb};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, (byte) 0x56};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {(byte) 0xFF, (byte) 0x54, (byte) 0xFE, (byte) 0xA8, (byte) 0x51, (byte) 0x01, (byte) 0x52};
        byte[] actualResult = new byte[7];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_otherLong() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {(byte) 0xff, (byte) 0x56};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc, (byte) 0xfb};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {(byte) 0xFF, (byte) 0x54, (byte) 0xFE, (byte) 0xA8, (byte) 0x51, (byte) 0x01, (byte) 0x52};
        byte[] actualResult = new byte[7];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_sameLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {(byte) 0xFF, (byte) 0xDE, (byte) 0x14, (byte) 0x58}; //FFDE1458
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xE1, (byte) 0xAA, (byte) 0x25, (byte) 0x37}; //E1AA2537
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        ((BigNatInternal) bn1).ctMult(bn2);

        byte[] expectedResult = {(byte) 0xE1, (byte) 0x8C, (byte) 0x3E, (byte) 0x8C, (byte) 0xEC, (byte) 0x17, (byte) 0x16, (byte) 0xE8};
        byte[] actualResult = new byte[8];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    /* blinded */

    @Test
    public void mult_oneByteFive_blindFalse() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctMult(bn2, (short) 0x00);

        byte[] expectedResult = {0x05, 0x0A};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mult_oneByteFive_blindTrue() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        bn1.ctMult(bn2, (short) 0xffff);

        byte[] expectedResult = {0x01, 0x02};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
