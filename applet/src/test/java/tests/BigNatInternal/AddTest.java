package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class AddTest {
    @Test
    public void add_thisLonger() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals(0, carry);
        byte[] expectedResult = {0x01, 0x04, 0x06};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisLonger_overflow_otherHigherBytes() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        short carry = bn1.ctAdd(bn2);

        Assertions.assertEquals(0, carry);
        byte[] expectedResult = {0x02, 0x00, 0x06};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisLonger_overflow_otherFFs() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, (byte) 0xff};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        short carry = bn1.ctAdd(bn2);

        Assertions.assertEquals(0, carry);
        byte[] expectedResult = {0x02, 0x01, 0x01};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisLonger_overflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x08, (byte) 0xff};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, (byte) 0x09};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals(0, carry);
        byte[] expectedResult = {0x02, 0x08, 0x08};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisLonger_overflowInnerZeroByteInThis() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x00, (byte) 0xff};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, (byte) 0x09};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals(0, carry);
        byte[] expectedResult = {0x02, 0x00, 0x08};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisLonger_overflow2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x08, (byte) 0xff};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, (byte) 0xff};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals(0, carry);
        byte[] expectedResult = {0x02, 0x08, (byte) 0xfe};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisLonger_highestByteOverflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {(byte) 0xff, 0x08, (byte) 0xff};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, (byte) 0xff};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        // test no overflow to higher byte
        bn1.ctResize((short) (bn1.length() + 1));
        Assertions.assertEquals((byte) 128, carry);
        byte[] expectedResult = {0x00, 0x00, 0x08, (byte) 0xfe};
        byte[] actualResult = new byte[4];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_sameLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals((byte) 0, carry);
        byte[] expectedResult = {0x04, 0x06};
        byte[] actualResult = new byte[2];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_sameLength_overflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0xff, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        // test no overflow to higher byte
        bn1.ctResize((short) (bn1.length() + 1));
        Assertions.assertEquals((byte) 128, carry);
        byte[] expectedResult = {0x00, 0x00, 0x06};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_otherLonger_overflow() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {(byte) 0xff, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x01, 0x02};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals((byte) 128, carry);
        bn1.ctResize((short) (bn1.length() + 1));
        Assertions.assertEquals((byte) 128, carry);
        byte[] expectedResult = {0x00, 0x00, 0x06};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_otherLonger() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x01, 0x01, 0x02};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals((byte) 0, carry);
        bn1.ctResize((short) (bn1.length() + 3));
        byte[] expectedResult = {0x00, 0x00, 0x00, 0x06};
        byte[] actualResult = new byte[4];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisBiggerMemory() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {(byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0x1};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals((byte) 0, carry);
        byte[] expectedResult = {0x01, 0x00, 0x00, 0x00};
        byte[] actualResult = new byte[4];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisBiggerMemory2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0x1};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals((byte) 128, carry);
        byte[] expectedResult = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] actualResult = new byte[6];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisBiggerMemory3() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 1, memoryType, rm);

        byte[] data1 = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x1, 0x1};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2);

        Assertions.assertEquals((byte) 128, carry);
        byte[] expectedResult = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
        byte[] actualResult = new byte[6];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    /* blinded */

    @Test
    public void add_thisLonger_blindFalse() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2, (short) 0x00);

        Assertions.assertEquals(0, carry);
        byte[] expectedResult = {0x01, 0x04, 0x06};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void add_thisLonger_blindTrue() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x01, 0x02};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        byte carry = bn1.ctAdd(bn2, (short) 0xffff);

        Assertions.assertEquals(0, carry);
        byte[] expectedResult = {0x01, 0x01, 0x02};
        byte[] actualResult = new byte[3];
        bn1.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
