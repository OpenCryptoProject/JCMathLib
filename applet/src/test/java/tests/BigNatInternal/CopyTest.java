package tests.BigNatInternal;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

/**
 * @author Veronika Hanulikova
 */
public class CopyTest {
    @Test
    public void copy_empty() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        /* This */
        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        /* Other */
        bn2.fromByteArray(new byte[]{}, (short) 0, (short) 0);

        bn1.ctCopy(bn2);

        byte[] actualResult = new byte[6];
        Arrays.fill(actualResult, (byte) 0xff);
        short resultSize = bn1.copyToByteArray(actualResult, (short) 0);
        /* Should be empty */
        Assertions.assertEquals(6, resultSize);
        /* Output buffer not changed */
        Assertions.assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0}, actualResult);
    }

    @Test
    public void copy_thisLonger() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctCopy(bn2);
        
        byte[] expectedResult = {0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        byte[] actualResult = new byte[6];
        short resultSize = bn1.copyToByteArray(actualResult, (short) 0);
        /* Should be empty */
        Assertions.assertEquals(6, resultSize);
        /* Output buffer not changed */
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void copy_leadingZeroes_thisLonger() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);
        BigNat bn2 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctCopy(bn2);

        byte[] expectedResult = {0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        byte[] actualResult = new byte[6];
        short resultSize = bn1.copyToByteArray(actualResult, (short) 0);
        /* Should be empty */
        Assertions.assertEquals(6, resultSize);
        /* Output buffer not changed */
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void copy_leadingZeroes_sameLength() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);
        BigNat bn2 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctCopy(bn2);

        byte[] expectedResult = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        byte[] actualResult = new byte[5];
        short resultSize = bn1.copyToByteArray(actualResult, (short) 0);
        /* Should be empty */
        Assertions.assertEquals(5, resultSize);
        /* Output buffer not changed */
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void copy_thisShorter() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);
        BigNat bn2 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        Assertions.assertThrows(ISOException.class, () -> bn1.ctCopy(bn2));
    }

    @Test
    public void copy_thisLonger_blindFalse() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctCopy(bn2, (short) 0x00);

        byte[] expectedResult = {0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        byte[] actualResult = new byte[6];
        short resultSize = bn1.copyToByteArray(actualResult, (short) 0);
        /* Should be empty */
        Assertions.assertEquals(6, resultSize);
        /* Output buffer not changed */
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void copy_thisLonger_blindTrue() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctCopy(bn2, (short) 0xffff);

        byte[] expectedResult = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        byte[] actualResult = new byte[6];
        short resultSize = bn1.copyToByteArray(actualResult, (short) 0);
        /* Should be empty */
        Assertions.assertEquals(6, resultSize);
        /* Output buffer not changed */
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
