package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class ModTest {
    @Test
    public void mod_15_3() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {15};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {3};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult = {};
        Assertions.assertEquals(0, bn1.copyToByteArray(actualResult, (short) 0));
    }

    @Test
    public void mod_3_15() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {3};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {15};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult =  new byte[1];
        byte[] expectedResult = {0x03};
        Assertions.assertEquals(1, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mod_8_2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {8};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {2};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult = {};
        Assertions.assertEquals(0, bn1.copyToByteArray(actualResult, (short) 0));
    }

    @Test
    public void mod_9_2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {9};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {2};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult =  new byte[1];
        byte[] expectedResult = {0x01};
        Assertions.assertEquals(1, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mod_9_8() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {9};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {8};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult =  new byte[1];
        byte[] expectedResult = {0x01};
        Assertions.assertEquals(1, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mod_9_9() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {9};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {9};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult = {};
        Assertions.assertEquals(0, bn1.copyToByteArray(actualResult, (short) 0));
    }

    @Test
    public void mod_15_4() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {15};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {4};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult =  new byte[1];
        byte[] expectedResult = {0x03};
        Assertions.assertEquals(1, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mod_0x010203040506_0x0102() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult =  new byte[1];
        byte[] expectedResult = {(byte) 0xf6};
        Assertions.assertEquals(1, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mod_0x010203040506_0x0102030405() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 20, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);
        BigNat bn3 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult =  new byte[1];
        byte[] expectedResult = {(byte) 0x06};
        Assertions.assertEquals(1, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mod_0xFFFFFF_0x090807() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 30, memoryType, rm);
        BigNat bn2 = new BigNat((short) 30, memoryType, rm);
        BigNat bn3 = new BigNat((short) 30, memoryType, rm);

        byte[] data1 = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x09, 0x08, 0x07};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult =  new byte[3];
        byte[] expectedResult = {(byte) 0x03, (byte) 0x1F, (byte) 0x3B};
        Assertions.assertEquals(3, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void mod_0x908070605040_0x0102030405() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 30, memoryType, rm);
        BigNat bn2 = new BigNat((short) 30, memoryType, rm);
        BigNat bn3 = new BigNat((short) 30, memoryType, rm);

        byte[] data1 = {(byte) 0x90, (byte) 0x80, (byte) 0x70, (byte) 0x60, (byte) 0x50, (byte) 0x40};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);

        bn1.ctMod(bn2, bn3);

        byte[] actualResult =  new byte[2];
        byte[] expectedResult = {(byte) 0x03, (byte) 0x60};
        Assertions.assertEquals(2, bn1.copyToByteArray(actualResult, (short) 0));
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
