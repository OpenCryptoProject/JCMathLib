package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class EqualsTest {
    @Test
    public void equals_sameLength_sameMemory_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0xffff, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_differentLength_differentMemory_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x01, 0x02, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0xffff, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_sameLength_sameMemory_firstByteDifferent() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x02, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0x00, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_sameLength_sameMemory_lastByteDifferent() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x02, 0x02, 0x03, 0x04, 0x05, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0x00, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_sameLength_differentMemory_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0xffff, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_sameLength_differentMemory_firstByteDifferent() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {0x02, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0x00, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_sameLength_differentMemory_lastByteDifferent() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 20, memoryType, rm);

        byte[] data1 = {0x02, 0x02, 0x03, 0x04, 0x05, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0x00, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_differentLength_sameMemory_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0xffff, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_differentLength_sameMemory_firstByteDifferent() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0x00, bn2.ctEquals(bn1));
    }

    @Test
    public void equals_differentLength_sameMemory_lastByteDifferent() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x02, 0x02, 0x03, 0x04, 0x05, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctEquals(bn2));
        Assertions.assertEquals((short) 0x00, bn2.ctEquals(bn1));
    }

    @Test
    public void equalsWithByte_length1_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x11};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctEquals((byte) 0x11));
    }

    @Test
    public void equalsWithByte_length2_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x00, 0x11};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctEquals((byte) 0x11));
    }

    @Test
    public void equalsWithByte_length3_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x11};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctEquals((byte) 0x11));
    }

    @Test
    public void equalsWithByte_false1() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x11, 0x00};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        Assertions.assertEquals((short) 0x00, bn1.ctEquals((byte) 0x11));
    }

    @Test
    public void equalsWithByte_false2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x11, 0x11};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        Assertions.assertEquals((short) 0x00, bn1.ctEquals((byte) 0x11));
    }

}
