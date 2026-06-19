package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class GetFirstBitPositionTest {
    @Test
    public void noZero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {(byte) 0xff};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        short position = bn.ctGetFirstBitPosition((byte) 0);
        Assertions.assertEquals((short) 8, position); /* no zero bit */
    }

    @Test
    public void noOne() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 10, memoryType, rm);

        byte[] data = {(byte) 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        short position = bn.ctGetFirstBitPosition((byte) 1);
        Assertions.assertEquals((short) 8, position); /* no zero bit */
    }

    @Test
    public void oneByteZero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {(byte) 0x1f};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        short position = bn.ctGetFirstBitPosition((byte) 0);
        Assertions.assertEquals((short) 5, position);
    }

    @Test
    public void oneByteOne() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {(byte) 0x20};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        short position = bn.ctGetFirstBitPosition((byte) 1);
        Assertions.assertEquals((short) 5, position);
    }

    @Test
    public void twoBytesZero() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {(byte) 0x3F, (byte) 0xff};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        short position = bn.ctGetFirstBitPosition((byte) 0);
        Assertions.assertEquals((short) 14, position);
    }

    @Test
    public void twoBytesOne() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {(byte) 0xC0, (byte) 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        short position = bn.ctGetFirstBitPosition((byte) 1);
        Assertions.assertEquals((short) 14, position);
    }

    @Test
    public void invalidParameter() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn = new BigNat((short) 3, memoryType, rm);

        byte[] data = {(byte) 0xC0, (byte) 0x00};
        bn.fromByteArray(data, (short) 0, (short) data.length);

        short position = bn.ctGetFirstBitPosition((byte) 3);
        Assertions.assertEquals((short) 2 * 8, position); // out of range
    }
}
