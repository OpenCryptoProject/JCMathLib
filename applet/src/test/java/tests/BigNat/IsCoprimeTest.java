package tests.BigNat;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class IsCoprimeTest {

    @Test
    public void a12_b5_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat a = new BigNat((short) 3, memoryType, rm);
        BigNat b = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {12};
        a.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {5};
        b.fromByteArray(data2, (short) 0, (short) data2.length);
        short result = a.ctIsCoprime(b);

        Assertions.assertEquals((short) 0xffff, result);
    }

    @Test
    public void a1_b1_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat a = new BigNat((short) 3, memoryType, rm);
        BigNat b = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {1};
        a.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {1};
        b.fromByteArray(data2, (short) 0, (short) data2.length);
        short result = a.ctIsCoprime(b);

        Assertions.assertEquals((short) 0xffff, result);
    }

    @Test
    public void a12_b3_false() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat a = new BigNat((short) 3, memoryType, rm);
        BigNat b = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {12};
        a.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {3};
        b.fromByteArray(data2, (short) 0, (short) data2.length);
        short result = a.ctIsCoprime(b);

        Assertions.assertEquals((short) 0, result);
    }
}
