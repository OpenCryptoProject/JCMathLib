package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class RemainderDivideTest {

    // Simple one byte divisions
    @Test
    public void n12_d4_q3_r0() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 1, memoryType, rm);
        BigNat denominator = new BigNat((short) 1, memoryType, rm);
        BigNat quotient = new BigNat((short) 1, memoryType, rm);
        BigNat remainder = new BigNat((short) 1, memoryType, rm);

        byte[] data1 = {0b1100};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0b100};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        byte[] actualResult = new byte[1];
        quotient.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0b11}, actualResult);
        Assertions.assertEquals(1, quotient.length());
        Assertions.assertEquals(0, remainder.length());
    }

    @Test
    public void n12_d5_q2_r2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 1, memoryType, rm);
        BigNat denominator = new BigNat((short) 1, memoryType, rm);
        BigNat quotient = new BigNat((short) 1, memoryType, rm);
        BigNat remainder = new BigNat((short) 1, memoryType, rm);

        byte[] data1 = {0b1100};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0b101};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        byte[] actualResult = new byte[1];
        quotient.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0b10}, actualResult);
        Assertions.assertEquals(1, quotient.length());
        remainder.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0b10}, actualResult);
        Assertions.assertEquals(1, remainder.length());
    }

    // Two byte divisions

    @Test
    public void n300_d5_q60_r0() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 2, memoryType, rm);
        BigNat denominator = new BigNat((short) 2, memoryType, rm);
        BigNat quotient = new BigNat((short) 2, memoryType, rm);
        BigNat remainder = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x01, 0x2C};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x05};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        byte[] actualResult = new byte[1];
        quotient.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x3C}, actualResult);
        Assertions.assertEquals(1, quotient.length());
        Assertions.assertEquals(0, remainder.length());
    }

    @Test
    public void n303_d5_q60_r3() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 2, memoryType, rm);
        BigNat denominator = new BigNat((short) 2, memoryType, rm);
        BigNat quotient = new BigNat((short) 2, memoryType, rm);
        BigNat remainder = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x01, 0x2F};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x05};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        Assertions.assertEquals(1, quotient.length());
        Assertions.assertEquals(1, remainder.length());
        byte[] actualResult = new byte[1];
        quotient.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x3C}, actualResult);
        remainder.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x03}, actualResult);
    }

    @Test
    public void n300_d299_q1_r1() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 2, memoryType, rm);
        BigNat denominator = new BigNat((short) 2, memoryType, rm);
        BigNat quotient = new BigNat((short) 2, memoryType, rm);
        BigNat remainder = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x01, 0x2C};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x2B};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        Assertions.assertEquals(1, quotient.length());
        Assertions.assertEquals(1, remainder.length());
        byte[] actualResult = new byte[1];
        quotient.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x01}, actualResult);

        remainder.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x01}, actualResult);
    }

    @Test
    public void n300_d301_q0_r300() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 2, memoryType, rm);
        BigNat denominator = new BigNat((short) 2, memoryType, rm);
        BigNat quotient = new BigNat((short) 2, memoryType, rm);
        BigNat remainder = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x01, 0x2C};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x2D};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        byte[] actualResult = new byte[2];
        Assertions.assertEquals(0, quotient.length());
        Assertions.assertEquals(2, remainder.length());
        remainder.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x01, 0x2C}, actualResult);
    }

    @Test
    public void n300_d1_q300_r0() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 2, memoryType, rm);
        BigNat denominator = new BigNat((short) 2, memoryType, rm);
        BigNat quotient = new BigNat((short) 2, memoryType, rm);
        BigNat remainder = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {0x01, 0x2C};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        Assertions.assertEquals(2, quotient.length());
        Assertions.assertEquals(0, remainder.length());
        byte[] actualResult = new byte[2];
        quotient.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x01, 0x2C}, actualResult);
    }

    // More bytes
    @Test
    public void n29910571_d1_q29910571_r0() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 4, memoryType, rm);
        BigNat denominator = new BigNat((short) 4, memoryType, rm);
        BigNat quotient = new BigNat((short) 4, memoryType, rm);
        BigNat remainder = new BigNat((short) 4, memoryType, rm);

        byte[] data1 = {0x01, (byte) 0xC8, 0x66, 0x2B};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        Assertions.assertEquals(4, quotient.length());
        Assertions.assertEquals(0, remainder.length());
        byte[] actualResult = new byte[4];
        quotient.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x01, (byte) 0xC8, 0x66, 0x2B}, actualResult);
    }

    @Test
    public void n29910571_d2_q14955285_r0() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 4, memoryType, rm);
        BigNat denominator = new BigNat((short) 4, memoryType, rm);
        BigNat quotient = new BigNat((short) 4, memoryType, rm);
        BigNat remainder = new BigNat((short) 4, memoryType, rm);

        byte[] data1 = {0x01, (byte) 0xC8, 0x66, 0x2B};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00, 0x02};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        Assertions.assertEquals(3, quotient.length());
        Assertions.assertEquals(1, remainder.length());
        byte[] actualResult = new byte[3];
        quotient.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{(byte) 0xE4, 0x33, 0x15}, actualResult);

        byte[] actualRemainder = new byte[1];
        remainder.copyToByteArray(actualRemainder, (short) 0);
        Assertions.assertArrayEquals(new byte[]{1}, actualRemainder);
    }

    @Test
    public void n35794167520984_d8965741_q3992326_r6617418() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 6, memoryType, rm);
        BigNat denominator = new BigNat((short) 6, memoryType, rm);
        BigNat quotient = new BigNat((short) 6, memoryType, rm);
        BigNat remainder = new BigNat((short) 6, memoryType, rm);

        byte[] data1 = {0x20, (byte) 0x8D, (byte) 0xFA, (byte) 0xA3, (byte) 0xDE, (byte) 0xD8};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0x88, (byte) 0xCE, (byte) 0x6D};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        Assertions.assertEquals(3, quotient.length());
        Assertions.assertEquals(3, remainder.length());
        byte[] actualResult = new byte[3];
        quotient.copyToByteArray(actualResult, (short) 0);
        byte[] correct = new byte[]{(byte) 0x3C, (byte) 0xEB, (byte) 0x06};
        Assertions.assertArrayEquals(correct, actualResult);

        remainder.copyToByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(new byte[]{(byte) 0x64, (byte) 0xF9, (byte) 0x4A}, actualResult);
    }

    @Test
    public void n12345678901234567_d123456789012300_q100_r4567() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 6, memoryType, rm);
        BigNat denominator = new BigNat((short) 6, memoryType, rm);
        BigNat quotient = new BigNat((short) 6, memoryType, rm);
        BigNat remainder = new BigNat((short) 6, memoryType, rm);

        byte[] data1 = {(byte) 0x2B, (byte) 0xDC, (byte) 0x54, (byte) 0x5D, (byte) 0x6B, (byte) 0x4B, (byte) 0x87};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0x70, (byte) 0x48, (byte) 0x86, (byte) 0x0D, (byte) 0xDF, (byte) 0x4C};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctRemainderDivide(denominator, quotient, remainder, (short) 0x00);

        Assertions.assertEquals(1, quotient.length());
        Assertions.assertEquals(2, remainder.length());
        byte[] actualResult = new byte[1];
        quotient.copyToByteArray(actualResult, (short) 0);
        byte[] correct = new byte[]{0x64};
        Assertions.assertArrayEquals(correct, actualResult);

        byte[] actualRemainder = new byte[2];
        remainder.copyToByteArray(actualRemainder, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0x11, (byte) 0xD7}, actualRemainder);
    }
}
