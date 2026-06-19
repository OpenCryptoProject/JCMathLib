package tests.BigNat;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Divide {
    @Test
    public void n12345678901234567_d123456789012300_q100_r4567() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat nominator = new BigNat((short) 7, memoryType, rm);
        BigNat denominator = new BigNat((short) 7, memoryType, rm);

        byte[] data1 = {(byte) 0x2B, (byte) 0xDC, (byte) 0x54, (byte) 0x5D, (byte) 0x6B, (byte) 0x4B, (byte) 0x87};
        nominator.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {(byte) 0x70, (byte) 0x48, (byte) 0x86, (byte) 0x0D, (byte) 0xDF, (byte) 0x4C};
        denominator.fromByteArray(data2, (short) 0, (short) data2.length);
        nominator.ctDivide(denominator);

        Assertions.assertEquals(1, nominator.length());
        byte[] actualResult = new byte[1];
        nominator.copyToByteArray(actualResult, (short) 0);
        byte[] correct = new byte[]{0x64};
        Assertions.assertArrayEquals(correct, actualResult);
    }
}
