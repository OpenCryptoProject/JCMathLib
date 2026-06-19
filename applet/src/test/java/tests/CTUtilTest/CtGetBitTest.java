package tests.CTUtilTest;

import opencrypto.jcmathlib.CTUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * ctGetBit Unit tests
 *
 * @author Veronika Hanulikova
 */
public class CtGetBitTest {
    @Test
    public void byteFirstBit() {
        byte[] data = {0b00000001};
        byte result = CTUtil.ctGetBit(data, (short) data.length, (short) 0);
        Assertions.assertEquals(0x01, result);
    }

    @Test
    public void byteSecondBit() {
        byte[] data = {0b00000001};
        byte result = CTUtil.ctGetBit(data, (short) data.length, (short) 1);
        Assertions.assertEquals(0x00, result);
    }

    @Test
    public void byteSeventhBit() {
        byte[] data = {(byte) 0b01000000};
        byte result = CTUtil.ctGetBit(data, (short) data.length, (short) 6);
        Assertions.assertEquals(0x01, result);
    }

    @Test
    public void byteEightBit() {
        byte[] data = {(byte) 0b10000000};
        byte result = CTUtil.ctGetBit(data, (short) data.length, (short) 7);
        Assertions.assertEquals(0x01, result );
    }

    @Test
    public void moreBytes_sixthBit() {
        byte[] data = {(byte) 0b01000000, 0x00};
        byte result = CTUtil.ctGetBit(data, (short) data.length, (short) 14);
        Assertions.assertEquals(0x01, result );
    }

    @Test
    public void moreBytes_eightBit() {
        byte[] data = {(byte) 0b10000000, 0x00};
        byte result = CTUtil.ctGetBit(data, (short) data.length, (short) 15);
        Assertions.assertEquals(0x01, result );
    }

    @Test
    public void moreBytes_eightBit_zero() {
        byte[] data = {(byte) 0b01000000, 0x00};
        byte result = CTUtil.ctGetBit(data, (short) data.length, (short) 15);
        Assertions.assertEquals(0x00, result );
    }
}
