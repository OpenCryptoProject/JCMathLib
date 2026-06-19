package tests.CTUtilTest;

import opencrypto.jcmathlib.CTUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * ctSetBit Unit tests
 *
 * @author Veronika Hanulikova
 */
public class CtSetBitTest {
    @Test
    public void oneByte_firstBit_one() {
        byte[] data = {0b00000000};
        CTUtil.ctSetBit(data, (short) data.length, (byte) 1, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0b00000001}, data);
    }

    @Test
    public void oneByte_firstBit_zero() {
        byte[] data = {0b00000001};
        CTUtil.ctSetBit(data, (short) data.length, (byte) 0, (short) 0);
        Assertions.assertArrayEquals(new byte[]{0b00000000}, data);
    }

    @Test
    public void oneByte_lastBit_one() {
        byte[] data = {0b00000000};
        CTUtil.ctSetBit(data, (short) data.length, (byte) 1, (short) 7);
        Assertions.assertArrayEquals(new byte[]{(byte) 0b10000000}, data);
    }

    @Test
    public void oneByte_lastBit_zero() {
        byte[] data = {(byte) 0b10000001};
        CTUtil.ctSetBit(data, (short) data.length, (byte) 0, (short) 7);
        Assertions.assertArrayEquals(new byte[]{0b00000001}, data);
    }

    @Test
    public void twoBytes_lastBit_one() {
        byte[] data = {0b01000001, (byte) 0xf0};
        CTUtil.ctSetBit(data, (short) data.length, (byte) 1, (short) 15);
        Assertions.assertArrayEquals(new byte[]{(byte) 0b11000001, (byte) 0xf0}, data);
    }

    @Test
    public void twoBytes_lastBit_zero() {
        byte[] data = {(byte) 0b11000001, (byte) 0xf0};
        CTUtil.ctSetBit(data, (short) data.length, (byte) 0, (short) 15);
        Assertions.assertArrayEquals(new byte[]{(byte) 0b01000001, (byte) 0xf0}, data);
    }
}
