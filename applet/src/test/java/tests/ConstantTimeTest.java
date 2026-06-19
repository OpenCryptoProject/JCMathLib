package tests;

import opencrypto.jcmathlib.ConstantTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * ConstantTime Unit tests
 *
 * @author Veronika Hanulikova
 */
public class ConstantTimeTest {
    /* ctMsb tests */
    @Test
    public void ctMsb_zero_1() {
        byte resultByte = ConstantTime.ctMsb((byte) 1);
        Assertions.assertEquals(0b00000000, resultByte);

        short resultShort = ConstantTime.ctMsb((short) 1);
        Assertions.assertEquals(0b0000000000000000, resultShort);
    }
    @Test
    public void ctMsb_zero_127() {
        byte resultByte = ConstantTime.ctMsb((byte) 127);
        Assertions.assertEquals(0b00000000, resultByte);

        short resultShort = ConstantTime.ctMsb((short) 127);
        Assertions.assertEquals(0b0000000000000000, resultShort);
    }
    @Test
    public void ctMsb_one_128() {
        byte resultByte = ConstantTime.ctMsb((byte) 128);
        Assertions.assertEquals(0b11111111, resultByte & 0xff);

        short resultShort = ConstantTime.ctMsb((short) 128);
        Assertions.assertNotEquals(0b1111111111111111, resultShort);
        Assertions.assertEquals(0b0000000000000000, resultShort);
    }

    @Test
    public void ctMsb_one_138() {
        byte result = ConstantTime.ctMsb((byte) 138);
        Assertions.assertEquals(0b11111111, result & 0xff);
    }

    @Test
    public void ctMsb_one_32768() {
        short resultShort = ConstantTime.ctMsb((short) 32768);
        Assertions.assertEquals(0b1111111111111111, resultShort & 0xffff);

        resultShort = ConstantTime.ctMsb((short) -32768);
        Assertions.assertEquals(0b1111111111111111, resultShort & 0xffff);
    }

    /* ctIsZero tests */
    @Test
    public void ctIsZero_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsZero((byte) 1));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsZero((byte) 255));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsZero((short) 1));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsZero((short) 65535));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsZero((short) -32768));

        byte nonZero = (byte) 0xff;
        Assertions.assertEquals((short) 0, ConstantTime.ctIsZero((short) nonZero));
    }

    @Test
    public void ctIsZero_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsZero((byte) 0));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsZero((short) 0));
    }

    /* ctIsNonZero tests */
    @Test
    public void ctIsNonZero_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonZero((byte) 1));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonZero((byte) 255));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonZero((short) 1));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonZero((short) 65535));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonZero((short) -32768));
    }

    @Test
    public void ctIsNonZero_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNonZero((byte) 0));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsNonZero((short) 0));
    }

    /* ctLessThan tests */
    @Test
    public void ctLessThan_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctLessThan((byte) 0, (byte) 0));
        Assertions.assertEquals((short) 0, ConstantTime.ctLessThan((short) 0, (short) 0));

        Assertions.assertEquals((byte) 0, ConstantTime.ctLessThan((byte) 255, (byte) 255));
        Assertions.assertEquals((short) 0, ConstantTime.ctLessThan((short) 65535, (short) 65535));

        Assertions.assertEquals((byte) 0, ConstantTime.ctLessThan((byte) 255, (byte) 128));
        Assertions.assertEquals((short) 0, ConstantTime.ctLessThan((short) 65535, (short) 32767));

        Assertions.assertEquals((byte) 0, ConstantTime.ctLessThan((byte) 127, (byte) 0));
        Assertions.assertEquals((short) 0, ConstantTime.ctLessThan((short) 32767, (short) 0));

        Assertions.assertEquals((byte) 0, ConstantTime.ctLessThan((byte) 128, (byte) 127));
        Assertions.assertEquals((short) 0, ConstantTime.ctLessThan((short) 32768, (short) 32767));
    }

    @Test
    public void ctLessThan_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctLessThan((byte) 0, (byte) 1));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctLessThan((short) 0, (short) 1));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctLessThan((byte) 254, (byte) 255));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctLessThan((short) 65534, (short) 65535));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctLessThan((byte) 55, (byte) 128));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctLessThan((short) 5535, (short) 32767));
    }

    /* ctGreaterOrEqual tests */
    @Test
    public void ctGreaterOrEqual_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreaterOrEqual((byte) 0, (byte) 0));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreaterOrEqual((short) 0, (short) 0));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreaterOrEqual((byte) 255, (byte) 255));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreaterOrEqual((short) 65535, (short) 65535));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreaterOrEqual((byte) 255, (byte) 128));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreaterOrEqual((short) 65535, (short) 32767));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreaterOrEqual((byte) 127, (byte) 0));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreaterOrEqual((short) 32767, (short) 0));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreaterOrEqual((byte) 128, (byte) 127));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreaterOrEqual((short) 32768, (short) 32767));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreaterOrEqual((byte) 248, (byte) 3));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreaterOrEqual((short) 41768, (short) 120));
    }

    @Test
    public void ctGreaterOrEqual_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctGreaterOrEqual((byte) 0, (byte) 1));
        Assertions.assertEquals((short) 0, ConstantTime.ctGreaterOrEqual((short) 0, (short) 1));

        Assertions.assertEquals((byte) 0, ConstantTime.ctGreaterOrEqual((byte) 254, (byte) 255));
        Assertions.assertEquals((short) 0, ConstantTime.ctGreaterOrEqual((short) 65534, (short) 65535));

        Assertions.assertEquals((byte) 0, ConstantTime.ctGreaterOrEqual((byte) 55, (byte) 128));
        Assertions.assertEquals((short) 0, ConstantTime.ctGreaterOrEqual((short) 5535, (short) 32767));
    }

    /* ctGreater tests */
    @Test
    public void ctGreater_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreater((byte) 1, (byte) 0));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreater((short) 1, (short) 0));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreater((byte) 255, (byte) 254));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreater((short) 65535, (short) 65534));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreater((byte) 255, (byte) 128));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreater((short) 65535, (short) 32767));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreater((byte) 127, (byte) 0));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreater((short) 32767, (short) 0));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreater((byte) 128, (byte) 127));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreater((short) 32768, (short) 32767));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctGreater((byte) 248, (byte) 3));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctGreater((short) 41768, (short) 120));
    }

    @Test
    public void ctGreater_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctGreater((byte) 0, (byte) 1));
        Assertions.assertEquals((short) 0, ConstantTime.ctGreater((short) 0, (short) 1));

        Assertions.assertEquals((byte) 0, ConstantTime.ctGreater((byte) 254, (byte) 255));
        Assertions.assertEquals((short) 0, ConstantTime.ctGreater((short) 65534, (short) 65535));

        Assertions.assertEquals((byte) 0, ConstantTime.ctGreater((byte) 55, (byte) 128));
        Assertions.assertEquals((short) 0, ConstantTime.ctGreater((short) 5535, (short) 32767));

        Assertions.assertEquals((byte) 0, ConstantTime.ctGreater((byte) 255, (byte) 255));
        Assertions.assertEquals((short) 0, ConstantTime.ctGreater((short) 65535, (short) 65535));

        Assertions.assertEquals((byte) 0, ConstantTime.ctGreater((byte) 128, (byte) 128));
        Assertions.assertEquals((short) 0, ConstantTime.ctGreater((short) 32767, (short) 32767));
    }

    /* ctEqual tests */
    @Test
    public void ctEqual_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctEqual((byte) 0, (byte) 1));
        Assertions.assertEquals((short) 0, ConstantTime.ctEqual((short) 0, (short) 1));

        Assertions.assertEquals((byte) 0, ConstantTime.ctEqual((byte) 254, (byte) 255));
        Assertions.assertEquals((short) 0, ConstantTime.ctEqual((short) 65534, (short) 65535));

        Assertions.assertEquals((byte) 0, ConstantTime.ctEqual((byte) 55, (byte) 128));
        Assertions.assertEquals((short) 0, ConstantTime.ctEqual((short) 5535, (short) 32767));
    }

    @Test
    public void ctEqual_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctEqual((byte) 1, (byte) 1));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctEqual((short) 1, (short) 1));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctEqual((byte) 255, (byte) 255));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctEqual((short) 65535, (short) 65535));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctEqual((byte) 128, (byte) 128));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctEqual((short) 32767, (short) 32767));
    }

    @Test
    public void ctNotEqual_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctNotEqual((byte) 1, (byte) 1));
        Assertions.assertEquals((short) 0, ConstantTime.ctNotEqual((short) 1, (short) 1));

        Assertions.assertEquals((byte) 0, ConstantTime.ctNotEqual((byte) 255, (byte) 255));
        Assertions.assertEquals((short) 0, ConstantTime.ctNotEqual((short) 65535, (short) 65535));

        Assertions.assertEquals((byte) 0, ConstantTime.ctNotEqual((byte) 128, (byte) 128));
        Assertions.assertEquals((short) 0, ConstantTime.ctNotEqual((short) 32767, (short) 32767));
    }

    @Test
    public void ctNotEqual_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctNotEqual((byte) 0, (byte) 1));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctNotEqual((short) 0, (short) 1));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctNotEqual((byte) 254, (byte) 255));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctNotEqual((short) 65534, (short) 65535));

        Assertions.assertEquals((byte) 0xff, ConstantTime.ctNotEqual((byte) 12, (byte) 128));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctNotEqual((short) 3276, (short) 32767));
    }

    /* ctSelect tests */
    @Test
    public void ctSelect_a() {
        Assertions.assertEquals((byte) 1, ConstantTime.ctSelect((byte) 0xff, (byte) 1, (byte) 2));
        Assertions.assertEquals((short) 1, ConstantTime.ctSelect((short) 0xff, (short) 1, (short) 2));

        Assertions.assertEquals((byte) 255, ConstantTime.ctSelect((byte) 0xff, (byte) 255, (byte) 254));
        Assertions.assertEquals((short) 65535, ConstantTime.ctSelect((short) 0xff, (short) 65535, (short) 65534));
    }

    @Test
    public void ctSelect_b() {
        Assertions.assertEquals((byte) 2, ConstantTime.ctSelect((byte) 0, (byte) 1, (byte) 2));
        Assertions.assertEquals((short) 2, ConstantTime.ctSelect((short) 0, (short) 1, (short) 2));

        Assertions.assertEquals((byte) 254, ConstantTime.ctSelect((byte) 0, (byte) 255, (byte) 254));
        Assertions.assertEquals((short) 65534, ConstantTime.ctSelect((short) 0, (short) 65535, (short) 65534));
    }

    /* ctIsPositive tests */
    @Test
    public void ctIsPositive_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsPositive((byte) 1));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsPositive((byte) 100));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsPositive((byte) 127));

        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsPositive((short) 1));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsPositive((short) 100));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsPositive((short) 32767));
    }

    @Test
    public void ctIsPositive_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsPositive((byte) 0));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsPositive((byte) -1));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsPositive((byte) -100));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsPositive((byte) -128));

        Assertions.assertEquals((short) 0, ConstantTime.ctIsPositive((short) 0));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsPositive((short) -1));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsPositive((short) -100));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsPositive((short) -32768));
    }

    /* csIsNegative tests */
    @Test
    public void ctIsNegative_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNegative((byte) 0));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNegative((byte) 100));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNegative((byte) 127));

        Assertions.assertEquals((short) 0, ConstantTime.ctIsNegative((short) 0));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsNegative((short) 100));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsNegative((short) 32767));
    }

    @Test
    public void ctIsNegative_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNegative((byte) -1));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNegative((byte) -100));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNegative((byte) -128));

        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNegative((short) -1));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNegative((short) -100));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNegative((short) -32768));
    }

    /* ctIsNonNegative tests */
    @Test
    public void ctIsNonNegative_true() {
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonNegative((byte) 0));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonNegative((byte) 1));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonNegative((byte) 100));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonNegative((byte) 127));

        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonNegative((short) 0));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonNegative((short) 1));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonNegative((short) 100));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonNegative((short) 32767));
    }

    @Test
    public void ctIsNonNegative_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNonNegative((byte) -1));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNonNegative((byte) -100));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNonNegative((byte) -128));

        Assertions.assertEquals((short) 0, ConstantTime.ctIsNonNegative((short) -1));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsNonNegative((short) -100));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsNonNegative((short) -32768));
    }

    /* csIsNonPositive tests */
    @Test
    public void ctIsNonPositive_false() {
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNonPositive((byte) 100));
        Assertions.assertEquals((byte) 0, ConstantTime.ctIsNonPositive((byte) 127));

        Assertions.assertEquals((short) 0, ConstantTime.ctIsNonPositive((short) 100));
        Assertions.assertEquals((short) 0, ConstantTime.ctIsNonPositive((short) 32767));
    }

    @Test
    public void ctIsNonPositive_true() {
        //Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonPositive((byte) 0));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonPositive((byte) -1));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonPositive((byte) -100));
        Assertions.assertEquals((byte) 0xff, ConstantTime.ctIsNonPositive((byte) -128));

        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonPositive((short) 0));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonPositive((short) -1));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonPositive((short) -100));
        Assertions.assertEquals((short) 0xffff, ConstantTime.ctIsNonPositive((short) -32768));
    }
}
