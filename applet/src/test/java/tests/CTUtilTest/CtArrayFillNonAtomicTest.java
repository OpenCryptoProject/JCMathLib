package tests.CTUtilTest;

import opencrypto.jcmathlib.CTUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * ctArrayFillNonAtomic Unit tests
 *
 * @author Veronika Hanulikova
 */
public class CtArrayFillNonAtomicTest {

    @Test
    public void nullArray() {
        Assertions.assertThrows(NullPointerException.class, () -> CTUtil.ctArrayFillNonAtomic(null, (short) 0, (short) 20, (byte) 0xff));
    }

    @Test
    public void arrayTooShort() {
        byte[] array = new byte[10];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctArrayFillNonAtomic(array, (short) 0, (short) 20, (byte) 0xff));
    }

    @Test
    public void invalidNegativeOffset() {
        byte[] array = new byte[10];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctArrayFillNonAtomic(array, (short) -1, (short) 20, (byte) 0xff));
    }

    @Test
    public void invalidBigOffset() {
        byte[] array = new byte[10];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctArrayFillNonAtomic(array, (short) 100, (short) 20, (byte) 0xff));
    }

    @Test
    public void fullLength() {
        byte[] result = {0x05, 0x05, 0x05, 0x05, 0x05, 0x05};
        byte[] array = new byte[6];
        CTUtil.ctArrayFillNonAtomic(array, (short) 0, (short) 6, (byte) 0x05);
        Assertions.assertArrayEquals(result, array);
    }

    @Test
    public void fullLength_blind() {
        byte[] result = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] array = new byte[6];
        CTUtil.ctArrayFillNonAtomic(array, (short) 0, (short) 6, (byte) 0x05, (short) 0xffff);
        Assertions.assertArrayEquals(result, array);
    }

    @Test
    public void partLength() {
        byte[] result = {0x05, 0x05, 0x05, 0x00, 0x00, 0x00};
        byte[] array = new byte[6];
        CTUtil.ctArrayFillNonAtomic(array, (short) 0, (short) 3, (byte) 0x05);
        Assertions.assertArrayEquals(result, array);
    }

    @Test
    public void partLength_blind() {
        byte[] result = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        byte[] array = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        CTUtil.ctArrayFillNonAtomic(array, (short) 0, (short) 3, (byte) 0x05, (short) 0xffff);
        Assertions.assertArrayEquals(result, array);
    }
}
