package tests.CTUtilTest;

import opencrypto.jcmathlib.CTUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * ctSet Unit tests
 *
 * @author Veronika Hanulikova
 */
public class CtSetTest {
    @Test
    public void set_firstElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 0;
        byte value = 10;
        CTUtil.ctSet(src, (short) src.length, index, value);
        Assertions.assertArrayEquals(new byte[]{10, 1, 2, 3, 4, 5}, src);
    }

    @Test
    public void set_lastElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 5;
        byte value = 10;
        CTUtil.ctSet(src, (short) src.length, index, value);
        Assertions.assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 10}, src);
    }

    @Test
    public void set_middleElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 3;
        byte value = 10;
        CTUtil.ctSet(src, (short) src.length, index, value);
        Assertions.assertArrayEquals(new byte[]{0, 1, 2, 10, 4, 5}, src);
    }

    @Test
    public void set_underflow() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = -1;
        byte value = 10;
        CTUtil.ctSet(src, (short) src.length, index, value);
        Assertions.assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 5}, src);
    }

    @Test
    public void set_overflow() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = -1;
        byte value = 10;
        CTUtil.ctSet(src, (short) src.length, index, value);
        Assertions.assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 5}, src);
    }

    @Test
    public void setSafe_firstElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 0;
        byte value = 10;
        CTUtil.ctSetSafe(src, (short) src.length, index, value);
        Assertions.assertArrayEquals(new byte[]{10, 1, 2, 3, 4, 5}, src);
    }

    @Test
    public void setSafe_lastElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 5;
        byte value = 10;
        CTUtil.ctSetSafe(src, (short) src.length, index, value);
        Assertions.assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 10}, src);
    }

    @Test
    public void setSafe_middleElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 3;
        byte value = 10;
        CTUtil.ctSetSafe(src, (short) src.length, index, value);
        Assertions.assertArrayEquals(new byte[]{0, 1, 2, 10, 4, 5}, src);
    }

    @Test
    public void setSafe_underflow() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = -1;
        byte value = 10;
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctSetSafe(src, (short) src.length, index, value));
    }

    @Test
    public void setSafe_overflow() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 6;
        byte value = 10;
        CTUtil.ctSet(src, (short) src.length, index, value);
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctSetSafe(src, (short) src.length, index, value));
    }
}
