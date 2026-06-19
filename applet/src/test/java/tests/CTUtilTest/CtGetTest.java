package tests.CTUtilTest;

import opencrypto.jcmathlib.CTUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * ctGet Unit tests
 *
 * @author Veronika Hanulikova
 */
public class CtGetTest {
    @Test
    public void get_firstElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 0;
        byte result = CTUtil.ctGet(src, (short) src.length, index);
        Assertions.assertEquals(src[index], result);
    }

    @Test
    public void get_lastElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 5;
        byte result = CTUtil.ctGet(src, (short) src.length, index);
        Assertions.assertEquals(src[index], result);
    }

    @Test
    public void get_middleElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 3;
        byte result = CTUtil.ctGet(src, (short) src.length, index);
        Assertions.assertEquals(src[index], result);
    }

    @Test
    public void get_underflow() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = -1;
        byte result = CTUtil.ctGet(src, (short) src.length, index);
        Assertions.assertEquals(0, result);
    }

    @Test
    public void get_overflow() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        byte result = CTUtil.ctGet(src, (short) src.length, (short) ((short) src.length + 1));
        Assertions.assertEquals(0, result);
    }

    @Test
    public void getSafe_firstElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 0;
        byte result = CTUtil.ctGetSafe(src, (short) src.length, index);
        Assertions.assertEquals(src[index], result);
    }

    @Test
    public void getSafe_lastElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 5;
        byte result = CTUtil.ctGetSafe(src, (short) src.length, index);
        Assertions.assertEquals(src[index], result);
    }

    @Test
    public void getSafe_middleElement() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        short index = 3;
        byte result = CTUtil.ctGetSafe(src, (short) src.length, index);
        Assertions.assertEquals(src[index], result);
    }

    @Test
    public void getSafe_underflow() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctGetSafe(src, (short) src.length, (short) -1));
    }

    @Test
    public void getSafe_overflow() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctGetSafe(src, (short) src.length, (short) ((short) src.length + 1)));
    }
}
