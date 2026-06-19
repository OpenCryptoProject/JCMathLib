package tests.CTUtilTest;

import opencrypto.jcmathlib.CTUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * ctArrayCopyNonAtomic Unit tests
 *
 * @author Veronika Hanulikova
 */
public class CtArrayCopyNonAtomicTest {
    @Test
    public void srcTooShort() {
        byte[] src = new byte[10];
        byte[] dest = new byte[12];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctArrayCopyNonAtomic(src, (short) 0, dest, (short) 0, (short) 11));
    }

    @Test
    public void destTooShort() {
        byte[] src = new byte[10];
        byte[] dest = new byte[12];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctArrayCopyNonAtomic(src, (short) 0, dest, (short) 0, (short) 11));
    }

    @Test
    public void sameLength_zeroOffset_blind() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        byte[] dest = new byte[6];
        CTUtil.ctArrayCopyNonAtomic(src, (short) 0, dest, (short) 0, (short) 6, (short) 0xffff);
        Assertions.assertArrayEquals(new byte[6], dest);
    }

    @Test
    public void sameLength_zeroOffset() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        byte[] dest = new byte[6];
        CTUtil.ctArrayCopyNonAtomic(src, (short) 0, dest, (short) 0, (short) 6);
        Assertions.assertArrayEquals(src, dest);
    }

    @Test
    public void sameLength_nonZeroSrcOffset() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        byte[] dest = new byte[6];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctArrayCopyNonAtomic(src, (short) 1, dest, (short) 0, (short) 6));
    }

    @Test
    public void sameLength_nonZeroDestOffset() {
        byte[] src = {0, 1, 2, 3, 4, 5};
        byte[] dest = new byte[6];
        Assertions.assertThrows(ArrayIndexOutOfBoundsException.class, () -> CTUtil.ctArrayCopyNonAtomic(src, (short) 0, dest, (short) 1, (short) 6));
    }

    @Test
    public void srcShorter() {
        byte[] src = {0, 1, 2, 3, 4};
        byte[] dest = new byte[6];
        CTUtil.ctArrayCopyNonAtomic(src, (short) 0, dest, (short) 0, (short) 5);
        Assertions.assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 0}, dest);
    }

    @Test
    public void srcShorter_nonZeroDestOffset() {
        byte[] src = {0, 1, 2, 3, 4};
        byte[] dest = new byte[6];
        CTUtil.ctArrayCopyNonAtomic(src, (short) 0, dest, (short) 1, (short) 5);
        Assertions.assertArrayEquals(new byte[] {0, 0, 1, 2, 3, 4}, dest);
    }

    @Test
    public void srcShorter_nonZeroSrcOffset() {
        byte[] src = {0, 1, 2, 3, 4};
        byte[] dest = new byte[6];
        CTUtil.ctArrayCopyNonAtomic(src, (short) 1, dest, (short) 0, (short) 4);
        Assertions.assertArrayEquals(new byte[] {1, 2, 3, 4, 0, 0}, dest);
    }

    @Test
    public void srcShorter_nonZeroSrcDestOffset() {
        byte[] src = {0, 1, 2, 3, 4};
        byte[] dest = new byte[6];
        CTUtil.ctArrayCopyNonAtomic(src, (short) 1, dest, (short) 1, (short) 4);
        Assertions.assertArrayEquals(new byte[] {0, 1, 2, 3, 4, 0}, dest);
    }
}
