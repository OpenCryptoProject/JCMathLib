package tests.Integer;

import opencrypto.jcmathlib.Integer;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AddOptimizedTest {

    /*this.isPositive() && other.isPositive()*/
    @Test
    public void bothPositive() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x01, 0x01, 0x02};
        byte[] data2 = {0x03, 0x04};
        Integer i1 = new Integer((byte) 0, data1, rm);
        Integer i2 = new Integer((byte) 0, data2, rm);
        i1.ctAddOptimized(i2);

        byte[] expectedResult = {/*sign*/ 0, 0x01, 0x04, 0x06};
        byte[] actualResult = new byte[4];
        i1.toByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    /*this.isNegative() && other.isNegative()*/
    @Test
    public void bothNegative() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x01, 0x01, 0x02};
        byte[] data2 = {0x03, 0x04};
        Integer i1 = new Integer((byte) 1, data1, rm);
        Integer i2 = new Integer((byte) 1, data2, rm);
        i1.ctAddOptimized(i2);

        byte[] expectedResult = {/*sign*/ 1, 0x01, 0x04, 0x06};
        byte[] actualResult = new byte[4];
        i1.toByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    /* this.isPositive() && other.getMagnitude().isLesser(this.getMagnitude()) */
    @Test
    public void firstPositive_otherNegativeSmaller() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x05, 0x06, 0x07};
        byte[] data2 = {0x03, 0x04};
        Integer i1 = new Integer((byte) 0, data1, rm);
        Integer i2 = new Integer((byte) 1, data2, rm);
        i1.ctAddOptimized(i2);

        byte[] expectedResult = {/*sign*/ 0, 0x05, 0x03, 0x03};
        byte[] actualResult = new byte[4];
        i1.toByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    /*this.isNegative() && other.getMagnitude().isLesser(this.getMagnitude())*/
    @Test
    public void firstNegative_otherPositiveSmaller() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x05, 0x06, 0x07};
        byte[] data2 = {0x03, 0x04};
        Integer i1 = new Integer((byte) 1, data1, rm);
        Integer i2 = new Integer((byte) 0, data2, rm);
        i1.ctAddOptimized(i2);

        byte[] expectedResult = {/*sign*/ 1, 0x05, 0x03, 0x03};
        byte[] actualResult = new byte[4];
        i1.toByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    /*this.isPositive() && this.getMagnitude().isLesser(other.getMagnitude())*/
    @Test
    public void firstPositive_otherNegativeLarger() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x05, 0x06, 0x07};
        byte[] data2 = {0x06, 0x07, 0x08};
        Integer i1 = new Integer((byte) 0, data1, rm);
        Integer i2 = new Integer((byte) 1, data2, rm);
        i1.ctAddOptimized(i2);

        byte[] expectedResult = {/*sign*/ 1, 0x01, 0x01, 0x01};
        byte[] actualResult = new byte[4];
        i1.toByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    /*this.isNegative() && this.getMagnitude().isLesser(other.getMagnitude())*/
    @Test
    public void firstNegative_otherPositiveLarger() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x00, 0x06, 0x07};
        byte[] data2 = {0x01, 0x06, 0x07};
        Integer i1 = new Integer((byte) 1, data1, rm);
        Integer i2 = new Integer((byte) 0, data2, rm);
        i1.ctAddOptimized(i2);

        byte[] expectedResult = {/*sign*/ 0, 0x01, 0x00, 0x00};
        byte[] actualResult = new byte[4];
        i1.toByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }

    @Test
    public void equal_thisPositive_otherNegative() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x01, 0x06, 0x07};
        byte[] data2 = {0x01, 0x06, 0x07};
        Integer i1 = new Integer((byte) 1, data1, rm);
        Integer i2 = new Integer((byte) 0, data2, rm);
        i1.ctAddOptimized(i2);

        byte[] expectedResult = {/*sign*/ 0, 0x00, 0x00, 0x00};
        byte[] actualResult = new byte[4];
        i1.toByteArray(actualResult, (short) 0);
        Assertions.assertArrayEquals(expectedResult, actualResult);
    }
}
