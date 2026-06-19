package tests.Integer;

import opencrypto.jcmathlib.Integer;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LesserTest {
    @Test
    public void lesser_thisPositive_otherNegative() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x00, 0x02, 0x03, 0x04};
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        Integer i1 = new Integer((byte) 0, data1, rm);
        Integer i2 = new Integer((byte) 1, data2, rm);

        Assertions.assertEquals((short) 0x00, i1.ctLesser(i2));
    }

    @Test
    public void lesser_thisNegative_otherPositive() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x05, 0x02, 0x03, 0x04};
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        Integer i1 = new Integer((byte) 1, data1, rm);
        Integer i2 = new Integer((byte) 0, data2, rm);

        Assertions.assertEquals((short) 0xffff, i1.ctLesser(i2));
    }

    @Test
    public void lesser_thisPositive_otherPositive_true() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x00, 0x02, 0x03, 0x04};
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        Integer i1 = new Integer((byte) 0, data1, rm);
        Integer i2 = new Integer((byte) 0, data2, rm);

        Assertions.assertEquals((short) 0xffff, i1.ctLesser(i2));
    }

    @Test
    public void lesser_thisPositive_otherPositive_false() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x02, 0x02, 0x03, 0x04};
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        Integer i1 = new Integer((byte) 0, data1, rm);
        Integer i2 = new Integer((byte) 0, data2, rm);

        Assertions.assertEquals((short) 0x00, i1.ctLesser(i2));
    }

    @Test
    public void lesser_thisNegative_otherNegative_true() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x02, 0x02, 0x03, 0x04};
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        Integer i1 = new Integer((byte) 1, data1, rm);
        Integer i2 = new Integer((byte) 1, data2, rm);

        Assertions.assertEquals((short) 0xffff, i1.ctLesser(i2));
    }

    @Test
    public void lesser_thisNegative_otherNegative_false() {
        ResourceManager rm = new ResourceManager((short) 256);

        byte[] data1 = {0x00, 0x02, 0x03, 0x04};
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        Integer i1 = new Integer((byte) 1, data1, rm);
        Integer i2 = new Integer((byte) 1, data2, rm);

        Assertions.assertEquals((short) 0x00, i1.ctLesser(i2));
    }
}
