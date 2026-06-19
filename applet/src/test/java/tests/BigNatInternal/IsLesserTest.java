package tests.BigNatInternal;

import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class IsLesserTest {
    // no shifts, other.size > this.size, same memory
    @Test
    public void isLesser_otherLonger_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_otherLonger_false() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00, 0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_otherLonger_false2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00, 0x00, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2));
    }

    // no shifts, other.size > this.size, different memory
    @Test
    public void isLesser_otherLonger_differentMemory_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_otherLonger_differentMemory_true2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 5, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    // no shifts, same length, same memory
    @Test
    public void isLesser_sameLength_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 3, memoryType, rm);
        BigNat bn2 = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_sameLength_true2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_sameLength_false() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x03};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_sameLength_false2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2));
    }

    // no shifts, same length, different memory
    @Test
    public void isLesser_sameLength_differentMemory_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 3, memoryType, rm);
        BigNat bn2 = new BigNat((short) 5, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    // no shifts, other.size < this.size, same memory
    @Test
    public void isLesser_thisLonger_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x00, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_thisLonger_true2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x01, 0x02, 0x03, 0x03};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_thisLonger_false() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2));
    }

    @Test
    public void isLesser_thisLonger_false2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x01, 0x02, 0x03, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2));
    }

    // no shifts, other.size < this.size, different memory
    @Test
    public void isLesser_thisLonger_differentMemory_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x00, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2));
    }

    // problem
    @Test
    public void isLesser_thisLonger_differentMemory_false() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 3, memoryType, rm);

        byte[] data1 = {0x00, 0x00, 0x01, 0x02, 0x03, 0x04};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2));
    }

    // shifts
    @Test
    public void isLesser_sameLength_shift1_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2, (short) 1, (short) 0));
    }

    @Test
    public void isLesser_thisLonger_shift3_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2, (short) 3, (short) 0));
    }

    @Test
    public void isLesser_thisLonger_shift1_false() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x00};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2, (short) 1, (short) 0));
    }

    // start
    @Test
    public void isLesser_thisLonger_start1_false() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2, (short) 0, (short) 1));
    }

    @Test
    public void isLesser_thisLonger_start1_true() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x00, 0x03, 0x04, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x00, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2, (short) 0, (short) 1));
    }

    @Test
    public void isLesser_thisLonger_start5_false() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x00, 0x03, 0x04, 0x05};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 =  {0x01, 0x00, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2, (short) 0, (short) 1));
    }

    // start & shift
    @Test
    public void isLesser_lesser_shift2Start1() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x00};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2, (short) 2, (short) 1));
    }

    @Test
    public void isLesser_same_shift2Start5() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x00};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2, (short) 2, (short) 5));
    }

    @Test
    public void isLesser_lesser_shift2Start4() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);
        BigNat bn2 = new BigNat((short) 10, memoryType, rm);

        byte[] data1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x00};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xffff, bn1.ctIsLesser(bn2, (short) 2, (short) 4));
    }

    // bug
    @Test
    public void isLesser_bug() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 2, memoryType, rm);
        BigNat bn2 = new BigNat((short) 2, memoryType, rm);

        byte[] data1 = {-50};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {1, 0};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn2.ctIsLesser(bn1));
    }

    @Test
    public void test() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);
        BigNat bn2 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        byte[] data1 = Util.hexStringToByteArray("B6BAA45E79B830920C9AFF2DF4369560524D75DFF32F5E614BE9B134D995B0667901E554A591293154F2502F4C1C2FF83597B9809097A51FBB160B58AD4A36DF");
        byte[] data2 = Util.hexStringToByteArray("C4C8F1EA6C5CA5DE7178D6D2A312D2438D8DC44400BF54DC8F5A539114281B8648EDB5442379879156B122DC783C8C905B621132A313FA2ED62F20E3F8B6F3C0");
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0xFF, bn1.ctIsLesser(bn2) & 0xff);
    }

    @Test
    public void bug2() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 7, memoryType, rm);
        BigNat bn2 = new BigNat((short) 7, memoryType, rm);

        byte[] data1 = {(byte) 0x2B, (byte) 0xDC, (byte) 0x54, (byte) 0x5D, (byte) 0x6B, (byte) 0x4B, (byte) 0x87};
        bn1.fromByteArray(data1, (short) 0, (short) data1.length);
        byte[] data2 = {112, 72, -122, 13, -33, 76};
        bn2.fromByteArray(data2, (short) 0, (short) data2.length);
        Assertions.assertEquals((short) 0x00, bn1.ctIsLesser(bn2));
    }
}
