package tests.BigNatInternal;

import opencrypto.jcmathlib.BigNatInternal;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class HighestBitTest {
    @Test
    public void lastBit() {
        short result = BigNatInternal.ctHighestOneBit((short) 0b0000000000000001);
        Assertions.assertEquals(15, result);
    }

    @Test
    public void secondToLastBit() {
        short result = BigNatInternal.ctHighestOneBit((short) 0b0000000000000010);
        Assertions.assertEquals(14, result);
    }

    @Test
    public void middleBit() {
        short result = BigNatInternal.ctHighestOneBit((short) 0b0000000100000000);
        Assertions.assertEquals(7, result);
    }

    @Test
    public void firstBit() {
        short result = BigNatInternal.ctHighestOneBit((short) 0b1000000000000000);
        Assertions.assertEquals(0, result);
    }

    @Test
    public void secondBit() {
        short result = BigNatInternal.ctHighestOneBit((short) 0b0100000000000000);
        Assertions.assertEquals(1, result);
    }

    @Test
    public void zero() {
        short result = BigNatInternal.ctHighestOneBit((short) 0);
        Assertions.assertEquals(16, result);
    }
}
