package tests.BigNatInternal;

import javacard.framework.JCSystem;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Veronika Hanulikova
 */
public class SetSizeTest {
    @Test
    public void setSizeNotBlind() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

       short error =  bn1.ctSetSizeReturnError((short) 3, (short) 0);
        Assertions.assertEquals((short) 3, bn1.length());
        Assertions.assertEquals((short) 0, error);
    }

    @Test
    public void setSizeBlind() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        bn1.ctSetSize((short) 3, (short) 0xffff);
        Assertions.assertEquals((short) 10, bn1.length());
    }

    @Test
    public void setSizeNotBlind_error() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        short error =  bn1.ctSetSizeReturnError((short) -1, (short) 0);
        Assertions.assertEquals((short) 10, bn1.length());
        Assertions.assertEquals((short) 0xffff, error);
    }

    @Test
    public void setSizeToMax_notBlind_notErase() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        bn1.ctSetSize((short) 3, (short) 0x0);
        bn1.ctSetSizeToMax(false, (short) 0x0);
        Assertions.assertEquals((short) 11, bn1.length());
    }

    @Test
    public void setSizeToMax_blind_notErase() {
        ResourceManager rm = new ResourceManager((short) 256);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        BigNat bn1 = new BigNat((short) 10, memoryType, rm);

        bn1.ctSetSize((short) 3, (short) 0x0);
        bn1.ctSetSizeToMax(false, (short) 0xffff);
        Assertions.assertEquals((short) 3, bn1.length());
    }
}
