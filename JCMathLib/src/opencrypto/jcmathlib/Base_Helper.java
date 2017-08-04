package opencrypto.jcmathlib;

/**
 *
 * @author Petr Svenda
 */
public class Base_Helper {
    final ResourceManager rm;

    /**
     * Helper flag which signalizes that code is executed inside simulator
     * (during tests). Is used to address simulator specific behaviour
     * workaround if required.
     */
    public boolean bIsSimulator = false;

    public Base_Helper(ResourceManager resman) {
        rm = resman;
    }
    
    /**
     * Lock/reserve provided object for subsequent use. Used to protect
     * corruption of pre-allocated shared objects in different, potentially
     * nested, operations. Must be unlocked later on.
     *
     * @param objToLock array to be locked
     * @throws SW_ALREADYLOCKED if already locked (is already in use by other
     * operation)
     */
/*    
    public void lock(Object objToLock) {
        rm.locker.lock(objToLock);
    }
*/
    public void lock(byte[] objToLock) {
        rm.locker.lock(objToLock);
    }

    /**
     * Unlock/release object from use. Used to protect corruption of
     * pre-allocated objects used in different nested operations. Must be locked
     * before.
     *
     * @param objToUnlock object to unlock
     * @throws SW_NOTLOCKED_BIGNAT if was not locked before (inconsistence in
     * lock/unlock sequence)
     */
/*    
    public void unlock(Object objToUnlock) {
        rm.locker.unlock(objToUnlock);
    }
*/
    public void unlock(byte[] objToUnlock) {
        rm.locker.unlock(objToUnlock);
    }

    /**
     * Unlocks all locked objects
     */
    public void unlockAll() {
        rm.locker.unlockAll();
    }

    /**
     * Check if provided object is logically locked
     *
     * @param objToUnlock object to be checked
     * @return true of array is logically locked, false otherwise
     */
/*    
    public boolean isLocked(Object objToUnlock) {
        return rm.locker.isLocked(objToUnlock);
    }    
*/    
    /**
     * Allocates new byte[] array with provided length either in RAM or EEPROM
     * based on an allocator type. Method updates internal counters of bytes
     * allocated with specific allocator. Use {@code getAllocatedInRAM()} or
     * {@code getAllocatedInEEPROM} for counters readout.
     *
     * @param length length of array
     * @param allocatorType type of allocator
     * @return allocated array
     */
    public byte[] allocateByteArray(short length, byte allocatorType) {
        return rm.memAlloc.allocateByteArray(length, allocatorType);        
    }    
}
