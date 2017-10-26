package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 *
* @author Vasilios Mavroudis and Petr Svenda
 */
public class ObjectLocker {
    /**
     * Configuration flag controlling clearing of shared objects on lock as
     * prevention of unwanted leak of sensitive information from previous
     * operation. If true, object is erased once locked for use
     */
    private boolean ERASE_ON_LOCK = false;
    /**
     * Configuration flag controlling clearing of shared objects on lock as
     * prevention of unwanted leak of sensitive information to next 
     * operation. If true, object is erased once unlocked from use
     */
    private boolean ERASE_ON_UNLOCK = false;    
    
    /**
     * Configuration flag controlling clearing of shared objects on lock as
     * prevention of unwanted leak of sensitive information to next operation.
     * If true, object is erased once unlocked from use
     */
    private boolean PROFILE_LOCKED_OBJECTS = true;
    /**
     * Array of pointers to objects which will be guarded by locks. 
     * Every even value contains pointer to registered object. Subsequent index 
     * contains null if not locked, !null if locked, 
     * Stored in RAM for fast access.
     */
    private Object[] lockedObjects;
    /**
     * Copy of pointers to objects from lockedObjects in persistent memory to refresh after card reset.
     * Refreshed by call {@code refreshAfterReset()}
     */
    private Object[] lockedObjectsPersistent;
    
    /**
     * Array to hold state of lock for all other objects implemented as N x N array [0...N-1][N...2N-1]...[] 
     * where [0...N-1] contains the states of lock for all other objects than first object (lockedObjects[0]). 
     * If no other object is locked after series of operations, [0...N-1] will contain 0 on all indexes. 
     * All objects (lockedObjects[i]) which happened to be locked together with have 1 at [0...i...N-1]. 
     */
    public byte[] profileLockedObjects;
    /**
     * If true, locking is performed, otherwise relevant method just return without any operation performed
     */
    private boolean bLockingActive = true;
    
    public ObjectLocker(short numArrays) {
        initialize(numArrays, ERASE_ON_LOCK, ERASE_ON_UNLOCK);
    }
    public ObjectLocker(short numArrays, boolean bEraseOnLock, boolean bEraseOnUnlock) {
        initialize(numArrays, bEraseOnLock, bEraseOnUnlock);
    }
    private final void initialize(short numObjects, boolean bEraseOnLock, boolean bEraseOnUnlock) {
        lockedObjects = JCSystem.makeTransientObjectArray((short) (2 * numObjects), JCSystem.CLEAR_ON_RESET);
        lockedObjectsPersistent = new Object[(short) (2 * numObjects)];
        ERASE_ON_LOCK = bEraseOnLock;
        ERASE_ON_UNLOCK = bEraseOnUnlock;
        profileLockedObjects = new byte[(short) (numObjects * numObjects)]; 
        resetProfileLocks();
    }
    
    /**
     * Reset profile array with profile locks statistics.
     */
    public void resetProfileLocks() {
        Util.arrayFillNonAtomic(profileLockedObjects, (short) 0, (short) profileLockedObjects.length, (byte) 0);
    }

    /**
     * Register new object for lock guarding. 
     * @param objToLock object to be guarded
     * @return index to internal array where registered object is stored (if known, lock/unlock is faster)
     */
    public short registerLock(Object objToLock) {
        short i;
        for (i = 0; i < (short) lockedObjects.length; i += 2) {
            if (lockedObjects[i] == null) {
                // Free slot found
                lockedObjects[i] = objToLock;
                lockedObjects[(short) (i + 1)] = null; // null means array is unlocked
                lockedObjectsPersistent[i] = objToLock; // Store same into persistent array as well
                lockedObjectsPersistent[(short) (i + 1)] = null; 
                return i; // Return index for potential speedup of locking
            }
        }
        ISOException.throwIt(ReturnCodes.SW_LOCK_NOFREESLOT);
        return -1;
    }
    /**
     * Locking array (placed in RAM) must be refreshed after card reset. Call this method during select()
     */
    public void refreshAfterReset() {
        for (short i = 0; i < (short) lockedObjects.length; i++) {
            lockedObjects[i] = lockedObjectsPersistent[i];
        }
    }
    
    /**
     * Controls if locking and unlocking is actually performed. The lock operations 
     * add some overhead, so it may be turned on/off as required. E.g., when developing 
     * new code or like to enjoy protection of automatic clearing of shared objects before/after lock
     * enable this feature. 
     * @param bLockActive if true, locking and unlocking is performed. If false, lock/unlock methods will return without any effect
     */
    public void setLockingActive(boolean bLockActive) {
        bLockingActive = bLockActive;
    }
    /**
     * Lock/reserve provided object for subsequent use. Used to protect corruption
     * of pre-allocated shared objects in different, potentially nested,
     * operations. Must be unlocked later on.
     *
     * @param objToLock array to be locked
     * @throws SW_ALREADYLOCKED if already locked (is already in use by
     * other operation)
     */
    public void lock(Object objToLock) {
        if (!bLockingActive) {
            return;
        }
        // Find object to lock
        short i;
        for (i = 0; i < (short) lockedObjects.length; i += 2) {
            if (lockedObjects[i] != null && lockedObjects[i].equals(objToLock)) {
                lock(objToLock, i);
                break;
            }
        }
        // If reached here, required array was not found
        if (i == (short) lockedObjects.length) {
            ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
        }
    }
    public void lock(byte[] objToLock) {
        if (!bLockingActive) {
            return;
        }
        lock((Object) objToLock);
        if (ERASE_ON_LOCK) {
            Util.arrayFillNonAtomic(objToLock, (short) 0, (short) objToLock.length, (byte) 0);
        }
    }
    /**
     * Unlock/release object from use. Used to protect corruption of
     * pre-allocated objects used in different nested operations. Must
     * be locked before.
     *
     * @param objToUnlock object to unlock
     * @throws SW_NOTLOCKED_BIGNAT if was not locked before (inconsistence in
     * lock/unlock sequence)
     */
    
    public void unlock(Object objToUnlock) {
        if (!bLockingActive) {
            return;
        }
        // Find object to unlock
        short i;
        for (i = 0; i < (short) lockedObjects.length; i += 2) {
            if (lockedObjects[i] != null && lockedObjects[i].equals(objToUnlock)) {
                unlock(objToUnlock, i);
                break;
            }
        }
        // If reached here, required array was not found
        if (i == (short) lockedObjects.length) {
            ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
        }
    }    

    public void unlock(byte[] objToUnlock) {
        if (!bLockingActive) {
            return;
        }
        unlock((Object) objToUnlock);
        if (ERASE_ON_UNLOCK) {
            Util.arrayFillNonAtomic(objToUnlock, (short) 0, (short) objToUnlock.length, (byte) 0);
        }
    }    
    
    /**
     * Unlocks all locked objects
     */
    public void unlockAll() {
        if (!bLockingActive) {
            return;
        }
        for (short i = 0; i < (short) lockedObjects.length; i += 2) {
            lockedObjects[(short) (i + 1)] = null;
        }
    }
    
    /**
     * Check if provided object is logically locked
     * @param objToUnlock object to be checked
     * @return true of array is logically locked, false otherwise 
     */
    
    public boolean isLocked(Object objToUnlock) {
        if (!bLockingActive) {
            return false;
        }
        // Find object to unlock
        short i;
        for (i = 0; i < (short) lockedObjects.length; i += 2) {
            if (lockedObjects[i] != null && lockedObjects[i].equals(objToUnlock)) {
                return lockedObjects[(short) (i + 1)] != null;
            }
        }
        // If reached here, required object was not found
        if (i == (short) lockedObjects.length) {
            ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
        }
        return false;
    }
    
    
    private void lock(Object objToLock, short lockIndex) {
        if (lockedObjects[lockIndex] != null && !lockedObjects[lockIndex].equals(objToLock)) {
            ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_MISMATCH);
        }
        // Next position in array signalizes logical lock (null == unlocked, !null == locked) 
        if (lockedObjects[(short) (lockIndex + 1)] == null) {
            lockedObjects[(short) (lockIndex + 1)] = objToLock; // lock logically by assigning object reference to [i + 1]
        } else {
            // this array is already locked, raise exception (incorrect sequence of locking and unlocking)
            ISOException.throwIt(ReturnCodes.SW_LOCK_ALREADYLOCKED);
        }
        if (PROFILE_LOCKED_OBJECTS) {
            // If enabled, check status of all other objects and mark these that are currently locked
            short profileLockOffset = (short) (lockIndex * (short) ((short) lockedObjects.length / 2)); // Obtain section of profileLockedObjects array relevant for current object
            
            for (short i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[(short) (i + 1)] != null) {
                    // Object at index i is locked, mark it to corresponding position in profileLockedObjects by setting value to 1
                    profileLockedObjects[(short) (profileLockOffset + (short) (i / 2))] = 1;
                }
            }
        }
    }
    
    private void unlock(Object objToUnlock, short lockIndex) {
        if (lockedObjects[lockIndex] != null && !lockedObjects[lockIndex].equals(objToUnlock)) {
            ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_MISMATCH);
        }
        // Next position in array signalizes logical lock (null == unlocked, !null == locked) 
        if (lockedObjects[(short) (lockIndex + 1)].equals(objToUnlock)) {
            lockedObjects[(short) (lockIndex + 1)] = null; // lock logically by assigning object reference to [i + 1]
        } else {
            // this array is not locked, raise exception (incorrect sequence of locking and unlocking)
            ISOException.throwIt(ReturnCodes.SW_LOCK_NOTLOCKED);
        }
    }
}
