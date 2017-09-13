package opencrypto.jcmathlib;

import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 *
 * @author Petr Svenda
 */
public class ResourceManager {
    /**
     * Object responsible for logical locking and unlocking of shared arrays and
     * objects
     */
    public ObjectLocker locker = null;
    /**
     * Object responsible for easy management of target placement (RAM/EEPROM)
     * fro allocated objects
     */
    public ObjectAllocator memAlloc = null;
    
    
    
    // Allocated arrays
    byte[] helper_BN_array1 = null;
    byte[] helper_BN_array2 = null;
    byte[] helper_uncompressed_point_arr1 = null;
    byte[] helper_hashArray = null;
    /**
     * Number of pre-allocated helper arrays
     */
    public static final byte NUM_HELPER_ARRAYS = 4;

    MessageDigest hashEngine;
    public static final byte NUM_SHARED_HELPER_OBJECTS = 1;
    

    // These Bignats helper_BN_? are allocated
    Bignat helper_BN_A;
    Bignat helper_BN_B;
    Bignat helper_BN_C;
    Bignat helper_BN_D;
    Bignat helper_BN_E;
    Bignat helper_BN_F;

    // These Bignats helperEC_BN_? are allocated
    Bignat helperEC_BN_A;
    Bignat helperEC_BN_B;
    Bignat helperEC_BN_C;
    Bignat helperEC_BN_D;
    Bignat helperEC_BN_E;
    Bignat helperEC_BN_F;
    
    public void initialize(short MAX_POINT_SIZE, short MAX_COORD_SIZE, short MAX_BIGNAT_SIZE, short MULT_RSA_ENGINE_MAX_LENGTH_BITS, Bignat_Helper bnh) {
        // Allocate long-term helper values
        locker = new ObjectLocker((short) (NUM_HELPER_ARRAYS + NUM_SHARED_HELPER_OBJECTS));
        //locker.setLockingActive(false); // if required, locking can be disabled
        memAlloc = new ObjectAllocator();
        memAlloc.setAllAllocatorsRAM();
        //if required, memory for helper objects and arrays can be in persistent memory to save RAM (or some tradeoff)       
        //ObjectAllocator.setAllAllocatorsEEPROM();  //ObjectAllocator.setAllocatorsTradeoff();
        

        // Multiplication speedup engines and arrays used by Bignat.mult_RSATrick()
        helper_BN_array1 = memAlloc.allocateByteArray((short) (MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_array1));
        locker.registerLock(helper_BN_array1);
        helper_BN_array2 = memAlloc.allocateByteArray((short) (MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_array2));
        locker.registerLock(helper_BN_array2);
        helper_uncompressed_point_arr1 = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.ECPH_uncompressed_point_arr1));
        locker.registerLock(helper_uncompressed_point_arr1);
        hashEngine = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        helper_hashArray = memAlloc.allocateByteArray(hashEngine.getLength(), memAlloc.getAllocatorType(ObjectAllocator.ECPH_hashArray));
        locker.registerLock(helper_hashArray);
        //locker.registerLock(hashEngine); // register hash engine to slightly speedup search for locked objects (hash engine used less frequently)
        
        
        helper_BN_A = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_A), bnh);
        helper_BN_B = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_B), bnh);
        helper_BN_C = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_C), bnh);
        helper_BN_D = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_D), bnh);
        helper_BN_E = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_E), bnh);
        helper_BN_F = new Bignat((short) (MAX_BIGNAT_SIZE + 2), memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_F), bnh); // +2 is to correct for infrequent RSA result with two or more leading zeroes 
        
        helperEC_BN_A = new Bignat(MAX_POINT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_A), bnh);
        helperEC_BN_B = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_B), bnh);
        helperEC_BN_C = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_C), bnh);
        helperEC_BN_D = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_D), bnh);
        helperEC_BN_E = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_E), bnh);
        helperEC_BN_F = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_F), bnh);
        
        
    }
    
    /**
     * Erase all values stored in helper objects
     */
    void erase() {
        helper_BN_A.erase();
        helper_BN_B.erase();
        helper_BN_C.erase();
        helper_BN_D.erase();
        helper_BN_E.erase();
        helper_BN_F.erase();
        
        helperEC_BN_A.erase();
        helperEC_BN_B.erase();
        helperEC_BN_C.erase();
        helperEC_BN_D.erase();
        helperEC_BN_E.erase();
        helperEC_BN_F.erase();
        

        Util.arrayFillNonAtomic(helper_BN_array1, (short) 0, (short) helper_BN_array1.length, (byte) 0);
        Util.arrayFillNonAtomic(helper_BN_array2, (short) 0, (short) helper_BN_array2.length, (byte) 0);
        Util.arrayFillNonAtomic(helper_uncompressed_point_arr1, (short) 0, (short) helper_uncompressed_point_arr1.length, (byte) 0);
    }    
    
    /**
     * Unlocks all helper objects
     */
    public void unlockAll() {
        if (helper_BN_A.isLocked()) {
            helper_BN_A.unlock();
        }
        if (helper_BN_B.isLocked()) {
            helper_BN_B.unlock();
        }
        if (helper_BN_C.isLocked()) {
            helper_BN_C.unlock();
        }
        if (helper_BN_D.isLocked()) {
            helper_BN_D.unlock();
        }
        if (helper_BN_E.isLocked()) {
            helper_BN_E.unlock();
        }
        if (helper_BN_F.isLocked()) {
            helper_BN_F.unlock();
        }

        if (helperEC_BN_A.isLocked()) {
            helperEC_BN_A.unlock();
        }
        if (helperEC_BN_B.isLocked()) {
            helperEC_BN_B.unlock();
        }
        if (helperEC_BN_C.isLocked()) {
            helperEC_BN_C.unlock();
        }
        if (helperEC_BN_D.isLocked()) {
            helperEC_BN_D.unlock();
        }
        if (helperEC_BN_E.isLocked()) {
            helperEC_BN_E.unlock();
        }
        if (helperEC_BN_F.isLocked()) {
            helperEC_BN_F.unlock();
        }
        if (locker.isLocked(helper_uncompressed_point_arr1)) {
            locker.unlock(helper_uncompressed_point_arr1);
        }
        if (locker.isLocked(helper_hashArray)) {
            locker.unlock(helper_hashArray);
        }
        
    }    
}
