package opencrypto.jcmathlib;

import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * @author Petr Svenda
 */
public class ResourceManager {
    /**
     * Object responsible for logical locking and unlocking of shared arrays and
     * objects
     */
    public ObjectLocker locker;
    /**
     * Object responsible for easy management of target placement (RAM/EEPROM)
     * for allocated objects
     */
    public ObjectAllocator memAlloc;


    // Allocated arrays
    byte[] helper_BN_array1;
    byte[] helper_BN_array2;
    byte[] helper_uncompressed_point_arr1;
    byte[] helper_uncompressed_point_arr2;
    byte[] helper_hashArray;
    /**
     * Number of pre-allocated helper arrays
     */
    public static final byte NUM_HELPER_ARRAYS = 5;

    MessageDigest hashEngine;
    KeyAgreement ecMultKA;
    Signature verifyEcdsa;
    public static final byte NUM_SHARED_HELPER_OBJECTS = 1;


    // These Bignats helper_BN_? are allocated
    BigNat helper_BN_A;
    BigNat helper_BN_B;
    BigNat helper_BN_C;
    BigNat helper_BN_D;
    BigNat helper_BN_E;
    BigNat helper_BN_F;

    // These Bignats helperEC_BN_? are allocated
    BigNat helperEC_BN_A;
    BigNat helperEC_BN_B;
    BigNat helperEC_BN_C;
    BigNat helperEC_BN_D;
    BigNat helperEC_BN_E;
    BigNat helperEC_BN_F;

    public void initialize(short MAX_POINT_SIZE, short MAX_COORD_SIZE, short MAX_BIGNAT_SIZE, short MULT_RSA_ENGINE_MAX_LENGTH_BITS, BigNatHelper bnh) {
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
        helper_uncompressed_point_arr2 = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.ECPH_uncompressed_point_arr2));
        locker.registerLock(helper_uncompressed_point_arr2);
        hashEngine = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        helper_hashArray = memAlloc.allocateByteArray(hashEngine.getLength(), memAlloc.getAllocatorType(ObjectAllocator.ECPH_hashArray));
        locker.registerLock(helper_hashArray);


        helper_BN_A = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_A), bnh);
        helper_BN_B = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_B), bnh);
        helper_BN_C = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_C), bnh);
        helper_BN_D = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_D), bnh);
        helper_BN_E = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_E), bnh);
        helper_BN_F = new BigNat((short) (MAX_BIGNAT_SIZE + 2), memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_F), bnh); // +2 is to correct for infrequent RSA result with two or more leading zeroes

        helperEC_BN_A = new BigNat(MAX_POINT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_A), bnh);
        helperEC_BN_B = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_B), bnh);
        helperEC_BN_C = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_C), bnh);
        helperEC_BN_D = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_D), bnh);
        helperEC_BN_E = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_E), bnh);
        helperEC_BN_F = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_F), bnh);

        // ECC Engines
        if (OperationSupport.getInstance().EC_HW_XY) {
            ecMultKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        } else if (OperationSupport.getInstance().EC_HW_X) {
            ecMultKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        }
        verifyEcdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

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
     * Lock a byte array
     * @param objToLock the byte array
     */
    public void lock(byte[] objToLock) {
        locker.lock(objToLock);
    }

    /**
     * Unlock a byte array
     * @param objToUnlock the byte array
     */
    public void unlock(byte[] objToUnlock) {
        locker.unlock(objToUnlock);
    }

    /**
     * Unlocks all locked objects
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

        locker.unlockAll();
    }
}
