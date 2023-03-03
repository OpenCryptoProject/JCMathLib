package opencrypto.jcmathlib;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * @author Petr Svenda
 */
public class ResourceManager {
    public ObjectLocker locker;
    public ObjectAllocator memAlloc;

    MessageDigest hashEngine;
    KeyAgreement ecMultKA;
    KeyAgreement ecAddKA;
    Signature verifyEcdsa;
    Cipher multCiph;
    RSAPublicKey expPub;
    RSAPrivateKey expPriv;
    Cipher expCiph;

    byte[] ARRAY_A, ARRAY_B, POINT_ARRAY_A, POINT_ARRAY_B, HASH_ARRAY;
    public static final byte LOCKER_ARRAYS = 5;
    byte[] RAM_WORD; // Without lock

    static byte[] CONST_TWO = {0x02};
    public static final byte LOCKER_OBJECTS = 1;

    BigNat BN_A, BN_B, BN_C, BN_D, BN_E, BN_F;
    BigNat EC_BN_A, EC_BN_B, EC_BN_C, EC_BN_D, EC_BN_E, EC_BN_F;
    public static BigNat ONE, TWO, THREE, ONE_COORD;

    // TODO remove if possible
    public final short MODULO_RSA_ENGINE_MAX_LENGTH_BITS;

    public ResourceManager(short MAX_POINT_SIZE, short MAX_COORD_SIZE, short MAX_BIGNAT_SIZE, short MULT_RSA_ENGINE_MAX_LENGTH_BITS, short MODULO_RSA_ENGINE_MAX_LENGTH_BITS) {
        this.MODULO_RSA_ENGINE_MAX_LENGTH_BITS = MODULO_RSA_ENGINE_MAX_LENGTH_BITS;
        // Allocate long-term helper values
        locker = new ObjectLocker((short) (LOCKER_ARRAYS + LOCKER_OBJECTS));
        // locker.setLockingActive(false); // if required, locking can be disabled
        memAlloc = new ObjectAllocator();
        memAlloc.setAllAllocatorsRAM();
        // if required, memory for helper objects and arrays can be in persistent memory to save RAM (or some tradeoff)
        // ObjectAllocator.setAllAllocatorsEEPROM();
        // ObjectAllocator.setAllocatorsTradeoff();


        ARRAY_A = memAlloc.allocateByteArray((short) (MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), memAlloc.getAllocatorType(ObjectAllocator.ARRAY_A));
        locker.registerLock(ARRAY_A);
        ARRAY_B = memAlloc.allocateByteArray((short) (MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), memAlloc.getAllocatorType(ObjectAllocator.ARRAY_B));
        locker.registerLock(ARRAY_B);
        POINT_ARRAY_A = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.POINT_ARRAY_A));
        locker.registerLock(POINT_ARRAY_A);
        POINT_ARRAY_B = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.POINT_ARRAY_B));
        locker.registerLock(POINT_ARRAY_B);
        hashEngine = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        HASH_ARRAY = memAlloc.allocateByteArray(hashEngine.getLength(), memAlloc.getAllocatorType(ObjectAllocator.HASH_ARRAY));
        locker.registerLock(HASH_ARRAY);
        RAM_WORD = memAlloc.allocateByteArray((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET); // only 2b RAM for faster add(short)

        BN_A = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_A), this);
        BN_B = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_B), this);
        BN_C = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_C), this);
        BN_D = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_D), this);
        BN_E = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_E), this);
        BN_F = new BigNat((short) (MAX_BIGNAT_SIZE + 2), memAlloc.getAllocatorType(ObjectAllocator.BN_F), this); // +2 is to correct for infrequent RSA result with two or more leading zeroes

        EC_BN_A = new BigNat(MAX_POINT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_A), this);
        EC_BN_B = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_B), this);
        EC_BN_C = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_C), this);
        EC_BN_D = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_D), this);
        EC_BN_E = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_E), this);
        EC_BN_F = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_F), this);

        // Allocate BN constants always in EEPROM (only reading)
        ONE = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        ONE.one();
        TWO = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        TWO.two();
        THREE = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        THREE.three();
        ONE_COORD = new BigNat(MAX_COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        ONE_COORD.one();

        // ECC Helpers
        if (OperationSupport.getInstance().EC_HW_XY) {
            // ecMultKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
            ecMultKA = KeyAgreement.getInstance((byte) 6, false);
        } else if (OperationSupport.getInstance().EC_HW_X) {
            // ecMultKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
            ecMultKA = KeyAgreement.getInstance((byte) 3, false);
        }
        // verifyEcdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        verifyEcdsa = Signature.getInstance((byte) 33, false);
        if (OperationSupport.getInstance().EC_HW_ADD) {
            // ecAddKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_PACE_GM, false);
            ecAddKA = KeyAgreement.getInstance((byte) 5, false);
        }

        // RSA Mult Helpers
        KeyPair multKP = new KeyPair(KeyPair.ALG_RSA_CRT, MULT_RSA_ENGINE_MAX_LENGTH_BITS);
        multKP.genKeyPair();
        RSAPublicKey multPK = (RSAPublicKey) multKP.getPublic();
        multPK.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
        multCiph = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        multCiph.init(multPK, Cipher.MODE_ENCRYPT);

        // RSA Exp Helpers
        expPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);
        expPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);
        expCiph = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }

    /**
     * Erase all values stored in helper objects
     */
    void erase() {
        BN_A.erase();
        BN_B.erase();
        BN_C.erase();
        BN_D.erase();
        BN_E.erase();
        BN_F.erase();

        EC_BN_A.erase();
        EC_BN_B.erase();
        EC_BN_C.erase();
        EC_BN_D.erase();
        EC_BN_E.erase();
        EC_BN_F.erase();

        Util.arrayFillNonAtomic(ARRAY_A, (short) 0, (short) ARRAY_A.length, (byte) 0);
        Util.arrayFillNonAtomic(ARRAY_B, (short) 0, (short) ARRAY_B.length, (byte) 0);
        Util.arrayFillNonAtomic(POINT_ARRAY_A, (short) 0, (short) POINT_ARRAY_A.length, (byte) 0);
        Util.arrayFillNonAtomic(RAM_WORD, (short) 0, (short) RAM_WORD.length, (byte) 0);
    }

    /**
     * Lock a byte array
     *
     * @param objToLock the byte array
     */
    public void lock(byte[] objToLock) {
        locker.lock(objToLock);
    }

    /**
     * Unlock a byte array
     *
     * @param objToUnlock the byte array
     */
    public void unlock(byte[] objToUnlock) {
        locker.unlock(objToUnlock);
    }

    /**
     * Unlocks all locked objects
     */
    public void unlockAll() {
        if (BN_A.isLocked()) {
            BN_A.unlock();
        }
        if (BN_B.isLocked()) {
            BN_B.unlock();
        }
        if (BN_C.isLocked()) {
            BN_C.unlock();
        }
        if (BN_D.isLocked()) {
            BN_D.unlock();
        }
        if (BN_E.isLocked()) {
            BN_E.unlock();
        }
        if (BN_F.isLocked()) {
            BN_F.unlock();
        }

        if (EC_BN_A.isLocked()) {
            EC_BN_A.unlock();
        }
        if (EC_BN_B.isLocked()) {
            EC_BN_B.unlock();
        }
        if (EC_BN_C.isLocked()) {
            EC_BN_C.unlock();
        }
        if (EC_BN_D.isLocked()) {
            EC_BN_D.unlock();
        }
        if (EC_BN_E.isLocked()) {
            EC_BN_E.unlock();
        }
        if (EC_BN_F.isLocked()) {
            EC_BN_F.unlock();
        }

        locker.unlockAll();
    }
}
