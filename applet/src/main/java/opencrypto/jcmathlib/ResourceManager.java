package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * @author Petr Svenda
 */
public class ResourceManager {
    public ObjectAllocator memAlloc;

    MessageDigest hashEngine;
    KeyAgreement ecMultKA;
    KeyAgreement ecAddKA;
    Signature verifyEcdsa;
    Cipher sqCiph, expCiph;
    RSAPublicKey sqPub, expPub;
    RSAPrivateKey sqPriv, expPriv;

    byte[] ARRAY_A, ARRAY_B, POINT_ARRAY_A, POINT_ARRAY_B, HASH_ARRAY;

    static byte[] CONST_TWO = {0x02};

    BigNat BN_WORD;
    BigNat BN_A, BN_B, BN_C, BN_D, BN_E, BN_F, BN_G;
    BigNat EC_BN_A, EC_BN_B, EC_BN_C, EC_BN_D, EC_BN_E, EC_BN_F;
    public static BigNat TWO, THREE, ONE_COORD;

    public final short MAX_EXP_BIT_LENGTH;
    public final short MAX_EXP_LENGTH;
    public final short MAX_SQ_BIT_LENGTH;
    public final short MAX_SQ_LENGTH;
    public final short MAX_BIGNAT_SIZE;
    public final short MAX_POINT_SIZE;
    public final short MAX_COORD_SIZE;

    public ResourceManager(short maxEcLength) {
        short min = OperationSupport.getInstance().MIN_RSA_BIT_LENGTH;
        if (maxEcLength <= (short) 256) {
            MAX_EXP_BIT_LENGTH = (short) 512 < min ? min : (short) 512;
            MAX_SQ_BIT_LENGTH = (short) 768 < min ? min : (short) 768;
            MAX_POINT_SIZE = (short) 64;
        }
        else if (maxEcLength <= (short) 384) {
            MAX_EXP_BIT_LENGTH = (short) 768 < min ? min : (short) 768;
            MAX_SQ_BIT_LENGTH = (short) 1024 < min ? min : (short) 1024;
            MAX_POINT_SIZE = (short) 96;
        }
        else if (maxEcLength <= (short) 512) {
            MAX_EXP_BIT_LENGTH = (short) 1024 < min ? min : (short) 1024;
            MAX_SQ_BIT_LENGTH = (short) 1280 < min ? min : (short) 1280;
            MAX_POINT_SIZE = (short) 128;
        }
        else {
            MAX_EXP_BIT_LENGTH = (short) 0;
            MAX_SQ_BIT_LENGTH = (short) 0;
            MAX_POINT_SIZE = (short) 0;
            ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
        }
        MAX_SQ_LENGTH = (short) (MAX_SQ_BIT_LENGTH / 8);
        MAX_EXP_LENGTH = (short) (MAX_EXP_BIT_LENGTH / 8);
        MAX_BIGNAT_SIZE = (short) ((short) (MAX_EXP_BIT_LENGTH / 8) + 1);
        MAX_COORD_SIZE = (short) ((short) (MAX_POINT_SIZE / 2) + 1);

        memAlloc = new ObjectAllocator();
        memAlloc.setAllAllocatorsRAM();
        // if required, memory for helper objects and arrays can be in persistent memory to save RAM (or some tradeoff)
        // ObjectAllocator.setAllAllocatorsEEPROM();
        // ObjectAllocator.setAllocatorsTradeoff();


        ARRAY_A = memAlloc.allocateByteArray(MAX_SQ_LENGTH, memAlloc.getAllocatorType(ObjectAllocator.ARRAY_A));
        locker.registerLock(ARRAY_A);
        ARRAY_B = memAlloc.allocateByteArray(MAX_SQ_LENGTH, memAlloc.getAllocatorType(ObjectAllocator.ARRAY_B));
        locker.registerLock(ARRAY_B);
        POINT_ARRAY_A = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.POINT_ARRAY_A));
        locker.registerLock(POINT_ARRAY_A);
        POINT_ARRAY_B = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.POINT_ARRAY_B));
        locker.registerLock(POINT_ARRAY_B);
        hashEngine = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        HASH_ARRAY = memAlloc.allocateByteArray(hashEngine.getLength(), memAlloc.getAllocatorType(ObjectAllocator.HASH_ARRAY));
        locker.registerLock(HASH_ARRAY);

        BN_WORD = new BigNat((short) 2, memAlloc.getAllocatorType(ObjectAllocator.BN_WORD), this);

        BN_A = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_A), this);
        BN_B = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_B), this);
        BN_C = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_C), this);
        BN_D = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_D), this);
        BN_E = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_E), this);
        BN_F = new BigNat(MAX_SQ_LENGTH, memAlloc.getAllocatorType(ObjectAllocator.BN_F), this);
        BN_G = new BigNat(MAX_SQ_LENGTH, memAlloc.getAllocatorType(ObjectAllocator.BN_G), this);

        EC_BN_A = new BigNat(MAX_POINT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_A), this);
        EC_BN_B = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_B), this);
        EC_BN_C = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_C), this);
        EC_BN_D = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_D), this);
        EC_BN_E = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_E), this);
        EC_BN_F = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_F), this);

        // Allocate BN constants always in EEPROM (only reading)
        TWO = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        TWO.setValue((byte) 2);
        THREE = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        THREE.setValue((byte) 3);
        ONE_COORD = new BigNat(MAX_COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        ONE_COORD.setSize((short) (MAX_POINT_SIZE / 2));
        ONE_COORD.setValue((byte) 1);
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

        // RSA Sq Helpers
        if (OperationSupport.getInstance().RSA_SQ) {
            Util.arrayFillNonAtomic(ARRAY_A, (short) 0, MAX_SQ_LENGTH, (byte) 0xff);
            sqCiph = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            if (OperationSupport.getInstance().RSA_PUB) {
                sqPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, MAX_SQ_BIT_LENGTH, false);
                sqPub.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
                sqPub.setModulus(ARRAY_A, (short) 0, MAX_SQ_LENGTH);
                sqCiph.init(sqPub, Cipher.MODE_ENCRYPT);
            } else {
                sqPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, MAX_SQ_BIT_LENGTH, false);
                sqPriv.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
                sqPriv.setModulus(ARRAY_A, (short) 0, MAX_SQ_LENGTH);
                sqCiph.init(sqPriv, Cipher.MODE_DECRYPT);
            }
        }

        // RSA Exp Helpers
        expPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, MAX_EXP_BIT_LENGTH, false);
        expPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, MAX_EXP_BIT_LENGTH, false);
        expCiph = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }

    /**
     * Erase all values stored in helper objects
     */
    void erase() {
        BN_WORD.erase();

        BN_A.erase();
        BN_B.erase();
        BN_C.erase();
        BN_D.erase();
        BN_E.erase();
        BN_F.erase();
        BN_G.erase();

        EC_BN_A.erase();
        EC_BN_B.erase();
        EC_BN_C.erase();
        EC_BN_D.erase();
        EC_BN_E.erase();
        EC_BN_F.erase();

        Util.arrayFillNonAtomic(ARRAY_A, (short) 0, (short) ARRAY_A.length, (byte) 0);
        Util.arrayFillNonAtomic(ARRAY_B, (short) 0, (short) ARRAY_B.length, (byte) 0);
        Util.arrayFillNonAtomic(POINT_ARRAY_A, (short) 0, (short) POINT_ARRAY_A.length, (byte) 0);
    }

    /// [DependencyBegin:ObjectLocker]
    public static final byte LOCKER_ARRAYS = 5;
    public static final byte LOCKER_OBJECTS = 1;
    public ObjectLocker locker = new ObjectLocker((short) (LOCKER_ARRAYS + LOCKER_OBJECTS));

    /**
     * Refresh RAM objects after reset.
     */
    public void refreshAfterReset() {
        if (locker != null) {
            locker.refreshAfterReset();
        }
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
        if (BN_G.isLocked()) {
            BN_G.unlock();
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
    /// [DependencyEnd:ObjectLocker]
}
