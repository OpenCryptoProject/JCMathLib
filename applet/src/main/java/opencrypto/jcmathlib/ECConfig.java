package opencrypto.jcmathlib;

import javacard.framework.ISOException;

/**
 * Configure itself to proper lengths and other parameters according to intended length of ECC
 * @author Petr Svenda
 */
public class ECConfig {
    /**
     * The size of speedup engine used for fast modulo exponent computation
     * (must be larger than biggest Bignat used)
     */
    public short MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
    /**
     * The size of speedup engine used for fast multiplication of large numbers
     * Must be larger than 2x biggest Bignat used
     */
    public short MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
    /**
     * The size of largest integer used in computations
     */
    public short MAX_BIGNAT_SIZE = (short) 65; // ((short) (MODULO_ENGINE_MAX_LENGTH_BITS / 8) + 1);
    /**
     * The size of largest ECC point used
     */
    public short MAX_POINT_SIZE = (short) 64;
    /**
     * The size of single coordinate of the largest ECC point used 
     */
    public short MAX_COORD_SIZE = (short) 32; // MAX_POINT_SIZE / 2
    
    
    public ResourceManager rm;

    /**
     * Creates new control structure for requested bit length with all preallocated arrays and engines 
     * @param maxECLength maximum length of ECPoint objects supported. The provided value is used to 
     *      initialize properly underlying arrays and engines.  
     */
    public ECConfig(short maxECLength) {
        if (maxECLength <= (short) 256) {
            setECC256Config();
        }
        else if (maxECLength <= (short) 384) {
            setECC384Config();
        } 
        else if (maxECLength <= (short) 512) {
            setECC512Config();
        }
        else {
            ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
        }

        rm = new ResourceManager(MAX_POINT_SIZE, MAX_COORD_SIZE, MAX_BIGNAT_SIZE, MULT_RSA_ENGINE_MAX_LENGTH_BITS, MODULO_RSA_ENGINE_MAX_LENGTH_BITS);
    }

    public void setECC256Config() {
        MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
        MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;        
        MAX_POINT_SIZE = (short) 64;
        computeDerivedLengths();
    }
    public void setECC384Config() {
        MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
        MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
        MAX_POINT_SIZE = (short) 96;
        computeDerivedLengths();
    }
    public void setECC512Config() {
        MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
        MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
        MAX_POINT_SIZE = (short) 128;
        computeDerivedLengths();
    }

    private void computeDerivedLengths() {
        MAX_BIGNAT_SIZE = (short) ((short) (MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8) + 1);
        MAX_COORD_SIZE = (short) (MAX_POINT_SIZE / 2);
    }

    /// [DependencyBegin:ObjectLocker]
    /**
     * Unlocks all logically locked arrays and objects. Useful as recovery after premature end of some operation (e.g., due to exception)
     * when some objects remains locked.
     */
    void unlockAll() {
        rm.unlockAll();
    }

    public void refreshAfterReset() {
        if (rm.locker != null) {
            rm.locker.refreshAfterReset();
        }
    }
    /// [DependencyEnd:ObjectLocker]
}
