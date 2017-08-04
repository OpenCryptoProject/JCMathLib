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
    
    
    public ResourceManager rm = null;
    /**
     * Helper structure containing all preallocated objects necessary for Bignat operations
     */
    public Bignat_Helper bnh = null;
    /**
     * Helper structure containing all preallocated objects necessary for ECPoint operations
     */
    public ECPoint_Helper ech = null;

    /**
     * Creates new control structure for requested bit length with all preallocated arrays and engines 
     * @param maxECLength maximum length of ECPoint objects supported. The provided value is used to 
     *      initialize properly underlying arrays and engines.  
     */
    public ECConfig(short maxECLength) {
        
        // Allocate helper objects for BN and EC
        // Note: due to circular references, we need to split object creation and actual alloaction and initailiztion later (initialize()) 
        rm = new ResourceManager();
        bnh = new Bignat_Helper(rm);
        ech = new ECPoint_Helper(rm);

        // Set proper lengths and other internal settings based on required ECC length
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
        
        // Allocate shared resources and initialize mapping between shared objects and helpers
        rm.initialize(MAX_POINT_SIZE, MAX_COORD_SIZE, MAX_BIGNAT_SIZE, MULT_RSA_ENGINE_MAX_LENGTH_BITS, bnh);
        bnh.initialize(MODULO_RSA_ENGINE_MAX_LENGTH_BITS, MULT_RSA_ENGINE_MAX_LENGTH_BITS);
        ech.initialize();
    }
    
    public void refreshAfterReset() {
        if (rm.locker != null) { 
            rm.locker.refreshAfterReset();
        }        
    }
    
    void reset() {
        bnh.FLAG_FAST_MULT_VIA_RSA = false;     
        ech.FLAG_FAST_EC_MULT_VIA_KA = false;   
    }
    
    public void setECC256Config() {
        reset();
        MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
        MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;        
        MAX_POINT_SIZE = (short) 64;
        computeDerivedLengths();
    }
    public void setECC384Config() {
        reset();
        MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
        MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
        MAX_POINT_SIZE = (short) 96;
        computeDerivedLengths();
    }
    public void setECC512Config() {
        reset();
        MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
        MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
        MAX_POINT_SIZE = (short) 128;
        computeDerivedLengths();
    }    
    public void setECC521Config() {
        reset();
        MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
        MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
        MAX_POINT_SIZE = (short) 129;
        computeDerivedLengths();
    }
    
    private void computeDerivedLengths() {
        MAX_BIGNAT_SIZE = (short) ((short) (bnh.MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8) + 1);
        MAX_COORD_SIZE = (short) (MAX_POINT_SIZE / 2);
    }

    /**
     * Unlocks all logically locked arrays and objects. Useful as recovery after premature end of some operation (e.g., due to exception)
     * when some objects remains locked.
     */
    void unlockAll() {
        rm.unlockAll();
        rm.locker.unlockAll();
    }
}
