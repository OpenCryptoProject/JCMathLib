package opencrypto.jcmathlib;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/**
 *
 * @author Petr Svenda
 */
public class BigNatHelper extends BaseHelper {
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
     * If true, fast multiplication of large numbers via RSA engine can be used.
     * Is set automatically after successful allocation of required engines
     */
    public boolean FLAG_FAST_MULT_VIA_RSA = false;
    /**
     * Threshold length in bits of an operand after which speedup with RSA
     * multiplication is used. Schoolbook multiplication is used for shorter
     * operands
     */
    public static final short FAST_MULT_VIA_RSA_TRESHOLD_LENGTH = (short) 16;
    
    byte[] tmp_array_short;
    
    //
    // References to underlying shared objects
    //
    byte[] fnc_mult_resultArray1;
    byte[] fnc_deep_resize_tmp;
    byte[] fnc_mult_resultArray2;
    byte[] fnc_same_value_array1;
    byte[] fnc_same_value_hash;
    byte[] fnc_shift_bytes_right_tmp;
    
    // These Bignats are just pointing to some helper_BN_? so reasonable naming is preserved yet no need to actually allocated whole Bignat object
    BigNat fnc_mod_exp_modBN;
    
    BigNat fnc_mod_add_tmp;
    BigNat fnc_mod_sub_tmp;
    BigNat fnc_mod_sub_tmpOther;
    BigNat fnc_mod_sub_tmpThis;

    BigNat fnc_mod_mult_tmpThis;

    BigNat fnc_mult_mod_tmpThis;
    BigNat fnc_mult_mod_tmp_x;
    BigNat fnc_mult_mod_tmp_mod;

    BigNat fnc_divide_tmpThis;

    BigNat fnc_gcd_tmp;
    BigNat fnc_gcd_tmpOther;

    BigNat fnc_is_coprime_tmp;

    BigNat fnc_exponentiation_i;
    BigNat fnc_exponentiation_tmp;

    BigNat fnc_sqrt_p_1;
    BigNat fnc_sqrt_Q;
    BigNat fnc_sqrt_S;
    BigNat fnc_sqrt_tmp;
    BigNat fnc_sqrt_exp;
    BigNat fnc_sqrt_z;

    BigNat fnc_mod_minus_2;

    BigNat fnc_negate_tmp;
    
    BigNat fnc_int_add_tmpMag;
    BigNat fnc_int_multiply_mod;
    BigNat fnc_int_multiply_tmpThis;
    BigNat fnc_int_divide_tmpThis;
            
    RSAPublicKey fnc_NmodE_pubKey;
    Cipher fnc_NmodE_cipher;
    
    public static BigNat ONE;
    public static BigNat TWO;
    public static BigNat THREE;

    
    // Helper objects for fast multiplication of two large numbers (without modulo)
    KeyPair fnc_mult_keypair;
    RSAPublicKey fnc_mult_pubkey_pow2;
    Cipher fnc_mult_cipher;
    MessageDigest hashEngine;

    static byte[] CONST_ONE = {0x01};
    static byte[] CONST_TWO = {0x02};
    
    public BigNatHelper(ResourceManager resman) {
        super(resman);
    }
    
    void initialize(short modRSAEngineMaxBits, short multRSAEngineMaxBits) {
        MODULO_RSA_ENGINE_MAX_LENGTH_BITS = modRSAEngineMaxBits;
        MULT_RSA_ENGINE_MAX_LENGTH_BITS = multRSAEngineMaxBits;
        
        fnc_deep_resize_tmp = rm.helper_BN_array1;
        fnc_mult_resultArray1 = rm.helper_BN_array1;
        fnc_mult_resultArray2 = rm.helper_BN_array2;

        fnc_same_value_array1 = rm.helper_BN_array1;
        fnc_same_value_hash = rm.helper_BN_array2;
        
        fnc_shift_bytes_right_tmp = rm.helper_BN_array1;
        
        // BN below are just reassigned allocated helper_BN_? so that same helper_BN_? is not used in parallel (checked by lock() unlock())
        fnc_mod_add_tmp = rm.helper_BN_A;

        fnc_mod_sub_tmpThis = rm.helper_BN_A;
        fnc_mod_sub_tmp = rm.helper_BN_B;
        fnc_mod_sub_tmpOther = rm.helper_BN_C;

        fnc_mult_mod_tmpThis = rm.helper_BN_A;
        fnc_mult_mod_tmp_mod = rm.helper_BN_B;
        fnc_mult_mod_tmp_x = rm.helper_BN_C;

        fnc_exponentiation_tmp = rm.helper_BN_A;
        fnc_exponentiation_i = rm.helper_BN_B;

        fnc_mod_minus_2 = rm.helper_BN_B;

        fnc_gcd_tmp = rm.helper_BN_A;
        fnc_gcd_tmpOther = rm.helper_BN_B;

        fnc_is_coprime_tmp = rm.helper_BN_C; // is_coprime calls gcd internally

        fnc_negate_tmp = rm.helper_BN_B;

        fnc_sqrt_S = rm.helper_BN_A;
        fnc_sqrt_exp = rm.helper_BN_A;
        fnc_sqrt_p_1 = rm.helper_BN_B;
        fnc_sqrt_Q = rm.helper_BN_C;
        fnc_sqrt_tmp = rm.helper_BN_D;
        fnc_sqrt_z = rm.helper_BN_E;

        fnc_mod_mult_tmpThis = rm.helper_BN_E; // mod_mult is called from  fnc_sqrt => requires helper_BN_E not being locked in fnc_sqrt when mod_mult is called

        fnc_divide_tmpThis = rm.helper_BN_E; // divide is called from  fnc_sqrt => requires helper_BN_E not being locked  in fnc_sqrt when divide is called

        fnc_mod_exp_modBN = rm.helper_BN_F;  // mod_exp is called from  fnc_sqrt => requires helper_BN_F not being locked  in fnc_sqrt when mod_exp is called

        fnc_int_add_tmpMag = rm.helper_BN_A;
        fnc_int_multiply_mod = rm.helper_BN_A;
        fnc_int_multiply_tmpThis = rm.helper_BN_B;
        fnc_int_divide_tmpThis = rm.helper_BN_A;        
        
        
        // Allocate BN constants always in EEPROM (only reading)
        ONE = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        ONE.one();
        TWO = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        TWO.two();
        THREE = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
        THREE.three();

        tmp_array_short = rm.memAlloc.allocateByteArray((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET); // only 2b RAM for faster add(short)
        fnc_NmodE_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        fnc_NmodE_pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);

        // Speedup for fast multiplication
        fnc_mult_keypair = new KeyPair(KeyPair.ALG_RSA_CRT, MULT_RSA_ENGINE_MAX_LENGTH_BITS);
        fnc_mult_keypair.genKeyPair();
        fnc_mult_pubkey_pow2 = (RSAPublicKey) fnc_mult_keypair.getPublic();
        //mult_privkey_pow2 = (RSAPrivateCrtKey) mult_keypair.getPrivate();
        fnc_mult_pubkey_pow2.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
        fnc_mult_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        hashEngine = rm.hashEngine;

        FLAG_FAST_MULT_VIA_RSA = false; // set true only if succesfully allocated and tested below
        try { // Subsequent code may fail on some real (e.g., Infineon CJTOP80K) cards - catch exception
            fnc_mult_cipher.init(fnc_mult_pubkey_pow2, Cipher.MODE_ENCRYPT);
            // Try operation - if doesn't work, exception SW_CANTALLOCATE_BIGNAT is emitted
            Util.arrayFillNonAtomic(fnc_mult_resultArray1, (short) 0, (short) fnc_mult_resultArray1.length, (byte) 6);
            fnc_mult_cipher.doFinal(fnc_mult_resultArray1, (short) 0, (short) fnc_mult_resultArray1.length, fnc_mult_resultArray1, (short) 0);
            FLAG_FAST_MULT_VIA_RSA = true;
        } catch (Exception ignored) {
        } // discard exception                
    }    
    
    /**
     * Erase all values stored in helper objects
     */
    void erase() {
        rm.erase();
        Util.arrayFillNonAtomic(tmp_array_short, (short) 0, (short) tmp_array_short.length, (byte) 0);
    }
}
