package opencrypto.jcmathlib;

import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 *
 * @author Petr Svenda
 */
public class ECPoint_Helper extends Base_Helper {
    // Selected constants missing from older JC API specs 
    public static final byte ALG_EC_SVDP_DH_PLAIN = (byte) 3;
    public static final byte ALG_EC_SVDP_DH_PLAIN_XY = (byte) 6;
    public static final byte ALG_ECDSA_SHA_256 = (byte) 33;

    byte[] uncompressed_point_arr1;
    byte[] uncompressed_point_arr2;
    byte[] fnc_isEqual_hashArray;
    byte[] fnc_multiplication_resultArray;

    // These Bignats are just pointing to some helperEC_BN_? so reasonable naming is preserved yet no need to actually allocated whole Bignat object
    Bignat fnc_add_x_r; // frequent write
    Bignat fnc_add_y_r; // frequent write
    Bignat fnc_add_x_p; // one init, then just read
    Bignat fnc_add_y_p; // one init, then just read
    Bignat fnc_add_x_q; // one init, then just read
    Bignat fnc_add_lambda; // write mod_mul (but only final result)
    Bignat fnc_add_nominator; // frequent write
    Bignat fnc_add_denominator; // frequent write

    Bignat fnc_multiplication_x; // result write
    Bignat fnc_multiplication_y_sq; // frequent write
    Bignat fnc_multiplication_scalar; // write once, read
    Bignat fnc_multiplication_y1; // mostly just read, write inside sqrt_FP
    Bignat fnc_multiplication_y2; // mostly just read, result write
    Bignat fnc_negate_yBN; // mostly just read, result write

    Bignat fnc_from_x_x;
    Bignat fnc_from_x_y_sq;
    Bignat fnc_from_x_y;

    Bignat fnc_is_y;

    KeyAgreement multKA;
    Signature    fnc_SignVerifyECDSA_signEngine; 
    MessageDigest fnc_isEqual_hashEngine;

    public ECPoint_Helper(ResourceManager rm) {
        super(rm);

        if(OperationSupport.getInstance().ECDH_XY) {
            multKA = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
        }
        else if(OperationSupport.getInstance().ECDH_X_ONLY) {
            multKA = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, false);
        }
        fnc_SignVerifyECDSA_signEngine = Signature.getInstance(ALG_ECDSA_SHA_256, false);
    }

    void initialize() {
        // Important: assignment of helper BNs is made according to two criteria:
        // 1. Correctness: same BN must not be assigned to overlapping operations (guarded by lock/unlock) 
        // 2. Memory tradeoff: we like to put as few BNs into RAM as possible. So most frequently used BNs for write should be in RAM
        //                      and at the same time we like to have as few BNs in RAM as possible. 
        // So think twice before changing the assignments!
        fnc_add_x_r = rm.helperEC_BN_B;
        fnc_add_y_r = rm.helperEC_BN_C;
        fnc_add_x_p = rm.helperEC_BN_D;
        fnc_add_y_p = rm.helperEC_BN_E;
        fnc_add_x_q = rm.helperEC_BN_F;
        fnc_add_nominator = rm.helperEC_BN_B;
        fnc_add_denominator = rm.helperEC_BN_C;
        fnc_add_lambda = rm.helperEC_BN_A;

        fnc_multiplication_scalar = rm.helperEC_BN_F;
        fnc_multiplication_x = rm.helperEC_BN_B;
        fnc_multiplication_y_sq = rm.helperEC_BN_C;
        fnc_multiplication_y1 = rm.helperEC_BN_D;
        fnc_multiplication_y2 = rm.helperEC_BN_B;
        fnc_multiplication_resultArray = rm.helper_BN_array1;

        fnc_negate_yBN = rm.helperEC_BN_C;

        Bignat fnc_from_x_x;
        Bignat fnc_from_x_y_sq;
        Bignat fnc_from_x_y;

        fnc_is_y = rm.helperEC_BN_C;

        fnc_isEqual_hashArray = rm.helper_hashArray;
        fnc_isEqual_hashEngine = rm.hashEngine;

        uncompressed_point_arr1 = rm.helper_uncompressed_point_arr1;
        uncompressed_point_arr2 = rm.helper_uncompressed_point_arr2;
    }
}
