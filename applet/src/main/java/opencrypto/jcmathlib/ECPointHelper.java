package opencrypto.jcmathlib;

import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * @author Petr Svenda
 */
public class ECPointHelper extends BaseHelper {
    byte[] uncompressed_point_arr1;
    byte[] uncompressed_point_arr2;
    byte[] fnc_isEqual_hashArray;
    byte[] fnc_multiplication_resultArray;

    BigNat fnc_add_x_r; // frequent write
    BigNat fnc_add_y_r; // frequent write
    BigNat fnc_add_x_p; // one init, then just read
    BigNat fnc_add_y_p; // one init, then just read
    BigNat fnc_add_x_q; // one init, then just read
    BigNat fnc_add_lambda; // write mod_mul (but only final result)
    BigNat fnc_add_nominator; // frequent write
    BigNat fnc_add_denominator; // frequent write

    BigNat fnc_multiplication_x; // result write
    BigNat fnc_multiplication_y_sq; // frequent write
    BigNat fnc_multiplication_scalar; // write once, read
    BigNat fnc_multiplication_y1; // mostly just read, write inside sqrt_FP
    BigNat fnc_multiplication_y2; // mostly just read, result write
    BigNat fnc_negate_yBN; // mostly just read, result write

    BigNat fnc_from_x_x;
    BigNat fnc_from_x_y_sq;
    BigNat fnc_from_x_y;

    BigNat fnc_is_y;

    KeyAgreement multKA;
    Signature verifyEcdsa;
    MessageDigest hash;

    public ECPointHelper(ResourceManager rm) {
        super(rm);

        if (OperationSupport.getInstance().EC_HW_XY) {
            multKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        } else if (OperationSupport.getInstance().EC_HW_X) {
            multKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        }
        verifyEcdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
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

        fnc_is_y = rm.helperEC_BN_C;

        fnc_isEqual_hashArray = rm.helper_hashArray;
        hash = rm.hashEngine;

        uncompressed_point_arr1 = rm.helper_uncompressed_point_arr1;
        uncompressed_point_arr2 = rm.helper_uncompressed_point_arr2;
    }
}
