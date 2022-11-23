package opencrypto.jcmathlib;

import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * @author Petr Svenda
 */
public class ECPointHelper extends BaseHelper {
    KeyAgreement multKA;
    Signature verifyEcdsa;

    public ECPointHelper(ResourceManager rm) {
        super(rm);

        if (OperationSupport.getInstance().EC_HW_XY) {
            multKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        } else if (OperationSupport.getInstance().EC_HW_X) {
            multKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        }
        verifyEcdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    }
}
