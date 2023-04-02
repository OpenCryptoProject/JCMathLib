package opencrypto.jcmathlib;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * 
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECCurve {
    public final short KEY_BIT_LENGTH, POINT_SIZE, COORD_SIZE;

    //Parameters
    public byte[] p, a, b, G, r;
    public BigNat pBN, aBN, bBN, rBN;

    public KeyPair disposablePair;
    public ECPrivateKey disposablePriv;
    public ECPublicKey disposablePub;

    

    /**
     * Creates new curve object from provided parameters. Either copy of provided
     * arrays is performed (copyArgs == true, input arrays can be reused later for other
     * purposes) or arguments are directly stored (copyArgs == false, usable for fixed static arrays) .
     * @param copyArgs if true, copy of arguments is created, otherwise reference is directly stored
     * @param p array with p
     * @param a array with a
     * @param b array with b
     * @param G array with base point G
     * @param r array with r
     */
    public ECCurve(boolean copyArgs, byte[] p, byte[] a, byte[] b, byte[] G, byte[] r) {
        KEY_BIT_LENGTH = (short) (p.length * 8);
        POINT_SIZE = (short) G.length;
        COORD_SIZE = (short) ((short) (G.length - 1) / 2);

        if (copyArgs) {
            // Copy curve parameters into newly allocated arrays in EEPROM (will be only read, not written later => good performance even when in EEPROM)
            this.p = new byte[(short) p.length];
            this.a = new byte[(short) a.length];
            this.b = new byte[(short) b.length];
            this.G = new byte[(short) G.length];
            this.r = new byte[(short) r.length];

            Util.arrayCopyNonAtomic(p, (short) 0, this.p, (short) 0, (short) this.p.length);
            Util.arrayCopyNonAtomic(a, (short) 0, this.a, (short) 0, (short) this.a.length);
            Util.arrayCopyNonAtomic(b, (short) 0, this.b, (short) 0, (short) this.b.length);
            Util.arrayCopyNonAtomic(G, (short) 0, this.G, (short) 0, (short) this.G.length);
            Util.arrayCopyNonAtomic(r, (short) 0, this.r, (short) 0, (short) this.r.length);
        }
        else {
            // No allocation, store directly provided arrays 
            this.p = p;
            this.a = a;
            this.b = b;
            this.G = G;
            this.r = r;
        }

        // We will not modify values of p/a/b/r during the lifetime of curve => allocate helper BigNats directly from the array
        // Additionally, these BigNats will be only read from so ResourceManager can be null (saving need to pass as argument to ECCurve)
        pBN = new BigNat(this.p, null);
        aBN = new BigNat(this.a, null);
        bBN = new BigNat(this.b, null);
        rBN = new BigNat(this.r, null);

        disposablePair = newKeyPair(null);
        disposablePriv = (ECPrivateKey) disposablePair.getPrivate();
        disposablePub = (ECPublicKey) disposablePair.getPublic();
    }    
    
    /**
     * Refresh critical information stored in RAM for performance reasons after a card reset (RAM was cleared).
     */
    public void updateAfterReset() {
        pBN.fromByteArray(p, (short) 0, (short) p.length);
        aBN.fromByteArray(a, (short) 0, (short) a.length);
        bBN.fromByteArray(b, (short) 0, (short) b.length);
        rBN.fromByteArray(r, (short) 0, (short) r.length);
    }
    
    /**
     * Creates a new keyPair based on this curve parameters. KeyPair object is reused if provided. Fresh keyPair value is generated.
     * @param existingKeyPair existing KeyPair object which is reused if required. If null, new KeyPair is allocated
     * @return new or existing object with fresh key pair value
     */
    KeyPair newKeyPair(KeyPair existingKeyPair) {
        ECPrivateKey privKey;
        ECPublicKey pubKey;
        if (existingKeyPair == null) { // Allocate if not supplied
            existingKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KEY_BIT_LENGTH);
        }
        
        // Some implementation will not return valid pub key until ecKeyPair.genKeyPair() is called
        // Other implementation will fail with exception if same is called => try catch and drop any exception 
        try {
            pubKey = (ECPublicKey) existingKeyPair.getPublic();
            if (pubKey == null) {
                existingKeyPair.genKeyPair();
            }
        } catch (Exception e) {
        } // intentionally do nothing
        
        privKey = (ECPrivateKey) existingKeyPair.getPrivate();
        pubKey = (ECPublicKey) existingKeyPair.getPublic();

        // Set required values
        privKey.setFieldFP(p, (short) 0, (short) p.length);
        privKey.setA(a, (short) 0, (short) a.length);
        privKey.setB(b, (short) 0, (short) b.length);
        privKey.setG(G, (short) 0, (short) G.length);
        privKey.setR(r, (short) 0, (short) r.length);
        privKey.setK((short) 1);

        pubKey.setFieldFP(p, (short) 0, (short) p.length);
        pubKey.setA(a, (short) 0, (short) a.length);
        pubKey.setB(b, (short) 0, (short) b.length);
        pubKey.setG(G, (short) 0, (short) G.length);
        pubKey.setR(r, (short) 0, (short) r.length);
        pubKey.setK((short) 1);

        existingKeyPair.genKeyPair();

        return existingKeyPair;
    }
}
