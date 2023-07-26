package opencrypto.jcmathlib;

import javacard.framework.JCSystem;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECCurve {
    public final short KEY_BIT_LENGTH, POINT_SIZE, COORD_SIZE;
    public ResourceManager rm;

    public byte[] p, a, b, G, r;
    public short k;
    public BigNat pBN, aBN, bBN, rBN;


    public KeyPair disposablePair;
    public ECPrivateKey disposablePriv;
    public ECPublicKey disposablePub;

    /**
     * Creates new curve object from provided parameters. Parameters are not copied, the
     * arrays must not be changed.
     *
     * @param p array with p
     * @param a array with a
     * @param b array with b
     * @param G array with base point G
     * @param r array with r
     */
    public ECCurve(byte[] p, byte[] a, byte[] b, byte[] G, byte[] r, short k, ResourceManager rm) {
        KEY_BIT_LENGTH = (short) (p.length * 8);
        POINT_SIZE = (short) G.length;
        COORD_SIZE = (short) ((short) (G.length - 1) / 2);

        this.p = p;
        this.a = a;
        this.b = b;
        this.G = G;
        this.r = r;
        this.k = k;
        this.rm = rm;

        pBN = new BigNat(COORD_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        pBN.fromByteArray(p, (short) 0, (short) p.length);
        aBN = new BigNat(COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        aBN.fromByteArray(a, (short) 0, (short) a.length);
        bBN = new BigNat(COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        bBN.fromByteArray(b, (short) 0, (short) b.length);
        rBN = new BigNat(COORD_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        rBN.fromByteArray(r, (short) 0, (short) r.length);

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
     * @param keyPair existing KeyPair object which is reused if required. If null, new KeyPair is allocated
     * @return new or existing object with fresh key pair value
     */
    KeyPair newKeyPair(KeyPair keyPair) {
        ECPublicKey pubKey;
        ECPrivateKey privKey;
        if (keyPair == null) {
            pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KEY_BIT_LENGTH, false);
            privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_BIT_LENGTH, false);
            keyPair = new KeyPair(pubKey, privKey);
        } else {
            pubKey = (ECPublicKey) keyPair.getPublic();
            privKey = (ECPrivateKey) keyPair.getPrivate();
        }

        privKey.setFieldFP(p, (short) 0, (short) p.length);
        privKey.setA(a, (short) 0, (short) a.length);
        privKey.setB(b, (short) 0, (short) b.length);
        privKey.setG(G, (short) 0, (short) G.length);
        privKey.setR(r, (short) 0, (short) r.length);
        privKey.setK(k);

        pubKey.setFieldFP(p, (short) 0, (short) p.length);
        pubKey.setA(a, (short) 0, (short) a.length);
        pubKey.setB(b, (short) 0, (short) b.length);
        pubKey.setG(G, (short) 0, (short) G.length);
        pubKey.setR(r, (short) 0, (short) r.length);
        pubKey.setK(k);

        keyPair.genKeyPair();

        return keyPair;
    }
}
