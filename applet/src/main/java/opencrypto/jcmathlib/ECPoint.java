package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.*;

/**
 * @author Vasilios Mavroudis and Petr Svenda and Antonin Dufka
 */
public class ECPoint {
    private final ResourceManager rm;

    private ECPublicKey point;
    private KeyPair pointKeyPair;
    private final ECCurve curve;

    /**
     * Creates new ECPoint object for provided {@code curve}. Random initial point value is generated.
     * The point will use helper structures from provided ECPoint_Helper object.
     *
     * @param curve point's elliptic curve
     * @param rm resource manager with prealocated objects and memory arrays
     */
    public ECPoint(ECCurve curve, ResourceManager rm) {
        this.curve = curve;
        this.rm = rm;
        updatePointObjects();
    }

    /**
     * Returns length of this point in bytes.
     *
     * @return length of this point in bytes
     */
    public short length() {
        return (short) (point.getSize() / 8);
    }

    /**
     * Properly updates all point values in case of a change of an underlying curve.
     * New random point value is generated.
     */
    public final void updatePointObjects() {
        pointKeyPair = curve.newKeyPair(pointKeyPair);
        point = (ECPublicKey) pointKeyPair.getPublic();
    }

    /**
     * Generates new random point value.
     */
    public void randomize() {
        if (pointKeyPair == null) {
            pointKeyPair = curve.newKeyPair(null);
            point = (ECPublicKey) pointKeyPair.getPublic();
        } else {
            pointKeyPair.genKeyPair();
        }
    }

    /**
     * Copy value of provided point into this. This and other point must have
     * curve with same parameters, only length is checked.
     *
     * @param other point to be copied
     */
    public void copy(ECPoint other) {
        if (length() != other.length()) {
            ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
        }
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        short len = other.getW(pointBuffer, (short) 0);
        setW(pointBuffer, (short) 0, len);
        rm.unlock(pointBuffer);
    }

    /**
     * Set this point value (parameter W) from array with value encoded as per ANSI X9.62.
     * The uncompressed form is always supported. If underlying native JavaCard implementation
     * of {@code ECPublicKey} supports compressed points, then this method accepts also compressed points.
     *
     * @param buffer array with serialized point
     * @param offset start offset within input array
     * @param length length of point
     */
    public void setW(byte[] buffer, short offset, short length) {
        point.setW(buffer, offset, length);
    }

    /**
     * Returns current value of this point.
     *
     * @param buffer memory array where to store serailized point value
     * @param offset start offset for output serialized point
     * @return length of serialized point (number of bytes)
     */
    public short getW(byte[] buffer, short offset) {
        return point.getW(buffer, offset);
    }

    /**
     * Returns this point value as ECPublicKey object. No copy of point is made
     * before return, so change of returned object will also change this point value.
     *
     * @return point as ECPublicKey object
     */
    public ECPublicKey asPublicKey() {
        return point;
    }

    /**
     * Returns curve associated with this point. No copy of curve is made
     * before return, so change of returned object will also change curve for
     * this point.
     *
     * @return curve as ECCurve object
     */
    public ECCurve getCurve() {
        return curve;
    }

    /**
     * Returns the X coordinate of this point in uncompressed form.
     *
     * @param buffer output array for X coordinate
     * @param offset start offset within output array
     * @return length of X coordinate (in bytes)
     */
    public short getX(byte[] buffer, short offset) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        point.getW(pointBuffer, (short) 0);
        Util.arrayCopyNonAtomic(pointBuffer, (short) 1, buffer, offset, curve.COORD_SIZE);
        rm.unlock(pointBuffer);
        return curve.COORD_SIZE;
    }

    /**
     * Returns the Y coordinate of this point in uncompressed form.
     *
     * @param buffer output array for Y coordinate
     * @param offset start offset within output array
     * @return length of Y coordinate (in bytes)
     */
    public short getY(byte[] buffer, short offset) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        point.getW(pointBuffer, (short) 0);
        Util.arrayCopyNonAtomic(pointBuffer, (short) (1 + curve.COORD_SIZE), buffer, offset, curve.COORD_SIZE);
        rm.unlock(pointBuffer);
        return curve.COORD_SIZE;
    }

    /**
     * Returns the Y coordinate of this point in form of BigNat object.
     *
     * @param yCopy BigNat object which will be set with value of this point
     */
    public void getY(BigNat yCopy) {
        yCopy.set_size(getY(yCopy.as_byte_array(), (short) 0));
    }

    /**
     * Double this point. Pure implementation without KeyAgreement.
     */
    public void swDouble() {
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        BigNat pX = rm.EC_BN_B;
        BigNat pY = rm.EC_BN_C;
        BigNat lambda = rm.EC_BN_D;
        BigNat tmp = rm.EC_BN_E;

        rm.lock(pointBuffer);
        getW(pointBuffer, (short) 0);

        pX.lock();
        pX.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) 1);

        pY.lock();
        pY.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) (1 + curve.COORD_SIZE));

        lambda.lock();
        lambda.mod_mult(pX, pX, curve.pBN);
        lambda.mod_mult(lambda, ResourceManager.THREE, curve.pBN);
        lambda.mod_add(curve.aBN, curve.pBN);

        tmp.lock();
        tmp.clone(pY);
        tmp.mod_add(tmp, curve.pBN);
        tmp.mod_inv(curve.pBN);
        lambda.mod_mult(lambda, tmp, curve.pBN);
        tmp.mod_mult(lambda, lambda, curve.pBN);
        tmp.mod_sub(pX, curve.pBN);
        tmp.mod_sub(pX, curve.pBN);
        tmp.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) 1);

        tmp.mod_sub(pX, curve.pBN);
        pX.unlock();
        tmp.mod_mult(tmp, lambda, curve.pBN);
        lambda.unlock();
        tmp.mod_add(pY, curve.pBN);
        tmp.mod_negate(curve.pBN);
        pY.unlock();
        tmp.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        tmp.unlock();

        setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
    }


    /**
     * Doubles the current value of this point.
     */
    public void makeDouble() {
        // doubling via add sometimes causes exception inside KeyAgreement engine
        // this.add(this);
        // Use bit slower, but more robust version via multiplication by 2
        this.multiplication(ResourceManager.TWO);
    }

    /**
     * Adds this (P) and provided (Q) point. Stores a resulting value into this point.
     *
     * @param other point to be added to this.
     */
    public void add(ECPoint other) {
        boolean samePoint = this == other || isEqual(other);
        if (samePoint && OperationSupport.getInstance().EC_HW_XY) {
            multiplication(ResourceManager.TWO);
            return;
        }

        byte[] pointBuffer = rm.POINT_ARRAY_A;
        BigNat xR = rm.EC_BN_B;
        BigNat yR = rm.EC_BN_C;
        BigNat xP = rm.EC_BN_D;
        BigNat yP = rm.EC_BN_E;
        BigNat xQ = rm.EC_BN_F;
        BigNat nominator = rm.EC_BN_B;
        BigNat denominator = rm.EC_BN_C;
        BigNat lambda = rm.EC_BN_A;

        rm.lock(pointBuffer);
        point.getW(pointBuffer, (short) 0);
        xP.lock();
        xP.set_size(curve.COORD_SIZE);
        xP.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) 1);
        yP.lock();
        yP.set_size(curve.COORD_SIZE);
        yP.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) (1 + curve.COORD_SIZE));
        rm.unlock(pointBuffer);


        // l = (y_q-y_p)/(x_q-x_p))
        // x_r = l^2 - x_p -x_q
        // y_r = l(x_p-x_r)-y_p

        // P + Q = R
        nominator.lock();
        denominator.lock();
        if (samePoint) {
            // lambda = (3(x_p^2)+a)/(2y_p)
            // (3(x_p^2)+a)
            nominator.clone(xP);
            nominator.mod_exp(ResourceManager.TWO, curve.pBN);
            nominator.mod_mult(nominator, ResourceManager.THREE, curve.pBN);
            nominator.mod_add(curve.aBN, curve.pBN);
            // (2y_p)
            denominator.clone(yP);
            denominator.mod_mult(yP, ResourceManager.TWO, curve.pBN);
            denominator.mod_inv(curve.pBN);

        } else {
            // lambda = (y_q-y_p) / (x_q-x_p) mod p
            rm.lock(pointBuffer);
            other.point.getW(pointBuffer, (short) 0);
            xQ.lock();
            xQ.set_size(curve.COORD_SIZE);
            xQ.from_byte_array(other.curve.COORD_SIZE, (short) 0, pointBuffer, (short) 1);
            nominator.set_size(curve.COORD_SIZE);
            nominator.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) (1 + curve.COORD_SIZE));
            rm.unlock(pointBuffer);

            nominator.mod(curve.pBN);

            nominator.mod_sub(yP, curve.pBN);

            // (x_q-x_p)
            denominator.clone(xQ);
            denominator.mod(curve.pBN);
            denominator.mod_sub(xP, curve.pBN);
            denominator.mod_inv(curve.pBN);
        }

        lambda.lock();
        lambda.resize_to_max(false);
        lambda.zero();
        lambda.mod_mult(nominator, denominator, curve.pBN);
        nominator.unlock();
        denominator.unlock();

        // (x_p, y_p) + (x_q, y_q) = (x_r, y_r)
        // lambda = (y_q - y_p) / (x_q - x_p)

        // x_r = lambda^2 - x_p - x_q
        xR.lock();
        if (samePoint) {
            short len = multXKA(ResourceManager.TWO, xR.as_byte_array(), (short) 0);
            xR.set_size(len);
        } else {
            xR.clone(lambda);
            xR.mod_exp2(curve.pBN);
            xR.mod_sub(xP, curve.pBN);
            xR.mod_sub(xQ, curve.pBN);
        }
        xQ.unlock();

        // y_r = lambda(x_p - x_r) - y_p
        yR.lock();
        yR.clone(xP);
        xP.unlock();
        yR.mod_sub(xR, curve.pBN);
        yR.mod_mult(yR, lambda, curve.pBN);
        lambda.unlock();
        yR.mod_sub(yP, curve.pBN);
        yP.unlock();

        rm.lock(pointBuffer);
        pointBuffer[0] = (byte) 0x04;
        // If x_r.length() and y_r.length() is smaller than curve.COORD_SIZE due to leading zeroes which were shrunk before, then we must add these back
        xR.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        xR.unlock();
        yR.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        yR.unlock();
        setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
    }

    /**
     * Multiply value of this point by provided scalar. Stores the result into
     * this point.
     *
     * @param scalarBytes value of scalar for multiplication
     */
    public void multiplication(byte[] scalarBytes, short scalarOffset, short scalarLen) {
        BigNat scalar = rm.EC_BN_F;

        scalar.lock();
        scalar.set_size(scalarLen);
        scalar.from_byte_array(scalarLen, (short) 0, scalarBytes, scalarOffset);
        multiplication(scalar);
        scalar.unlock();
    }

    /**
     * Multiply value of this point by provided scalar. Stores the result into this point.
     *
     * @param scalar value of scalar for multiplication
     */
    public void multiplication(BigNat scalar) {
        if (OperationSupport.getInstance().EC_SW_DOUBLE && scalar.same_value(ResourceManager.TWO)) {
            swDouble();
        // } else if (rm.ecMultKA.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY) {
        } else if (rm.ecMultKA.getAlgorithm() == (byte) 6) {
            multXY(scalar);
        } else if (rm.ecMultKA.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN) {
            multX(scalar);
        } else {
            ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);
        }
    }

    public void multAndAdd(BigNat scalar, ECPoint point) {
        byte[] pointBuffer = rm.POINT_ARRAY_B;

        rm.lock(pointBuffer);
        setW(pointBuffer, (short) 0, multAndAddKA(scalar, point, pointBuffer, (short) 0));
        rm.unlock(pointBuffer);
    }

    public short multAndAddKA(BigNat scalar, ECPoint point, byte[] outBuffer, short outBufferOffset) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        short len = this.getW(pointBuffer, (short) 0);
        curve.disposable_priv.setG(pointBuffer, (short) 0, len);
        curve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());
        rm.ecAddKA.init(curve.disposable_priv);

        len = point.getW(pointBuffer, (short) 0);
        len = rm.ecAddKA.generateSecret(pointBuffer, (short) 0, len, outBuffer, outBufferOffset);
        rm.unlock(pointBuffer);
        return len;
    }

    /**
     * Multiply value of this point by provided scalar using XY key agreement. Stores the result into this point.
     *
     * @param scalar value of scalar for multiplication
     */
    public void multXY(BigNat scalar) {
        byte[] pointBuffer = rm.POINT_ARRAY_B;

        rm.lock(pointBuffer);
        short len = multXYKA(scalar, pointBuffer, (short) 0);
        setW(pointBuffer, (short) 0, len);
        rm.unlock(pointBuffer);
    }

    /**
     * Multiplies this point value with provided scalar and stores result into
     * provided array. No modification of this point is performed.
     * Native XY KeyAgreement engine is used.
     *
     * @param scalar          value of scalar for multiplication
     * @param outBuffer       output array for resulting value
     * @param outBufferOffset offset within output array
     * @return length of resulting value (in bytes)
     */
    public short multXYKA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        curve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());
        rm.ecMultKA.init(curve.disposable_priv);

        rm.lock(pointBuffer);
        short len = getW(pointBuffer, (short) 0);
        len = rm.ecMultKA.generateSecret(pointBuffer, (short) 0, len, outBuffer, outBufferOffset);
        rm.unlock(pointBuffer);
        return len;
    }

    /**
     * Multiply value of this point by provided scalar using X-only key agreement. Stores the result into this point.
     *
     * @param scalar value of scalar for multiplication
     */
    private void multX(BigNat scalar) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        byte[] resultBuffer = rm.ARRAY_A;
        BigNat x = rm.EC_BN_B;
        BigNat ySq = rm.EC_BN_C;
        BigNat y1 = rm.EC_BN_D;
        BigNat y2 = rm.EC_BN_B;

        x.lock();
        short len = multXKA(scalar, x.as_byte_array(), (short) 0);
        x.set_size(len);

        //Y^2 = X^3 + XA + B = x(x^2+A)+B
        ySq.lock();
        ySq.clone(x);
        ySq.mod_exp(ResourceManager.TWO, curve.pBN);
        ySq.mod_add(curve.aBN, curve.pBN);
        ySq.mod_mult(ySq, x, curve.pBN);
        ySq.mod_add(curve.bBN, curve.pBN);
        y1.lock();
        y1.clone(ySq);
        ySq.unlock();
        y1.sqrt_FP(curve.pBN);

        // Construct public key with <x, y_1>
        rm.lock(pointBuffer);
        pointBuffer[0] = 0x04;
        x.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        x.unlock();
        y1.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        setW(pointBuffer, (short) 0, curve.POINT_SIZE); //So that we can convert to pub key

        // Check if public point <x, y_1> corresponds to the "secret" (i.e., our scalar)
        rm.lock(resultBuffer);
        if (!SignVerifyECDSA(curve.bignatAsPrivateKey(scalar), asPublicKey(), rm.verifyEcdsa, resultBuffer)) { // If verification fails, then pick the <x, y_2>
            y2.lock();
            y2.clone(curve.pBN); // y_2 = p - y_1
            y2.mod_sub(y1, curve.pBN);
            y2.copy_to_buffer(pointBuffer, (short) (1 + curve.COORD_SIZE));
            y2.unlock();
        }
        rm.unlock(resultBuffer);
        y1.unlock();


        setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
    }

    /**
     * Multiplies this point value with provided scalar and stores result into
     * provided array. No modification of this point is performed.
     * Native X-only KeyAgreement engine is used.
     *
     * @param scalar          value of scalar for multiplication
     * @param outBuffer       output array for resulting value
     * @param outBufferOffset offset within output array
     * @return length of resulting value (in bytes)
     */
    private short multXKA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        // NOTE: potential problem on real cards (j2e) - when small scalar is used (e.g., BigNat.TWO), operation sometimes freezes
        curve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());

        rm.ecMultKA.init(curve.disposable_priv);

        rm.lock(pointBuffer);
        short len = getW(pointBuffer, (short) 0);
        len = rm.ecMultKA.generateSecret(pointBuffer, (short) 0, len, outBuffer, outBufferOffset);
        rm.unlock(pointBuffer);
        // Return always length of whole coordinate X instead of len - some real cards returns shorter value equal to SHA-1 output size although PLAIN results is filled into buffer (GD60) 
        return curve.COORD_SIZE;
    }

    /**
     * Computes negation of this point.
     * The operation will dump point into uncompressed_point_arr, negate Y and restore back
     */
    public void negate() {
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        BigNat y = rm.EC_BN_C;

        y.lock();
        rm.lock(pointBuffer);
        point.getW(pointBuffer, (short) 0);
        y.set_size(curve.COORD_SIZE);
        y.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) (1 + curve.COORD_SIZE));
        y.mod_negate(curve.pBN);
        y.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        y.unlock();
        setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
    }

    /**
     * Restore point from X coordinate. Stores one of the two results into this point.
     *
     * @param xCoord  byte array containing the X coordinate
     * @param xOffset offset in the byte array
     * @param xLen    length of the X coordinate
     */
    public void fromX(byte[] xCoord, short xOffset, short xLen) {
        BigNat x = rm.EC_BN_F;

        x.lock();
        x.set_size(xLen);
        x.from_byte_array(xLen, (short) 0, xCoord, xOffset);
        fromX(x);
        x.unlock();
    }

    /**
     * Restore point from X coordinate. Stores one of the two results into this point.
     *
     * @param x the x coordinate
     */
    private void fromX(BigNat x) {
        BigNat y_sq = rm.EC_BN_C;
        BigNat y = rm.EC_BN_D;
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        //Y^2 = X^3 + XA + B = x(x^2+A)+B
        y_sq.lock();
        y_sq.clone(x);
        y_sq.mod_exp(ResourceManager.TWO, curve.pBN);
        y_sq.mod_add(curve.aBN, curve.pBN);
        y_sq.mod_mult(y_sq, x, curve.pBN);
        y_sq.mod_add(curve.bBN, curve.pBN);
        y.lock();
        y.clone(y_sq);
        y_sq.unlock();
        y.sqrt_FP(curve.pBN);

        // Construct public key with <x, y_1>
        rm.lock(pointBuffer);
        pointBuffer[0] = 0x04;
        x.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        y.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        y.unlock();
        setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
    }

    /**
     * Returns true if Y coordinate is even; false otherwise.
     *
     * @return true if Y coordinate is even; false otherwise
     */
    public boolean isYEven() {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        point.getW(pointBuffer, (short) 0);
        boolean result = pointBuffer[(short) (curve.POINT_SIZE - 1)] % 2 == 0;
        rm.unlock(pointBuffer);
        return result;
    }

    /**
     * Compares this and provided point for equality. The comparison is made using hash of both values to prevent leak of position of mismatching byte.
     *
     * @param other second point for comparison
     * @return true if both point are exactly equal (same length, same value), false otherwise
     */
    public boolean isEqual(ECPoint other) {
        if (length() != other.length()) {
            return false;
        }
        // The comparison is made with hash of point values instead of directly values.
        // This way, offset of first mismatching byte is not leaked via timing side-channel.
        // Additionally, only single array is required for storage of plain point values thus saving some RAM.
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        byte[] hashBuffer = rm.HASH_ARRAY;

        rm.lock(pointBuffer);
        rm.lock(hashBuffer);
        short len = getW(pointBuffer, (short) 0);
        rm.hashEngine.doFinal(pointBuffer, (short) 0, len, hashBuffer, (short) 0);
        len = other.getW(pointBuffer, (short) 0);
        len = rm.hashEngine.doFinal(pointBuffer, (short) 0, len, pointBuffer, (short) 0);
        boolean bResult = Util.arrayCompare(hashBuffer, (short) 0, pointBuffer, (short) 0, len) == 0;
        rm.unlock(hashBuffer);
        rm.unlock(pointBuffer);

        return bResult;
    }

    static byte[] msg = {(byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x03};

    public static boolean SignVerifyECDSA(ECPrivateKey privateKey, ECPublicKey publicKey, Signature signEngine, byte[] tmpSignArray) {
        signEngine.init(privateKey, Signature.MODE_SIGN);
        short signLen = signEngine.sign(msg, (short) 0, (short) msg.length, tmpSignArray, (short) 0);
        signEngine.init(publicKey, Signature.MODE_VERIFY);
        return signEngine.verify(msg, (short) 0, (short) msg.length, tmpSignArray, (short) 0, signLen);
    }


    //
    // ECKey methods
    //
    public void setFieldFP(byte[] bytes, short s, short s1) throws CryptoException {
        point.setFieldFP(bytes, s, s1);
    }

    public void setFieldF2M(short s) throws CryptoException {
        point.setFieldF2M(s);
    }

    public void setFieldF2M(short s, short s1, short s2) throws CryptoException {
        point.setFieldF2M(s, s1, s2);
    }

    public void setA(byte[] bytes, short s, short s1) throws CryptoException {
        point.setA(bytes, s, s1);
    }

    public void setB(byte[] bytes, short s, short s1) throws CryptoException {
        point.setB(bytes, s, s1);
    }

    public void setG(byte[] bytes, short s, short s1) throws CryptoException {
        point.setG(bytes, s, s1);
    }

    public void setR(byte[] bytes, short s, short s1) throws CryptoException {
        point.setR(bytes, s, s1);
    }

    public void setK(short s) {
        point.setK(s);
    }

    public short getField(byte[] bytes, short s) throws CryptoException {
        return point.getField(bytes, s);
    }

    public short getA(byte[] bytes, short s) throws CryptoException {
        return point.getA(bytes, s);
    }

    public short getB(byte[] bytes, short s) throws CryptoException {
        return point.getB(bytes, s);
    }

    public short getG(byte[] bytes, short s) throws CryptoException {
        return point.getG(bytes, s);
    }

    public short getR(byte[] bytes, short s) throws CryptoException {
        return point.getR(bytes, s);
    }

    public short getK() throws CryptoException {
        return point.getK();
    }
}
