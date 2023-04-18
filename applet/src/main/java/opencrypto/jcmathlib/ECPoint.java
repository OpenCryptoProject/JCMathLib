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
     *
     * @param curve point's elliptic curve
     */
    public ECPoint(ECCurve curve) {
        this.curve = curve;
        this.rm = curve.rm;
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
        pointKeyPair.genKeyPair();
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
        yCopy.setSize(getY(yCopy.asByteArray(), (short) 0));
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
        pX.fromByteArray(pointBuffer, (short) 1, curve.COORD_SIZE);

        pY.lock();
        pY.fromByteArray(pointBuffer, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);

        lambda.lock();
        lambda.clone(pX);
        lambda.modSq(curve.pBN);
        lambda.modMult(lambda, ResourceManager.THREE, curve.pBN);
        lambda.modAdd(curve.aBN, curve.pBN);

        tmp.lock();
        tmp.clone(pY);
        tmp.modAdd(tmp, curve.pBN);
        tmp.modInv(curve.pBN);
        lambda.modMult(lambda, tmp, curve.pBN);
        tmp.clone(lambda);
        tmp.modSq(curve.pBN);
        tmp.modSub(pX, curve.pBN);
        tmp.modSub(pX, curve.pBN);
        tmp.prependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);

        tmp.modSub(pX, curve.pBN);
        pX.unlock();
        tmp.modMult(tmp, lambda, curve.pBN);
        lambda.unlock();
        tmp.modAdd(pY, curve.pBN);
        tmp.modNegate(curve.pBN);
        pY.unlock();
        tmp.prependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
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
        if (OperationSupport.getInstance().EC_HW_ADD) {
            hwAdd(other);
        } else {
            swAdd(other);
        }
    }

    /**
     * Implements adding of two points without ALG_EC_PACE_GM.
     *
     * @param other point to be added to this.
     */
    private void swAdd(ECPoint other) {
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
        xP.setSize(curve.COORD_SIZE);
        xP.fromByteArray(pointBuffer, (short) 1, curve.COORD_SIZE);
        yP.lock();
        yP.setSize(curve.COORD_SIZE);
        yP.fromByteArray(pointBuffer, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);
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
            nominator.modSq(curve.pBN);
            nominator.modMult(nominator, ResourceManager.THREE, curve.pBN);
            nominator.modAdd(curve.aBN, curve.pBN);
            // (2y_p)
            denominator.clone(yP);
            denominator.modMult(yP, ResourceManager.TWO, curve.pBN);
            denominator.modInv(curve.pBN);

        } else {
            // lambda = (y_q-y_p) / (x_q-x_p) mod p
            rm.lock(pointBuffer);
            other.point.getW(pointBuffer, (short) 0);
            xQ.lock();
            xQ.setSize(curve.COORD_SIZE);
            xQ.fromByteArray(pointBuffer, (short) 1, other.curve.COORD_SIZE);
            nominator.setSize(curve.COORD_SIZE);
            nominator.fromByteArray(pointBuffer, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);
            rm.unlock(pointBuffer);

            nominator.mod(curve.pBN);

            nominator.modSub(yP, curve.pBN);

            // (x_q-x_p)
            denominator.clone(xQ);
            denominator.mod(curve.pBN);
            denominator.modSub(xP, curve.pBN);
            denominator.modInv(curve.pBN);
        }

        lambda.lock();
        lambda.resizeToMax(false);
        lambda.zero();
        lambda.modMult(nominator, denominator, curve.pBN);
        nominator.unlock();
        denominator.unlock();

        // (x_p, y_p) + (x_q, y_q) = (x_r, y_r)
        // lambda = (y_q - y_p) / (x_q - x_p)

        // x_r = lambda^2 - x_p - x_q
        xR.lock();
        if (samePoint) {
            short len = multXKA(ResourceManager.TWO, xR.asByteArray(), (short) 0);
            xR.setSize(len);
        } else {
            xR.clone(lambda);
            xR.modSq(curve.pBN);
            xR.modSub(xP, curve.pBN);
            xR.modSub(xQ, curve.pBN);
        }
        xQ.unlock();

        // y_r = lambda(x_p - x_r) - y_p
        yR.lock();
        yR.clone(xP);
        xP.unlock();
        yR.modSub(xR, curve.pBN);
        yR.modMult(yR, lambda, curve.pBN);
        lambda.unlock();
        yR.modSub(yP, curve.pBN);
        yP.unlock();

        rm.lock(pointBuffer);
        pointBuffer[0] = (byte) 0x04;
        // If x_r.length() and y_r.length() is smaller than curve.COORD_SIZE due to leading zeroes which were shrunk before, then we must add these back
        xR.prependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        xR.unlock();
        yR.prependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        yR.unlock();
        setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
    }

    /**
     * Implements adding of two points via ALG_EC_PACE_GM.
     *
     * @param other point to be added to this.
     */
    private void hwAdd(ECPoint other) {
        byte[] pointBuffer = rm.POINT_ARRAY_B;

        rm.lock(pointBuffer);
        setW(pointBuffer, (short) 0, multAndAddKA(ResourceManager.ONE_COORD, other, pointBuffer, (short) 0));
        rm.unlock(pointBuffer);
    }

    /**
     * Multiply value of this point by provided scalar. Stores the result into this point.
     *
     * @param scalarBytes value of scalar for multiplication
     */
    public void multiplication(byte[] scalarBytes, short scalarOffset, short scalarLen) {
        BigNat scalar = rm.EC_BN_F;

        scalar.lock();
        scalar.setSize(scalarLen);
        scalar.fromByteArray(scalarBytes, scalarOffset, scalarLen);
        multiplication(scalar);
        scalar.unlock();
    }

    /**
     * Multiply value of this point by provided scalar. Stores the result into this point.
     *
     * @param scalar value of scalar for multiplication
     */
    public void multiplication(BigNat scalar) {
        if (OperationSupport.getInstance().EC_SW_DOUBLE && scalar.equals(ResourceManager.TWO)) {
            swDouble();
        // } else if (rm.ecMultKA.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY) {
        } else if (rm.ecMultKA.getAlgorithm() == (byte) 6) {
            multXY(scalar);
        //} else if (rm.ecMultKA.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN) {
        } else if (rm.ecMultKA.getAlgorithm() == (byte) 3) {
            multX(scalar);
        } else {
            ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);
        }
    }

    /**
     * Multiply this point by a given scalar and add another point to the result.
     *
     * @param scalar value of scalar for multiplication
     * @param point the other point
     */
    public void multAndAdd(BigNat scalar, ECPoint point) {
        if (OperationSupport.getInstance().EC_HW_ADD) {
            byte[] pointBuffer = rm.POINT_ARRAY_B;

            rm.lock(pointBuffer);
            setW(pointBuffer, (short) 0, multAndAddKA(scalar, point, pointBuffer, (short) 0));
            rm.unlock(pointBuffer);
        } else {
            multiplication(scalar);
            add(point);
        }
    }

    /**
     * Multiply this point by a given scalar and add another point to the result and store the result into outBuffer.
     *
     * @param scalar value of scalar for multiplication
     * @param point the other point
     * @param outBuffer output buffer
     * @param outBufferOffset offset in the output buffer
     */
    private short multAndAddKA(BigNat scalar, ECPoint point, byte[] outBuffer, short outBufferOffset) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        short len = this.getW(pointBuffer, (short) 0);
        curve.disposablePriv.setG(pointBuffer, (short) 0, len);
        curve.disposablePriv.setS(scalar.asByteArray(), (short) 0, scalar.length());
        rm.ecAddKA.init(curve.disposablePriv);

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

        curve.disposablePriv.setS(scalar.asByteArray(), (short) 0, scalar.length());
        rm.ecMultKA.init(curve.disposablePriv);

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
        short len = multXKA(scalar, x.asByteArray(), (short) 0);
        x.setSize(len);

        //Y^2 = X^3 + XA + B = x(x^2+A)+B
        ySq.lock();
        ySq.clone(x);
        ySq.modExp(ResourceManager.TWO, curve.pBN);
        ySq.modAdd(curve.aBN, curve.pBN);
        ySq.modMult(ySq, x, curve.pBN);
        ySq.modAdd(curve.bBN, curve.pBN);
        y1.lock();
        y1.clone(ySq);
        ySq.unlock();
        y1.modSqrt(curve.pBN);

        // Prepare for SignVerify
        rm.lock(pointBuffer);
        getW(pointBuffer, (short) 0);
        curve.disposablePriv.setG(pointBuffer, (short) 0, curve.POINT_SIZE);
        curve.disposablePub.setG(pointBuffer, (short) 0, curve.POINT_SIZE);

        // Construct public key with <x, y_1>
        pointBuffer[0] = 0x04;
        x.prependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        x.unlock();
        y1.prependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));

        // Check if public point <x, y_1> corresponds to the "secret" (i.e., our scalar)
        curve.disposablePriv.setS(scalar.asByteArray(), (short) 0, scalar.length());
        curve.disposablePub.setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.lock(resultBuffer);
        if (!SignVerifyECDSA(curve.disposablePriv, curve.disposablePub, rm.verifyEcdsa, resultBuffer)) { // If verification fails, then pick the <x, y_2>
            y2.lock();
            y2.clone(curve.pBN); // y_2 = p - y_1
            y2.modSub(y1, curve.pBN);
            y2.copyToBuffer(pointBuffer, (short) (1 + curve.COORD_SIZE));
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
        curve.disposablePriv.setS(scalar.asByteArray(), (short) 0, scalar.length());

        rm.ecMultKA.init(curve.disposablePriv);

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
        y.setSize(curve.COORD_SIZE);
        y.fromByteArray(pointBuffer, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);
        y.modNegate(curve.pBN);
        y.prependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
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
        x.setSize(xLen);
        x.fromByteArray(xCoord, xOffset, xLen);
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
        y_sq.modSq(curve.pBN);
        y_sq.modAdd(curve.aBN, curve.pBN);
        y_sq.modMult(y_sq, x, curve.pBN);
        y_sq.modAdd(curve.bBN, curve.pBN);
        y.lock();
        y.clone(y_sq);
        y_sq.unlock();
        y.modSqrt(curve.pBN);

        // Construct public key with <x, y_1>
        rm.lock(pointBuffer);
        pointBuffer[0] = 0x04;
        x.prependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        y.prependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
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


    /**
     * Decode SEC1-encoded point and load it into this.
     *
     * @param point array containing SEC1-encoded point
     * @param offset offset within the output buffer
     * @param length length of the encoded point
     * @return true if the point was compressed; false otherwise
     */
    public boolean decode(byte[] point, short offset, short length) {
        if(length == (short) (1 + 2 * curve.COORD_SIZE) && point[offset] == 0x04) {
            setW(point, offset, length);
            return false;
        }
        if (length == (short) (1 + curve.COORD_SIZE)) {
            BigNat y = rm.EC_BN_C;
            BigNat x = rm.EC_BN_D;
            BigNat p = rm.EC_BN_E;
            byte[] pointBuffer = rm.POINT_ARRAY_A;

            x.lock();
            x.fromByteArray(point, (short) (offset + 1), curve.COORD_SIZE);

            //Y^2 = X^3 + XA + B = x(x^2+A)+B
            y.lock();
            y.clone(x);
            y.modSq(curve.pBN);
            y.modAdd(curve.aBN, curve.pBN);
            y.modMult(y, x, curve.pBN);
            y.modAdd(curve.bBN, curve.pBN);
            y.modSqrt(curve.pBN);

            rm.lock(pointBuffer);
            pointBuffer[0] = 0x04;
            x.prependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);
            x.unlock();

            p.lock();
            byte parity = (byte) ((y.asByteArray()[(short) (curve.COORD_SIZE - 1)] & 0xff) % 2);
            if ((parity == 0 && point[offset] != (byte) 0x02) || (parity == 1 && point[offset] != (byte) 0x03)) {
                p.clone(curve.pBN);
                p.subtract(y);
                p.prependZeros(curve.COORD_SIZE, pointBuffer, (short) (curve.COORD_SIZE + 1));
            } else {
                y.prependZeros(curve.COORD_SIZE, pointBuffer, (short) (curve.COORD_SIZE + 1));
            }
            y.unlock();
            p.unlock();
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);
            rm.unlock(pointBuffer);
            return true;
        }
        ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALID);
        return true; // unreachable
    }

    /**
     * Encode this point into the output buffer.
     *
     * @param output output buffer; MUST be able to store offset + uncompressed size bytes
     * @param offset offset within the output buffer
     * @param compressed output compressed point if true; uncompressed otherwise
     * @return length of output point
     */
    public short encode(byte[] output, short offset, boolean compressed) {
        getW(output, offset);

        if(compressed) {
            if(output[offset] == (byte) 0x04) {
                output[offset] = (byte) (((output[(short) (offset + 2 * curve.COORD_SIZE)] & 0xff) % 2) == 0 ? 2 : 3);
            }
            return (short) (curve.COORD_SIZE + 1);
        }

        if(output[offset] != (byte) 0x04) {
            BigNat y = rm.EC_BN_C;
            BigNat x = rm.EC_BN_D;
            BigNat p = rm.EC_BN_E;
            x.lock();
            x.fromByteArray(output, (short) (offset + 1), curve.COORD_SIZE);

            //Y^2 = X^3 + XA + B = x(x^2+A)+B
            y.lock();
            y.clone(x);
            y.modSq(curve.pBN);
            y.modAdd(curve.aBN, curve.pBN);
            y.modMult(y, x, curve.pBN);
            x.unlock();
            y.modAdd(curve.bBN, curve.pBN);
            y.modSqrt(curve.pBN);
            p.lock();
            byte parity = (byte) ((y.asByteArray()[(short) (curve.COORD_SIZE - 1)] & 0xff) % 2);
            if ((parity == 0 && output[offset] != (byte) 0x02) || (parity == 1 && output[offset] != (byte) 0x03)) {
                p.clone(curve.pBN);
                p.subtract(y);
                p.prependZeros(curve.COORD_SIZE, output, (short) (offset + curve.COORD_SIZE + 1));
            } else {
                y.prependZeros(curve.COORD_SIZE, output, (short) (offset + curve.COORD_SIZE + 1));
            }
            y.unlock();
            p.unlock();
            output[offset] = (byte) 0x04;
        }
        return (short) (2 * curve.COORD_SIZE + 1);
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
