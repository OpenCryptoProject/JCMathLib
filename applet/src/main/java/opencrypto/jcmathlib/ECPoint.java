package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.*;

/**
 * @author Vasilios Mavroudis and Petr Svenda and Antonin Dufka, modified by Veronika Hanulikova
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
    public void ctRandomize() {
        if (OperationSupport.getInstance().EC_GEN == (short) 0xffff) {
            pointKeyPair.genKeyPair(); // Fails for some curves on some cards
        } else {
            BigNat tmp = rm.EC_BN_A;
            rm.lock(rm.ARRAY_A);
            rm.rng.generateData(rm.ARRAY_A, (short) 0, (short) (curve.KEY_BIT_LENGTH / 8 + 16));
            tmp.lock();
            tmp.ctFromByteArray(rm.ARRAY_A, (short) 0, (short) (curve.KEY_BIT_LENGTH / 8 + 16));
            tmp.ctMod(curve.rBN);
            tmp.ctShrink();
            rm.unlock(rm.ARRAY_A);
            point.setW(curve.G, (short) 0, (short) curve.G.length);
            ctMultiplication(tmp);
            tmp.unlock();
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
     * @param buffer memory array where to store serialized point value
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
    public short ctGetX(byte[] buffer, short offset) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        point.getW(pointBuffer, (short) 0);
        CTUtil.ctArrayCopyNonAtomic(pointBuffer, (short) 1, buffer, offset, curve.COORD_SIZE);
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
    public short ctGetY(byte[] buffer, short offset) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        point.getW(pointBuffer, (short) 0);
        CTUtil.ctArrayCopyNonAtomic(pointBuffer, (short) (1 + curve.COORD_SIZE), buffer, offset, curve.COORD_SIZE);
        rm.unlock(pointBuffer);
        return curve.COORD_SIZE;
    }

    /**
     * Double this point. Pure implementation without KeyAgreement.
     */
    public void ctSwDouble() {
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        BigNat pX = rm.EC_BN_B;
        BigNat pY = rm.EC_BN_C;
        BigNat lambda = rm.EC_BN_D;
        BigNat tmp = rm.EC_BN_E;

        rm.lock(pointBuffer);
        getW(pointBuffer, (short) 0);

        pX.lock();
        pX.ctFromByteArray(pointBuffer, (short) 1, curve.COORD_SIZE);

        pY.lock();
        pY.ctFromByteArray(pointBuffer, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);

        lambda.lock();
        lambda.ctClone(pX);
        lambda.ctModSq(curve.pBN);
        lambda.ctModMult(ResourceManager.THREE, curve.pBN);
        lambda.ctModAdd(curve.aBN, curve.pBN);

        tmp.lock();
        tmp.ctClone(pY);
        tmp.ctModAdd(tmp, curve.pBN);
        tmp.ctModInv(curve.pBN);
        lambda.ctModMult(tmp, curve.pBN);
        tmp.ctClone(lambda);
        tmp.ctModSq(curve.pBN);
        tmp.ctModSub(pX, curve.pBN);
        tmp.ctModSub(pX, curve.pBN);
        tmp.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);

        tmp.ctModSub(pX, curve.pBN);
        pX.unlock();
        tmp.ctModMult(lambda, curve.pBN);
        lambda.unlock();
        tmp.ctModAdd(pY, curve.pBN);
        tmp.ctModNegate(curve.pBN);
        pY.unlock();
        tmp.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        tmp.unlock();

        setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
    }

    /**
     * Doubles the current value of this point.
     */
    public void ctMakeDouble() {
        // doubling via add sometimes causes exception inside KeyAgreement engine
        // this.add(this);
        // Use bit slower, but more robust version via multiplication by 2
        ctSwDouble();
    }

    /**
     * Adds this (P) and provided (Q) point. Stores a resulting value into this point.
     *
     * @param other point to be added to this.
     */
    public void ctAdd(ECPoint other) {
        if (OperationSupport.getInstance().EC_HW_ADD == (short) 0xffff) {
            ctHwAdd(other);
        } else {
            swAdd(other);
        }
    }

    /**
     * Implements adding of two points without ALG_EC_PACE_GM.
     *
     * @param other point to be added to this.
     * @implNote reimplementation skipped deu to complicated algorithm, removing if-else statements would need temporary objects to work on
     */
    private void swAdd(ECPoint other) {
        boolean samePoint = this == other || (ctIsEqual(other) == (short) 0xffff);
        if (samePoint && (OperationSupport.getInstance().EC_HW_XY == (short) 0xffff)) {
            this.ctMultiplication(ResourceManager.TWO);
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
        xP.ctSetSize(curve.COORD_SIZE);
        xP.fromByteArray(pointBuffer, (short) 1, curve.COORD_SIZE);
        yP.lock();
        yP.ctSetSize(curve.COORD_SIZE);
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
            nominator.ctClone(xP);
            nominator.ctModSq(curve.pBN);
            nominator.ctModMult(ResourceManager.THREE, curve.pBN);
            nominator.ctModAdd(curve.aBN, curve.pBN);
            // (2y_p)
            denominator.ctClone(yP);
            denominator.ctModMult(ResourceManager.TWO, curve.pBN);
            denominator.ctModInv(curve.pBN);

        } else {
            // lambda = (y_q-y_p) / (x_q-x_p) mod p
            rm.lock(pointBuffer);
            other.point.getW(pointBuffer, (short) 0);
            xQ.lock();
            xQ.ctSetSize(curve.COORD_SIZE);
            xQ.fromByteArray(pointBuffer, (short) 1, other.curve.COORD_SIZE);
            nominator.ctSetSize(curve.COORD_SIZE);
            nominator.fromByteArray(pointBuffer, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);
            rm.unlock(pointBuffer);

            nominator.ctMod(curve.pBN);

            nominator.ctModSub(yP, curve.pBN);

            // (x_q-x_p)
            denominator.ctClone(xQ);
            denominator.ctMod(curve.pBN);
            denominator.ctModSub(xP, curve.pBN);
            denominator.ctModInv(curve.pBN);
        }

        lambda.lock();
        lambda.ctClone(nominator);
        lambda.ctModMult(denominator, curve.pBN);
        nominator.unlock();
        denominator.unlock();

        // (x_p, y_p) + (x_q, y_q) = (x_r, y_r)
        // lambda = (y_q - y_p) / (x_q - x_p)

        // x_r = lambda^2 - x_p - x_q
        xR.lock();
        if (samePoint) {
            rm.lock(pointBuffer);
            short len = ctMultXKA(ResourceManager.TWO, pointBuffer, (short) 0);
            xR.fromByteArray(pointBuffer, (short) 0, len);
            rm.unlock(pointBuffer);
        } else {
            xR.ctClone(lambda);
            xR.ctModSq(curve.pBN);
            xR.ctModSub(xP, curve.pBN);
            xR.ctModSub(xQ, curve.pBN);
        }
        xQ.unlock();

        // y_r = lambda(x_p - x_r) - y_p
        yR.lock();
        yR.ctClone(xP);
        xP.unlock();
        yR.ctModSub(xR, curve.pBN);
        yR.ctModMult(lambda, curve.pBN);
        lambda.unlock();
        yR.ctModSub(yP, curve.pBN);
        yP.unlock();

        rm.lock(pointBuffer);
        pointBuffer[0] = (byte) 0x04;
        // If x_r.length() and y_r.length() is smaller than curve.COORD_SIZE due to leading zeroes which were shrunk before, then we must add these back
        xR.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        xR.unlock();
        yR.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        yR.unlock();
        setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
    }

    /**
     * Implements adding of two points via ALG_EC_PACE_GM.
     *
     * @param other point to be added to this.
     */
    private void ctHwAdd(ECPoint other) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        setW(pointBuffer, (short) 0, ctMultAndAddKA(ResourceManager.ONE_COORD, other, pointBuffer, (short) 0));
        rm.unlock(pointBuffer);
    }

    /**
     * Multiply value of this point by provided scalar. Stores the result into this point.
     *
     * @param scalarBytes value of scalar for multiplication
     */
    public void ctMultiplication(byte[] scalarBytes, short scalarOffset, short scalarLen) {
        BigNat scalar = rm.EC_BN_F;

        scalar.lock();
        scalar.ctSetSize(scalarLen);
        scalar.fromByteArray(scalarBytes, scalarOffset, scalarLen);
        this.ctMultiplication(scalar);
        scalar.unlock();
    }

    /**
     * Multiply value of this point by provided scalar. Stores the result into this point.
     *
     * @param scalar value of scalar for multiplication
     * @implNote simplified: scalar should be checked for being the same number - use doubling
     */
    public void ctMultiplication(BigNat scalar) {
        if (rm.ecMultKA.getAlgorithm() == (byte) 6) {
            ctMultXY(scalar);
            //} else if (rm.ecMultKA.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN) {
        } else if (rm.ecMultKA.getAlgorithm() == (byte) 3) {
            ctMultX(scalar);
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
    public void ctMultAndAdd(BigNat scalar, ECPoint point) {
        if (OperationSupport.getInstance().EC_HW_ADD == (short) 0xffff) {
            byte[] pointBuffer = rm.POINT_ARRAY_A;

            rm.lock(pointBuffer);
            setW(pointBuffer, (short) 0, ctMultAndAddKA(scalar, point, pointBuffer, (short) 0));
            rm.unlock(pointBuffer);
        } else {
            ctMultiplication(scalar);
            ctAdd(point);
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
    private short ctMultAndAddKA(BigNat scalar, ECPoint point, byte[] outBuffer, short outBufferOffset) {
        byte[] pointBuffer = rm.POINT_ARRAY_B;

        rm.lock(pointBuffer);
        short len = getW(pointBuffer, (short) 0);
        curve.disposablePriv.setG(pointBuffer, (short) 0, len);
        scalar.ctPrependZeros((short) curve.r.length, pointBuffer, (short) 0);
        curve.disposablePriv.setS(pointBuffer, (short) 0, (short) curve.r.length);
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
    public void ctMultXY(BigNat scalar) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;

        rm.lock(pointBuffer);
        short len = ctMultXYKA(scalar, pointBuffer, (short) 0);
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
    public short ctMultXYKA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
        byte[] pointBuffer = rm.POINT_ARRAY_B;

        rm.lock(pointBuffer);
        scalar.ctPrependZeros((short) curve.r.length, pointBuffer, (short) 0); // this is the only reimplemented thing
        curve.disposablePriv.setS(pointBuffer, (short) 0, (short) curve.r.length);
        rm.ecMultKA.init(curve.disposablePriv);

        short len = getW(pointBuffer, (short) 0);
        len = rm.ecMultKA.generateSecret(pointBuffer, (short) 0, len, outBuffer, outBufferOffset);
        rm.unlock(pointBuffer);
        return len;
    }

    /**
     * Multiply value of this point by provided scalar using X-only key agreement. Stores the result into this point.
     * Partially implemeneted
     * @param scalar value of scalar for multiplication
     * @implNote too slow for actual verification because of ctModSqrt
     */
    private void ctMultX(BigNat scalar) {
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        byte[] pointBuffer2 = rm.POINT_ARRAY_B;
        byte[] resultBuffer = rm.ARRAY_A;
        BigNat x = rm.EC_BN_B;
        BigNat ySq = rm.EC_BN_C;
        BigNat y = rm.EC_BN_D;
        BigNat lambda = rm.EC_BN_E;
        BigNat tmp = rm.EC_BN_F;
        BigNat denominator = rm.EC_BN_D;

        rm.lock(pointBuffer);
        short len = ctMultXKA(scalar, pointBuffer, (short) 0);
        x.lock();
        x.fromByteArray(pointBuffer, (short) 0, len);
        rm.unlock(pointBuffer);

        // Solve for Y in Weierstrass equation: Y^2 = X^3 + XA + B = x(x^2+A)+B
        ySq.lock();
        ySq.ctClone(x);
        ySq.ctModExp(ResourceManager.TWO, curve.pBN);
        ySq.ctModAdd(curve.aBN, curve.pBN);
        ySq.ctModMult(x, curve.pBN);
        ySq.ctModAdd(curve.bBN, curve.pBN);
        y.lock();
        y.ctClone(ySq);
        ySq.unlock();
        y.ctModSqrt(curve.pBN);

        // Construct public key with <x, y>
        rm.lock(pointBuffer);
        pointBuffer[0] = 0x04;
        x.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        x.unlock();
        y.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        y.unlock();

        short negate; // cannot remove boolean here
        if (OperationSupport.getInstance().EC_HW_X_ECDSA == (short) 0xffff) {
            rm.lock(pointBuffer2);
            getW(pointBuffer2, (short) 0);
            curve.disposablePriv.setG(pointBuffer2, (short) 0, curve.POINT_SIZE);
            curve.disposablePub.setG(pointBuffer2, (short) 0, curve.POINT_SIZE);
            rm.unlock(pointBuffer2);

            setW(pointBuffer, (short) 0, curve.POINT_SIZE);

            // Check if <x, y> corresponds to the "secret" (i.e., our scalar)
            rm.lock(resultBuffer);
            scalar.ctPrependZeros((short) curve.r.length, resultBuffer, (short) 0);
            curve.disposablePriv.setS(resultBuffer, (short) 0, (short) curve.r.length);
            curve.disposablePub.setW(pointBuffer, (short) 0, curve.POINT_SIZE);
            negate = (short) (SignVerifyECDSA(curve.disposablePriv, curve.disposablePub, rm.verifyEcdsa, resultBuffer) ? 0 : (short) 0xffff);
            rm.unlock(resultBuffer);
        } else {
            // Check that (<x, y> + P)_x == ((scalar + 1)P)_x
            x.lock();
            rm.lock(resultBuffer);
            scalar.ctIncrement();
            len = ctMultXKA(scalar, resultBuffer, (short) 0);
            x.fromByteArray(resultBuffer, (short) 0, len);
            rm.unlock(resultBuffer);
            scalar.ctDecrement(); // keep the original

            rm.lock(pointBuffer2);
            getW(pointBuffer2, (short) 0);
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);

            // y_1 - y_2
            lambda.lock();
            lambda.fromByteArray(pointBuffer2, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);
            tmp.lock();
            tmp.fromByteArray(pointBuffer, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);
            lambda.ctModSub(tmp, curve.pBN);

            // (x_1 - x_2)^-1
            denominator.lock();
            denominator.fromByteArray(pointBuffer2, (short) 1, curve.COORD_SIZE);
            tmp.fromByteArray(pointBuffer, (short) 1, curve.COORD_SIZE);
            denominator.ctModSub(tmp, curve.pBN);
            denominator.ctModInv(curve.pBN);

            // λ = (y_1 - y_2)/(x_1 - x_2)
            lambda.ctModMult(denominator, curve.pBN);
            denominator.unlock();

            // x_3 = λ^2 - x_1 - x_2
            lambda.ctModSq(curve.pBN);
            tmp.fromByteArray(pointBuffer2, (short) 1, curve.COORD_SIZE);
            lambda.ctModSub(tmp, curve.pBN);
            tmp.fromByteArray(pointBuffer, (short) 1, curve.COORD_SIZE);
            lambda.ctModSub(tmp, curve.pBN);
            tmp.unlock();

            // If <x, y> + P != (scalar + 1)P, negate the point
            negate = (short) ~lambda.ctEquals(x);
            lambda.unlock();
            x.unlock();
        }
        rm.unlock(pointBuffer);

        if (negate == (short) 0xffff) // time leak, could be solved by creating temporary object
            ctNegate();
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
    private short ctMultXKA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
        byte[] pointBuffer = rm.POINT_ARRAY_B;
        // NOTE: potential problem on real cards (j2e) - when small scalar is used (e.g., BigNat.TWO), operation sometimes freezes
        rm.lock(pointBuffer);
        scalar.ctPrependZeros((short) curve.r.length, pointBuffer, (short) 0);
        curve.disposablePriv.setS(pointBuffer, (short) 0, (short) curve.r.length);

        rm.ecMultKA.init(curve.disposablePriv);

        short len = getW(pointBuffer, (short) 0);
        rm.ecMultKA.generateSecret(pointBuffer, (short) 0, len, outBuffer, outBufferOffset);
        rm.unlock(pointBuffer);
        // Return always length of whole coordinate X instead of len - some real cards returns shorter value equal to SHA-1 output size although PLAIN results is filled into buffer (GD60)
        return curve.COORD_SIZE;
    }

    /**
     * Computes negation of this point.
     * The operation will dump point into uncompressed_point_arr, negate Y and restore back
     */
    public void ctNegate() {
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        BigNat y = rm.EC_BN_C;

        y.lock();
        rm.lock(pointBuffer);
        point.getW(pointBuffer, (short) 0);
        y.ctSetSize(curve.COORD_SIZE);
        y.ctFromByteArray(pointBuffer, (short) (1 + curve.COORD_SIZE), curve.COORD_SIZE);
        y.ctModNegate(curve.pBN);
        y.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
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
    public short ctFromX(byte[] xCoord, short xOffset, short xLen) {
        BigNat x = rm.EC_BN_F;

        x.lock();
        x.ctSetSize(xLen);
        x.fromByteArray(xCoord, xOffset, xLen);
        short result = ctFromX(x);
        x.unlock();
        return result;
    }

    /**
     * Restore point from X coordinate. Stores one of the two results into this point.
     *
     * @param x the x coordinate
     * @implNote too slow for actual verification because of ctModSqrt
     */
    private short ctFromX(BigNat x) {
        BigNat ySq = rm.EC_BN_C;
        BigNat y = rm.EC_BN_D;
        byte[] pointBuffer = rm.POINT_ARRAY_A;
        short result = (short) 0xffff;

        //Y^2 = X^3 + XA + B = x(x^2+A)+B
        ySq.lock();
        ySq.ctClone(x);
        ySq.ctModSq(curve.pBN);
        ySq.ctModAdd(curve.aBN, curve.pBN);
        ySq.ctModMult(x, curve.pBN);
        ySq.ctModAdd(curve.bBN, curve.pBN);
        y.lock();
        y.ctClone(ySq);
        result &= y.ctIsQuadraticResidue(curve.pBN); // denotes whether there should be any side effect

        ySq.unlock();
        y.ctModSqrt(curve.pBN);

        // Construct public key with <x, y_1>
        rm.lock(pointBuffer);
        pointBuffer[0] = 0x04;
        x.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);
        y.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
        y.unlock();
        
        if (result == (short) 0xffff) // time leak
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);
        rm.unlock(pointBuffer);
        return result;
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
     * @return 0xffff if both point are exactly equal (same length, same value), 0x0000 otherwise
     */
    public short ctIsEqual(ECPoint other) {
        short result = ConstantTime.ctEqual(length(), other.length());

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
        short bResult = ConstantTime.ctIsZero(Util.arrayCompare(hashBuffer, (short) 0, pointBuffer, (short) 0, len));
        rm.unlock(hashBuffer);
        rm.unlock(pointBuffer);

        return (short) (bResult & result & (short) 0xffff);
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
     * @return 0xffff if the point was compressed; 0x0000 otherwise
     * @implNote partially reimplemented, still distinguishing among compressed and uncompressed
     * @implNote too slow for actual verification because of ctModSqrt
     */
    public short ctDecode(byte[] point, short offset, short length) {
        if(length == (short) (1 + 2 * curve.COORD_SIZE) && point[offset] == 0x04) {
            setW(point, offset, length);
            return (short) 0x0000;
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
            y.ctClone(x);
            y.ctModSq(curve.pBN);
            y.ctModAdd(curve.aBN, curve.pBN);
            y.ctModMult(x, curve.pBN);
            y.ctModAdd(curve.bBN, curve.pBN);
            y.ctModSqrt(curve.pBN);

            rm.lock(pointBuffer);
            pointBuffer[0] = 0x04;
            x.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) 1);
            x.unlock();

            p.lock();
            short odd = y.ctIsOdd();
            short mask = (short) ((~odd & ~ConstantTime.ctEqual(point[offset], (byte) 0x02))
                    | (odd & ~ConstantTime.ctEqual(point[offset], (byte) 0x03)));
            p.ctClone(curve.pBN, (short) ~mask);
            p.ctSubtract(y, (short) ~mask);
            p.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) (curve.COORD_SIZE + 1), (short) ~mask);
            y.ctPrependZeros(curve.COORD_SIZE, pointBuffer, (short) (curve.COORD_SIZE + 1), mask);
            
            y.unlock();
            p.unlock();
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);
            rm.unlock(pointBuffer);
            return (short) 0xffff;
        }
        ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALID);
        return (short) 0xffff; // unreachable
    }

    /**
     * Encode this point into the output buffer.
     *
     * @param output output buffer; MUST be able to store offset + uncompressed size bytes
     * @param offset offset within the output buffer
     * @param compressed output compressed point if true; uncompressed otherwise
     * @return length of output point
     * @implNote partially reimplemented, still distinguishing among compressed and uncompressed
     * @implNote too slow for actual verification because of ctModSqrt
     */
    public short ctEncode(byte[] output, short offset, boolean compressed) {
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
            y.ctClone(x);
            y.ctModSq(curve.pBN);
            y.ctModAdd(curve.aBN, curve.pBN);
            y.ctModMult(x, curve.pBN);
            x.unlock();
            y.ctModAdd(curve.bBN, curve.pBN);
            y.ctModSqrt(curve.pBN);
            p.lock();
            short odd = y.ctIsOdd();
            short mask = (short) ((~odd & ~ConstantTime.ctEqual(output[offset], (byte) 0x02))
                                | (odd & ~ConstantTime.ctEqual(output[offset], (byte) 0x03)));
            p.ctClone(curve.pBN, (short) ~mask);
            p.ctSubtract(y, (short) ~mask);
            p.ctPrependZeros(curve.COORD_SIZE, output, (short) (offset + curve.COORD_SIZE + 1), (short) ~mask);
            y.ctPrependZeros(curve.COORD_SIZE, output, (short) (offset + curve.COORD_SIZE + 1), mask);

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
