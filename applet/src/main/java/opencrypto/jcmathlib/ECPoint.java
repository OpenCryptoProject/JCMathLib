package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.Signature;

/**
 * 
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECPoint {	
    private final ECPointHelper ech;

    private ECPublicKey thePoint;
    private KeyPair thePointKeyPair;
    private final ECCurve theCurve;
    
    /**
     * Creates new ECPoint object for provided {@code curve}. Random initial point value is generated. 
     * The point will use helper structures from provided ECPoint_Helper object.
     * @param curve point's elliptic curve
     * @param ech object with preallocated helper objects and memory arrays
     */
    public ECPoint(ECCurve curve, ECPointHelper ech) {
        this.theCurve = curve;		
        this.ech = ech;
        updatePointObjects();
    }
    
    /**
     * Returns length of this point in bytes.
     *
     * @return
     */
    public short length() {
        return (short) (thePoint.getSize() / 8);
    }
    
    /**
     * Properly updates all point values in case of a change of an underlying curve.
     * New random point value is generated.
     */
    public final void updatePointObjects() {
        this.thePointKeyPair = this.theCurve.newKeyPair(this.thePointKeyPair);
        this.thePoint = (ECPublicKey) thePointKeyPair.getPublic();
    }
    /**
     * Generates new random point value.
     */
    public void randomize(){
        if (this.thePointKeyPair == null) {
            this.thePointKeyPair = this.theCurve.newKeyPair(this.thePointKeyPair);
            this.thePoint = (ECPublicKey) thePointKeyPair.getPublic();
        }
        else {
            this.thePointKeyPair.genKeyPair();
        }
    }

    /**
     * Copy value of provided point into this. This and other point must have 
     * curve with same parameters, only length is checked.
     * @param other point to be copied 
     */
    public void copy(ECPoint other) {
        if (this.length() != other.length()) {
            ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
        }
        ech.lock(ech.uncompressed_point_arr1);
        short len = other.getW(ech.uncompressed_point_arr1, (short) 0); 
        this.setW(ech.uncompressed_point_arr1, (short) 0, len);
        ech.unlock(ech.uncompressed_point_arr1);
    }

    /**
     * Set this point value (parameter W) from array with value encoded as per ANSI X9.62. 
     * The uncompressed form is always supported. If underlying native JavaCard implementation 
     * of {@code ECPublickKey} supports compressed points, then this method accepts also compressed points. 
     * @param buffer array with serialized point
     * @param offset start offset within input array
     * @param length length of point
     */
    public void setW(byte[] buffer, short offset, short length) {
        this.thePoint.setW(buffer, offset, length);
    }

    /**
     * Returns current value of this point. 
     * @param buffer    memory array where to store serailized point value
     * @param offset    start offset for output serialized point    
     * @return length of serialized point (number of bytes)
     */
    public short getW(byte[] buffer, short offset) {
        return thePoint.getW(buffer, offset);
    }

    /**
     * Returns this point value as ECPublicKey object. No copy of point is made 
     * before return, so change of returned object will also change this point value. 
     * @return point as ECPublicKey object
     */
    public ECPublicKey asPublicKey() {
        return this.thePoint;
    }
    
    /**
     * Returns curve associated with this point. No copy of curve is made
     * before return, so change of returned object will also change curve for 
     * this point.
     *
     * @return curve as ECCurve object
     */
    public ECCurve getCurve() {
    	return theCurve;
    }
    
    /**
     * Returns the X coordinate of this point in uncompressed form.
     * @param buffer output array for X coordinate
     * @param offset start offset within output array
     * @return length of X coordinate (in bytes)
     */
    public short getX(byte[] buffer, short offset) {
        ech.lock(ech.uncompressed_point_arr1);
        thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
        Util.arrayCopyNonAtomic(ech.uncompressed_point_arr1, (short) 1, buffer, offset, this.theCurve.COORD_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
        return this.theCurve.COORD_SIZE;
    }
	
    /**
     * Returns the Y coordinate of this point in uncompressed form.
     *
     * @param buffer output array for Y coordinate
     * @param offset start offset within output array
     * @return length of Y coordinate (in bytes)
     */    
    public short getY(byte[] buffer, short offset) {
        ech.lock(ech.uncompressed_point_arr1);
        thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
        Util.arrayCopyNonAtomic(ech.uncompressed_point_arr1, (short)(1 + this.theCurve.COORD_SIZE), buffer, offset, this.theCurve.COORD_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
        return this.theCurve.COORD_SIZE;
    }
    /**
     * Returns the Y coordinate of this point in form of Bignat object.
     *
     * @param yCopy Bignat object which will be set with value of this point
     */    
    public void getY(BigNat yCopy) {
        yCopy.set_size(this.getY(yCopy.as_byte_array(), (short) 0));
    }    

    /**
     * Double this point. Pure implementation without KeyAgreement.
     */
    public void swDouble() {
        ech.lock(ech.uncompressed_point_arr1);
        getW(ech.uncompressed_point_arr1, (short) 0);

        BigNat pX = ech.rm.helperEC_BN_B;
        pX.lock();
        pX.from_byte_array(theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) 1);

        BigNat pY = ech.rm.helperEC_BN_C;
        pY.lock();
        pY.from_byte_array(theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) (1 + theCurve.COORD_SIZE));

        BigNat lambda = ech.rm.helperEC_BN_D;
        lambda.lock();
        lambda.mod_mult(pX, pX, theCurve.pBN);
        lambda.mod_mult(lambda, BigNatHelper.THREE, theCurve.pBN);
        lambda.mod_add(theCurve.aBN, theCurve.pBN);

        BigNat tmp = ech.rm.helperEC_BN_E;
        tmp.lock();
        tmp.clone(pY);
        tmp.mod_add(tmp, theCurve.pBN);
        tmp.mod_inv(theCurve.pBN);
        lambda.mod_mult(lambda, tmp, theCurve.pBN);
        tmp.mod_mult(lambda, lambda, theCurve.pBN);
        tmp.mod_sub(pX, theCurve.pBN);
        tmp.mod_sub(pX, theCurve.pBN);
        tmp.prepend_zeros(theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) 1);

        tmp.mod_sub(pX, theCurve.pBN);
        pX.unlock();
        tmp.mod_mult(tmp, lambda, theCurve.pBN);
        lambda.unlock();
        tmp.mod_add(pY, theCurve.pBN);
        tmp.mod_negate(theCurve.pBN);
        pY.unlock();
        tmp.prepend_zeros(theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) (1 + theCurve.COORD_SIZE));
        tmp.unlock();

        this.setW(ech.uncompressed_point_arr1, (short) 0, theCurve.POINT_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
    }

     
    /**
     * Doubles the current value of this point. 
     */
    public void makeDouble() {
        // doubling via add sometimes causes exception inside KeyAgreement engine
        // this.add(this);
        // Use bit slower, but more robust version via multiplication by 2
        this.multiplication(BigNatHelper.TWO);
    }

    /**
     * Adds this (P) and provided (Q) point. Stores a resulting value into this point.
     * @param other point to be added to this.
     */
    public void add(ECPoint other) {
        boolean samePoint = this == other || isEqual(other);
        if (samePoint && OperationSupport.getInstance().ECDH_XY) {
            this.multiplication(BigNatHelper.TWO);
            return;
        }

        ech.lock(ech.uncompressed_point_arr1);
        this.thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
        ech.fnc_add_x_p.lock();
        ech.fnc_add_x_p.set_size(this.theCurve.COORD_SIZE);
        ech.fnc_add_x_p.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) 1);
        ech.fnc_add_y_p.lock();
        ech.fnc_add_y_p.set_size(this.theCurve.COORD_SIZE);
        ech.fnc_add_y_p.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
        ech.unlock(ech.uncompressed_point_arr1);


        // l = (y_q-y_p)/(x_q-x_p))
        // x_r = l^2 - x_p -x_q
        // y_r = l(x_p-x_r)-y_p

        // P+Q=R
        ech.fnc_add_nominator.lock();
        ech.fnc_add_denominator.lock();
        if (samePoint) {
            //lambda = (3(x_p^2)+a)/(2y_p)
            //(3(x_p^2)+a)
            ech.fnc_add_nominator.clone(ech.fnc_add_x_p);
            ech.fnc_add_nominator.mod_exp(BigNatHelper.TWO, this.theCurve.pBN);
            ech.fnc_add_nominator.mod_mult(ech.fnc_add_nominator, BigNatHelper.THREE, this.theCurve.pBN);
            ech.fnc_add_nominator.mod_add(this.theCurve.aBN, this.theCurve.pBN);
            // (2y_p)
            ech.fnc_add_denominator.clone(ech.fnc_add_y_p);
            ech.fnc_add_denominator.mod_mult(ech.fnc_add_y_p, BigNatHelper.TWO, this.theCurve.pBN);
            ech.fnc_add_denominator.mod_inv(this.theCurve.pBN);

        } else {
            // lambda=(y_q-y_p)/(x_q-x_p) mod p
            ech.lock(ech.uncompressed_point_arr1);
            other.thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
            ech.fnc_add_x_q.lock();
            ech.fnc_add_x_q.set_size(this.theCurve.COORD_SIZE);
            ech.fnc_add_x_q.from_byte_array(other.theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) 1);
            ech.fnc_add_nominator.set_size(this.theCurve.COORD_SIZE);
            ech.fnc_add_nominator.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
            ech.unlock(ech.uncompressed_point_arr1);

            ech.fnc_add_nominator.mod(this.theCurve.pBN);

            ech.fnc_add_nominator.mod_sub(ech.fnc_add_y_p, this.theCurve.pBN);

            // (x_q-x_p)
            ech.fnc_add_denominator.clone(ech.fnc_add_x_q);
            ech.fnc_add_denominator.mod(this.theCurve.pBN);
            ech.fnc_add_denominator.mod_sub(ech.fnc_add_x_p, this.theCurve.pBN);
            ech.fnc_add_denominator.mod_inv(this.theCurve.pBN);        	
        }
        
        ech.fnc_add_lambda.lock();
        ech.fnc_add_lambda.resize_to_max(false);
        ech.fnc_add_lambda.zero();
        ech.fnc_add_lambda.mod_mult(ech.fnc_add_nominator, ech.fnc_add_denominator, this.theCurve.pBN);
        ech.fnc_add_nominator.unlock();
        ech.fnc_add_denominator.unlock();

        // (x_p,y_p)+(x_q,y_q)=(x_r,y_r)
        // lambda=(y_q-y_p)/(x_q-x_p)

        //x_r=lambda^2-x_p-x_q
        ech.fnc_add_x_r.lock();
        if (samePoint) {
            short len = this.multiplication_x_KA(BigNatHelper.TWO, ech.fnc_add_x_r.as_byte_array(), (short) 0);
            ech.fnc_add_x_r.set_size(len); 
        } else {        
            ech.fnc_add_x_r.clone(ech.fnc_add_lambda);
            //m_occ.ecHelper.fnc_add_x_r.mod_exp(occ.bnHelper.TWO, this.TheCurve.pBN);
            ech.fnc_add_x_r.mod_exp2(this.theCurve.pBN);
            ech.fnc_add_x_r.mod_sub(ech.fnc_add_x_p, this.theCurve.pBN);
            ech.fnc_add_x_r.mod_sub(ech.fnc_add_x_q, this.theCurve.pBN);
            ech.fnc_add_x_q.unlock();                
        }
        //y_r=lambda(x_p-x_r)-y_p        
        ech.fnc_add_y_r.lock();
        ech.fnc_add_y_r.clone(ech.fnc_add_x_p);
        ech.fnc_add_x_p.unlock();
        ech.fnc_add_y_r.mod_sub(ech.fnc_add_x_r, this.theCurve.pBN);
        ech.fnc_add_y_r.mod_mult(ech.fnc_add_y_r, ech.fnc_add_lambda, this.theCurve.pBN);
        ech.fnc_add_lambda.unlock();
        ech.fnc_add_y_r.mod_sub(ech.fnc_add_y_p, this.theCurve.pBN);
        ech.fnc_add_y_p.unlock();

        ech.lock(ech.uncompressed_point_arr1);
        ech.uncompressed_point_arr1[0] = (byte)0x04;
        // If x_r.length() and y_r.length() is smaller than this.TheCurve.COORD_SIZE due to leading zeroes which were shrinked before, then we must add these back
        ech.fnc_add_x_r.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) 1);
        ech.fnc_add_x_r.unlock();
        ech.fnc_add_y_r.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
        ech.fnc_add_y_r.unlock();
        this.setW(ech.uncompressed_point_arr1, (short) 0, this.theCurve.POINT_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
    }

    /**
     * Multiply value of this point by provided scalar. Stores the result into
     * this point.
     *
     * @param scalar value of scalar for multiplication
     */
    public void multiplication(byte[] scalar, short scalarOffset, short scalarLen) {
        ech.fnc_multiplication_scalar.lock();
        ech.fnc_multiplication_scalar.set_size(scalarLen);
        ech.fnc_multiplication_scalar.from_byte_array(scalarLen, (short) 0, scalar, scalarOffset);
        multiplication(ech.fnc_multiplication_scalar);
        ech.fnc_multiplication_scalar.unlock();
    }

    /**
     * Multiply value of this point by provided scalar. Stores the result into this point.
     * @param scalar value of scalar for multiplication
     */
    public void multiplication(BigNat scalar) {
        if(OperationSupport.getInstance().EC_SW_DOUBLE && scalar.same_value(BigNatHelper.TWO)) {
            swDouble();
            return;
        }
        if (ech.multKA.getAlgorithm() == ECPointHelper.ALG_EC_SVDP_DH_PLAIN_XY) {
            this.multiplication_xy(scalar);
        } else if (ech.multKA.getAlgorithm() == ECPointHelper.ALG_EC_SVDP_DH_PLAIN) {
            this.multiplication_x(scalar);
        } else {
            ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);
        }
    }

    /**
     * Multiply value of this point by provided scalar using XY key agreement. Stores the result into this point.
     * @param scalar value of scalar for multiplication
     */
    public void multiplication_xy(BigNat scalar) {
        ech.lock(ech.uncompressed_point_arr2);
        short len = multiplication_xy_KA(scalar, ech.uncompressed_point_arr2, (short) 0);
        this.setW(ech.uncompressed_point_arr2, (short) 0, len);
        ech.unlock(ech.uncompressed_point_arr2);
    }

    /**
     * Multiplies this point value with provided scalar and stores result into
     * provided array. No modification of this point is performed.
     * Native XY KeyAgreement engine is used.
     *
     * @param scalar value of scalar for multiplication
     * @param outBuffer output array for resulting value
     * @param outBufferOffset offset within output array
     * @return length of resulting value (in bytes)
     */
    public short multiplication_xy_KA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
        theCurve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());
        ech.multKA.init(theCurve.disposable_priv);

        ech.lock(ech.uncompressed_point_arr1);
        short len = this.getW(ech.uncompressed_point_arr1, (short) 0);
        len = ech.multKA.generateSecret(ech.uncompressed_point_arr1, (short) 0, len, outBuffer, outBufferOffset);
        ech.unlock(ech.uncompressed_point_arr1);
        return len;
    }

    /**
     * Multiply value of this point by provided scalar using X-only key agreement. Stores the result into this point.
     * @param scalar value of scalar for multiplication
    */
    private void multiplication_x(BigNat scalar) {
        ech.fnc_multiplication_x.lock();
        short len = this.multiplication_x_KA(scalar, ech.fnc_multiplication_x.as_byte_array(), (short) 0);
        ech.fnc_multiplication_x.set_size(len); 

        //Y^2 = X^3 + XA + B = x(x^2+A)+B
        ech.fnc_multiplication_y_sq.lock();
        ech.fnc_multiplication_y_sq.clone(ech.fnc_multiplication_x);
        ech.fnc_multiplication_y_sq.mod_exp(BigNatHelper.TWO, this.theCurve.pBN);
        ech.fnc_multiplication_y_sq.mod_add(this.theCurve.aBN, this.theCurve.pBN);
        ech.fnc_multiplication_y_sq.mod_mult(ech.fnc_multiplication_y_sq, ech.fnc_multiplication_x, this.theCurve.pBN);
        ech.fnc_multiplication_y_sq.mod_add(this.theCurve.bBN, this.theCurve.pBN);
        ech.fnc_multiplication_y1.lock();
        ech.fnc_multiplication_y1.clone(ech.fnc_multiplication_y_sq); 
        ech.fnc_multiplication_y_sq.unlock();
        ech.fnc_multiplication_y1.sqrt_FP(this.theCurve.pBN);
        
        // Construct public key with <x, y_1>
        ech.lock(ech.uncompressed_point_arr1);
        ech.uncompressed_point_arr1[0] = 0x04;
        ech.fnc_multiplication_x.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) 1);
        ech.fnc_multiplication_x.unlock();
        ech.fnc_multiplication_y1.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) (1 + theCurve.COORD_SIZE));
        this.setW(ech.uncompressed_point_arr1, (short) 0, theCurve.POINT_SIZE); //So that we can convert to pub key

        // Check if public point <x, y_1> corresponds to the "secret" (i.e., our scalar)
        ech.lock(ech.fnc_multiplication_resultArray);
        if (!SignVerifyECDSA(this.theCurve.bignatAsPrivateKey(scalar), this.asPublicKey(), this.ech.fnc_SignVerifyECDSA_signEngine, ech.fnc_multiplication_resultArray)) { //If verification fails, then pick the <x, y_2>
            ech.fnc_multiplication_y2.lock();
            ech.fnc_multiplication_y2.clone(this.theCurve.pBN); //y_2 = p - y_1
            ech.fnc_multiplication_y2.mod_sub(ech.fnc_multiplication_y1, this.theCurve.pBN);
            ech.fnc_multiplication_y2.copy_to_buffer(ech.uncompressed_point_arr1, (short) (1 + theCurve.COORD_SIZE));
            ech.fnc_multiplication_y2.unlock();
        }
        ech.unlock(ech.fnc_multiplication_resultArray);
        ech.fnc_multiplication_y1.unlock();
        

        this.setW(ech.uncompressed_point_arr1, (short)0, theCurve.POINT_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
        
    }
    
    /**
     * Multiplies this point value with provided scalar and stores result into
     * provided array. No modification of this point is performed.
     * Native X-only KeyAgreement engine is used.
     *
     * @param scalar value of scalar for multiplication
     * @param outBuffer output array for resulting value
     * @param outBufferOffset offset within output array
     * @return length of resulting value (in bytes)
     */
    private short multiplication_x_KA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
        // NOTE: potential problem on real cards (j2e) - when small scalar is used (e.g., Bignat.TWO), operation sometimes freezes
        theCurve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());

        ech.multKA.init(theCurve.disposable_priv);

        ech.lock(ech.uncompressed_point_arr1);
        short len = this.getW(ech.uncompressed_point_arr1, (short) 0); 
        len = ech.multKA.generateSecret(ech.uncompressed_point_arr1, (short) 0, len, outBuffer, outBufferOffset);
        ech.unlock(ech.uncompressed_point_arr1);
        // Return always length of whole coordinate X instead of len - some real cards returns shorter value equal to SHA-1 output size although PLAIN results is filled into buffer (GD60) 
        return this.theCurve.COORD_SIZE;
    }

    /**
     * Computes negation of this point.
     */
    public void negate() {
        // Operation will dump point into uncompressed_point_arr, negate Y and restore back
        ech.fnc_negate_yBN.lock();
        ech.lock(ech.uncompressed_point_arr1);
        thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
        ech.fnc_negate_yBN.set_size(this.theCurve.COORD_SIZE);
        ech.fnc_negate_yBN.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
        ech.fnc_negate_yBN.mod_negate(this.theCurve.pBN);
        
        // Restore whole point back
        ech.fnc_negate_yBN.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
        ech.fnc_negate_yBN.unlock();
        this.setW(ech.uncompressed_point_arr1, (short) 0, this.theCurve.POINT_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
    }

    /**
     * Restore point from X coordinate. Stores one of the two results into this point.
     *
     * @param xCoord byte array containing the X coordinate
     * @param xOffset offset in the byte array
     * @param xLen length of the X coordinate
     */
    public void from_x(byte[] xCoord, short xOffset, short xLen) {
        ech.fnc_from_x_x.lock();
        ech.fnc_from_x_x.set_size(xLen);
        ech.fnc_from_x_x.from_byte_array(xLen, (short) 0, xCoord, xOffset);
        from_x(ech.fnc_from_x_x);
        ech.fnc_from_x_x.unlock();
    }

    /**
     * Restore point from X coordinate. Stores one of the two results into this point.
     *
     * @param x the x coordinate
     */
    private void from_x(BigNat x) {
        //Y^2 = X^3 + XA + B = x(x^2+A)+B
        ech.fnc_from_x_y_sq.lock();
        ech.fnc_from_x_y_sq.clone(x);
        ech.fnc_from_x_y_sq.mod_exp(BigNatHelper.TWO, this.theCurve.pBN);
        ech.fnc_from_x_y_sq.mod_add(this.theCurve.aBN, this.theCurve.pBN);
        ech.fnc_from_x_y_sq.mod_mult(ech.fnc_from_x_y_sq, x, this.theCurve.pBN);
        ech.fnc_from_x_y_sq.mod_add(this.theCurve.bBN, this.theCurve.pBN);
        ech.fnc_from_x_y.lock();
        ech.fnc_from_x_y.clone(ech.fnc_from_x_y_sq);
        ech.fnc_from_x_y_sq.unlock();
        ech.fnc_from_x_y.sqrt_FP(this.theCurve.pBN);

        // Construct public key with <x, y_1>
        ech.lock(ech.uncompressed_point_arr1);
        ech.uncompressed_point_arr1[0] = 0x04;
        x.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) 1);
        ech.fnc_from_x_y.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) (1 + theCurve.COORD_SIZE));
        ech.fnc_from_x_y.unlock();
        this.setW(ech.uncompressed_point_arr1, (short) 0, theCurve.POINT_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
    }

    /**
     * Returns true if Y coordinate is even; false otherwise.
     *
     * @return true if Y coordinate is even; false otherwise
     */
    public boolean is_y_even() {
        ech.fnc_is_y.lock();
        ech.lock(ech.uncompressed_point_arr1);
        thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
        boolean result = ech.uncompressed_point_arr1[(short)(theCurve.POINT_SIZE - 1)] % 2 == 0;
        ech.unlock(ech.uncompressed_point_arr1);
        ech.fnc_is_y.unlock();
        return result;
    }

    /**
     * Compares this and provided point for equality. The comparison is made using hash of both values to prevent leak of position of mismatching byte.
     * @param other second point for comparison
     * @return true if both point are exactly equal (same length, same value), false otherwise
     */
    public boolean isEqual(ECPoint other) {
        boolean bResult = false;
        if (this.length() != other.length()) {
            return false;
        } 
        else {
            // The comparison is made with hash of point values instead of directly values. 
            // This way, offset of first mismatching byte is not leaked via timing side-channel. 
            // Additionally, only single array is required for storage of plain point values thus saving some RAM.            
            ech.lock(ech.uncompressed_point_arr1);
            ech.lock(ech.fnc_isEqual_hashArray);
            //ech.lock(ech.fnc_isEqual_hashEngine);
            short len = this.getW(ech.uncompressed_point_arr1, (short) 0);
            ech.fnc_isEqual_hashEngine.doFinal(ech.uncompressed_point_arr1, (short) 0, len, ech.fnc_isEqual_hashArray, (short) 0);
            len = other.getW(ech.uncompressed_point_arr1, (short) 0);
            len = ech.fnc_isEqual_hashEngine.doFinal(ech.uncompressed_point_arr1, (short) 0, len, ech.uncompressed_point_arr1, (short) 0);
            bResult = Util.arrayCompare(ech.fnc_isEqual_hashArray, (short) 0, ech.uncompressed_point_arr1, (short) 0, len) == 0;
            //ech.unlock(ech.fnc_isEqual_hashEngine);
            ech.unlock(ech.fnc_isEqual_hashArray);
            ech.unlock(ech.uncompressed_point_arr1);
        }

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
        thePoint.setFieldFP(bytes, s, s1);
    }

    public void setFieldF2M(short s) throws CryptoException {
        thePoint.setFieldF2M(s);
    }

    public void setFieldF2M(short s, short s1, short s2) throws CryptoException {
        thePoint.setFieldF2M(s, s1, s2);
    }

    public void setA(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setA(bytes, s, s1);
    }

    public void setB(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setB(bytes, s, s1);
    }

    public void setG(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setG(bytes, s, s1);
    }

    public void setR(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setR(bytes, s, s1);
    }

    public void setK(short s) {
        thePoint.setK(s);
    }

    public short getField(byte[] bytes, short s) throws CryptoException {
        return thePoint.getField(bytes, s);
    }

    public short getA(byte[] bytes, short s) throws CryptoException {
        return thePoint.getA(bytes, s);
    }

    public short getB(byte[] bytes, short s) throws CryptoException {
        return thePoint.getB(bytes, s);
    }

    public short getG(byte[] bytes, short s) throws CryptoException {
        return thePoint.getG(bytes, s);
    }

    public short getR(byte[] bytes, short s) throws CryptoException {
        return thePoint.getR(bytes, s);
    }

    public short getK() throws CryptoException {
        return thePoint.getK();
    }    
}
