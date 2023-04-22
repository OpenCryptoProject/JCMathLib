package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import javacard.security.KeyBuilder;

/**
 * @author Vasilios Mavroudis and Petr Svenda and Antonin Dufka
 */
public class BigNat extends BigNatInternal {

    /**
     * Construct a BigNat of given size.
     *
     * @param size the size of the new BigNat in bytes
     * @param allocatorType type of allocator storage
     */
    public BigNat(short size, byte allocatorType, ResourceManager rm) {
        super(size, allocatorType, rm);
    }

    /**
     * Equality check using hash values.
     *
     * @param other BigNat to compare
     * @return true if this and other have the same value, false otherwise.
     */
    public boolean equals(BigNatInternal other) {
        short hashLen;
        byte[] tmpBuffer = rm.ARRAY_A;
        byte[] hashBuffer = rm.ARRAY_B;

        rm.lock(tmpBuffer);
        rm.lock(hashBuffer);
        if (this.length() == other.length()) {
            rm.hashEngine.doFinal(this.asByteArray(), (short) 0, this.length(), hashBuffer, (short) 0);
            hashLen = rm.hashEngine.doFinal(other.asByteArray(), (short) 0, other.length(), tmpBuffer, (short) 0);
        } else {
            if (this.length() < other.length()) {
                this.prependZeros(other.length(), tmpBuffer, (short) 0);
                rm.hashEngine.doFinal(tmpBuffer, (short) 0, other.length(), hashBuffer, (short) 0);
                hashLen = rm.hashEngine.doFinal(other.asByteArray(), (short) 0, other.length(), tmpBuffer, (short) 0);
            } else {
                other.prependZeros(this.length(), tmpBuffer, (short) 0);
                rm.hashEngine.doFinal(tmpBuffer, (short) 0, this.length(), hashBuffer, (short) 0);
                hashLen = rm.hashEngine.doFinal(this.asByteArray(), (short) 0, this.length(), tmpBuffer, (short) 0);
            }
        }

        boolean result = Util.arrayCompare(hashBuffer, (short) 0, tmpBuffer, (short) 0, hashLen) == 0;

        rm.unlock(tmpBuffer);
        rm.unlock(hashBuffer);

        return result;
    }

    /**
     * Add other BigNat to this BigNat modulo mod.
     *
     * @param other value to add
     * @param mod modulo
     */
    public void modAdd(BigNat other, BigNat mod) {
        BigNat tmp = rm.BN_A;

        short tmpSize = length();
        if (tmpSize < other.length()) {
            tmpSize = other.length();
        }
        tmpSize++;
        tmp.lock();
        tmp.setSize(tmpSize);
        tmp.zero();
        tmp.copy(this);
        tmp.add(other);
        tmp.mod(mod);
        tmp.shrink();
        this.clone(tmp);
        tmp.unlock();
    }

    /**
     * Subtract other BigNat from this BigNat modulo mod.
     *
     * @param other  value to subtract
     * @param mod value of modulo to apply
     */
    public void modSub(BigNat other, BigNat mod) {
        BigNat tmp = rm.BN_B;
        BigNat tmpOther = rm.BN_C;
        BigNat tmpThis = rm.BN_A;

        if (other.lesser(this)) { // CTO
            this.subtract(other);
            this.mod(mod);
        } else { // other > this (mod - other + this)
            tmpOther.lock();
            tmpOther.clone(other);
            tmpOther.mod(mod);

            tmpThis.lock();
            tmpThis.clone(this);
            tmpThis.mod(mod);

            tmp.lock();
            tmp.clone(mod);
            tmp.subtract(tmpOther);
            tmpOther.unlock();
            tmp.add(tmpThis); // this will never overflow as "other" is larger than "this"
            tmpThis.unlock();
            tmp.mod(mod);
            tmp.shrink();
            this.clone(tmp);
            tmp.unlock();
        }
    }

    /**
     * Division of this BigNat by provided other BigNat.
     *
     * @param other divisor
     */
    public void divide(BigNat other) {
        BigNat tmp = rm.BN_E;

        tmp.lock();
        tmp.clone(this);
        tmp.remainderDivide(other, this);
        this.clone(tmp);
        tmp.unlock();
    }

    /**
     * Greatest common divisor of this BigNat with other BigNat. Result is stored into this.
     *
     * @param other value of other BigNat
     */
    public void gcd(BigNat other) {
        BigNat tmp = rm.BN_A;
        BigNat tmpOther = rm.BN_B;

        tmp.lock();
        tmpOther.lock();

        tmpOther.clone(other);

        // TODO: optimise?
        while (!other.isZero()) {
            tmp.clone(tmpOther);
            this.mod(tmpOther);
            tmpOther.clone(this);
            this.clone(tmp);
        }

        tmp.unlock();
        tmpOther.unlock();
    }

    /**
     * Decides whether the arguments are co-prime or not.
     *
     * @param a BigNat value
     * @param b BigNat value
     * @return true if co-prime, false otherwise
     */
    public boolean isCoprime(BigNat a, BigNat b) {
        BigNat tmp = rm.BN_C;

        tmp.lock();
        tmp.clone(a);

        tmp.gcd(b);
        return tmp.equals(ResourceManager.ONE);
    }

    /**
     * Square computation supporting base greater than MAX_BIGNAT_LENGTH.
     */
    public void sq() {
        if (!OperationSupport.getInstance().RSA_SQ) {
            BigNat tmp = rm.BN_A;
            tmp.lock();
            tmp.clone(this);
            multSw(tmp, tmp);
            return;
        }
        if ((short) (rm.MAX_SQ_LENGTH - 1) < (short) (2 * length())) {
            ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDSQ);
        }

        byte[] resultBuffer = rm.ARRAY_A;
        short offset = (short) (rm.MAX_SQ_LENGTH - length());

        rm.lock(resultBuffer);
        Util.arrayFillNonAtomic(resultBuffer, (short) 0, offset, (byte) 0x00);
        copyToBuffer(resultBuffer, offset);
        short len = rm.sqCiph.doFinal(resultBuffer, (short) 0, rm.MAX_SQ_LENGTH, resultBuffer, (short) 0);
        if (len != rm.MAX_SQ_LENGTH) {
            if (OperationSupport.getInstance().RSA_PREPEND_ZEROS) {
                Util.arrayCopyNonAtomic(resultBuffer, (short) 0, resultBuffer, (short) (rm.MAX_SQ_LENGTH - len), len);
                Util.arrayFillNonAtomic(resultBuffer, (short) 0, (short) (rm.MAX_SQ_LENGTH - len), (byte) 0);
            } else {
                ISOException.throwIt(ReturnCodes.SW_ECPOINT_UNEXPECTED_KA_LEN);
            }
        }
        short zeroPrefix = (short) (rm.MAX_SQ_LENGTH - (short) 2 * length());
        fromByteArray(resultBuffer, zeroPrefix, (short) (rm.MAX_SQ_LENGTH - zeroPrefix));
        rm.unlock(resultBuffer);
        shrink();
    }

    /**
     * Computes x * y and stores the result into this. Chooses computation approach based on operation support and operand size.
     *
     * @param x left operand
     * @param y right operand
     */
    public void mult(BigNat x, BigNat y) {
        if (OperationSupport.getInstance().RSA_CHECK_ONE && x.isOne()) {
            clone(y);
            return;
        }
        if (!OperationSupport.getInstance().RSA_SQ || x.length() <= (short) 16) {
            multSw(x, y);
            return;
        }

        BigNat result = rm.BN_F;
        BigNat tmp = rm.BN_G;

        result.lock();
        result.clone(x);
        result.add(y);
        result.sq();

        tmp.lock();
        if (x.lesser(y)) {
            tmp.clone(y);
            tmp.subtract(x);
        } else {
            tmp.clone(x);
            tmp.subtract(y);
        }
        tmp.sq();

        result.subtract(tmp);
        tmp.unlock();
        result.shiftRight((short) 2);

        resizeToMax(false);
        copy(result);
        result.unlock();
        shrink();
    }

    /**
     * Multiplication of BigNats x and y computed modulo mod.
     * The result is stored to this.
     *
     * @param x first value to multiply
     * @param y second value to multiply
     * @param mod value of modulo
     */
    public void modMult(BigNat x, BigNat y, BigNat mod) {
        BigNat tmp = rm.BN_D;
        BigNat result = rm.BN_E;

        if (OperationSupport.getInstance().RSA_CHECK_ONE && x.isOne()) {
            clone(y);
            return;
        }

        result.lock();
        if (!OperationSupport.getInstance().RSA_SQ) {
            result.resizeToMax(false);
            result.mult(x, y);
            result.mod(mod);
            result.shrink();
        } else {
            result.clone(x);
            result.modAdd(y, mod);

            result.deepResize(mod.length());
            byte carry = (byte) 0;
            if (result.isOdd()) {
                carry = result.add(mod);
            }
            result.shiftRight((short) 1, carry != 0 ? (short) (1 << 7) : (short) 0);

            tmp.lock();
            tmp.clone(result);
            tmp.modSub(y, mod);

            result.modSq(mod);
            tmp.modSq(mod);

            result.modSub(tmp, mod);
            tmp.unlock();
        }
        this.clone(result);
        result.unlock();
    }

    /**
     * Computes (this ^ exponent % modulo) using RSA algorithm and store results into this.
     *
     * @param exponent exponent
     * @param modulo modulo
     */
    public void modExp(BigNat exponent, BigNat modulo) {
        if (!OperationSupport.getInstance().RSA_EXP)
            ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);

        BigNat tmpMod = rm.BN_F; // modExp is called from modSqrt => requires BN_F not being locked when modExp is called
        byte[] tmpBuffer = rm.ARRAY_A;
        short modLength;

        tmpMod.lock();
        tmpMod.setSize(rm.MAX_EXP_LENGTH);

        if (OperationSupport.getInstance().RSA_PUB) {
            // Verify if pre-allocated engine match the required values
            if (rm.expPub.getSize() < (short) (modulo.length() * 8) || rm.expPub.getSize() < (short) (this.length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (OperationSupport.getInstance().RSA_KEY_REFRESH) {
                // Simulator fails when reusing the original object
                rm.expPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rm.MAX_EXP_BIT_LENGTH, false);
            }
            rm.expPub.setExponent(exponent.asByteArray(), (short) 0, exponent.length());
            rm.lock(tmpBuffer);
            if (OperationSupport.getInstance().RSA_RESIZE_MOD) {
                if (OperationSupport.getInstance().RSA_APPEND_MOD) {
                    modulo.appendZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                } else {
                    modulo.prependZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                }
                rm.expPub.setModulus(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);
                modLength = rm.MAX_EXP_LENGTH;
            } else {
                rm.expPub.setModulus(modulo.asByteArray(), (short) 0, modulo.length());
                modLength = modulo.length();
            }
            rm.expCiph.init(rm.expPub, Cipher.MODE_DECRYPT);
        } else {
            // Verify if pre-allocated engine match the required values
            if (rm.expPriv.getSize() < (short) (modulo.length() * 8) || rm.expPriv.getSize() < (short) (this.length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (OperationSupport.getInstance().RSA_KEY_REFRESH) {
                // Simulator fails when reusing the original object
                rm.expPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, rm.MAX_EXP_BIT_LENGTH, false);
            }
            rm.expPriv.setExponent(exponent.asByteArray(), (short) 0, exponent.length());
            rm.lock(tmpBuffer);
            if (OperationSupport.getInstance().RSA_RESIZE_MOD) {
                if (OperationSupport.getInstance().RSA_APPEND_MOD) {
                    modulo.appendZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                } else {
                    modulo.prependZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);

                }
                rm.expPriv.setModulus(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);
                modLength = rm.MAX_EXP_LENGTH;
            } else {
                rm.expPriv.setModulus(modulo.asByteArray(), (short) 0, modulo.length());
                modLength = modulo.length();
            }
            rm.expCiph.init(rm.expPriv, Cipher.MODE_DECRYPT);
        }

        prependZeros(modLength, tmpBuffer, (short) 0);
        short len = rm.expCiph.doFinal(tmpBuffer, (short) 0, modLength, tmpBuffer, (short) 0);

        if (len != rm.MAX_EXP_LENGTH) {
            if (OperationSupport.getInstance().RSA_PREPEND_ZEROS) {
                // Decrypted length can be either tmp_size or less because of leading zeroes consumed by simulator engine implementation
                // Move obtained value into proper position with zeroes prepended
                Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, tmpBuffer, (short) (rm.MAX_EXP_LENGTH - len), len);
                Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) (rm.MAX_EXP_LENGTH - len), (byte) 0);
            } else {
                // real cards should keep whole length of block
                ISOException.throwIt(ReturnCodes.SW_ECPOINT_UNEXPECTED_KA_LEN);
            }
        }
        tmpMod.fromByteArray(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);
        rm.unlock(tmpBuffer);

        if (OperationSupport.getInstance().RSA_EXTRA_MOD) {
            tmpMod.mod(modulo);
        }
        tmpMod.shrink();
        this.clone(tmpMod);
        tmpMod.unlock();
    }


    /**
     * Computes square root of provided BigNat which MUST be prime using Tonelli
     * Shanks Algorithm. The result (one of the two roots) is stored to this.
     *
     * @param p value to compute square root from
     */
    public void modSqrt(BigNat p) {
        BigNat s = rm.BN_A;
        BigNat exp = rm.BN_A;
        BigNat p1 = rm.BN_B;
        BigNat q = rm.BN_C;
        BigNat tmp = rm.BN_D;
        BigNat z = rm.BN_E;

        // 1. By factoring out powers of 2, find Q and S such that p-1=Q2^S p-1=Q*2^S and Q is odd
        p1.lock();
        p1.clone(p);
        p1.decrement();

        // Compute Q
        q.lock();
        q.clone(p1);
        q.shiftRight((short) 1); // Q /= 2

        // Compute S
        s.lock();
        s.setSize(p.length());
        s.zero();
        tmp.lock();
        tmp.setSize(p.length());
        tmp.zero();

        while (!tmp.equals(q)) {
            s.increment();
            // TODO investigate why just mod_mult(s, q, p) does not work (apart from locks)
            tmp.resizeToMax(false);
            tmp.mult(s, q);
            tmp.mod(p);
            tmp.shrink();
        }
        tmp.unlock();
        s.unlock();

        // 2. Find the first quadratic non-residue z by brute-force search
        exp.lock();
        exp.clone(p1);
        exp.shiftRight((short) 1);


        z.lock();
        z.setSize(p.length());
        z.setValue((byte) 1);
        tmp.lock();
        tmp.zero();
        tmp.copy(ResourceManager.ONE);

        while (!tmp.equals(p1)) {
            z.increment();
            tmp.copy(z);
            tmp.modExp(exp, p);
        }
        p1.unlock();
        tmp.unlock();
        z.unlock();
        exp.copy(q);
        q.unlock();
        exp.increment();
        exp.shiftRight((short) 1);

        this.mod(p);
        this.modExp(exp, p);
        exp.unlock();
    }

    /**
     * Computes modulo and stores it in this.
     *
     * @param modulo value of modulo
     */
    public void mod(BigNat modulo) {
        remainderDivide(modulo, null);
    }

    /**
     * Computes modular inversion. The result is stored into this.
     *
     * @param modulo modulo
     */
    public void modInv(BigNat modulo) {
        BigNat tmp = rm.BN_B;
        tmp.lock();
        tmp.clone(modulo);
        tmp.decrement();
        tmp.decrement();

        modExp(tmp, modulo);
        tmp.unlock();
    }

    public void modSq(BigNat modulo) {
        if (OperationSupport.getInstance().RSA_SQ) {
            modExp(ResourceManager.TWO, modulo);
        } else {
            modMult(this, this, modulo);
        }
    }

    /**
     * Negate current BigNat modulo provided modulus.
     *
     * @param mod modulus
     */
    public void modNegate(BigNat mod) {
        BigNat tmp = rm.BN_B;

        tmp.lock();
        tmp.setSize(mod.length());
        tmp.copy(mod);

        if (!this.lesser(mod)) {
            this.mod(mod);
        }
        tmp.subtract(this);
        this.copy(tmp);
        tmp.unlock();
    }
}
