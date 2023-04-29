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
     * Construct a BigNat of a given size in bytes.
     */
    public BigNat(short size, byte allocatorType, ResourceManager rm) {
        super(size, allocatorType, rm);
    }

    /**
     * Division of this BigNat by provided other BigNat.
     */
    public void divide(BigNat other) {
        BigNat tmp = rm.BN_E;

        tmp.lock();
        tmp.clone(this);
        tmp.remainderDivide(other, this);
        copy(tmp);
        tmp.unlock();
    }

    /**
     * Greatest common divisor of this BigNat with other BigNat. Result is stored into this.
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
            mod(tmpOther);
            tmpOther.clone(this);
            clone(tmp);
        }

        tmp.unlock();
        tmpOther.unlock();
    }

    /**
     * Decides whether the arguments are co-prime or not.
     */
    public boolean isCoprime(BigNat a, BigNat b) {
        BigNat tmp = rm.BN_C;

        tmp.lock();
        tmp.clone(a);

        tmp.gcd(b);
        boolean result = tmp.isOne();
        tmp.unlock();
        return result;
    }

    /**
     * Square computation supporting base greater than MAX_BIGNAT_LENGTH.
     */
    public void sq() {
        if (!OperationSupport.getInstance().RSA_SQ) {
            BigNat tmp = rm.BN_E;
            tmp.lock();
            tmp.setSize(this.length());
            tmp.copy(this);
            setSizeToMax(true);
            super.mult(tmp, tmp);
            shrink();
            return;
        }
        if ((short) (rm.MAX_SQ_LENGTH - 1) < (short) (2 * length())) {
            ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDSQ);
        }

        byte[] resultBuffer = rm.ARRAY_A;
        short offset = (short) (rm.MAX_SQ_LENGTH - length());

        rm.lock(resultBuffer);
        Util.arrayFillNonAtomic(resultBuffer, (short) 0, offset, (byte) 0x00);
        copyToByteArray(resultBuffer, offset);
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
     * Computes x * y and stores the result into this.
     */
    public void mult(BigNat x, BigNat y) {
        if (OperationSupport.getInstance().RSA_CHECK_ONE && x.isOne()) {
            clone(y);
            return;
        }
        if (!OperationSupport.getInstance().RSA_SQ || x.length() <= (short) 16) {
            setSizeToMax(true);
            super.mult(x, y);
            shrink();
            return;
        }

        BigNat result = rm.BN_F;
        BigNat tmp = rm.BN_G;

        result.lock();
        result.clone(x);
        result.add(y);
        result.sq();

        tmp.lock();
        if (x.isLesser(y)) {
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

        copy(result);
        result.unlock();
    }

    /**
     * Computes modulo and stores the result in this.
     */
    public void mod(BigNat mod) {
        remainderDivide(mod, null);
    }

    /**
     * Negate current BigNat modulo provided modulus.
     */
    public void modNegate(BigNat mod) {
        BigNat tmp = rm.BN_B;

        tmp.lock();
        tmp.clone(mod);
        tmp.subtract(this);
        setSize(mod.length());
        copy(tmp);
        tmp.unlock();
    }

    /**
     * Modular addition of a BigNat to this.
     */
    public void modAdd(BigNat other, BigNat mod) {
        BigNat tmp = rm.BN_A;

        tmp.lock();
        tmp.setSize((short) (mod.length() + 1));
        tmp.copy(this);
        tmp.add(other);
        if (!tmp.isLesser(mod)) {
            tmp.subtract(mod);
        }
        setSize(mod.length());
        copy(tmp);
        tmp.unlock();
    }

    /**
     * Modular subtraction of a BigNat from this.
     */
    public void modSub(BigNat other, BigNat mod) {
        BigNat tmp = rm.BN_A;

        tmp.lock();
        tmp.setSize((short) (mod.length() + 1));
        tmp.copy(this);
        if (tmp.isLesser(other)) {
            tmp.add(mod);
        }
        tmp.subtract(other);
        setSize(mod.length());
        copy(tmp);
        tmp.unlock();
    }

    /**
     * Computes (this ^ exp % mod) using RSA algorithm and store results into this.
     */
    public void modExp(BigNat exp, BigNat mod) {
        if (!OperationSupport.getInstance().RSA_EXP)
            ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);

        BigNat tmpMod = rm.BN_F; // modExp is called from modSqrt => requires BN_F not being locked when modExp is called
        byte[] tmpBuffer = rm.ARRAY_A;
        short modLength;

        tmpMod.lock();
        tmpMod.setSize(rm.MAX_EXP_LENGTH);

        if (OperationSupport.getInstance().RSA_PUB) {
            // Verify if pre-allocated engine match the required values
            if (rm.expPub.getSize() < (short) (mod.length() * 8) || rm.expPub.getSize() < (short) (length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (OperationSupport.getInstance().RSA_KEY_REFRESH) {
                // Simulator fails when reusing the original object
                rm.expPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rm.MAX_EXP_BIT_LENGTH, false);
            }
            rm.lock(tmpBuffer);
            short len = exp.copyToByteArray(tmpBuffer, (short) 0);
            rm.expPub.setExponent(tmpBuffer, (short) 0, len);
            if (OperationSupport.getInstance().RSA_RESIZE_MOD) {
                if (OperationSupport.getInstance().RSA_APPEND_MOD) {
                    mod.appendZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                } else {
                    mod.prependZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                }
                rm.expPub.setModulus(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);
                modLength = rm.MAX_EXP_LENGTH;
            } else {
                modLength = mod.copyToByteArray(tmpBuffer, (short) 0);
                rm.expPub.setModulus(tmpBuffer, (short) 0, modLength);
            }
            rm.expCiph.init(rm.expPub, Cipher.MODE_DECRYPT);
        } else {
            // Verify if pre-allocated engine match the required values
            if (rm.expPriv.getSize() < (short) (mod.length() * 8) || rm.expPriv.getSize() < (short) (length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (OperationSupport.getInstance().RSA_KEY_REFRESH) {
                // Simulator fails when reusing the original object
                rm.expPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, rm.MAX_EXP_BIT_LENGTH, false);
            }
            rm.lock(tmpBuffer);
            short len = exp.copyToByteArray(tmpBuffer, (short) 0);
            rm.expPriv.setExponent(tmpBuffer, (short) 0, len);
            if (OperationSupport.getInstance().RSA_RESIZE_MOD) {
                if (OperationSupport.getInstance().RSA_APPEND_MOD) {
                    mod.appendZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                } else {
                    mod.prependZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);

                }
                rm.expPriv.setModulus(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);
                modLength = rm.MAX_EXP_LENGTH;
            } else {
                modLength = mod.copyToByteArray(tmpBuffer, (short) 0);
                rm.expPriv.setModulus(tmpBuffer, (short) 0, modLength);
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
            tmpMod.mod(mod);
        }
        setSize(mod.length());
        copy(tmpMod);
        tmpMod.unlock();
    }

    /**
     * Computes modular inversion. The result is stored into this.
     */
    public void modInv(BigNat mod) {
        BigNat tmp = rm.BN_B;
        tmp.lock();
        tmp.clone(mod);
        tmp.decrement();
        tmp.decrement();

        modExp(tmp, mod);
        tmp.unlock();
    }

    /**
     * Multiplication of BigNats x and y computed modulo mod. The result is stored to this.
     */
    public void modMult(BigNat x, BigNat y, BigNat mod) {
        BigNat tmp = rm.BN_D;
        BigNat result = rm.BN_E;

        setSize(mod.length());
        if (OperationSupport.getInstance().RSA_CHECK_ONE && x.isOne()) {
            copy(y);
            return;
        }

        result.lock();
        if (!OperationSupport.getInstance().RSA_SQ) {
            result.setSizeToMax(false);
            result.mult(x, y);
            result.mod(mod);
        } else {
            result.clone(x);
            result.modAdd(y, mod);

            result.resize(mod.length());
            short carry = (byte) 0;
            if (result.isOdd()) {
                carry = result.add(mod);
            }
            result.shiftRight((short) 1, carry);

            tmp.lock();
            tmp.clone(result);
            tmp.modSub(y, mod);

            result.modSq(mod);
            tmp.modSq(mod);

            result.modSub(tmp, mod);
            tmp.unlock();
        }
        copy(result);
        result.unlock();
    }

    /**
     * Computes modulo square of this BigNat.
     */
    public void modSq(BigNat mod) {
        if (OperationSupport.getInstance().RSA_SQ) {
            modExp(ResourceManager.TWO, mod);
        } else {
            modMult(this, this, mod);
        }
    }

    /**
     * Computes square root of provided BigNat which MUST be prime using Tonelli Shanks Algorithm. The result (one of
     * the two roots) is stored to this.
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
            // TODO replace with modMult(s, q, p)
            tmp.setSizeToMax(false);
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
        tmp.setValue((byte) 1);

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

        mod(p);
        modExp(exp, p);
        exp.unlock();
    }
}
