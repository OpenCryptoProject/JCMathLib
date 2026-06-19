package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import javacard.security.KeyBuilder;

/**
 * @author Vasilios Mavroudis and Petr Svenda and Antonin Dufka, modified by Veronika Hanulikova
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
    public void ctDivide(BigNat other) {
        BigNat tmp = rm.BN_A; // rm.BN_Eis too big for ctIsLesser implementation over 128B numbers

        tmp.lock();
        tmp.ctClone( this);
        tmp.ctRemainderDivideOptimized(other, this);
        tmp.unlock();
    }

    /**
     * Greatest common divisor of this BigNat with other BigNat. Result is stored into this.
     */
    public void ctGcd(BigNat other) {
        BigNat tmp = rm.BN_A;
        BigNat tmpOther = rm.BN_B;

        tmp.lock();
        tmpOther.lock();

        tmpOther.ctClone(other);

        short thisZeros = ctShiftRightByTrailingZeroes((short) 0);
        short otherZeros = tmpOther.ctShiftRightByTrailingZeroes((short) 0);
        short done = 0;
        short count = 273;
        while(count > 0) {
            // Swap if necessary so other ≤ this
            short thisLesser = this.ctIsLesser(tmpOther);
            tmp.ctClone(this, done);
            this.ctClone(tmpOther, (short) (~thisLesser | done));
            tmpOther.ctClone(tmp, (short) (~thisLesser | done));
            // Identity 4: gcd(u, v) = gcd(u, v-u) as u ≤ v and u, v are both odd
            this.ctSubtract(tmpOther, done);
            // this is now even
            done |= this.ctIsZero();

            // Identity 3: gcd(u, 2ʲ v) = gcd(u, v) as u is odd
            this.ctShiftRightByTrailingZeroes(done);
            count--;
        }
        this.ctClone(tmpOther);
        short min = ConstantTime.ctSelect((ConstantTime.ctLessThan(thisZeros, otherZeros)), thisZeros, otherZeros);
        this.ctShiftLeft(min);
        ctShrink();
    }

    /**
     * Decides whether the arguments are co-prime or not.
     */
    public short ctIsCoprime(BigNat other) {
        BigNat tmp = rm.BN_C;

        tmp.lock();
        tmp.ctClone(this);

        tmp.ctGcd(other);
        short result = tmp.ctIsOne();
        tmp.unlock();
        return result;
    }

    /**
     * Square computation supporting base greater than MAX_BIGNAT_LENGTH.
     * Constant-time implementation.
     * Use with RSA_SQ = 0x0000, when length of number is smaller than 2 or bigger than 155
     */
    public void ctSq() {
        if (OperationSupport.getInstance().RSA_SQ != (short) 0xffff) {
            BigNat tmp = rm.BN_E;
            tmp.lock();
            tmp.ctSetSize(length());
            tmp.ctCopy(this);
            super.ctMult(tmp);
            tmp.unlock();
            return;
        }

        if ((short) (rm.MAX_SQ_LENGTH - 1) < (short) (2 * length())) {
            ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDSQ);
        }

        byte[] resultBuffer = rm.ARRAY_A;
        byte[] tmpBuffer = rm.ARRAY_B;
        short offset = (short) (rm.MAX_SQ_LENGTH - length());

        rm.lock(resultBuffer);
        rm.lock(tmpBuffer);
        Util.arrayFillNonAtomic(resultBuffer, (short) 0, offset, (byte) 0x00);
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, offset, (byte) 0x00);
        ctCopyToByteArray(resultBuffer, offset);
        ctCopyToByteArray(tmpBuffer, offset);
        short len = rm.sqCiph.doFinal(resultBuffer, (short) 0, rm.MAX_SQ_LENGTH, resultBuffer, (short) 0);
        rm.sqCiph.doFinal(tmpBuffer, (short) 0, rm.MAX_SQ_LENGTH, tmpBuffer, (short) 0);
        BigNat tmp = rm.BN_E;
        tmp.lock();
        tmp.ctSetSize(length());

        short lenMax = ConstantTime.ctEqual(len, rm.MAX_SQ_LENGTH);
        short blind = (short) (~(~lenMax & OperationSupport.getInstance().RSA_PREPEND_ZEROS));
        CTUtil.ctArrayCopyNonAtomic(resultBuffer, (short) 0, resultBuffer, (short) (rm.MAX_SQ_LENGTH - len), len, blind);
        CTUtil.ctArrayFillNonAtomic(resultBuffer, (short) 0, (short) (rm.MAX_SQ_LENGTH - len), (byte) 0, blind);

        short zeroPrefix = (short) (rm.MAX_SQ_LENGTH - (short) 2 * length());
        fromByteArray(resultBuffer, zeroPrefix, (short) (rm.MAX_SQ_LENGTH - zeroPrefix));
        rm.unlock(resultBuffer);
        ctShrink();

        if ((~lenMax & ~OperationSupport.getInstance().RSA_PREPEND_ZEROS) == (short) 0xffff) {
            ISOException.throwIt(ReturnCodes.SW_ECPOINT_UNEXPECTED_KA_LEN);
        }
    }

    /**
     * Computes this * other and stores the result into this.
     */
    public void ctMult(BigNat other) {
        if (OperationSupport.getInstance().RSA_SQ == (short) 0x0000) {
            super.ctMultDirect(other);
            return;
        }

        BigNat result = rm.BN_F;
        BigNat tmp = rm.BN_G;

        result.lock();
        result.ctSetSize((short) ((length() > other.length() ? length() : other.length()) + 1));
        result.ctCopy(this);
        result.ctAdd(other);
        result.ctSq();

        tmp.lock();
        short thisLesser = ctIsLesser(other);
        tmp.ctClone(other, (short) ~thisLesser);
        tmp.ctSubtract(this,  (short) ~thisLesser);
        tmp.ctClone(this, thisLesser);
        tmp.ctSubtract(other, thisLesser);
        tmp.ctSq();

        result.ctSubtract(tmp);
        tmp.unlock();
        result.ctShiftRightBits((short) 2);

        ctSetSizeToMax(false, (short) 0x00);
        ctCopy(result);
        ctShrink();
        result.unlock();
    }

    /**
     * Computes modulo and stores the result in this.
     */
    public void ctMod(BigNat mod) {
        BigNat tmpQuotient = rm.BN_C;
        tmpQuotient.lock();
        ctRemainderDivideOptimized(mod, tmpQuotient);
        tmpQuotient.unlock();
    }

    /**
     * Negate current BigNat modulo provided modulus.
     */
    public void ctModNegate(BigNat mod) {
        BigNat tmp = rm.BN_B;

        tmp.lock();
        tmp.ctClone(mod);
        tmp.ctSubtract(this);
        ctSetSize(mod.length());
        ctCopy(tmp);
        tmp.unlock();
    }

    /**
     * Modular addition of a BigNat to this.
     */
    public void ctModAdd(BigNat other, BigNat mod) {
        ctResize((short) (mod.length() + 1));
        ctAdd(other);
        short thisIsLesser = ctIsLesser(mod);
        ctSubtract(mod, thisIsLesser);
        ctSetSize(mod.length());
    }

    /**
     * Modular subtraction of a BigNat from this.
     */
    public void ctModSub(BigNat other, BigNat mod) {
        ctResize((short) (mod.length() + 1));
        short thisLesser = ctIsLesser(other);
        ctAdd(mod, (short) (~thisLesser));
        ctSubtract(other);
        ctSetSize(mod.length());
    }

    /**
     * Square this mod a modulus fixed with fixModSqMod method.
     */
    private short ctModSqFixed() {
        short error = 0;

        BigNat tmpMod = rm.BN_F;
        byte[] tmpBuffer = rm.ARRAY_A;
        short modLength;

        tmpMod.ctSetSize(rm.MAX_EXP_LENGTH);

        // not based on sensitive data, might stay as it is
        if (OperationSupport.getInstance().RSA_RESIZE_MOD == (short) 0xffff) {
            modLength = rm.MAX_EXP_LENGTH;
        } else {
            modLength = rm.fixedMod.length();
        }

        ctPrependZeros(modLength, tmpBuffer, (short) 0);
        short len = rm.modSqCiph.doFinal(tmpBuffer, (short) 0, modLength, tmpBuffer, (short) 0);

        // len == rm.MAX_EXP_LENGTH
        short validLength = ConstantTime.ctEqual(len, rm.MAX_EXP_LENGTH);
        // len != rm.MAX_EXP_LENGTH && !OperationSupport.getInstance().RSA_PREPEND_ZEROS
        error = (short) (~validLength & ~OperationSupport.getInstance().RSA_PREPEND_ZEROS);
        short mask = (short) (~validLength & OperationSupport.getInstance().RSA_PREPEND_ZEROS);
        CTUtil.ctArrayCopyNonAtomic(tmpBuffer, (short) 0, tmpBuffer, (short) (rm.MAX_EXP_LENGTH - len), len, (short) ~mask);
        CTUtil.ctArrayFillNonAtomic(tmpBuffer, (short) 0, (short) (rm.MAX_EXP_LENGTH - len), (byte) 0, (short) ~mask);

        tmpMod.ctFromByteArray(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);

        // not based on sensitive data, might stay as it is
        if (OperationSupport.getInstance().RSA_EXTRA_MOD == (short) 0xffff) {
            tmpMod.ctMod(rm.fixedMod);
        }
        ctSetSize(rm.fixedMod.length(), error);
        ctCopy(tmpMod, error);
        return error;
    }


    /**
     * Computes (this ^ exp % mod) using RSA algorithm and store results into this.
     * @param exp
     * @param mod
     * @implNote will not work when
     *  1. exponent is 1 AND card does not support RSA with exponent 1
     *  2. exponent is 2 AND card does not support using RSA for squaring
     */
    public void ctModExp(BigNat exp, BigNat mod) {
        // These branches are hard to incorporate into CT code, let it leak
        if (OperationSupport.getInstance().RSA_EXP != (short) 0xffff)
            ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);
        if ((OperationSupport.getInstance().RSA_CHECK_EXP_ONE & exp.ctIsOne()) == (short) 0xffff)
            return;
        if ((~OperationSupport.getInstance().RSA_SQ & exp.ctIsTwo()) == (short) 0xffff) {
            ctModMult(this, mod);
            return;
        }

        BigNat tmpMod = rm.BN_F; // modExp is called from modSqrt => requires BN_F not being locked when modExp is called
        byte[] tmpBuffer = rm.ARRAY_A;
        short modLength;

        tmpMod.lock();
        tmpMod.ctSetSize(rm.MAX_EXP_LENGTH);

        if (OperationSupport.getInstance().RSA_PUB == (short) 0xffff) {
            // Verify if pre-allocated engine match the required values
            // leaking length of mod
            if (rm.expPub.getSize() < (short) (mod.length() * 8) || rm.expPub.getSize() < (short) (length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (OperationSupport.getInstance().RSA_KEY_REFRESH == (short) 0xffff) {
                // Simulator fails when reusing the original object
                rm.expPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rm.MAX_EXP_BIT_LENGTH, false);
            }
            rm.lock(tmpBuffer);
            short len = exp.ctCopyToByteArray(tmpBuffer, (short) 0);
            rm.expPub.setExponent(tmpBuffer, (short) 0, len);
            if (OperationSupport.getInstance().RSA_RESIZE_MOD == (short) 0xffff) {
                if (OperationSupport.getInstance().RSA_APPEND_MOD == (short) 0xffff) {
                    mod.ctAppendZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                } else {
                    mod.ctAppendZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                }
                rm.expPub.setModulus(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);
                modLength = rm.MAX_EXP_LENGTH;
            } else {
                modLength = mod.ctCopyToByteArray(tmpBuffer, (short) 0);
                rm.expPub.setModulus(tmpBuffer, (short) 0, modLength);
            }
            rm.expCiph.init(rm.expPub, Cipher.MODE_DECRYPT);
        } else {
            // Verify if pre-allocated engine match the required values
            // leaking length of mod
            if (rm.expPriv.getSize() < (short) (mod.length() * 8) || rm.expPriv.getSize() < (short) (length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (OperationSupport.getInstance().RSA_KEY_REFRESH == (short) 0xffff) {
                // Simulator fails when reusing the original object
                rm.expPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, rm.MAX_EXP_BIT_LENGTH, false);
            }
            rm.lock(tmpBuffer);
            short len = exp.ctCopyToByteArray(tmpBuffer, (short) 0);
            rm.expPriv.setExponent(tmpBuffer, (short) 0, len);
            if (OperationSupport.getInstance().RSA_RESIZE_MOD == (short) 0xffff) {
                if (OperationSupport.getInstance().RSA_APPEND_MOD == (short) 0xffff) {
                    mod.ctAppendZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);
                } else {
                    mod.ctPrependZeros(rm.MAX_EXP_LENGTH, tmpBuffer, (short) 0);

                }
                rm.expPriv.setModulus(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);
                modLength = rm.MAX_EXP_LENGTH;
            } else {
                modLength = mod.ctCopyToByteArray(tmpBuffer, (short) 0);
                rm.expPriv.setModulus(tmpBuffer, (short) 0, modLength);
            }
            rm.expCiph.init(rm.expPriv, Cipher.MODE_DECRYPT);
        }

        ctPrependZeros(modLength, tmpBuffer, (short) 0);
        short len = rm.expCiph.doFinal(tmpBuffer, (short) 0, modLength, tmpBuffer, (short) 0);

        // len == rm.MAX_EXP_LENGTH
        short validLength = ConstantTime.ctEqual(len, rm.MAX_EXP_LENGTH);
        // len != rm.MAX_EXP_LENGTH && !OperationSupport.getInstance().RSA_PREPEND_ZEROS
        short error = (short) (~validLength & ~OperationSupport.getInstance().RSA_PREPEND_ZEROS);
        short mask = (short) (~validLength & OperationSupport.getInstance().RSA_PREPEND_ZEROS);
        CTUtil.ctArrayCopyNonAtomic(tmpBuffer, (short) 0, tmpBuffer, (short) (rm.MAX_EXP_LENGTH - len), len, (short) ~mask);
        CTUtil.ctArrayFillNonAtomic(tmpBuffer, (short) 0, (short) (rm.MAX_EXP_LENGTH - len), (byte) 0, (short) ~mask);

        tmpMod.ctFromByteArray(tmpBuffer, (short) 0, rm.MAX_EXP_LENGTH);
        rm.unlock(tmpBuffer);

        if (OperationSupport.getInstance().RSA_EXTRA_MOD == (short) 0xffff) {
            tmpMod.ctMod(mod);
        }
        ctSetSize(mod.length(), error);
        ctCopy(tmpMod, error);
        tmpMod.unlock();
    }


    /**
     * Computes modular inversion. The result is stored into this.
     */
    public void ctModInv(BigNat mod) {
        BigNat tmp = rm.BN_B;
        tmp.lock();
        tmp.ctClone(mod);
        tmp.ctSubtract(ResourceManager.TWO);

        ctModExp(tmp, mod);
        tmp.unlock();
    }

    /**
     * Multiplication of this and other modulo mod. The result is stored to this.
     * @param other
     * @param mod
     * @implNote will not work, when this is 1
     */
    public void ctModMult(BigNat other, BigNat mod) {
        BigNat tmp = rm.BN_D;
        BigNat result = rm.BN_E;

        result.lock();
        if ((OperationSupport.getInstance().RSA_SQ != (short) 0xffff) || (OperationSupport.getInstance().RSA_EXTRA_MOD == (short) 0xffff)) {
            // simple slow implementation
            result.ctClone(this);
            result.ctMult(other);
            result.ctMod(mod);
        } else {
            result.ctSetSize((short) (mod.length() + 1));
            result.ctCopy(this);
            result.ctAdd(other);

            short isOdd = result.ctIsOdd();
            short isLesser = result.ctIsLesser(mod);
            short carry = result.ctAdd(mod, (short) ~(isOdd & isLesser));
            result.ctSubtract(mod, (short) ~(isOdd & ~isLesser));

            result.ctShiftRightBits((short) 1, carry);
            result.ctResize(mod.length());

            tmp.lock();
            tmp.ctClone(result);
            tmp.ctModSub(other, mod);

            result.ctModSq(mod);
            tmp.ctModSq(mod);

            result.ctModSub(tmp, mod);
            tmp.unlock();
        }
        ctSetSize(mod.length());
        ctCopy(result);
        result.unlock();
    }

    /**Constant-time implementation of modulo square of this BigNat.
     *
     * @param mod modulo BigNat
     */
    public void ctModSq(BigNat mod) {
        if (OperationSupport.getInstance().RSA_SQ == (short) 0xffff) {
            if (rm.fixedMod != null && rm.fixedMod == mod) {
                ctModSqFixed();
            } else {
                ctModExp(ResourceManager.TWO, mod);
            }
        } else {
            ctModMult(this, mod);
        }
    }

    /**
     * Checks whether this BigNat is a quadratic residue modulo p.
     * @param p modulo
     */
    public short ctIsQuadraticResidue(BigNat p) {
        BigNat tmp = rm.BN_A;
        BigNat exp = rm.BN_B;
        tmp.ctClone(this);
        exp.ctClone(p);
        exp.ctDecrement();
        exp.ctShiftRight((short) 1, (short) 0x00);
        tmp.ctModExp(exp, p);
        return tmp.ctIsOne();
    }

    /**
     * Computes square root of provided BigNat which MUST be prime using Tonelli Shanks Algorithm. The result (one of
     * the two roots) is stored to this.
     *
     * @implNote: CT methods applied but due to the nature of the algorithm reimplemented version with bounded loops would be unusably slow
     */
    public void ctModSqrt(BigNat p) {
        BigNat exp = rm.BN_G;
        BigNat p1 = rm.BN_B;
        BigNat q = rm.BN_C;
        BigNat tmp = rm.BN_D;
        BigNat z = rm.BN_A;
        BigNat t = rm.BN_B;
        BigNat b = rm.BN_C;

        // 1. Find Q and S such that p - 1 = Q * 2^S and Q is odd
        p1.lock();
        p1.ctClone(p);
        p1.ctDecrement();

        q.lock();
        q.ctClone(p1);

        short s = 0;
        while (q.ctIsOdd() == (short) 0x0000) {
            ++s;
            q.ctShiftRightBits((short) 1);
        }

        // 2. Find the first quadratic non-residue z by brute-force search
        exp.lock();
        exp.ctClone(p1);
        exp.ctShiftRightBits((short) 1);

        z.lock();
        z.ctSetSize(p.length());
        z.ctSetValue((byte) 1);
        tmp.lock();
        tmp.ctSetSize(p.length());
        tmp.ctSetValue((byte) 1);

        while (tmp.ctEquals(p1) == (short) 0x0000) {
            z.ctIncrement();
            tmp.ctCopy(z);
            tmp.ctModExp(exp, p); // Euler's criterion
        }
        p1.unlock();
        tmp.unlock();

        // 3. Compute the first candidate
        exp.ctClone(q);
        exp.ctIncrement();
        exp.ctShiftRightBits((short) 1);

        t.lock();
        t.ctClone(this);
        t.ctModExp(q, p);

        if (t.ctIsZero() == (short) 0xffff) {
            z.unlock();
            t.unlock();
            exp.unlock();
            q.unlock();
            ctZero();
            return;
        }

        ctMod(p);
        ctModExp(exp, p);
        exp.unlock();

        if (t.ctIsOne() == (short) 0xffff) {
            z.unlock();
            t.unlock();
            q.unlock();
            return;
        }

        // 4. Search for further candidates
        z.ctModExp(q, p);
        q.unlock();

        while(true) {
            tmp.lock();
            tmp.ctClone(t);
            short i = 0;

            do {
                tmp.ctModSq(p);
                ++i;
            } while (tmp.ctIsOne() == (short) 0x0000);

            tmp.unlock();

            b.lock();
            b.ctClone(z);
            s -= i;
            --s;

            tmp.lock();
            tmp.ctSetSize((short) 1);
            tmp.ctSetValue((byte) 1);
            while(s != 0) {
                tmp.ctShiftLeftBits((short) 1);
                --s;
            }
            b.ctModExp(tmp, p);
            tmp.unlock();
            s = i;
            z.ctClone(b);
            z.ctModSq(p);
            t.ctModMult(z, p);
            ctModMult(b, p);
            b.unlock();

            if(t.ctIsZero() == (short) 0xffff) {
                ctZero();
                break;
            }
            if(t.ctIsOne() == (short) 0xffff) {
                break;
            }
        }
        z.unlock();
        t.unlock();
    }
}
