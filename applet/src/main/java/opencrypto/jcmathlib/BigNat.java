package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import javacard.security.KeyBuilder;

/**
 * Credits: Based on BigNat library from <a href="https://ovchip.cs.ru.nl/OV-chip_2.0">OV-chip project.</a> by Radboud University Nijmegen
 *
 * @author Vasilios Mavroudis and Petr Svenda
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
     * Construct a BigNat with provided array used as internal storage as well as initial value.
     *
     * @param valueBuffer internal storage
     */
    public BigNat(byte[] valueBuffer, ResourceManager rm) {
        super(valueBuffer, rm);
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
     * @return true if coprime, false otherwise
     */
    public boolean isCoprime(BigNat a, BigNat b) {
        BigNat tmp = rm.BN_C;

        tmp.lock();
        tmp.clone(a);

        tmp.gcd(b);
        return tmp.equals(ResourceManager.ONE);
    }

    /**
     * Computes base^exp and stores result into this BigNat
     *
     * @param base value of base
     * @param exp  value of exponent
     */
    public void exponentiation(BigNat base, BigNat exp) {
        BigNat tmp = rm.BN_A;
        BigNat i = rm.BN_B;

        this.setValue((byte) 1);
        i.lock();
        i.setSize(exp.length());
        i.zero();
        tmp.lock();
        tmp.setSize((short) (2 * this.length()));
        for (; i.lesser(exp); i.increment()) {
            tmp.mult(this, base);
            this.copy(tmp);
        }
        i.unlock();
        tmp.unlock();
    }

    /**
     * Computes x * y and stores the result into this. Chooses computation approach based on operation support and operand size.
     *
     * @param x left operand
     * @param y right operand
     */
    public void mult(BigNat x, BigNat y) {
        if (!OperationSupport.getInstance().RSA_MULT_TRICK || x.length() < (short) 16) {
            multSchoolbook(x, y);
        } else {
            multRsaTrick(x, y, null, null);
        }
    }

    /**
     * Performs multiplication of two BigNat x and y and stores result into this.
     * RSA engine is used to speedup operation for large values.
     *
     * @param x   first value to multiply
     * @param y   second value to multiply
     * @param mod modulus
     */
    private void modMultRsaTrick(BigNat x, BigNat y, BigNat mod) {
        this.clone(x);
        this.modAdd(y, mod);
        this.modSq(mod);

        BigNat tmp = rm.BN_D;
        tmp.lock();
        tmp.clone(x);
        tmp.modSq(mod);
        this.modSub(tmp, mod);

        tmp.clone(y);
        tmp.modSq(mod);
        this.modSub(tmp, mod);
        tmp.unlock();

        boolean carry = false;
        if (this.isOdd()) {
            carry = this.addCarry(mod);
        }

        this.divideByTwo(carry ? (short) (1 << 7) : (short) 0);
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
        BigNat tmp = rm.BN_E; // modMult is called from modSqrt => requires BN_E not being locked when modMult is called

        tmp.lock();

        if (OperationSupport.getInstance().RSA_MOD_MULT_TRICK) {
            tmp.modMultRsaTrick(x, y, mod);
        } else {
            tmp.resizeToMax(false);
            tmp.mult(x, y);
            tmp.mod(mod);
            tmp.shrink();
        }
        this.clone(tmp);
        tmp.unlock();
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
        q.divideByTwo(); // Q /= 2

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
        exp.divideByTwo();


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
        exp.divideByTwo();

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
        modExp(ResourceManager.TWO, modulo);
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
