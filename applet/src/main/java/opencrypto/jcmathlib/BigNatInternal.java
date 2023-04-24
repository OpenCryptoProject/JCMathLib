package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Based on BigNat library from <a href="https://ovchip.cs.ru.nl/OV-chip_2.0">OV-chip project.</a> by Radboud University Nijmegen
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class BigNatInternal {
    protected final ResourceManager rm;
    private final boolean ALLOW_RUNTIME_REALLOCATION = false;
    private static final short DIGIT_MASK = 0xff, DIGIT_LEN = 8, DOUBLE_DIGIT_LEN = 16, POSITIVE_DOUBLE_DIGIT_MASK = 0x7fff;

    private byte[] value;
    private short size = -1; // The current size of internal representation in bytes.
    private byte allocatorType;

    /**
     * Construct a BigNat of given size in bytes.
     *
     * @param size the size of the new BigNat in bytes
     * @param allocatorType type of allocator storage
     */
    public BigNatInternal(short size, byte allocatorType, ResourceManager rm) {
        this.rm = rm;
        this.allocatorType = allocatorType;
        allocateStorageArray(size, allocatorType);
    }

    /**
     * Allocates required underlying storage array.
     *
     * @param maxSize maximum size of this BigNat in bytes
     * @param allocatorType type of allocator storage
     */
    private void allocateStorageArray(short maxSize, byte allocatorType) {
        this.size = maxSize;
        this.allocatorType = allocatorType;
        this.value = rm.memAlloc.allocateByteArray(maxSize, allocatorType);
    }

    /**
     * Return a byte representation of this BigNat.
     *
     * @return the byte array
     */
    public byte[] asByteArray() {
        return value;
    }

    /**
     * Set value of this from a byte array representation.
     *
     * @param source the byte array
     * @param sourceOffset offset in the byte array
     * @param length length of the value representation
     * @return number of bytes read
     */
    public short fromByteArray(byte[] source, short sourceOffset, short length) {
        short read = length <= (short) value.length ? length : (short) value.length;
        setSize(read);
        Util.arrayCopyNonAtomic(source, sourceOffset, value, (short) 0, read);
        return read;
    }

    /**
     * Serialize this BigNat value into a provided byte array.
     *
     * @param dst the byte array
     * @param dstOffset offset in the byte array
     * @return number of bytes written
     */
    public short copyToByteArray(byte[] dst, short dstOffset) {
        Util.arrayCopyNonAtomic(value, (short) 0, dst, dstOffset, size);
        return size;
    }

    /**
     * Get size of this BigNat in bytes.
     *
     * @return size in bytes
     */
    public short length() {
        return size;
    }

    /**
     * Sets the size of this BigNat in bytes.
     *
     * Previous value is kept so value is either non-destructively trimmed or enlarged.
     *
     * @param newSize the new size
     */
    public void setSize(short newSize) {
        if (newSize < 0 || newSize > value.length) {
            ISOException.throwIt(ReturnCodes.SW_BIGNAT_RESIZETOLONGER);
        }
        size = newSize;
    }

    /**
     * Set size of this BigNat to the maximum size given during object creation.
     *
     * @param erase flag indicating whether to set internal representation to zero
     */
    public void setSizeToMax(boolean erase) {
        setSize((short) value.length);
        if (erase) {
            erase();
        }
    }

    /**
     * Resize this BigNat value to given size in bytes. May result in truncation.
     *
     * @param newSize new size in bytes
     */
    public void resize(short newSize) {
        if (newSize > (short) value.length) {
            if (!ALLOW_RUNTIME_REALLOCATION) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED);
            }
            allocateStorageArray(newSize, allocatorType);
        }

        if (size == newSize) {
            return;
        }
        if (size >= newSize) {
            Util.arrayCopyNonAtomic(value, (short) (size - newSize), value, (short) 0, newSize);
            Util.arrayFillNonAtomic(value, newSize, (short) ((short) value.length - newSize), (byte) 0);
        } else {
            short end = (short) (newSize - size);
            Util.arrayCopyNonAtomic(value, (short) 0, value, end, size);
            Util.arrayFillNonAtomic(value, (short) 0, end, (byte) 0);
        }
        setSize(newSize);
    }

    /**
     * Append zeros to reach the defined byte length and store the result in an output buffer.
     *
     * @param targetLength required length including appended zeroes
     * @param outBuffer    output buffer for value with appended zeroes
     * @param outOffset    start offset inside outBuffer for write
     */
    public void appendZeros(short targetLength, byte[] outBuffer, short outOffset) {
        Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, outOffset, size);
        Util.arrayFillNonAtomic(outBuffer, (short) (outOffset + size), (short) (targetLength - size), (byte) 0);
    }

    /**
     * Prepend zeros to reach the defined byte length and store the result in an output buffer.
     *
     * @param targetLength required length including prepended zeroes
     * @param outBuffer    output buffer for value with prepended zeroes
     * @param outOffset    start offset inside outBuffer for write
     */
    public void prependZeros(short targetLength, byte[] outBuffer, short outOffset) {
        short start = (short) (targetLength - size);
        if (start > 0) {
            Util.arrayFillNonAtomic(outBuffer, outOffset, start, (byte) 0);
        }
        Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, (short) (outOffset + start), size);
    }

    /**
     * Remove leading zeroes from this BigNat and decrease its byte size accordingly.
     */
    public void shrink() {
        short i;
        for (i = 0; i < length(); i++) { // Find first non-zero byte
            if (value[i] != 0) {
                break;
            }
        }

        short newSize = (short) (size - i);
        if (newSize < 0) {
            ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDRESIZE);
        }
        resize(newSize);
    }

    /**
     * Set this BigNat value to zero. Previous size is kept.
     */
    public void zero() {
        Util.arrayFillNonAtomic(value, (short) 0, size, (byte) 0);
    }

    /**
     * Erase the internal array of this BigNat.
     */
    public void erase() {
        Util.arrayFillNonAtomic(value, (short) 0, (short) value.length, (byte) 0);
    }

    /**
     * Set this BigNat to a given value. Previous size is kept.
     */
    public void setValue(byte newValue) {
        zero();
        value[(short) (size - 1)] = (byte) (newValue & DIGIT_MASK);
    }

    /**
     * Set this BigNat to a given value. Previous size is kept.
     */
    public void setValue(short newValue) {
        zero();
        value[(short) (size - 1)] = (byte) (newValue & DIGIT_MASK);
        value[(short) (size - 2)] = (byte) (newValue & (short) (DIGIT_MASK << 8));
    }

    /**
     * Copies a BigNat into this without changing size. May throw an exception if this is too small.
     */
    public void copy(BigNatInternal other) {
        short thisStart, otherStart, len;
        if (size >= other.size) {
            thisStart = (short) (size - other.size);
            otherStart = 0;
            len = other.size;

            if (thisStart > 0) {
                Util.arrayFillNonAtomic(value, (short) 0, thisStart, (byte) 0);
            }
        } else {
            thisStart = 0;
            otherStart = (short) (other.size - size);
            len = size;
            // Verify here that other have leading zeroes up to otherStart
            for (short i = 0; i < otherStart; i++) {
                if (other.value[i] != 0) {
                    ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDCOPYOTHER);
                }
            }
        }
        Util.arrayCopyNonAtomic(other.value, otherStart, value, thisStart, len);
    }

    /**
     * Copies a BigNat into this including its size. May require reallocation.
     */
    public void clone(BigNatInternal other) {
        if (other.length() > (short) value.length) {
            if (!ALLOW_RUNTIME_REALLOCATION) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED);
            }
            allocateStorageArray(other.length(), allocatorType);
        }

        other.copyToByteArray(value, (short) 0);
        short diff = (short) ((short) value.length - other.length());
        if (diff > 0) {
            Util.arrayFillNonAtomic(value, other.length(), diff, (byte) 0);
        }
        this.size = other.length();
    }

    /**
     * Test equality with zero.
     */
    public boolean isZero() {
        for (short i = 0; i < size; i++) {
            if (value[i] != 0) {
                return false; // CTO
            }
        }
        return true;
    }

    /**
     * Test equality with one.
     */
    public boolean isOne() {
        for (short i = 0; i < (short) (size - 1); i++) {
            if (value[i] != 0) {
                return false; // CTO
            }
        }
        return value[(short) (size - 1)] == (byte) 0x01;
    }

    /**
     * Check if stored BigNat is odd.
     */
    public boolean isOdd() {
        return (byte) (value[(short) (size - 1)] & (byte) 1) != (byte) 0;
    }

    /**
     * Returns true if this BigNat is lesser than the other.
     */
    public boolean isLesser(BigNatInternal other) {
        return isLesser(other, (short) 0, (short) 0);
    }

    /**
     * Returns true if this is lesser than other shifted by a given number of digits.
     */
    private boolean isLesser(BigNatInternal other, short shift, short start) {
        short j = (short) (other.size + shift - size + start);

        for (short i = start; i < j; ++i) {
            if (other.value[i] != 0) {
                return true;
            }
        }

        for (short i = start; i < size; i++, j++) {
            short thisValue = (short) (value[i] & DIGIT_MASK);
            short otherValue = (j >= 0 && j < other.size) ? (short) (other.value[j] & DIGIT_MASK) : (short) 0;
            if (thisValue < otherValue) {
                return true; // CTO
            }
            if (thisValue > otherValue) {
                return false;
            }
        }
        return false;
    }

    /**
     * Increment this BigNat.
     */
    public void increment() {
        for (short i = (short) (size - 1); i >= 0; i--) {
            short tmp = (short) (value[i] & 0xff);
            value[i] = (byte) (tmp + 1);
            if (tmp < 255) {
                break; // CTO
            }
        }
    }

    /**
     * Decrement this BigNat.
     */
    public void decrement() {
        short tmp;
        for (short i = (short) (size - 1); i >= 0; i--) {
            tmp = (short) (value[i] & 0xff);
            value[i] = (byte) (tmp - 1);
            if (tmp != 0) {
                break; // CTO
            }
        }
    }

    /**
     * Add short value to this BigNat
     *
     * @param other short value to add
     */
    public byte add(short other) {
        rm.BN_WORD.lock();
        rm.BN_WORD.setValue(other);
        byte carry = add(rm.BN_WORD);
        rm.BN_WORD.unlock();
        return carry;
    }

    /**
     * Adds other to this. Outputs carry bit.
     *
     * @param other BigNat to add
     * @return true if carry occurs, false otherwise
     */
    public byte add(BigNatInternal other) {
        return add(other, (short) 0, (short) 1);
    }

    /**
     * Computes other * multiplier, shifts the results by shift and adds it to this.
     * Multiplier must be in range [0; 2^8 - 1].
     * This must be large enough to fit the results.
     */
    private byte add(BigNatInternal other, short shift, short multiplier) {
        short acc = 0;
        short i = (short) (other.size - 1);
        short j = (short) (size - 1 - shift);
        for (; i >= 0 && j >= 0; i--, j--) {
            acc += (short) ((short) (value[j] & DIGIT_MASK) + (short) (multiplier * (other.value[i] & DIGIT_MASK)));

            value[j] = (byte) (acc & DIGIT_MASK);
            acc = (short) ((acc >> DIGIT_LEN) & DIGIT_MASK);
        }

        for (; acc > 0 && j >= 0; --j) {
            acc += (short) (value[j] & DIGIT_MASK);
            value[j] = (byte) (acc & DIGIT_MASK);
            acc = (short) ((acc >> DIGIT_LEN) & DIGIT_MASK);
        }

        // output carry bit if present
        return (byte) ((byte) (((short) (acc | -acc) & (short) 0xFFFF) >>> 15) & 0x01);
    }

    /**
     * Subtract provided other BigNat from this BigNat.
     *
     * @param other BigNat to be subtracted from this
     */
    public void subtract(BigNatInternal other) {
        subtract(other, (short) 0, (short) 1);
    }

    /**
     * Computes other * multiplier, shifts the results by shift and subtract it from this.
     * Multiplier must be in range [0; 2^8 - 1].
     */
    private void subtract(BigNatInternal other, short shift, short multiplier) {
        short acc = 0;
        short i = (short) (size - 1 - shift);
        short j = (short) (other.size - 1);
        for (; i >= 0 && j >= 0; i--, j--) {
            acc += (short) (multiplier * (other.value[j] & DIGIT_MASK));
            short tmp = (short) ((value[i] & DIGIT_MASK) - (acc & DIGIT_MASK));

            value[i] = (byte) (tmp & DIGIT_MASK);
            acc = (short) ((acc >> DIGIT_LEN) & DIGIT_MASK);
            if (tmp < 0) {
                acc++;
            }
        }

        // deal with carry as long as there are digits left in this
        for (; i >= 0 && acc != 0; --i) {
            short tmp = (short) ((value[i] & DIGIT_MASK) - (acc & DIGIT_MASK));
            value[i] = (byte) (tmp & DIGIT_MASK);
            acc = (short) ((acc >> DIGIT_LEN) & DIGIT_MASK);
            if (tmp < 0) {
                acc++;
            }
        }
    }

    /**
     * Multiplies x and y using software multiplications and stores results into this.
     *
     * @param x left operand
     * @param y right operand
     */
    public void mult(BigNatInternal x, BigNatInternal y) {
        for (short i = (short) (y.size - 1); i >= 0; i--) {
            add(x, (short) (y.size - 1 - i), (short) (y.value[i] & DIGIT_MASK));
        }
    }

    /**
     * Right bit shift with carry
     *
     * @param bits number of bits to shift by
     * @param carry XORed into the highest byte
     */
    protected void shiftRight(short bits, short carry) {
        // assumes 0 <= bits < 8
        short mask = (short) ((short) (1 << bits) - 1); // lowest `bits` bits set to 1
        for (short i = 0; i < size; i++) {
            short current = (short) (value[i] & 0xff);
            short previous = current;
            current >>= bits;
            value[i] = (byte) (current | carry);
            carry = (short) (previous & mask);
            carry <<= (short) (8 - bits);
        }
    }

    /**
     * Right bit shift
     *
     * @param bits number of bits to shift by
     */
    public void shiftRight(short bits) {
        shiftRight(bits, (short) 0);
    }

    /**
     * Divide this by divisor and store the remained in this and quotient in quotient.
     *
     * Quadratic complexity in digit difference of this and divisor.
     *
     * @param divisor non-zero number
     * @param quotient may be null
     */
    public void remainderDivide(BigNatInternal divisor, BigNatInternal quotient) {
        if (quotient != null) {
            quotient.zero();
        }

        short divisorIndex = 0;
        while (divisor.value[divisorIndex] == 0) {
            divisorIndex++;
        }

        short divisorShift = (short) (size - divisor.size + divisorIndex);
        short divisionRound = 0;
        short firstDivisorDigit = (short) (divisor.value[divisorIndex] & DIGIT_MASK);
        short divisorBitShift = (short) (highestOneBit((short) (firstDivisorDigit + 1)) - 1);
        byte secondDivisorDigit = divisorIndex < (short) (divisor.size - 1) ? divisor.value[(short) (divisorIndex + 1)] : 0;
        byte thirdDivisorDigit = divisorIndex < (short) (divisor.size - 2) ? divisor.value[(short) (divisorIndex + 2)] : 0;

        while (divisorShift >= 0) {
            while (!isLesser(divisor, divisorShift, (short) (divisionRound > 0 ? divisionRound - 1 : 0))) {
                short dividentDigits = divisionRound == 0 ? 0 : (short) ((short) (value[(short) (divisionRound - 1)]) << DIGIT_LEN);
                dividentDigits |= (short) (value[divisionRound] & DIGIT_MASK);

                short divisorDigit;
                if (dividentDigits < 0) {
                    dividentDigits = (short) ((dividentDigits >>> 1) & POSITIVE_DOUBLE_DIGIT_MASK);
                    divisorDigit = (short) ((firstDivisorDigit >>> 1) & POSITIVE_DOUBLE_DIGIT_MASK);
                } else {
                    short dividentBitShift = (short) (highestOneBit(dividentDigits) - 1);
                    short bitShift = dividentBitShift <= divisorBitShift ? dividentBitShift : divisorBitShift;

                    dividentDigits = shiftBits(
                            dividentDigits, divisionRound < (short) (size - 1) ? value[(short) (divisionRound + 1)] : 0,
                            divisionRound < (short) (size - 2) ? value[(short) (divisionRound + 2)] : 0,
                            bitShift
                    );
                    divisorDigit = shiftBits(firstDivisorDigit, secondDivisorDigit, thirdDivisorDigit, bitShift);

                }

                short multiple = (short) (dividentDigits / (short) (divisorDigit + 1));
                if (multiple < 1) {
                    multiple = 1;
                }

                subtract(divisor, divisorShift, multiple);

                if (quotient != null) {
                    short quotientDigit = (short) ((quotient.value[(short) (quotient.size - 1 - divisorShift)] & DIGIT_MASK) + multiple);
                    quotient.value[(short) (quotient.size - 1 - divisorShift)] = (byte) quotientDigit;
                }
            }
            divisionRound++;
            divisorShift--;
        }
    }

    /**
     * Get the index of the highest bit set to 1. Used in remainderDivide.
     */
    private static short highestOneBit(short x) {
        for (short i = 0; i < DOUBLE_DIGIT_LEN; ++i) {
            if (x < 0) {
                return i;
            }
            x <<= 1;
        }
        return DOUBLE_DIGIT_LEN;
    }

    /**
     * Shift to the left and fill. Used in remainderDivide.
     *
     * @param high most significant 16 bits
     * @param middle middle 8 bits
     * @param low least significant 8 bits
     * @param shift the left shift
     * @return most significant 16 bits as short
     */
    private static short shiftBits(short high, byte middle, byte low, short shift) {
        // shift high
        high <<= shift;

        // merge middle bits
        byte mask = (byte) (DIGIT_MASK << (shift >= DIGIT_LEN ? 0 : DIGIT_LEN - shift));
        short bits = (short) ((short) (middle & mask) & DIGIT_MASK);
        if (shift > DIGIT_LEN) {
            bits <<= shift - DIGIT_LEN;
        } else {
            bits >>>= DIGIT_LEN - shift;
        }
        high |= bits;

        if (shift <= DIGIT_LEN) {
            return high;
        }

        // merge low bits
        mask = (byte) (DIGIT_MASK << DOUBLE_DIGIT_LEN - shift);
        bits = (short) ((((short) (low & mask) & DIGIT_MASK) >> DOUBLE_DIGIT_LEN - shift));
        high |= bits;

        return high;
    }

    /// [DependencyBegin:ObjectLocker]
    private boolean ERASE_ON_LOCK = false;
    private boolean ERASE_ON_UNLOCK = false;
    private boolean locked = false; // Logical flag to store info if this BigNat is currently used for some operation. Used as a prevention of unintentional parallel use of same temporary pre-allocated BigNat.

    /**
     * Lock/reserve this BigNat for subsequent use.
     * Used to protect corruption of pre-allocated temporary BigNat used in different,
     * potentially nested operations. Must be unlocked by unlock() later on.
     */
    public void lock() {
        if (locked) {
            ISOException.throwIt(ReturnCodes.SW_LOCK_ALREADYLOCKED);
        }
        locked = true;
        if (ERASE_ON_LOCK) {
            erase();
        }
    }

    /**
     * Unlock/release this BigNat from use. Used to protect corruption
     * of pre-allocated temporary BigNat used in different nested operations.
     * Must be locked before.
     */
    public void unlock() {
        if (!locked) {
            ISOException.throwIt(ReturnCodes.SW_LOCK_NOTLOCKED);
        }
        locked = false;
        if (ERASE_ON_UNLOCK) {
            erase();
        }
    }

    /**
     * Return current state of logical lock of this object
     *
     * @return true if object is logically locked (reserved), false otherwise
     */
    public boolean isLocked() {
        return locked;
    }
    /// [DependencyEnd:ObjectLocker]
}
