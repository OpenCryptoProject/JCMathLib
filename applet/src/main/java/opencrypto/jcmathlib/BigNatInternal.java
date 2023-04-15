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
    private short size = -1; // Current size of this representation in value array; left-aligned.
    private byte allocatorType;

    /**
     * Construct a BigNat of given size.
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
     * @param maxSize maximum size of this BigNat
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
     * Serialize this BigNat value into a provided buffer.
     *
     * @param buffer target buffer
     * @param bufferOffset start offset in buffer
     * @return number of bytes copied
     */
    public short copyToBuffer(byte[] buffer, short bufferOffset) {
        Util.arrayCopyNonAtomic(value, (short) 0, buffer, bufferOffset, size);
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
     * Sets internal size of BigNat. Previous value are kept so value is either non-destructively trimmed or enlarged.
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
     * Resize internal length of this BigNat to the maximum size given during object
     * creation. If required, object is also set to zero.
     *
     * @param erase if true, the internal array is erased. If false, the previous value is kept.
     */
    public void resizeToMax(boolean erase) {
        setSize((short) value.length);
        if (erase) {
            erase();
        }
    }

    /**
     * Create BigNat with different number of bytes. Will cause the longer number to shrink (loss of the more significant
     * bytes) and shorter to be prepended with zeroes.
     *
     * @param newSize new size in bytes
     */
    public void deepResize(short newSize) {
        if (newSize > (short) value.length) {
            if (!ALLOW_RUNTIME_REALLOCATION) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED);
            }
            allocateStorageArray(newSize, allocatorType);
        }

        if (newSize == this.size) {
            return;
        }

        byte[] tmpBuffer = rm.ARRAY_A;
        short thisStart, otherStart, len;

        rm.lock(tmpBuffer);
        if (this.size >= newSize) {
            thisStart = (short) (this.size - newSize);
            len = newSize;

            // Shrinking/cropping
            Util.arrayCopyNonAtomic(value, thisStart, tmpBuffer, (short) 0, len);
            Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, value, (short) 0, len); // Move bytes in item array towards beginning
            // Erase rest of allocated array with zeroes (just as sanitization)
            short toErase = (short) ((short) value.length - newSize);
            if (toErase > 0) {
                Util.arrayFillNonAtomic(value, newSize, toErase, (byte) 0);
            }
        } else {
            thisStart = 0;
            otherStart = (short) (newSize - this.size);
            len = this.size;
            // Enlarging => Insert zeroes at begging, move bytes in item array towards the end
            Util.arrayCopyNonAtomic(value, thisStart, tmpBuffer, (short) 0, len);
            // Move bytes in item array towards end
            Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, value, otherStart, len);
            // Fill begin of array with zeroes (just as sanitization)
            if (otherStart > 0) {
                Util.arrayFillNonAtomic(value, (short) 0, otherStart, (byte) 0);
            }
        }
        rm.unlock(tmpBuffer);

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
        Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, outOffset, this.size); // Copy the value
        Util.arrayFillNonAtomic(outBuffer, (short) (outOffset + this.size), (short) (targetLength - this.size), (byte) 0); // Append zeros
    }

    /**
     * Prepend zeros to reach the defined byte length and store the result in an output buffer.
     *
     * @param targetLength required length including prepended zeroes
     * @param outBuffer    output buffer for value with prepended zeroes
     * @param outOffset    start offset inside outBuffer for write
     */
    public void prependZeros(short targetLength, byte[] outBuffer, short outOffset) {
        short other_start = (short) (targetLength - this.size);
        if (other_start > 0) {
            Util.arrayFillNonAtomic(outBuffer, outOffset, other_start, (byte) 0); //fill prefix with zeros
        }
        Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, (short) (outOffset + other_start), this.size); //copy the value
    }

    /**
     * Remove leading zeroes from this BigNat and decrease its size accordingly.
     */
    public void shrink() {
        short i;
        for (i = 0; i < this.length(); i++) { // Find first non-zero byte
            if (this.value[i] != 0) {
                break;
            }
        }

        short newSize = (short) (this.size - i);
        if (newSize < 0) {
            ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDRESIZE);
        }
        this.deepResize(newSize);
    }

    /**
     * Stores zero in this object for currently used subpart given by internal size.
     */
    public void zero() {
        Util.arrayFillNonAtomic(value, (short) 0, this.size, (byte) 0);
    }

    /**
     * Erase value stored inside this BigNat.
     */
    public void erase() {
        Util.arrayFillNonAtomic(value, (short) 0, (short) value.length, (byte) 0);
    }

    /**
     * Sets new value. Keeps previous size of this BigNat.
     *
     * @param newValue new value to set
     */
    public void setValue(byte newValue) {
        zero();
        value[(short) (size - 1)] = (byte) (newValue & DIGIT_MASK);
    }

    /**
     * Sets new value. Keeps previous size of this BigNat.
     *
     * @param newValue new value to set
     */
    public void setValue(short newValue) {
        zero();
        value[(short) (size - 1)] = (byte) (newValue & DIGIT_MASK);
        value[(short) (size - 2)] = (byte) (newValue & (short) (DIGIT_MASK << 8));
    }

    /**
     * Copies a BigNat into this without changing size.
     *
     * @param other BigNat to copy into this object.
     */
    public void copy(BigNatInternal other) {
        short thisStart, otherStart, len;
        if (this.size >= other.size) {
            thisStart = (short) (this.size - other.size);
            otherStart = 0;
            len = other.size;
        } else {
            thisStart = 0;
            otherStart = (short) (other.size - this.size);
            len = this.size;
            // Verify here that other have leading zeroes up to otherStart
            for (short i = 0; i < otherStart; i++) {
                if (other.value[i] != 0) {
                    ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDCOPYOTHER);
                }
            }
        }

        if (thisStart > 0) {
            Util.arrayFillNonAtomic(this.value, (short) 0, thisStart, (byte) 0);
        }
        Util.arrayCopyNonAtomic(other.value, otherStart, this.value, thisStart, len);
    }

    /**
     * Copies a BigNat into this. May change size and require reallocation.
     *
     * @param other BigNat to clone into this object.
     */
    public void clone(BigNatInternal other) {
        if (other.length() > (short) value.length) {
            if (!ALLOW_RUNTIME_REALLOCATION) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED);
            }
            allocateStorageArray(other.length(), this.allocatorType);
        }

        other.copyToBuffer(value, (short) 0);
        short diff = (short) ((short) value.length - other.length());
        if (diff > 0) {
            Util.arrayFillNonAtomic(value, other.length(), diff, (byte) 0);
        }
        this.size = other.length();
    }

    /**
     * Addition of big integers x and y stored in byte arrays with specified offset and length.
     * The result is stored into x array argument.
     *
     * @param x       array with first BigNat
     * @param xOffset start offset in array of {@code x}
     * @param xLength length of {@code x}
     * @param y       array with second BigNat
     * @param yOffset start offset in array of {@code y}
     * @param yLength length of {@code y}
     * @return 0x01 if carry of most significant byte occurs, 0x00 otherwise
     */
    public static byte add(byte[] x, short xOffset, short xLength, byte[] y,
                           short yOffset, short yLength) {
        short result = 0;
        short i = (short) (xLength + xOffset - 1);
        short j = (short) (yLength + yOffset - 1);

        for (; i >= xOffset && j >= 0; i--, j--) {
            result = (short) (result + (short) (x[i] & DIGIT_MASK) + (short) (y[j] & DIGIT_MASK));

            x[i] = (byte) (result & DIGIT_MASK);
            result = (short) ((result >> DIGIT_LEN) & DIGIT_MASK);
        }
        while (result > 0 && i >= xOffset) {
            result = (short) (result + (short) (x[i] & DIGIT_MASK));
            x[i] = (byte) (result & DIGIT_MASK);
            result = (short) ((result >> DIGIT_LEN) & DIGIT_MASK);
            i--;
        }

        // 1. result != 0 => result | -result will have the sign bit set
        // 2. casting magic to overcome the absence of int
        // 3. move the sign bit to the rightmost position
        // 4. discard the sign bit which is present due to the unavoidable casts
        //    and return the value of the rightmost bit
        return (byte) ((byte) (((short) (result | -result) & (short) 0xFFFF) >>> 15) & 0x01);
    }

    /**
     * Subtracts big integer y from x specified by offset and length.
     * The result is stored into x array argument.
     *
     * @param x       array with first BigNat
     * @param xOffset start offset in array of {@code x}
     * @param xLength length of {@code x}
     * @param y       array with second BigNat
     * @param yOffset start offset in array of {@code y}
     * @param yLength length of {@code y}
     * @return true if carry of most significant byte occurs, false otherwise
     */
    public static boolean subtract(byte[] x, short xOffset, short xLength, byte[] y,
                                   short yOffset, short yLength) {
        short i = (short) (xLength + xOffset - 1);
        short j = (short) (yLength + yOffset - 1);
        short carry = 0;

        for (; i >= xOffset && j >= yOffset; i--, j--) {
            short subtractionResult = (short) ((x[i] & DIGIT_MASK) - (y[j] & DIGIT_MASK) - carry);
            x[i] = (byte) (subtractionResult & DIGIT_MASK);
            carry = (short) (subtractionResult < 0 ? 1 : 0);
        }
        for (; i >= xOffset && carry > 0; i--) {
            if (x[i] != 0) {
                carry = 0;
            }
            x[i] -= 1;
        }

        return carry > 0;
    }

    /**
     * Subtract provided other BigNat from this BigNat.
     *
     * @param other BigNat to be subtracted from this
     */
    public void subtract(BigNatInternal other) {
        this.timesMinus(other, (short) 0, (short) 1);
    }

    /**
     * Scaled subtraction. Subtracts {@code mult * 2^(}{@link #DIGIT_LEN}
     * {@code  * shift) * other} from this.
     * <p>
     * That is, shifts {@code mult * other} precisely {@code shift} digits to
     * the left and subtracts that value from this. {@code mult} must be less
     * than BigNat base, that is, it must fit into one digit. It is
     * only declared as short here to avoid negative values.
     * <p>
     * {@code mult} has type short.
     * <p>
     * No size constraint. However, an assertion is thrown, if the result would
     * be negative. {@code other} can have more digits than this object, but
     * then sufficiently many leading digits must be zero to avoid the
     * underflow.
     * <p>
     * Used in division.
     *
     * @param other BigNat to subtract from this object
     * @param shift number of digits to shift {@code other} to the left
     * @param mult  of type short, multiple of {@code other} to subtract from this
     *              object. Must be below BigNat base.
     */
    public void timesMinus(BigNatInternal other, short shift, short mult) {
        short akku = 0;
        short i = (short) (this.size - 1 - shift);
        short j = (short) (other.size - 1);
        for (; i >= 0 && j >= 0; i--, j--) {
            akku = (short) (akku + (short) (mult * (other.value[j] & DIGIT_MASK)));
            short subtraction_result = (short) ((value[i] & DIGIT_MASK) - (akku & DIGIT_MASK));

            value[i] = (byte) (subtraction_result & DIGIT_MASK);
            akku = (short) ((akku >> DIGIT_LEN) & DIGIT_MASK);
            if (subtraction_result < 0) {
                akku++;
            }
        }

        // deal with carry as long as there are digits left in this
        while (i >= 0 && akku != 0) {
            short subtraction_result = (short) ((value[i] & DIGIT_MASK) - (akku & DIGIT_MASK));
            value[i] = (byte) (subtraction_result & DIGIT_MASK);
            akku = (short) ((akku >> DIGIT_LEN) & DIGIT_MASK);
            if (subtraction_result < 0) {
                akku++;
            }
            i--;
        }
    }

    /**
     * Decrement this BigNat.
     */
    public void decrement() {
        short tmp;
        for (short i = (short) (this.size - 1); i >= 0; i--) {
            tmp = (short) (this.value[i] & 0xff);
            this.value[i] = (byte) (tmp - 1);
            if (tmp != 0) {
                break; // CTO
            } else {
                // need to modify also one byte up, continue with cycle
            }
        }
    }

    /**
     * Increment this BigNat.
     */
    public void increment() {
        for (short i = (short) (this.size - 1); i >= 0; i--) {
            short tmp = (short) (this.value[i] & 0xff);
            this.value[i] = (byte) (tmp + 1);
            if (tmp < 255) {
                break; // CTO
            } else {
                // need to modify also one byte up (carry) , continue with cycle
            }
        }
    }

    /**
     * Index of the most significant 1 bit.
     * <p>
     * {@code x} has type short.
     * <p>
     * Utility method, used in division.
     *
     * @param x of type short
     * @return index of the most significant 1 bit in {@code x}, returns
     * {@link #DOUBLE_DIGIT_LEN} for {@code x == 0}.
     */
    private static short highestBit(short x) {
        for (short i = 0; i < DOUBLE_DIGIT_LEN; i++) {
            if (x < 0) {
                return i;
            }
            x <<= 1;
        }
        return DOUBLE_DIGIT_LEN;
    }

    /**
     * Shift to the left and fill. Takes {@code high} {@code middle} {@code low}
     * as 4 digits, shifts them {@code shift} bits to the left and returns the
     * most significant {@link #DOUBLE_DIGIT_LEN} bits.
     * <p>
     * Utility method, used in division.
     *
     * @param high   of type short, most significant {@link #DOUBLE_DIGIT_LEN} bits
     * @param middle of type byte, middle {@link #DIGIT_LEN} bits
     * @param low    of type byte, the least significant {@link #DIGIT_LEN} bits
     * @param shift  amount of left shift
     * @return most significant {@link #DOUBLE_DIGIT_LEN} as short
     */
    private static short shiftBits(short high, byte middle, byte low, short shift) {
        // shift high
        high <<= shift;

        // merge middle bits
        byte mask = (byte) (DIGIT_MASK << (shift >= DIGIT_LEN ? 0 : DIGIT_LEN
                - shift));
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

    /**
     * Scaled comparison. Compares this number with {@code other * 2^(}
     * {@link #DIGIT_LEN} {@code * shift)}. That is, shifts {@code other}
     * {@code shift} digits to the left and compares then. This BigNat and
     * {@code other} will not be modified inside this method.
     * <p>
     * <p>
     * As optimization {@code start} can be greater than zero to skip the first
     * {@code start} digits in the comparison. These first digits must be zero
     * then, otherwise an assertion is thrown. (So the optimization takes only
     * effect when <a
     * href="../../../overview-summary.html#NO_CARD_ASSERT">NO_CARD_ASSERT</a>
     * is defined.)
     *
     * @param other BigNat to compare to
     * @param shift left shift of other before the comparison
     * @param start digits to skip at the beginning
     * @return true if this number is strictly less than the shifted
     * {@code other}, false otherwise.
     */
    public boolean shiftLesser(BigNatInternal other, short shift, short start) {
        short j;

        j = (short) (other.size + shift - this.size + start);
        short thisShort, otherShort;
        for (short i = start; i < this.size; i++, j++) {
            thisShort = (short) (this.value[i] & DIGIT_MASK);
            if (j >= 0 && j < other.size) {
                otherShort = (short) (other.value[j] & DIGIT_MASK);
            } else {
                otherShort = 0;
            }
            if (thisShort < otherShort) {
                return true; // CTO
            }
            if (thisShort > otherShort) {
                return false;
            }
        }
        return false;
    }

    /**
     * Compares this and other BigNat.
     *
     * @param other other value to compare with
     * @return true if this BigNat is smaller, false if bigger or equal
     */
    public boolean smaller(BigNatInternal other) {
        short indexThis = 0;
        for (short i = 0; i < this.length(); i++) {
            if (this.value[i] != 0x00) {
                indexThis = i;
            }
        }

        short indexOther = 0;
        for (short i = 0; i < other.length(); i++) {
            if (other.value[i] != 0x00) {
                indexOther = i;
            }
        }

        if ((short) (this.length() - indexThis) < (short) (other.length() - indexOther)) {
            return true; // CTO
        }
        short i = 0;
        while (i < this.length() && i < other.length()) {
            if (((short) (this.value[i] & DIGIT_MASK)) < ((short) (other.value[i] & DIGIT_MASK))) {
                return true; // CTO
            }
            i = (short) (1 + i);
        }

        return false;
    }


    /**
     * Comparison of this and other.
     *
     * @param other BigNat to compare with
     * @return true if this number is strictly lesser than {@code other}, false
     * otherwise.
     */
    public boolean lesser(BigNatInternal other) {
        return shiftLesser(other, (short) 0, (short) 0);
    }

    /**
     * Test equality with zero.
     *
     * @return true if this BigNat equals zero.
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
     *
     * @return true if this BigNat equals one.
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
     *
     * @return true if odd, false if even
     */
    public boolean isOdd() {
        return (byte) (value[(short) (this.size - 1)] & (byte) 1) != (byte) 0;
    }

    /**
     * Divide this by divisor and store the remained in this. Quotient is stored
     * in quotient. Uses schoolbook division inside and has O^2 complexity in the
     * difference of significant digits of the divident (in this number) and the
     * divisor. For numbers of equal size complexity is linear.
     *
     * @param divisor must be non-zero
     * @param quotient gets the quotient if non-null
     */
    public void remainderDivide(BigNatInternal divisor, BigNatInternal quotient) {
        // There are some size requirements, namely that quotient must
        // be big enough. However, this depends on the value of the
        // divisor and is therefore not stated here.

        // zero-initialize the quotient, because we are only adding to it below
        if (quotient != null) {
            quotient.zero();
        }

        // divisorIndex is the first nonzero digit (short) in the divisor
        short divisorIndex = 0;
        while (divisor.value[divisorIndex] == 0) {
            divisorIndex++;
        }

        // The size of this might be different from divisor. Therefore,
        // for the first subtraction round we have to shift the divisor
        // divisorShift = this.size - divisor.size + divisorIndex
        // digits to the left. If this amount is negative, then
        // this is already smaller than divisor, and we are done.
        // Below we do divisor_shift + 1 subtraction rounds. As an
        // additional loop index we also count the rounds (from
        // zero upwards) in divisionRound. This gives access to the
        // first remaining divident digits.
        short divisorShift = (short) (this.size - divisor.size + divisorIndex);
        short divisionRound = 0;

        // We could express now a size constraint, namely that
        // divisor_shift + 1 <= quotient.size
        // However, in the proof protocol we divide x / v, where
        // x has 2*n digits when v has n digits. There the above size
        // constraint is violated, the division is however valid, because
        // it will always hold that x < v * (v - 1) and therefore the
        // quotient will always fit into n digits.
        // System.out.format("XX this size %d div ind %d div shift %d " +
        // "quo size %d\n" +
        // "%s / %s\n",
        // this.size,
        // divisor_index,
        // divisor_shift,
        // quotient != null ? quotient.size : -1,
        // this.to_hex_string(),
        // divisor.to_hex_string());
        // The first digits of the divisor are needed in every
        // subtraction round.
        short firstDivisorDigit = (short) (divisor.value[divisorIndex] & DIGIT_MASK);
        short divisorBitShift = (short) (highestBit((short) (firstDivisorDigit + 1)) - 1);
        byte secondDivisorDigit = divisorIndex < (short) (divisor.size - 1) ? divisor.value[(short) (divisorIndex + 1)]
                : 0;
        byte thirdDivisorDigit = divisorIndex < (short) (divisor.size - 2) ? divisor.value[(short) (divisorIndex + 2)]
                : 0;

        // The following variables are used inside the loop only.
        // Declared here as optimization.
        // divident_digits and divisor_digit hold the first one or two
        // digits. Needed to compute the multiple of the divisor to
        // subtract from this.
        short dividentDigits, divisorDigit;

        // To increase precisision the first digits are shifted to the
        // left or right a bit. The following variables compute the shift.
        short dividentBitShift, bitShift;

        // Declaration of the multiple, with which the divident is
        // multiplied in each round and the quotient_digit. Both are
        // a single digit, but declared as a double digit to avoid the
        // trouble with negative numbers. If quotient != null multiple is
        // added to the quotient. This addition is done with quotient_digit.
        short multiple, quotientDigit;
        short numLoops = 0;
        short numLoops2 = 0;
        while (divisorShift >= 0) {
            numLoops++; // CTO number of outer loops is constant (for given length of divisor)
            // Keep subtracting from this until
            // divisor * 2^(8 * divisor_shift) is bigger than this.
            while (!shiftLesser(divisor, divisorShift,
                    (short) (divisionRound > 0 ? divisionRound - 1 : 0))) {
                numLoops2++; // BUGBUG: CTO - number of these loops fluctuates heavily => strong impact on operation time
                // this is bigger or equal than the shifted divisor.
                // Need to subtract some multiple of divisor from this.
                // Make a conservative estimation of the multiple to subtract.
                // We estimate a lower bound to avoid underflow, and continue
                // to subtract until the remainder in this gets smaller than
                // the shifted divisor.
                // For the estimation get first the two relevant digits
                // from this and the first relevant digit from divisor.
                dividentDigits = divisionRound == 0 ? 0
                        : (short) ((short) (value[(short) (divisionRound - 1)]) << DIGIT_LEN);
                dividentDigits |= (short) (value[divisionRound] & DIGIT_MASK);

                // The multiple to subtract from this is
                // divident_digits / divisor_digit, but there are two
                // complications:
                // 1. divident_digits might be negative,
                // 2. both might be very small, in which case the estimated
                // multiple is very inaccurate.
                if (dividentDigits < 0) {
                    // case 1: shift both one bit to the right
                    // In standard java (ie. in the test frame) the operation
                    // for >>= and >>>= seems to be done in integers,
                    // even if the left hand side is a short. Therefore,
                    // for a short left hand side there is no difference
                    // between >>= and >>>= !!!
                    // Do it the complicated way then.
                    dividentDigits = (short) ((dividentDigits >>> 1) & POSITIVE_DOUBLE_DIGIT_MASK);
                    divisorDigit = (short) ((firstDivisorDigit >>> 1) & POSITIVE_DOUBLE_DIGIT_MASK);
                } else {
                    // To avoid case 2 shift both to the left
                    // and add relevant bits.
                    dividentBitShift = (short) (highestBit(dividentDigits) - 1);
                    // Below we add one to divisor_digit to avoid underflow.
                    // Take therefore the highest bit of divisor_digit + 1
                    // to avoid running into the negatives.
                    bitShift = dividentBitShift <= divisorBitShift ? dividentBitShift
                            : divisorBitShift;

                    dividentDigits = shiftBits(
                            dividentDigits,
                            divisionRound < (short) (this.size - 1) ? value[(short) (divisionRound + 1)]
                                    : 0,
                            divisionRound < (short) (this.size - 2) ? value[(short) (divisionRound + 2)]
                                    : 0, bitShift);
                    divisorDigit = shiftBits(firstDivisorDigit,
                            secondDivisorDigit, thirdDivisorDigit,
                            bitShift);

                }

                // add one to divisor to avoid underflow
                multiple = (short) (dividentDigits / (short) (divisorDigit + 1));

                // Our strategy to avoid underflow might yield multiple == 0.
                // We know however, that divident >= divisor, therefore make
                // sure multiple is at least 1.
                if (multiple < 1) {
                    multiple = 1;
                }

                timesMinus(divisor, divisorShift, multiple);

                // build quotient if desired
                if (quotient != null) {
                    // Express the size constraint only here. The check is
                    // essential only in the first round, because
                    // divisor_shift decreases. divisor_shift must be
                    // strictly lesser than quotient.size, otherwise
                    // quotient is not big enough. Note that the initially
                    // computed divisor_shift might be bigger, this
                    // is OK, as long as we don't reach this point.

                    quotientDigit = (short) ((quotient.value[(short) (quotient.size - 1 - divisorShift)] & DIGIT_MASK) + multiple);
                    quotient.value[(short) (quotient.size - 1 - divisorShift)] = (byte) (quotientDigit);
                }
            }

            // treat loop indices
            divisionRound++;
            divisorShift--;
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
        short akku = 0;
        short j = (short) (this.size - 1);
        for (short i = (short) (other.size - 1); i >= 0 && j >= 0; i--, j--) {
            akku = (short) (akku + (short) (this.value[j] & DIGIT_MASK) + (short) (other.value[i] & DIGIT_MASK));

            this.value[j] = (byte) (akku & DIGIT_MASK);
            akku = (short) ((akku >> DIGIT_LEN) & DIGIT_MASK);
        }
        // add carry at position j
        while (akku > 0 && j >= 0) {
            akku = (short) (akku + (short) (this.value[j] & DIGIT_MASK));
            this.value[j] = (byte) (akku & DIGIT_MASK);
            akku = (short) ((akku >> DIGIT_LEN) & DIGIT_MASK);
            j--;
        }

        // 1. result != 0 => result | -result will have the sign bit set
        // 2. casting magic to overcome the absence of int
        // 3. move the sign bit to the rightmost position
        // 4. discard the sign bit which is present due to the unavoidable casts
        //    and return the value of the rightmost bit
        return (byte) ((byte) (((short) (akku | -akku) & (short) 0xFFFF) >>> 15) & 0x01);
    }

    /**
     * Scaled addition. Add {@code mult * other} to this number. {@code mult}
     * must be below BigNat base, that is, it must fit into one digit.
     * It is only declared as a short here to avoid negative numbers.
     * <p>
     * Asserts (overly restrictive) that this and other have the same size.
     * <p>
     * Same as {@link #timesAddShift times_add_shift}{@code (other, 0, mult)}
     * but without the shift overhead.
     * <p>
     * Used in multiplication.
     *
     * @param other BigNat to add
     * @param multiplier factor to multiply other with before addition
     */
    public void timesAdd(BigNatInternal other, short multiplier) {
        short akku = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            akku = (short) (akku + (short) (this.value[i] & DIGIT_MASK) + (short) (multiplier * (other.value[i] & DIGIT_MASK)));
            this.value[i] = (byte) (akku & DIGIT_MASK);
            akku = (short) ((akku >> DIGIT_LEN) & DIGIT_MASK);
        }
    }

    /**
     * Scaled addition. Adds {@code mult * other * 2^(}{@link #DIGIT_LEN}
     * {@code * shift)} to this. That is, shifts other {@code shift} digits to
     * the left, multiplies it with {@code mult} and adds then.
     * <p>
     * {@code mult} must be less than BigNat base, that is, it must fit
     * into one digit. It is only declared as a short here to avoid negative
     * numbers.
     * <p>
     * Asserts that the size of this is greater than or equal to
     * {@code other.size + shift + 1}.
     *
     * @param x     BigNat to add
     * @param mult  of short, factor to multiply {@code other} with before
     *              addition. Must be less than BigNat base.
     * @param shift number of digits to shift {@code other} to the left, before
     *              addition.
     */
    public void timesAddShift(BigNatInternal x, short shift, short mult) {
        short akku = 0;
        short j = (short) (this.size - 1 - shift);
        for (short i = (short) (x.size - 1); i >= 0; i--, j--) {
            akku = (short) (akku + (short) (this.value[j] & DIGIT_MASK) + (short) (mult * (x.value[i] & DIGIT_MASK)));

            this.value[j] = (byte) (akku & DIGIT_MASK);
            akku = (short) ((akku >> DIGIT_LEN) & DIGIT_MASK);
        }
        // add carry at position j
        akku = (short) (akku + (short) (this.value[j] & DIGIT_MASK));
        this.value[j] = (byte) (akku & DIGIT_MASK);
        // BUGUG: assert no overflow
    }

    /**
     * Slow schoolbook algorithm for multiplication.
     *
     * @param x left operand
     * @param y right operand
     */
    protected void multSchoolbook(BigNatInternal x, BigNatInternal y) {
        zero(); // important to keep, used in exponentiation()
        for (short i = (short) (y.size - 1); i >= 0; i--) {
            timesAddShift(x, (short) (y.size - 1 - i), (short) (y.value[i] & DIGIT_MASK));
        }
    }

    /**
     * Multiplies x and y using RSA exponentiation and store result into this.
     *
     * @param x left operand
     * @param y right operand
     * @param xSq if not null, array with precomputed value x^2 is expected
     * @param ySq if not null, array with precomputed value y^2 is expected
     */
    protected void multRsaTrick(BigNatInternal x, BigNatInternal y, byte[] xSq, byte[] ySq) {
        short xOffset;
        short yOffset;

        byte[] resultBuffer1 = rm.ARRAY_A;
        byte[] resultBuffer2 = rm.ARRAY_B;

        rm.lock(resultBuffer1);

        // x+y
        Util.arrayFillNonAtomic(resultBuffer1, (short) 0, (short) resultBuffer1.length, (byte) 0);
        // We must copy bigger number first
        if (x.size > y.size) {
            // Copy x to the end of mult_resultArray
            xOffset = (short) (resultBuffer1.length - x.length());
            Util.arrayCopyNonAtomic(x.value, (short) 0, resultBuffer1, xOffset, x.length());

            // modified for CT
            byte carry = add(resultBuffer1, xOffset, x.size, y.value, (short) 0, y.size);
            xOffset--;
            resultBuffer1[xOffset] = carry; // add carry if occured
        } else {
            // Copy x to the end of mult_resultArray
            yOffset = (short) (resultBuffer1.length - y.length());
            Util.arrayCopyNonAtomic(y.value, (short) 0, resultBuffer1, yOffset, y.length());

            // modified for CT
            byte carry = add(resultBuffer1, yOffset, y.size, x.value, (short) 0, x.size);
            yOffset--;
            resultBuffer1[yOffset] = carry; // add carry if occured
        }

        // ((x+y)^2)
        rm.multCiph.doFinal(resultBuffer1, (byte) 0, (short) resultBuffer1.length, resultBuffer1, (short) 0);

        // x^2
        rm.lock(resultBuffer2);
        if (xSq == null) {
            // x^2 is not precomputed
            Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
            xOffset = (short) (resultBuffer2.length - x.length());
            Util.arrayCopyNonAtomic(x.value, (short) 0, resultBuffer2, xOffset, x.length());
            rm.multCiph.doFinal(resultBuffer2, (byte) 0, (short) resultBuffer2.length, resultBuffer2, (short) 0);
        } else {
            // x^2 is precomputed
            if ((short) xSq.length != (short) resultBuffer2.length) {
                Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
                xOffset = (short) ((short) resultBuffer2.length - (short) xSq.length);
            } else {
                xOffset = 0;
            }
            Util.arrayCopyNonAtomic(xSq, (short) 0, resultBuffer2, xOffset, (short) xSq.length);
        }
        // ((x+y)^2) - x^2
        subtract(resultBuffer1, (short) 0, (short) resultBuffer1.length, resultBuffer2, (short) 0, (short) resultBuffer2.length);

        // y^2
        if (ySq == null) {
            // y^2 is not precomputed
            Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
            yOffset = (short) (resultBuffer2.length - y.length());
            Util.arrayCopyNonAtomic(y.value, (short) 0, resultBuffer2, yOffset, y.length());
            rm.multCiph.doFinal(resultBuffer2, (byte) 0, (short) resultBuffer2.length, resultBuffer2, (short) 0);
        } else {
            // y^2 is precomputed
            if ((short) ySq.length != (short) resultBuffer2.length) {
                Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
                yOffset = (short) ((short) resultBuffer2.length - (short) ySq.length);
            } else {
                yOffset = 0;
            }
            Util.arrayCopyNonAtomic(ySq, (short) 0, resultBuffer2, yOffset, (short) ySq.length);
        }


        // {(x+y)^2) - x^2} - y^2
        subtract(resultBuffer1, (short) 0, (short) resultBuffer1.length, resultBuffer2, (short) 0, (short) resultBuffer2.length);

        // we now have 2xy in mult_resultArray, divide it by 2 => shift by one bit and fill back into this
        short multOffset = (short) ((short) resultBuffer1.length - 1);
        // this.length() must be different from multOffset, set proper ending condition
        short stopOffset = 0;
        if (this.length() > multOffset) {
            stopOffset = (short) (this.length() - multOffset); // only part of this.value will be filled
        } else {
            stopOffset = 0; // whole this.value will be filled
        }
        if (stopOffset > 0) {
            Util.arrayFillNonAtomic(this.value, (short) 0, stopOffset, (byte) 0);
        }
        for (short i = (short) (this.length() - 1); i >= stopOffset; i--) {
            short res = (short) (resultBuffer1[multOffset] & 0xff);
            res = (short) (res >> 1);
            short res2 = (short) (resultBuffer1[(short) (multOffset - 1)] & 0xff);
            res2 = (short) (res2 << 7);
            this.value[i] = (byte) (short) (res | res2);
            multOffset--;
        }
        rm.unlock(resultBuffer1);
        rm.unlock(resultBuffer2);
    }

    /**
     * Right bit shift with carry
     *
     * @param bits number of bits to shift by
     * @param carry XORed into the highest byte
     */
    private void shiftRight(short bits, short carry) {
        // assumes 0 <= bits < 8
        short mask = (short) ((short) (1 << bits) - 1); // lowest `bits` bits set to 1
        for (short i = 0; i < this.size; i++) {
            short current = (short) (this.value[i] & 0xff);
            short previous = current;
            current >>= bits;
            this.value[i] = (byte) (current | carry);
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
     * Set value of this from a byte array representation.
     *
     * @param source the byte array
     * @param sourceOffset offset in the byte array
     * @param length length of the value representation
     * @return the number of bytes actually read
     */
    public short fromByteArray(byte[] source, short sourceOffset, short length) {
        short max = length <= this.size ? length : this.size;
        Util.arrayCopyNonAtomic(source, sourceOffset, value, (short) 0, max);
        return length == this.size ? (short) (length + 1) : max;
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
