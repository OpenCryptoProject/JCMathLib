/**
 * Credits: Based on Bignat library from OV-chip project https://ovchip.cs.ru.nl/OV-chip_2.0 by Radboud University Nijmegen
 */
package opencrypto.jcmathlib;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import javacard.security.KeyBuilder;

/**
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class BigNat {
    // Threshold bit length of mult operand to invoke RSA trick
    public static final short FAST_MULT_VIA_RSA_THRESHOLD_LENGTH = (short) 16;

    private final ResourceManager rm;
    /**
     * Configuration flag controlling re-allocation of internal array. If true, internal BigNat buffer can be enlarged during clone
     * operation if required (keep false to prevent slow reallocations)
     */
    boolean ALLOW_RUNTIME_REALLOCATION = false;

    /**
     * Configuration flag controlling clearing of shared BigNats on lock as prevention of unwanted leak of sensitive information from previous operation.
     * If true, internal storage array is erased once BigNat is locked for use
     */
    boolean ERASE_ON_LOCK = false;
    /**
     * Configuration flag controlling clearing of shared Bignats on unlock as
     * prevention of unwanted leak of sensitive information to next operation.
     * If true, internal storage array is erased once Bignat is unlocked from use
     */
    boolean ERASE_ON_UNLOCK = false;

    /**
     * Factor for converting digit size into short length. 1 for the short/short
     * converting, 4 for the int/long configuration.
     */
    public static final short size_multiplier = 1;

    /**
     * Bitmask for extracting a digit out of a longer int/short value. short
     * 0xff for the short/short configuration, long 0xffffffffL the int/long
     * configuration.
     */
    public static final short digit_mask = 0xff;

    /**
     * Bitmask for the highest bit in a digit. short 0x80 for the short/short
     * configuration, long 0x80000000 for the int/long configuration.
     */
    public static final short digit_first_bit_mask = 0x80;

    /**
     * Bitmask for the second highest bit in a digit. short 0x40 for the
     * short/short configuration, long 0x40000000 for the int/long
     * configuration.
     */
    public static final short digit_second_bit_mask = 0x40;

    /**
     * Bitmask for the two highest bits in a digit. short 0xC0 for the
     * short/short configuration, long 0xC0000000 for the int/long
     * configuration.
     */
    public static final short digit_first_two_bit_mask = 0xC0;

    /**
     * Size in bits of one digit. 8 for the short/short configuration, 32 for
     * the int/long configuration.
     */
    public static final short digit_len = 8;

    /**
     * Size in bits of a double digit. 16 for the short/short configuration, 64
     * for the int/long configuration.
     */
    private static final short double_digit_len = 16;

    /**
     * Bitmask for erasing the sign bit in a double digit. short 0x7fff for the
     * short/short configuration, long 0x7fffffffffffffffL for the int/long
     * configuration.
     */
    private static final short positive_double_digit_mask = 0x7fff;

    /**
     * Bitmask for the highest bit in a double digit.
     */
    public static final short highest_digit_bit = (short) (1L << (digit_len - 1));

    /**
     * The base as a double digit. The base is first value that does not fit
     * into a single digit. 2^8 for the short/short configuration and 2^32 for
     * the int/long configuration.
     */
    public static final short bignat_base = (short) (1L << digit_len);

    /**
     * Bitmask with just the highest bit in a double digit.
     */
    public static final short highest_double_digit_bit = (short) (1L << (double_digit_len - 1));

    /**
     * Digit array. Elements have type byte.
     */

    /**
     * Internal storage array for this Bignat. The current version uses byte array with
     * intermediate values stored which can be quickly processed with
     */
    private byte[] value;
    private short size = -1;     // Current size of stored Bignat. Current number is encoded in first {@code size} of value array, starting from value[0]
    private short max_size = -1; // Maximum size of this Bignat. Corresponds to value.length
    private byte allocatorType = JCSystem.MEMORY_TYPE_PERSISTENT; // Memory storage type for value buffer

    private boolean locked = false;    // Logical flag to store info if this Bignat is currently used for some operation. Used as a prevention of unintentional parallel use of same temporary pre-allocated Bignats.

    /**
     * Construct a Bignat of size {@code size} in shorts. Allocated in EEPROM or RAM based on
     * {@code allocatorType}. JCSystem.MEMORY_TYPE_PERSISTENT, in RAM otherwise.
     *
     * @param size          the size of the new Bignat in bytes
     * @param allocatorType type of allocator storage
     *                      JCSystem.MEMORY_TYPE_PERSISTENT => EEPROM (slower writes, but RAM is saved)
     *                      JCSystem.MEMORY_TYPE_TRANSIENT_RESET => RAM
     *                      JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT => RAM
     * @param bignatHelper  {@code Bignat_Helper} class with helper objects
     */
    public BigNat(short size, byte allocatorType, ResourceManager rm) {
        this.rm = rm;
        allocate_storage_array(size, allocatorType);
    }

    /**
     * Construct a Bignat with provided array used as internal storage as well as initial value.
     * No copy of array is made. If this Bignat is used in operation which modifies the Bignat value,
     * content of provided array is changed.
     *
     * @param valueBuffer  internal storage
     * @param bignatHelper {@code Bignat_Helper} class with all relevant settings and helper objects
     */
    public BigNat(byte[] valueBuffer, ResourceManager rm) {
        this.rm = rm;
        this.size = (short) valueBuffer.length;
        this.max_size = (short) valueBuffer.length;
        this.allocatorType = -1; // no allocator
        this.value = valueBuffer;
    }

    /**
     * Lock/reserve this bignat for subsequent use.
     * Used to protect corruption of pre-allocated temporary Bignats used in different,
     * potentially nested operations. Must be unlocked by {@code unlock()} later on.
     *
     * @throws SW_LOCK_ALREADYLOCKED if already locked (is already in use by other operation)
     */
    public void lock() {
        if (!locked) {
            locked = true;
            if (ERASE_ON_LOCK) {
                erase();
            }
        } else {
            // this Bignat is already locked, raise exception (incorrect sequence of locking and unlocking)
            ISOException.throwIt(ReturnCodes.SW_LOCK_ALREADYLOCKED);
        }
    }

    /**
     * Unlock/release this bignat from use. Used to protect corruption
     * of pre-allocated temporary Bignats used in different nested operations.
     * Must be locked before.
     *
     * @throws SW_LOCK_NOTLOCKED if was not locked before (inconsistence in lock/unlock sequence)
     */
    public void unlock() {
        if (locked) {
            locked = false;
            if (ERASE_ON_UNLOCK) {
                erase();
            }
        } else {
            // this Bignat is not locked, raise exception (incorrect sequence of locking and unlocking)
            ISOException.throwIt(ReturnCodes.SW_LOCK_NOTLOCKED);
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

    /**
     * Return this Bignat as byte array. For the short/short configuration
     * simply the digit array is returned. For other configurations a new short
     * array is allocated and returned. Modifying the returned short array
     * therefore might or might not change this bignat.
     * IMPORTANT: this function returns directly the underlying storage array.
     * Current value of this Bignat can be stored in smaller number of bytes.
     * Use {@code getLength()} method to obtain actual size.
     *
     * @return this BigNat as byte array
     */
    public byte[] as_byte_array() {
        return value;
    }

    /**
     * Serialize this BigNat value into a provided buffer
     *
     * @param buffer       target buffer
     * @param bufferOffset start offset in buffer
     * @return number of bytes copied
     */
    public short copy_to_buffer(byte[] buffer, short bufferOffset) {
        Util.arrayCopyNonAtomic(value, (short) 0, buffer, bufferOffset, size);
        return size;
    }


    /**
     * Return the size in digits. Provides access to the internal {@link #size}
     * field.
     * <p>
     * The return value is adjusted by {@link #set_size}.
     *
     * @return size in digits.
     */
    public short length() {
        return size;
    }

    /**
     * Sets internal size of BigNat. Previous value are kept so value is either non-destructively trimmed or enlarged.
     *
     * @param newSize new size of BigNat. Must be in range of [0, max_size] where max_size was provided during object creation
     */
    public void set_size(short newSize) {
        if (newSize < 0 || newSize > max_size) {
            ISOException.throwIt(ReturnCodes.SW_BIGNAT_RESIZETOLONGER);
        } else {
            this.size = newSize;
        }
    }

    /**
     * Resize internal length of this Bignat to maximum size given during object
     * creation. If required, object is also zeroized
     *
     * @param bZeroize if true, all bytes of internal array are also set to
     *                 zero. If false, previous value is kept.
     */
    public void resize_to_max(boolean bZeroize) {
        set_size(max_size);
        if (bZeroize) {
            zero();
        }
    }

    /**
     * Create BigNat with different number of bytes used. Will cause longer number
     * to shrink (loss of the more significant bytes) and shorter to be prepended with zeroes
     *
     * @param new_size new size in bytes
     */
    void deep_resize(short new_size) {
        if (new_size > this.max_size) {
            if (ALLOW_RUNTIME_REALLOCATION) {
                allocate_storage_array(new_size, this.allocatorType);
            } else {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED); // Reallocation to longer size not permitted
            }
        }

        if (new_size == this.size) {
            return;
        }

        byte[] tmpBuffer = rm.ARRAY_A;
        short this_start, other_start, len;

        rm.lock(tmpBuffer);
        if (this.size >= new_size) {
            this_start = (short) (this.size - new_size);
            other_start = 0;
            len = new_size;

            // Shrinking/cropping
            Util.arrayCopyNonAtomic(value, this_start, tmpBuffer, (short) 0, len);
            Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, value, (short) 0, len); // Move bytes in item array towards beginning
            // Erase rest of allocated array with zeroes (just as sanitization)
            short toErase = (short) (this.max_size - new_size);
            if (toErase > 0) {
                Util.arrayFillNonAtomic(value, new_size, toErase, (byte) 0);
            }
        } else {
            this_start = 0;
            other_start = (short) (new_size - this.size);
            len = this.size;
            // Enlarging => Insert zeroes at begging, move bytes in item array towards the end
            Util.arrayCopyNonAtomic(value, this_start, tmpBuffer, (short) 0, len);
            // Move bytes in item array towards end
            Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, value, other_start, len);
            // Fill begin of array with zeroes (just as sanitization)
            if (other_start > 0) {
                Util.arrayFillNonAtomic(value, (short) 0, other_start, (byte) 0);
            }
        }
        rm.unlock(tmpBuffer);

        set_size(new_size);
    }


    /**
     * Appends zeros in the suffix to reach the defined byte length
     * Essentially multiplies the number with 16 (HEX)
     *
     * @param targetLength required length including appended zeroes
     * @param outBuffer    output buffer for value with appended zeroes
     * @param outOffset    start offset inside outBuffer for write
     */
    public void append_zeros(short targetLength, byte[] outBuffer, short outOffset) {
        Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, outOffset, this.size); //copy the value
        Util.arrayFillNonAtomic(outBuffer, (short) (outOffset + this.size), (short) (targetLength - this.size), (byte) 0); //append zeros
    }

    /**
     * Prepends zeros before the value of this Bignat up to target length.
     *
     * @param targetLength required length including prepended zeroes
     * @param outBuffer    output buffer for value with prepended zeroes
     * @param outOffset    start offset inside outBuffer for write
     */
    public void prepend_zeros(short targetLength, byte[] outBuffer, short outOffset) {
        short other_start = (short) (targetLength - this.size);
        if (other_start > 0) {
            Util.arrayFillNonAtomic(outBuffer, outOffset, other_start, (byte) 0); //fill prefix with zeros
        }
        Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, (short) (outOffset + other_start), this.size); //copy the value
    }

    /**
     * Remove leading zeroes (if any) from Bignat value and decrease size accordingly
     */
    public void shrink() {
        short i = 0;
        for (i = 0; i < this.length(); i++) { // Find first non-zero byte
            if (this.value[i] != 0) {
                break;
            }
        }

        short new_size = (short) (this.size - i);
        if (new_size < 0) {
            ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDRESIZE);
        }
        this.deep_resize(new_size);
    }


    /**
     * Stores zero in this object for currently used subpart given by internal size.
     */
    public void zero() {
        Util.arrayFillNonAtomic(value, (short) 0, this.size, (byte) 0);
    }

    /**
     * Stores zero in this object for whole internal buffer regardless of current size.
     */
    public void zero_complete() {
        Util.arrayFillNonAtomic(value, (short) 0, (short) value.length, (byte) 0);
    }

    /**
     * Erase value stored inside this Bignat
     */
    public void erase() {
        zero_complete();
    }


    /**
     * Stores one in this object. Keeps previous size of this Bignat
     * (1 is prepended with required number of zeroes).
     */
    public void one() {
        this.zero();
        value[(short) (size - 1)] = 1;
    }

    /**
     * Stores two in this object. Keeps previous size of this Bignat (2 is
     * prepended with required number of zeroes).
     */
    public void two() {
        this.zero();
        value[(short) (size - 1)] = 0x02;
    }

    /**
     * Stores three in this object. Keeps previous size of this Bignat (3 is
     * prepended with required number of zeroes).
     */
    public void three() {
        this.zero();
        value[(short) (size - 1)] = 0x03;
    }

    /**
     * Copies {@code other} into this. No size requirements. If {@code other}
     * has more digits then the superfluous leading digits of {@code other} are
     * asserted to be zero. If this bignat has more digits than its leading
     * digits are correctly initilized to zero. This function will not change size
     * attribute of this object.
     *
     * @param other Bignat to copy into this object.
     */
    public void copy(BigNat other) {
        short this_start, other_start, len;
        if (this.size >= other.size) {
            this_start = (short) (this.size - other.size);
            other_start = 0;
            len = other.size;
        } else {
            this_start = 0;
            other_start = (short) (other.size - this.size);
            len = this.size;
            // Verify here that other have leading zeroes up to other_start
            for (short i = 0; i < other_start; i++) {
                if (other.value[i] != 0) {
                    ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDCOPYOTHER);
                }
            }
        }

        if (this_start > 0) {
            // if this bignat has more digits than its leading digits are initilized to zero
            Util.arrayFillNonAtomic(this.value, (short) 0, this_start, (byte) 0);
        }
        Util.arrayCopyNonAtomic(other.value, other_start, this.value, this_start, len);
    }

    /**
     * Copies content of {@code other} into this and set size of this to {@code other}.
     * The size attribute (returned by length()) is updated. If {@code other}
     * is longer than maximum capacity of this, internal buffer is reallocated if enabled
     * (ALLOW_RUNTIME_REALLOCATION), otherwise exception is thrown.
     *
     * @param other Bignat to clone into this object.
     */
    public void clone(BigNat other) {
        // Reallocate array only if current array cannot store the other value and reallocation is enabled by ALLOW_RUNTIME_REALLOCATION
        if (this.max_size < other.length()) {
            // Reallocation necessary
            if (ALLOW_RUNTIME_REALLOCATION) {
                allocate_storage_array(other.length(), this.allocatorType);
            } else {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED);
            }
        }

        // copy value from other into proper place in this (this can be longer than other so rest of bytes wil be filled with 0)
        other.copy_to_buffer(this.value, (short) 0);
        if (this.max_size > other.length()) {
            Util.arrayFillNonAtomic(this.value, other.length(), (short) (this.max_size - other.length()), (byte) 0);
        }
        this.size = other.length();
    }

    /**
     * Equality check. Requires that this object and other have the same size or are padded with zeroes.
     * Returns true if all digits (except for leading zeroes) are equal.
     *
     * @param other BigNat to compare
     * @return true if this and other have the same value, false otherwise.
     */
    public boolean same_value(BigNat other) {
        short hashLen;
        byte[] tmpBuffer = rm.ARRAY_A;
        byte[] hashBuffer = rm.ARRAY_B;

        // Compare using hash engine
        // The comparison is made with hash of point values instead of directly values.
        // This way, offset of first mismatching byte is not leaked via timing side-channel.
        rm.lock(tmpBuffer);
        rm.lock(hashBuffer);
        if (this.length() == other.length()) {
            // Same length, we can hash directly from BN values
            rm.hashEngine.doFinal(this.value, (short) 0, this.length(), hashBuffer, (short) 0);
            hashLen = rm.hashEngine.doFinal(other.value, (short) 0, other.length(), tmpBuffer, (short) 0);
        } else {
            // Different length of bignats - can be still same if prepended with zeroes 
            // Find the length of longer one and padd other one with starting zeroes
            if (this.length() < other.length()) {
                this.prepend_zeros(other.length(), tmpBuffer, (short) 0);
                rm.hashEngine.doFinal(tmpBuffer, (short) 0, other.length(), hashBuffer, (short) 0);
                hashLen = rm.hashEngine.doFinal(other.value, (short) 0, other.length(), tmpBuffer, (short) 0);
            } else {
                other.prepend_zeros(this.length(), tmpBuffer, (short) 0);
                rm.hashEngine.doFinal(tmpBuffer, (short) 0, this.length(), hashBuffer, (short) 0);
                hashLen = rm.hashEngine.doFinal(this.value, (short) 0, this.length(), tmpBuffer, (short) 0);
            }
        }

        boolean result = Util.arrayCompare(hashBuffer, (short) 0, tmpBuffer, (short) 0, hashLen) == 0;

        rm.unlock(tmpBuffer);
        rm.unlock(hashBuffer);

        return result;
    }


    /**
    * Addition of big integers x and y stored in byte arrays with specified offset and length.
    * The result is stored into x array argument. 
    * @param x          array with first bignat
    * @param xOffset    start offset in array of {@code x}
    * @param xLength    length of {@code x}
    * @param y          array with second bignat
    * @param yOffset    start offset in array of {@code y}
    * @param yLength    length of {@code y}
    * @return 0x01 if carry of most significant byte occurs, 0x00 otherwise
    */
    public static byte add(byte[] x, short xOffset, short xLength, byte[] y,
                    short yOffset, short yLength) {
        short result = 0;
        short i = (short) (xLength + xOffset - 1);
        short j = (short) (yLength + yOffset - 1);

        for (; i >= xOffset && j >= 0; i--, j--) {
            result = (short) (result + (short) (x[i] & digit_mask) + (short) (y[j] & digit_mask));

            x[i] = (byte) (result & digit_mask);
            result = (short) ((result >> digit_len) & digit_mask);
        }
        while (result > 0 && i >= xOffset) {
            result = (short) (result + (short) (x[i] & digit_mask));
            x[i] = (byte) (result & digit_mask);
            result = (short) ((result >> digit_len) & digit_mask);
            i--;
        }

        // 1. result != 0 => result | -result will have the sign bit set
        // 2. casting magic to overcome the absence of int
        // 3. move the sign bit to the rightmost position
        // 4. discard the sign bit which is present due to the unavoidable casts
        //    and return the value of the rightmost bit
        return (byte) ((byte) (((short)(result | -result) & (short)0xFFFF) >>> 15) & 0x01);
    }

    /**
     * Subtracts big integer y from x specified by offset and length.
     * The result is stored into x array argument.
     *
     * @param x       array with first bignat
     * @param xOffset start offset in array of {@code x}
     * @param xLength length of {@code x}
     * @param y       array with second bignat
     * @param yOffset start offset in array of {@code y}
     * @param yLength length of {@code y}
     * @return true if carry of most significant byte occurs, false otherwise
     */
    public static boolean subtract(byte[] x, short xOffset, short xLength, byte[] y,
                                   short yOffset, short yLength) {
        short i = (short) (xLength + xOffset - 1);
        short j = (short) (yLength + yOffset - 1);
        short carry = 0;
        short subtraction_result = 0;

        for (; i >= xOffset && j >= yOffset; i--, j--) {
            subtraction_result = (short) ((x[i] & digit_mask) - (y[j] & digit_mask) - carry);
            x[i] = (byte) (subtraction_result & digit_mask);
            carry = (short) (subtraction_result < 0 ? 1 : 0);
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
     * Substract provided other bignat from this bignat.
     *
     * @param other bignat to be substracted from this
     */
    public void subtract(BigNat other) {
        this.times_minus(other, (short) 0, (short) 1);
    }

    /**
     * Scaled subtraction. Subtracts {@code mult * 2^(}{@link #digit_len}
     * {@code  * shift) * other} from this.
     * <p>
     * That is, shifts {@code mult * other} precisely {@code shift} digits to
     * the left and subtracts that value from this. {@code mult} must be less
     * than {@link #bignat_base}, that is, it must fit into one digit. It is
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
     * @param other Bignat to subtract from this object
     * @param shift number of digits to shift {@code other} to the left
     * @param mult  of type short, multiple of {@code other} to subtract from this
     *              object. Must be below {@link #bignat_base}.
     */
    public void times_minus(BigNat other, short shift, short mult) {
        short akku = 0;
        short subtraction_result;
        short i = (short) (this.size - 1 - shift);
        short j = (short) (other.size - 1);
        for (; i >= 0 && j >= 0; i--, j--) {
            akku = (short) (akku + (short) (mult * (other.value[j] & digit_mask)));
            subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));

            value[i] = (byte) (subtraction_result & digit_mask);
            akku = (short) ((akku >> digit_len) & digit_mask);
            if (subtraction_result < 0) {
                akku++;
            }
        }

        // deal with carry as long as there are digits left in this
        while (i >= 0 && akku != 0) {
            subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));
            value[i] = (byte) (subtraction_result & digit_mask);
            akku = (short) ((akku >> digit_len) & digit_mask);
            if (subtraction_result < 0) {
                akku++;
            }
            i--;
        }
    }

    /**
     * Quick function for decrement of this BigNat value by 1. Faster than {@code substract(BigNat.one())}
     */
    public void decrement_one() {
        short tmp = 0;
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
     * Quick function for increment of this bignat value by 1. Faster than
     * {@code add(Bignat.one())}
     */
    public void increment_one() {
        short tmp = 0;
        for (short i = (short) (this.size - 1); i >= 0; i--) {
            tmp = (short) (this.value[i] & 0xff);
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
     * {@link #double_digit_len} for {@code x == 0}.
     */
    private static short highest_bit(short x) {
        for (short i = 0; i < double_digit_len; i++) {
            if (x < 0) {
                return i;
            }
            x <<= 1;
        }
        return double_digit_len;
    }

    /**
     * Shift to the left and fill. Takes {@code high} {@code middle} {@code low}
     * as 4 digits, shifts them {@code shift} bits to the left and returns the
     * most significant {@link #double_digit_len} bits.
     * <p>
     * Utility method, used in division.
     *
     * @param high   of type short, most significant {@link #double_digit_len} bits
     * @param middle of type byte, middle {@link #digit_len} bits
     * @param low    of type byte, least significant {@link #digit_len} bits
     * @param shift  amount of left shift
     * @return most significant {@link #double_digit_len} as short
     */
    private static short shift_bits(short high, byte middle, byte low,
                                    short shift) {
        // shift high
        high <<= shift;

        // merge middle bits
        byte mask = (byte) (digit_mask << (shift >= digit_len ? 0 : digit_len
                - shift));
        short bits = (short) ((short) (middle & mask) & digit_mask);
        if (shift > digit_len) {
            bits <<= shift - digit_len;
        } else {
            bits >>>= digit_len - shift;
        }
        high |= bits;

        if (shift <= digit_len) {
            return high;
        }

        // merge low bits
        mask = (byte) (digit_mask << double_digit_len - shift);
        bits = (short) ((((short) (low & mask) & digit_mask) >> double_digit_len - shift));
        high |= bits;

        return high;
    }

    /**
     * Scaled comparison. Compares this number with {@code other * 2^(}
     * {@link #digit_len} {@code * shift)}. That is, shifts {@code other}
     * {@code shift} digits to the left and compares then. This bignat and
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
     * @param other Bignat to compare to
     * @param shift left shift of other before the comparison
     * @param start digits to skip at the beginning
     * @return true if this number is strictly less than the shifted
     * {@code other}, false otherwise.
     */
    public boolean shift_lesser(BigNat other, short shift, short start) {
        short j;

        j = (short) (other.size + shift - this.size + start);
        short this_short, other_short;
        for (short i = start; i < this.size; i++, j++) {
            this_short = (short) (this.value[i] & digit_mask);
            if (j >= 0 && j < other.size) {
                other_short = (short) (other.value[j] & digit_mask);
            } else {
                other_short = 0;
            }
            if (this_short < other_short) {
                return true; // CTO
            }
            if (this_short > other_short) {
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
    public boolean smaller(BigNat other) {
        short index_this = 0;
        for (short i = 0; i < this.length(); i++) {
            if (this.value[i] != 0x00) {
                index_this = i;
            }
        }

        short index_other = 0;
        for (short i = 0; i < other.length(); i++) {
            if (other.value[i] != 0x00) {
                index_other = i;
            }
        }

        if ((short) (this.length() - index_this) < (short) (other.length() - index_other)) {
            return true; // CTO
        }
        short i = 0;
        while (i < this.length() && i < other.length()) {
            if (((short) (this.value[i] & digit_mask)) < ((short) (other.value[i] & digit_mask))) {
                return true; // CTO
            }
            i = (short) (1 + i);
        }

        return false;
    }


    /**
     * Comparison of this and other.
     *
     * @param other Bignat to compare with
     * @return true if this number is strictly lesser than {@code other}, false
     * otherwise.
     */
    public boolean lesser(BigNat other) {
        return this.shift_lesser(other, (short) 0, (short) 0);
    }

    /**
     * Test equality with zero.
     *
     * @return true if this bignat equals zero.
     */
    public boolean is_zero() {
        for (short i = 0; i < size; i++) {
            if (value[i] != 0) {
                return false; // CTO
            }
        }
        return true;
    }

    /**
     * Check if stored bignat is odd.
     *
     * @return true if odd, false if even
     */
    public boolean is_odd() {
        if ((value[(short) (this.size - 1)] & 1) == 0) {
            return false; // CTO
        }
        return true;
    }

    /**
     * Remainder and Quotient. Divide this number by {@code divisor} and store
     * the remainder in this. If {@code quotient} is non-null store the quotient
     * there.
     * <p>
     * There are no direct size constraints, but if {@code quotient} is
     * non-null, it must be big enough for the quotient, otherwise an assertion
     * is thrown.
     * <p>
     * Uses schoolbook division inside and has O^2 complexity in the difference
     * of significant digits of the divident (in this number) and the divisor.
     * For numbers of equal size complexity is linear.
     *
     * @param divisor  must be non-zero
     * @param quotient gets the quotient if non-null
     */
    public void remainder_divide(BigNat divisor, BigNat quotient) {
        // There are some size requirements, namely that quotient must
        // be big enough. However, this depends on the value of the
        // divisor and is therefore not stated here.

        // zero-initialize the quotient, because we are only adding to it below
        if (quotient != null) {
            quotient.zero();
        }

        // divisor_index is the first nonzero digit (short) in the divisor
        short divisor_index = 0;
        while (divisor.value[divisor_index] == 0) {
            divisor_index++;
        }

        // The size of this might be different from divisor. Therefore,
        // for the first subtraction round we have to shift the divisor
        // divisor_shift = this.size - divisor.size + divisor_index
        // digits to the left. If this amount is negative, then
        // this is already smaller then divisor and we are done.
        // Below we do divisor_shift + 1 subtraction rounds. As an
        // additional loop index we also count the rounds (from
        // zero upwards) in division_round. This gives access to the
        // first remaining divident digits.
        short divisor_shift = (short) (this.size - divisor.size + divisor_index);
        short division_round = 0;

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
        short first_divisor_digit = (short) (divisor.value[divisor_index] & digit_mask);
        short divisor_bit_shift = (short) (highest_bit((short) (first_divisor_digit + 1)) - 1);
        byte second_divisor_digit = divisor_index < (short) (divisor.size - 1) ? divisor.value[(short) (divisor_index + 1)]
                : 0;
        byte third_divisor_digit = divisor_index < (short) (divisor.size - 2) ? divisor.value[(short) (divisor_index + 2)]
                : 0;

        // The following variables are used inside the loop only.
        // Declared here as optimization.
        // divident_digits and divisor_digit hold the first one or two
        // digits. Needed to compute the multiple of the divisor to
        // subtract from this.
        short divident_digits, divisor_digit;

        // To increase precisision the first digits are shifted to the
        // left or right a bit. The following variables compute the shift.
        short divident_bit_shift, bit_shift;

        // Declaration of the multiple, with which the divident is
        // multiplied in each round and the quotient_digit. Both are
        // a single digit, but declared as a double digit to avoid the
        // trouble with negative numbers. If quotient != null multiple is
        // added to the quotient. This addition is done with quotient_digit.
        short multiple, quotient_digit;
        short numLoops = 0;
        short numLoops2 = 0;
        while (divisor_shift >= 0) {
            numLoops++; // CTO number of outer loops is constant (for given length of divisor)
            // Keep subtracting from this until
            // divisor * 2^(8 * divisor_shift) is bigger than this.
            while (!shift_lesser(divisor, divisor_shift,
                    (short) (division_round > 0 ? division_round - 1 : 0))) {
                numLoops2++; // BUGBUG: CTO - number of these loops fluctuates heavily => strong impact on operation time 
                // this is bigger or equal than the shifted divisor.
                // Need to subtract some multiple of divisor from this.
                // Make a conservative estimation of the multiple to subtract.
                // We estimate a lower bound to avoid underflow, and continue
                // to subtract until the remainder in this gets smaller than
                // the shifted divisor.
                // For the estimation get first the two relevant digits
                // from this and the first relevant digit from divisor.
                divident_digits = division_round == 0 ? 0
                        : (short) ((short) (value[(short) (division_round - 1)]) << digit_len);
                divident_digits |= (short) (value[division_round] & digit_mask);

                // The multiple to subtract from this is
                // divident_digits / divisor_digit, but there are two
                // complications:
                // 1. divident_digits might be negative,
                // 2. both might be very small, in which case the estimated
                // multiple is very inaccurate.
                if (divident_digits < 0) {
                    // case 1: shift both one bit to the right
                    // In standard java (ie. in the test frame) the operation
                    // for >>= and >>>= seems to be done in integers,
                    // even if the left hand side is a short. Therefore,
                    // for a short left hand side there is no difference
                    // between >>= and >>>= !!!
                    // Do it the complicated way then.
                    divident_digits = (short) ((divident_digits >>> 1) & positive_double_digit_mask);
                    divisor_digit = (short) ((first_divisor_digit >>> 1) & positive_double_digit_mask);
                } else {
                    // To avoid case 2 shift both to the left
                    // and add relevant bits.
                    divident_bit_shift = (short) (highest_bit(divident_digits) - 1);
                    // Below we add one to divisor_digit to avoid underflow.
                    // Take therefore the highest bit of divisor_digit + 1
                    // to avoid running into the negatives.
                    bit_shift = divident_bit_shift <= divisor_bit_shift ? divident_bit_shift
                            : divisor_bit_shift;

                    divident_digits = shift_bits(
                            divident_digits,
                            division_round < (short) (this.size - 1) ? value[(short) (division_round + 1)]
                                    : 0,
                            division_round < (short) (this.size - 2) ? value[(short) (division_round + 2)]
                                    : 0, bit_shift);
                    divisor_digit = shift_bits(first_divisor_digit,
                            second_divisor_digit, third_divisor_digit,
                            bit_shift);

                }

                // add one to divisor to avoid underflow
                multiple = (short) (divident_digits / (short) (divisor_digit + 1));

                // Our strategy to avoid underflow might yield multiple == 0.
                // We know however, that divident >= divisor, therefore make
                // sure multiple is at least 1.
                if (multiple < 1) {
                    multiple = 1;
                }

                times_minus(divisor, divisor_shift, multiple);

                // build quotient if desired
                if (quotient != null) {
                    // Express the size constraint only here. The check is
                    // essential only in the first round, because
                    // divisor_shift decreases. divisor_shift must be
                    // strictly lesser than quotient.size, otherwise
                    // quotient is not big enough. Note that the initially
                    // computed divisor_shift might be bigger, this
                    // is OK, as long as we don't reach this point.

                    quotient_digit = (short) ((quotient.value[(short) (quotient.size - 1 - divisor_shift)] & digit_mask) + multiple);
                    quotient.value[(short) (quotient.size - 1 - divisor_shift)] = (byte) (quotient_digit);
                }
            }

            // treat loop indices
            division_round++;
            divisor_shift--;
        }
    }


    /**
     * Add short value to this bignat
     *
     * @param other short value to add
     */
    public void add(short other) {
        Util.setShort(rm.RAM_WORD, (short) 0, other); // serialize other into array
        this.add_carry(rm.RAM_WORD, (short) 0, (short) 2); // add as array
    }

    /**
     * Addition with carry report. Adds other to this number. If this is too
     * small for the result (i.e., an overflow occurs) the method returns true.
     * Further, the result in {@code this} will then be the correct result of an
     * addition modulo the first number that does not fit into {@code this} (
     * {@code 2^(}{@link #digit_len}{@code * }{@link #size this.size}{@code )}),
     * i.e., only one leading 1 bit is missing. If there is no overflow the
     * method will return false.
     * <p>
     * <p>
     * It would be more natural to report the overflow with an
     * {@link javacard.framework.UserException}, however its
     * {@link javacard.framework.UserException#throwIt throwIt} method dies with
     * a null pointer exception when it runs in a host test frame...
     * <p>
     * <p>
     * Asserts that the size of other is not greater than the size of this.
     *
     * @param other       Bignat to add
     * @param otherOffset start offset within other buffer
     * @param otherLen    length of other
     * @return true if carry occurs, false otherwise
     */
    public boolean add_carry(byte[] other, short otherOffset, short otherLen) {
        short akku = 0;
        short j = (short) (this.size - 1);
        for (short i = (short) (otherLen - 1); i >= 0 && j >= 0; i--, j--) {
            akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (other[(short) (i + otherOffset)] & digit_mask));

            this.value[j] = (byte) (akku & digit_mask);
            akku = (short) ((akku >> digit_len) & digit_mask);
        }
        // add carry at position j
        while (akku > 0 && j >= 0) {
            akku = (short) (akku + (short) (this.value[j] & digit_mask));
            this.value[j] = (byte) (akku & digit_mask);
            akku = (short) ((akku >> digit_len) & digit_mask);
            j--;
        }

        return akku != 0;
    }

    /**
     * Add with carry. See {@code add_cary()} for full description
     *
     * @param other value to be added
     * @return true if carry happens, false otherwise
     */
    public boolean add_carry(BigNat other) {
        return add_carry(other.value, (short) 0, other.size);
    }


    /**
     * Addition. Adds other to this number.
     * <p>
     * Same as {@link #times_add times_add}{@code (other, 1)} but without the
     * multiplication overhead.
     * <p>
     * Asserts that the size of other is not greater than the size of this.
     *
     * @param other Bignat to add
     */
    public void add(BigNat other) {
        add_carry(other);
    }

    /**
     * Add other bignat to this bignat modulo {@code modulo} value.
     *
     * @param other  value to add
     * @param modulo value of modulo to compute
     */
    public void mod_add(BigNat other, BigNat modulo) {
        BigNat tmp = rm.BN_A;

        short tmp_size = this.size;
        if (tmp_size < other.size) {
            tmp_size = other.size;
        }
        tmp_size++;
        tmp.lock();
        tmp.set_size(tmp_size);
        tmp.zero();
        tmp.copy(this);
        tmp.add(other);
        tmp.mod(modulo);
        tmp.shrink();
        this.clone(tmp);
        tmp.unlock();
    }

    /**
     * Subtract other BigNat from this BigNat modulo {@code modulo} value.
     *
     * @param other  value to substract
     * @param modulo value of modulo to apply
     */
    public void mod_sub(BigNat other, BigNat modulo) {
        BigNat tmp = rm.BN_B;
        BigNat tmpOther = rm.BN_C;
        BigNat tmpThis = rm.BN_A;

        if (other.lesser(this)) { // CTO
            this.subtract(other);
            this.mod(modulo);
        } else { //other>this (mod-other+this)
            tmpOther.lock();
            tmpOther.clone(other);
            tmpOther.mod(modulo);

            //fnc_mod_sub_tmpThis = new Bignat(this.length());
            tmpThis.lock();
            tmpThis.clone(this);
            tmpThis.mod(modulo);

            tmp.lock();
            tmp.clone(modulo);
            tmp.subtract(tmpOther);
            tmpOther.unlock();
            tmp.add(tmpThis); //this will never overflow as "other" is larger than "this"
            tmpThis.unlock();
            tmp.mod(modulo);
            tmp.shrink();
            this.clone(tmp);
            tmp.unlock();
        }
    }


    /**
     * Scaled addition. Add {@code mult * other} to this number. {@code mult}
     * must be below {@link #bignat_base}, that is, it must fit into one digit.
     * It is only declared as a short here to avoid negative numbers.
     * <p>
     * Asserts (overly restrictive) that this and other have the same size.
     * <p>
     * Same as {@link #times_add_shift times_add_shift}{@code (other, 0, mult)}
     * but without the shift overhead.
     * <p>
     * Used in multiplication.
     *
     * @param other Bignat to add
     * @param mult  of short, factor to multiply {@code other} with before
     *              addition. Must be less than {@link #bignat_base}.
     */
    public void times_add(BigNat other, short mult) {
        short akku = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            akku = (short) (akku + (short) (this.value[i] & digit_mask) + (short) (mult * (other.value[i] & digit_mask)));
            this.value[i] = (byte) (akku & digit_mask);
            akku = (short) ((akku >> digit_len) & digit_mask);
        }
    }

    /**
     * Scaled addition. Adds {@code mult * other * 2^(}{@link #digit_len}
     * {@code * shift)} to this. That is, shifts other {@code shift} digits to
     * the left, multiplies it with {@code mult} and adds then.
     * <p>
     * {@code mult} must be less than {@link #bignat_base}, that is, it must fit
     * into one digit. It is only declared as a short here to avoid negative
     * numbers.
     * <p>
     * Asserts that the size of this is greater than or equal to
     * {@code other.size + shift + 1}.
     *
     * @param x     Bignat to add
     * @param mult  of short, factor to multiply {@code other} with before
     *              addition. Must be less than {@link #bignat_base}.
     * @param shift number of digits to shift {@code other} to the left, before
     *              addition.
     */
    public void times_add_shift(BigNat x, short shift, short mult) {
        short akku = 0;
        short j = (short) (this.size - 1 - shift);
        for (short i = (short) (x.size - 1); i >= 0; i--, j--) {
            akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (mult * (x.value[i] & digit_mask)));

            this.value[j] = (byte) (akku & digit_mask);
            akku = (short) ((akku >> digit_len) & digit_mask);
        }
        // add carry at position j
        akku = (short) (akku + (short) (this.value[j] & digit_mask));
        this.value[j] = (byte) (akku & digit_mask);
        // BUGUG: assert no overflow
    }

    /**
     * Division of this bignat by provided other bignat.
     *
     * @param other value of divisor
     */
    public void divide(BigNat other) {
        BigNat tmp = rm.BN_E;

        tmp.lock();
        tmp.clone(this);
        tmp.remainder_divide(other, this);
        this.clone(tmp);
        tmp.unlock();
    }

    /**
     * Greatest common divisor of this BigNat with other BigNat. Result is
     * stored into this.
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
        while (!other.is_zero()) {
            tmp.clone(tmpOther);
            this.mod(tmpOther);
            tmpOther.clone(this);
            this.clone(tmp);
        }

        tmp.unlock();
        tmpOther.unlock();
    }

    /**
     * Decides whether the arguments are coprime or not.
     *
     * @param a BigNat value
     * @param b BigNat value
     * @return true if coprime, false otherwise
     */
    public boolean is_coprime(BigNat a, BigNat b) {
        BigNat tmp = rm.BN_C; // is_coprime calls gcd internally

        tmp.lock();
        tmp.clone(a);

        tmp.gcd(b);
        return tmp.same_value(ResourceManager.ONE);
    }

    /**
     * Computes base^exp and stores result into this bignat
     *
     * @param base value of base
     * @param exp  value of exponent
     */
    public void exponentiation(BigNat base, BigNat exp) {
        BigNat tmp = rm.BN_A;
        BigNat i = rm.BN_B;

        this.one();
        i.lock();
        i.set_size(exp.length());
        i.zero();
        tmp.lock();
        tmp.set_size((short) (2 * this.length()));
        for (; i.lesser(exp); i.increment_one()) {
            tmp.mult(this, base);
            this.copy(tmp);
        }
        i.unlock();
        tmp.unlock();
    }

    /**
     * Multiplication. Automatically selects fastest available algorithm.
     * Stores {@code x * y} in this. To ensure this is big
     * enough for the result it is asserted that the size of this is greater
     * than or equal to the sum of the sizes of {@code x} and {@code y}.
     *
     * @param x first factor
     * @param y second factor
     */
    public void mult(BigNat x, BigNat y) {
        if (!OperationSupport.getInstance().RSA_MULT_TRICK || x.length() < FAST_MULT_VIA_RSA_THRESHOLD_LENGTH) {
            // If simulator or not supported, use slow multiplication
            // Use slow multiplication also when numbers are small => faster to do in software
            mult_schoolbook(x, y);
        } else {
            mult_rsa_trick(x, y, null, null);
        }
    }

    /**
     * Slow schoolbook algorithm for multiplication
     *
     * @param x first number to multiply
     * @param y second number to multiply
     */
    public void mult_schoolbook(BigNat x, BigNat y) {
        this.zero(); // important to keep, used in exponentiation()
        for (short i = (short) (y.size - 1); i >= 0; i--) {
            this.times_add_shift(x, (short) (y.size - 1 - i), (short) (y.value[i] & digit_mask));
        }
    }

    /**
     * Performs multiplication of two bignats x and y and stores result into this.
     * RSA engine is used to speedup operation for large values.
     * Idea of speedup:
     * We need to mutiply x.y where both x and y are 32B
     * (x + y)^2 == x^2 + y^2 + 2xy
     * Fast RSA engine is available (a^b mod n)
     * n can be set bigger than 64B => a^b mod n == a^b
     * [(x + y)^2 mod n] - [x^2 mod n] - [y^2 mod n] => 2xy where [] means single RSA operation
     * 2xy / 2 => result of mult(x,y)
     * Note: if multiplication is used with either x or y argument same repeatedly,
     * [x^2 mod n] or [y^2 mod n] can be precomputed and passed as arguments x_pow_2 or y_pow_2
     *
     * @param x       first value to multiply
     * @param y       second value to multiply
     * @param x_pow_2 if not null, array with precomputed value x^2 is expected
     * @param y_pow_2 if not null, array with precomputed value y^2 is expected
     */
    public void mult_rsa_trick(BigNat x, BigNat y, byte[] x_pow_2, byte[] y_pow_2) {
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
        if (x_pow_2 == null) {
            // x^2 is not precomputed
            Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
            xOffset = (short) (resultBuffer2.length - x.length());
            Util.arrayCopyNonAtomic(x.value, (short) 0, resultBuffer2, xOffset, x.length());
            rm.multCiph.doFinal(resultBuffer2, (byte) 0, (short) resultBuffer2.length, resultBuffer2, (short) 0);
        } else {
            // x^2 is precomputed
            if ((short) x_pow_2.length != (short) resultBuffer2.length) {
                Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
                xOffset = (short) ((short) resultBuffer2.length - (short) x_pow_2.length);
            } else {
                xOffset = 0;
            }
            Util.arrayCopyNonAtomic(x_pow_2, (short) 0, resultBuffer2, xOffset, (short) x_pow_2.length);
        }
        // ((x+y)^2) - x^2
        subtract(resultBuffer1, (short) 0, (short) resultBuffer1.length, resultBuffer2, (short) 0, (short) resultBuffer2.length);

        // y^2
        if (y_pow_2 == null) {
            // y^2 is not precomputed
            Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
            yOffset = (short) (resultBuffer2.length - y.length());
            Util.arrayCopyNonAtomic(y.value, (short) 0, resultBuffer2, yOffset, y.length());
            rm.multCiph.doFinal(resultBuffer2, (byte) 0, (short) resultBuffer2.length, resultBuffer2, (short) 0);
        } else {
            // y^2 is precomputed
            if ((short) y_pow_2.length != (short) resultBuffer2.length) {
                Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
                yOffset = (short) ((short) resultBuffer2.length - (short) y_pow_2.length);
            } else {
                yOffset = 0;
            }
            Util.arrayCopyNonAtomic(y_pow_2, (short) 0, resultBuffer2, yOffset, (short) y_pow_2.length);
        }


        // {(x+y)^2) - x^2} - y^2
        subtract(resultBuffer1, (short) 0, (short) resultBuffer1.length, resultBuffer2, (short) 0, (short) resultBuffer2.length);

        // we now have 2xy in mult_resultArray, divide it by 2 => shift by one bit and fill back into this
        short multOffset = (short) ((short) resultBuffer1.length - 1);
        short res = 0;
        short res2 = 0;
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
            res = (short) (resultBuffer1[multOffset] & 0xff);
            res = (short) (res >> 1);
            res2 = (short) (resultBuffer1[(short) (multOffset - 1)] & 0xff);
            res2 = (short) (res2 << 7);
            this.value[i] = (byte) (short) (res | res2);
            multOffset--;
        }
        rm.unlock(resultBuffer1);
        rm.unlock(resultBuffer2);
    }


    /**
     * Performs multiplication of two BigNat x and y and stores result into this.
     * RSA engine is used to speedup operation for large values.
     *
     * @param x       first value to multiply
     * @param y       second value to multiply
     * @param mod     modulus
     */
    public void mod_mult_rsa_trick(BigNat x, BigNat y, BigNat mod) {
        this.clone(x);
        this.mod_add(y, mod);
        this.mod_exp2(mod);

        BigNat tmp = rm.BN_D;
        tmp.lock();
        tmp.clone(x);
        tmp.mod_exp2(mod);
        this.mod_sub(tmp, mod);

        tmp.clone(y);
        tmp.mod_exp2(mod);
        this.mod_sub(tmp, mod);
        tmp.unlock();

        boolean carry = false;
        if(this.is_odd()) {
            carry = this.add_carry(mod);
        }

        this.divide_by_2(carry ? (short) (1 << 7) : (short) 0);
    }

    /**
     * Multiplication of bignats x and y computed by modulo {@code modulo}.
     * The result is stored to this.
     *
     * @param x      first value to multiply
     * @param y      second value to multiply
     * @param modulo value of modulo
     */
    public void mod_mult(BigNat x, BigNat y, BigNat modulo) {
        BigNat tmp = rm.BN_E; // mod_mult is called from sqrt_FP => requires BN_E not being locked when mod_mult is called

        tmp.lock();

        if(OperationSupport.getInstance().RSA_MOD_MULT_TRICK) {
            tmp.mod_mult_rsa_trick(x, y, modulo);
        } else {
            tmp.resize_to_max(false);
            tmp.mult(x, y);
            tmp.mod(modulo);
            tmp.shrink();
        }
        this.clone(tmp);
        tmp.unlock();
    }
    // Potential speedup for  modular multiplication
    // Binomial theorem: (op1 + op2)^2 - (op1 - op2)^2 = 4 * op1 * op2 mod (mod)


    /**
     * One digit left shift.
     * <p>
     * Asserts that the first digit is zero.
     */
    public void shift_left() {
        // NOTE: assumes that overlapping src and dest arrays are properly handled by Util.arrayCopyNonAtomic
        Util.arrayCopyNonAtomic(this.value, (short) 1, this.value, (short) 0, (short) (size - 1));
        value[(short) (size - 1)] = 0;
    }

    /**
     * Optimized division by value two with carry
     *
     * @param carry XORed into the highest byte
     */
    private void divide_by_2(short carry) {
        short tmp = 0;
        short tmp2 = 0;
        for (short i = 0; i < this.size; i++) {
            tmp = (short) (this.value[i] & 0xff);
            tmp2 = tmp;
            tmp >>= 1; // shift by 1 => divide by 2
            this.value[i] = (byte) (tmp | carry);
            carry = (short) (tmp2 & 0x01); // save lowest bit
            carry <<= 7; // shifted to highest position
        }
    }

    /**
     * Optimized division by value two
     */
    private void divide_by_2() {
        divide_by_2((short) 0);
    }

    /**
     * Computes square root of provided bignat which MUST be prime using Tonelli
     * Shanks Algorithm. The result (one of the two roots) is stored to this.
     *
     * @param p value to compute square root from
     */
    public void sqrt_FP(BigNat p) {
        BigNat s = rm.BN_A;
        BigNat exp = rm.BN_A;
        BigNat p1 = rm.BN_B;
        BigNat q = rm.BN_C;
        BigNat tmp = rm.BN_D;
        BigNat z = rm.BN_E;

        // 1. By factoring out powers of 2, find Q and S such that p-1=Q2^S p-1=Q*2^S and Q is odd
        p1.lock();
        p1.clone(p);
        p1.decrement_one();

        // Compute Q
        q.lock();
        q.clone(p1);
        q.divide_by_2(); // Q /= 2

        //Compute S
        s.lock();
        s.set_size(p.length());
        s.zero();
        tmp.lock();
        tmp.set_size(p.length());
        tmp.zero();

        while (!tmp.same_value(q)) {
            s.increment_one();
            // TODO investigate why just mod_mult(s, q, p) does not work (apart from locks)
            tmp.resize_to_max(false);
            tmp.mult(s, q);
            tmp.mod(p);
            tmp.shrink();
        }
        tmp.unlock();
        s.unlock();

        // 2. Find the first quadratic non-residue z by brute-force search
        exp.lock();
        exp.clone(p1);
        exp.divide_by_2();


        z.lock();
        z.set_size(p.length());
        z.one();
        tmp.lock();
        tmp.zero();
        tmp.copy(ResourceManager.ONE);

        while (!tmp.same_value(p1)) {
            z.increment_one();
            tmp.copy(z);
            tmp.mod_exp(exp, p);
        }
        p1.unlock();
        tmp.unlock();
        z.unlock();
        exp.copy(q);
        q.unlock();
        exp.increment_one();
        exp.divide_by_2();

        this.mod(p);
        this.mod_exp(exp, p);
        exp.unlock();
    }


    /**
     * Computes and stores modulo of this bignat.
     *
     * @param modulo value of modulo
     */
    public void mod(BigNat modulo) {
        this.remainder_divide(modulo, null);
        // NOTE: attempt made to utilize crypto co-processor in pow2Mod_RSATrick_worksOnlyAbout30pp, but doesn't work for all inputs 
    }


    /**
     * Computes inversion of this bignat taken modulo {@code modulo}.
     * The result is stored into this.
     *
     * @param modulo value of modulo
     */
    public void mod_inv(BigNat modulo) {
        BigNat tmp = rm.BN_B;
        tmp.lock();
        tmp.clone(modulo);
        tmp.decrement_one();
        tmp.decrement_one();

        mod_exp(tmp, modulo);
        tmp.unlock();
    }

    /**
     * Computes {@code res := this ** exponent mod modulo} and store results into this.
     * Uses RSA engine to quickly compute this^exponent % modulo
     *
     * @param exponent value of exponent
     * @param modulo   value of modulo
     */
    public void mod_exp(BigNat exponent, BigNat modulo) {
        if (!OperationSupport.getInstance().RSA_MOD_EXP)
            ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);

        BigNat tmpMod = rm.BN_F;  // mod_exp is called from sqrt_FP => requires BN_F not being locked when mod_exp is called
        byte[] tmpBuffer = rm.ARRAY_A;
        short tmpSize = (short) (rm.MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8);
        short modLength;

        tmpMod.lock();
        tmpMod.set_size(tmpSize);

        if(OperationSupport.getInstance().RSA_MOD_EXP_PUB) {
            // Verify if pre-allocated engine match the required values
            if (rm.expPub.getSize() < (short) (modulo.length() * 8) || rm.expPub.getSize() < (short) (this.length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (OperationSupport.getInstance().RSA_KEY_REFRESH) {
                // Simulator fails when reusing the original object
                rm.expPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rm.MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);
            }
            rm.expPub.setExponent(exponent.as_byte_array(), (short) 0, exponent.length());
            rm.lock(tmpBuffer);
            if (OperationSupport.getInstance().RSA_RESIZE_MODULUS) {
                if (OperationSupport.getInstance().RSA_RESIZE_MODULUS_APPEND) {
                    modulo.append_zeros(tmpSize, tmpBuffer, (short) 0);
                } else {
                    modulo.prepend_zeros(tmpSize, tmpBuffer, (short) 0);

                }
                rm.expPub.setModulus(tmpBuffer, (short) 0, tmpSize);
                modLength = tmpSize;
            } else {
                rm.expPub.setModulus(modulo.as_byte_array(), (short) 0, modulo.length());
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
                rm.expPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, rm.MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);
            }
            rm.expPriv.setExponent(exponent.as_byte_array(), (short) 0, exponent.length());
            rm.lock(tmpBuffer);
            if (OperationSupport.getInstance().RSA_RESIZE_MODULUS) {
                if (OperationSupport.getInstance().RSA_RESIZE_MODULUS_APPEND) {
                    modulo.append_zeros(tmpSize, tmpBuffer, (short) 0);
                } else {
                    modulo.prepend_zeros(tmpSize, tmpBuffer, (short) 0);

                }
                rm.expPriv.setModulus(tmpBuffer, (short) 0, tmpSize);
                modLength = tmpSize;
            } else {
                rm.expPriv.setModulus(modulo.as_byte_array(), (short) 0, modulo.length());
                modLength = modulo.length();
            }
            rm.expCiph.init(rm.expPriv, Cipher.MODE_DECRYPT);
        }
        short len;
        if (OperationSupport.getInstance().RSA_RESIZE_BASE) {
            this.prepend_zeros(modLength, tmpBuffer, (short) 0);
            len = rm.expCiph.doFinal(tmpBuffer, (short) 0, modLength, tmpMod.value, (short) 0);
        } else {
            len = rm.expCiph.doFinal(this.as_byte_array(), (short) 0, this.length(), tmpMod.value, (short) 0);
        }
        rm.unlock(tmpBuffer);

        if (OperationSupport.getInstance().RSA_PREPEND_ZEROS) {
            // Decrypted length can be either tmp_size or less because of leading zeroes consumed by simulator engine implementation
            // Move obtained value into proper position with zeroes prepended
            if (len != tmpSize) {
                rm.lock(tmpBuffer);
                Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0);
                Util.arrayCopyNonAtomic(tmpMod.value, (short) 0, tmpBuffer, (short) (tmpSize - len), len);
                Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, tmpMod.value, (short) 0, tmpSize);
                rm.unlock(tmpBuffer);
            }
        } else {
            // real cards should keep whole length of block, just check
            if (len != tmpSize) {
                ISOException.throwIt(ReturnCodes.SW_ECPOINT_UNEXPECTED_KA_LEN);
            }
        }
        if (OperationSupport.getInstance().RSA_MOD_EXP_EXTRA_MOD) {
            tmpMod.mod(modulo);
        }
        tmpMod.shrink();
        this.clone(tmpMod);
        tmpMod.unlock();
    }


    public void mod_exp2(BigNat modulo) {
        mod_exp(ResourceManager.TWO, modulo);
    }

    /**
     * Negate current Bignat modulo provided modulus
     *
     * @param mod value of modulus
     */
    public void mod_negate(BigNat mod) {
        BigNat tmp = rm.BN_B;

        tmp.lock();
        tmp.set_size(mod.length());
        tmp.copy(mod); //-y=mod-y

        if (!this.lesser(mod)) { // y<mod
            this.mod(mod);//-y=y-mod
        }
        tmp.subtract(this);
        this.copy(tmp);
        tmp.unlock();
    }

    /**
     * Shifts stored value to right by specified number of bytes. This operation equals to multiplication by value numBytes * 256.
     *
     * @param numBytes number of bytes to shift
     */
    public void shift_bytes_right(short numBytes) {
        byte[] tmp = rm.ARRAY_A;

        // Move whole content by numBytes offset
        rm.lock(tmp);
        Util.arrayCopyNonAtomic(this.value, (short) 0, tmp, (short) 0, (short) (this.value.length));
        Util.arrayCopyNonAtomic(tmp, (short) 0, this.value, numBytes, (short) ((short) (this.value.length) - numBytes));
        Util.arrayFillNonAtomic(this.value, (short) 0, numBytes, (byte) 0);
        rm.unlock(tmp);
    }

    /**
     * Allocates required underlying storage array with given maximum size and
     * allocator type (RAM or EEROM). Maximum size can be increased only by
     * future reallocation if allowed by ALLOW_RUNTIME_REALLOCATION flag
     *
     * @param maxSize       maximum size of this Bignat
     * @param allocatorType memory allocator type. If
     *                      JCSystem.MEMORY_TYPE_PERSISTENT then memory is allocated in EEPROM. Use
     *                      JCSystem.CLEAR_ON_RESET or JCSystem.CLEAR_ON_DESELECT for allocation in
     *                      RAM with corresponding clearing behaviour.
     */
    private void allocate_storage_array(short maxSize, byte allocatorType) {
        this.size = maxSize;
        this.max_size = maxSize;
        this.allocatorType = allocatorType;
        this.value = rm.memAlloc.allocateByteArray(this.max_size, allocatorType);
    }

    /**
     * Set content of Bignat internal array
     *
     * @param from_array_length available data in {@code from_array}
     * @param this_offset       offset where data should be stored
     * @param from_array        data array to deserialize from
     * @param from_array_offset offset in {@code from_array}
     * @return the number of shorts actually read, except for the case where
     * deserialization finished by reading precisely {@code len} shorts, in this
     * case {@code len + 1} is returned.
     */
    public short from_byte_array(short from_array_length, short this_offset, byte[] from_array, short from_array_offset) {
        short max
                = (short) (this_offset + from_array_length) <= this.size
                ? from_array_length : (short) (this.size - this_offset);
        Util.arrayCopyNonAtomic(from_array, from_array_offset, value, this_offset, max);
        if ((short) (this_offset + from_array_length) == this.size) {
            return (short) (from_array_length + 1);
        } else {
            return max;
        }
    }

    /**
     * Set content of BigNat internal array
     *
     * @param from_array data array to deserialize from
     * @return the number of shorts actually read
     */
    public short from_byte_array(byte[] from_array) {
        return this.from_byte_array((short) from_array.length, (short) (this.value.length - from_array.length), from_array, (short) 0);
    }
}
