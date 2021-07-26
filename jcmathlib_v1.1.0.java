// Merged file class by JavaPresso (https://github.com/petrs/JavaPresso) 
// TODO: Change 'your_package' to your real package name as necessary
// TODO: Add 'import your_package.jcmathlib.*;' to access all classes as usual

package your_package;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class jcmathlib {
    public static String version = "1.1.0"; 

    
    /**
     *
     * @author Petr Svenda
     */
    public static class Base_Helper {
        final ResourceManager rm;
    
        /**
         * Helper flag which signalizes that code is executed inside simulator
         * (during tests). Is used to address simulator specific behaviour
         * workaround if required.
         */
        public boolean bIsSimulator = false;
    
        public Base_Helper(ResourceManager resman) {
            rm = resman;
        }
        
        /**
         * Lock/reserve provided object for subsequent use. Used to protect
         * corruption of pre-allocated shared objects in different, potentially
         * nested, operations. Must be unlocked later on.
         *
         * @param objToLock array to be locked
         * @throws SW_ALREADYLOCKED if already locked (is already in use by other
         * operation)
         */
    /*    
        public void lock(Object objToLock) {
            rm.locker.lock(objToLock);
        }
    */
        public void lock(byte[] objToLock) {
            rm.locker.lock(objToLock);
        }
    
        /**
         * Unlock/release object from use. Used to protect corruption of
         * pre-allocated objects used in different nested operations. Must be locked
         * before.
         *
         * @param objToUnlock object to unlock
         * @throws SW_NOTLOCKED_BIGNAT if was not locked before (inconsistence in
         * lock/unlock sequence)
         */
    /*    
        public void unlock(Object objToUnlock) {
            rm.locker.unlock(objToUnlock);
        }
    */
        public void unlock(byte[] objToUnlock) {
            rm.locker.unlock(objToUnlock);
        }
    
        /**
         * Unlocks all locked objects
         */
        public void unlockAll() {
            rm.locker.unlockAll();
        }
    
        /**
         * Check if provided object is logically locked
         *
         * @param objToUnlock object to be checked
         * @return true of array is logically locked, false otherwise
         */
    /*    
        public boolean isLocked(Object objToUnlock) {
            return rm.locker.isLocked(objToUnlock);
        }    
    */    
        /**
         * Allocates new byte[] array with provided length either in RAM or EEPROM
         * based on an allocator type. Method updates internal counters of bytes
         * allocated with specific allocator. Use {@code getAllocatedInRAM()} or
         * {@code getAllocatedInEEPROM} for counters readout.
         *
         * @param length length of array
         * @param allocatorType type of allocator
         * @return allocated array
         */
        public byte[] allocateByteArray(short length, byte allocatorType) {
            return rm.memAlloc.allocateByteArray(length, allocatorType);        
        }    
    }
    /**
     * Credits: Based on Bignat library from OV-chip project https://ovchip.cs.ru.nl/OV-chip_2.0 by Radboud University Nijmegen 
     */
    
    
    /**
     * 
     * @author Vasilios Mavroudis and Petr Svenda
     */
    public static class Bignat {        
        private final Bignat_Helper bnh;
        /**
         * Configuration flag controlling re-allocation of internal array. If true, internal Bignat buffer can be enlarged during clone
         * operation if required (keep false to prevent slow reallocations)
         */
        boolean ALLOW_RUNTIME_REALLOCATION = false; 
        
        /**
         * Configuration flag controlling clearing of shared Bignats on lock as prevention of unwanted leak of sensitive information from previous operation.
         * If true, internal storage array is erased once Bignat is locked for use 
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
        * 
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
        * 
        */
        public static final short digit_first_bit_mask = 0x80;
    
        /**
        * Bitmask for the second highest bit in a digit. short 0x40 for the
        * short/short configuration, long 0x40000000 for the int/long
        * configuration.
        * 
        */
        public static final short digit_second_bit_mask = 0x40;
    
        /**
        * Bitmask for the two highest bits in a digit. short 0xC0 for the
        * short/short configuration, long 0xC0000000 for the int/long
        * configuration.
        * 
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
    
        private boolean bLocked = false;    // Logical flag to store info if this Bignat is currently used for some operation. Used as a prevention of unintentional parallel use of same temporary pre-allocated Bignats.
    
        /**
         * Construct a Bignat of size {@code size} in shorts. Allocated in EEPROM or RAM based on 
         * {@code allocatorType}. JCSystem.MEMORY_TYPE_PERSISTENT, in RAM otherwise.
         *
         * @param size the size of the new Bignat in bytes
         * @param allocatorType type of allocator storage 
         *      JCSystem.MEMORY_TYPE_PERSISTENT => EEPROM (slower writes, but RAM is saved)
         *      JCSystem.MEMORY_TYPE_TRANSIENT_RESET => RAM 
         *      JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT => RAM
         * @param bignatHelper {@code Bignat_Helper} class with helper objects
         */
        public Bignat(short size, byte allocatorType, Bignat_Helper bignatHelper) {
            this.bnh = bignatHelper;
            allocate_storage_array(size, allocatorType);
        }
    
        /**
         * Construct a Bignat with provided array used as internal storage as well as initial value.
         * No copy of array is made. If this Bignat is used in operation which modifies the Bignat value, 
         * content of provided array is changed.
         * @param valueBuffer internal storage
         * @param bignatHelper {@code Bignat_Helper} class with all relevant settings and helper objects
         */
        public Bignat(byte[] valueBuffer, Bignat_Helper bignatHelper) {
            this.bnh = bignatHelper;
            this.size = (short) valueBuffer.length;
            this.max_size = (short) valueBuffer.length;
            this.allocatorType = -1; // no allocator
            this.value = valueBuffer;
        }
    
        /**
         * Lock/reserve this bignat for subsequent use. 
         * Used to protect corruption of pre-allocated temporary Bignats used in different, 
         * potentially nested operations. Must be unlocked by {@code unlock()} later on. 
         * @throws SW_ALREADYLOCKED_BIGNAT if already locked (is already in use by other operation)
         */
        public void lock() {
            if (!bLocked) {
                bLocked = true;
                if (ERASE_ON_LOCK) {
                    erase();
                }
            }
            else {
                // this Bignat is already locked, raise exception (incorrect sequence of locking and unlocking)
               ISOException.throwIt(ReturnCodes.SW_LOCK_ALREADYLOCKED);
            }
        }
        /**
         * Unlock/release this bignat from use. Used to protect corruption
         * of pre-allocated temporary Bignats used in different nested operations.
         * Must be locked before.
         *
         * @throws SW_NOTLOCKED_BIGNAT if was not locked before (inconsistence in lock/unlock sequence)
         */
        public void unlock() {
            if (bLocked) {
                bLocked = false;
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
         * @return true if object is logically locked (reserved), false otherwise
         */
        public boolean isLocked() {
            return bLocked;
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
        * @return this bignat as byte array
        */
        public byte[] as_byte_array() { 
            return value;
        }
    
        /**
         * Serialize this Bignat value into a provided buffer
         * @param buffer target buffer
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
        * <P>
        * The return value is adjusted by {@link #set_size}.
        * 
        * @return size in digits.
        */
        public short length() {
            return size;
        }
    
        /**
         * Sets internal size of Bignat. Previous value are kept so value is either non-destructively trimmed or enlarged. 
         * @param newSize new size of Bignat. Must be in range of [0, max_size] where max_size was provided during object creation
         */
        public void set_size(short newSize) {
            if (newSize < 0 || newSize > max_size) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_RESIZETOLONGER);
            }
            else {
                this.size = newSize;
            }
        }                
        
        /**
         * Resize internal length of this Bignat to maximum size given during object
         * creation. If required, object is also zeroized
         *
         * @param bZeroize if true, all bytes of internal array are also set to
         * zero. If false, previous value is kept.
         */
        public void resize_to_max(boolean bZeroize) {
            set_size(max_size);
            if (bZeroize) {
                zero();
            }
        }
    
        /**
         * Create Bignat with different number of bytes used. Will cause longer number 
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
                // No need to resize enything, same length
            } 
            else {
                short this_start, other_start, len;
                bnh.lock(bnh.fnc_deep_resize_tmp);
                if (this.size >= new_size) {
                    this_start = (short) (this.size - new_size);
                    other_start = 0;
                    len = new_size;
    
                    // Shrinking/cropping 
                    Util.arrayCopyNonAtomic(value, this_start, bnh.fnc_deep_resize_tmp, (short) 0, len);
                    Util.arrayCopyNonAtomic(bnh.fnc_deep_resize_tmp, (short) 0, value, (short) 0, len); // Move bytes in item array towards beggining
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
                    Util.arrayCopyNonAtomic(value, this_start, bnh.fnc_deep_resize_tmp, (short) 0, len);
                    // Move bytes in item array towards end
                    Util.arrayCopyNonAtomic(bnh.fnc_deep_resize_tmp, (short) 0, value, other_start, len);
                    // Fill begin of array with zeroes (just as sanitization)
                    if (other_start > 0) {
                        Util.arrayFillNonAtomic(value, (short) 0, other_start, (byte) 0);
                    }
                }
                bnh.unlock(bnh.fnc_deep_resize_tmp);
    
                set_size(new_size);
            }
        }
        
        
        /**
         * Appends zeros in the suffix to reach the defined byte length 
         * Essentially multiplies the number with 16 (HEX) 
         * @param targetLength required length including appended zeroes
         * @param outBuffer output buffer for value with appended zeroes
         * @param outOffset start offset inside outBuffer for write
         */
        public void append_zeros(short targetLength, byte[] outBuffer, short outOffset) {
            Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, outOffset, this.size); //copy the value
            Util.arrayFillNonAtomic(outBuffer, (short) (outOffset + this.size), (short) (targetLength - this.size), (byte) 0); //append zeros
        } 
        /**
         * Prepends zeros before the value of this Bignat up to target length. 
         *
         * @param targetLength required length including prepended zeroes
         * @param outBuffer output buffer for value with prepended zeroes
         * @param outOffset start offset inside outBuffer for write
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
    
            short new_size = (short)(this.size-i);
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
    
        public void three() {
            this.zero();
            value[(short) (size - 1)] = 0x03;
        }
    
        public void four() {
            this.zero();
            value[(short) (size - 1)] = 0x04;
        }
    
        public void five() {
            this.zero();
            value[(short) (size - 1)] = 0x05;
        }
        public void eight() {
            this.zero();
            value[(short) (size - 1)] = 0x08;
        }
    
        public void ten() {
            this.zero();
            value[(short) (size - 1)] = 0x0A;
        }
    	
        public void twentyfive() {
            this.zero();
            value[(short)(size-1)] = 0x19;
        }
    
        public void twentyseven() {
            this.zero();
            value[(short)(size-1)] = 0x1B;
        }
        
        public void athousand() {
            this.zero();
            value[(short)(size-2)] = (byte)0x03;
            value[(short)(size-1)] = (byte)0xE8;
        }
        
        
    
    
        /**
        * Copies {@code other} into this. No size requirements. If {@code other}
        * has more digits then the superfluous leading digits of {@code other} are
        * asserted to be zero. If this bignat has more digits than its leading
        * digits are correctly initilized to zero. This function will not change size 
        * attribute of this object.
        * 
        * @param other
        *            Bignat to copy into this object.
        */
        public void copy(Bignat other) {
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
                for (short i = 0; i < other_start; i ++) {
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
         * @param other 
         *            Bignat to clone into this object.
         */    
        public void clone(Bignat other) { 
            // Reallocate array only if current array cannot store the other value and reallocation is enabled by ALLOW_RUNTIME_REALLOCATION
            if (this.max_size < other.length()) {
                // Reallocation necessary
                if (ALLOW_RUNTIME_REALLOCATION) {
                    allocate_storage_array(other.length(), this.allocatorType);
                }
                else {
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
         *
         * @param other Bignat to compare
         * @return true if this and other have the same value, false otherwise.
         */
        public boolean same_value(Bignat other) { 
            short hashLen;
            // Compare using hash engine
            // The comparison is made with hash of point values instead of directly values. 
            // This way, offset of first mismatching byte is not leaked via timing side-channel. 
            bnh.lock(bnh.fnc_same_value_array1);
            bnh.lock(bnh.fnc_same_value_hash);
            if (this.length() == other.length()) {
                // Same length, we can hash directly from BN values
                bnh.hashEngine.doFinal(this.value, (short) 0, this.length(), bnh.fnc_same_value_hash, (short) 0);
                hashLen = bnh.hashEngine.doFinal(other.value, (short) 0, other.length(), bnh.fnc_same_value_array1, (short) 0);
            }
            else {
                // Different length of bignats - can be still same if prepended with zeroes 
                // Find the length of longer one and padd other one with starting zeroes
                if (this.length() < other.length()) {
                    this.prepend_zeros(other.length(), bnh.fnc_same_value_array1, (short) 0);
                    bnh.hashEngine.doFinal(bnh.fnc_same_value_array1, (short) 0, other.length(), bnh.fnc_same_value_hash, (short) 0);
                    hashLen = bnh.hashEngine.doFinal(other.value, (short) 0, other.length(), bnh.fnc_same_value_array1, (short) 0);
                }
                else {
                    other.prepend_zeros(this.length(), bnh.fnc_same_value_array1, (short) 0);
                    bnh.hashEngine.doFinal(bnh.fnc_same_value_array1, (short) 0, this.length(), bnh.fnc_same_value_hash, (short) 0);
                    hashLen = bnh.hashEngine.doFinal(this.value, (short) 0, this.length(), bnh.fnc_same_value_array1, (short) 0);
                }
            }
    
            boolean bResult = Util.arrayCompare(bnh.fnc_same_value_hash, (short) 0, bnh.fnc_same_value_array1, (short) 0, hashLen) == 0;
    
            bnh.unlock(bnh.fnc_same_value_array1);
            bnh.unlock(bnh.fnc_same_value_hash);
    
            return bResult;
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
        * @return true if carry of most significant byte occurs, false otherwise  
        */
        public static boolean add(byte[] x, short xOffset, short xLength, byte[] y,
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
    
            return result != 0;
        }
    
        /**
        * Subtracts big integer y from x specified by offset and length.
        * The result is stored into x array argument.
        * @param x array with first bignat
         * @param xOffset start offset in array of {@code x}
         * @param xLength length of {@code x}
         * @param y array with second bignat
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
         * @param other bignat to be substracted from this
         */
        public void subtract(Bignat other) {
            this.times_minus(other, (short) 0, (short) 1);
        }
        
        /**
        * Scaled subtraction. Subtracts {@code mult * 2^(}{@link #digit_len}
        * {@code  * shift) * other} from this.
        * <P>
        * That is, shifts {@code mult * other} precisely {@code shift} digits to
        * the left and subtracts that value from this. {@code mult} must be less
        * than {@link #bignat_base}, that is, it must fit into one digit. It is
        * only declared as short here to avoid negative values.
        * <P>
        * {@code mult} has type short.
        * <P>
        * No size constraint. However, an assertion is thrown, if the result would
        * be negative. {@code other} can have more digits than this object, but
        * then sufficiently many leading digits must be zero to avoid the
        * underflow.
        * <P>
        * Used in division.
        * 
        * @param other
        *            Bignat to subtract from this object
        * @param shift
        *            number of digits to shift {@code other} to the left
        * @param mult
        *            of type short, multiple of {@code other} to subtract from this
        *            object. Must be below {@link #bignat_base}.
        */
        public void times_minus(Bignat other, short shift, short mult) {
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
         * Quick function for decrement of this bignat value by 1. Faster than {@code substract(Bignat.one())}
         */
        public void decrement_one() {
            short tmp = 0;
            for (short i = (short) (this.size - 1); i >= 0; i--) {
                tmp = (short) (this.value[i] & 0xff);
                this.value[i] = (byte) (tmp - 1);
                if (tmp != 0) {
                    break; // CTO
                }
                else {
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
        * <P>
        * {@code x} has type short.
        * <P>
        * Utility method, used in division.
        * 
        * @param x
        *            of type short
        * @return index of the most significant 1 bit in {@code x}, returns
        *         {@link #double_digit_len} for {@code x == 0}.
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
        * <P>
        * Utility method, used in division.
        * 
        * 
        * @param high
        *            of type short, most significant {@link #double_digit_len} bits
        * @param middle
        *            of type byte, middle {@link #digit_len} bits
        * @param low
        *            of type byte, least significant {@link #digit_len} bits
        * @param shift
        *            amount of left shift
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
            }
            else {
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
        * <P>
        * 
        * As optimization {@code start} can be greater than zero to skip the first
        * {@code start} digits in the comparison. These first digits must be zero
        * then, otherwise an assertion is thrown. (So the optimization takes only
        * effect when <a
        * href="../../../overview-summary.html#NO_CARD_ASSERT">NO_CARD_ASSERT</a>
        * is defined.)
        * 
        * @param other
        *            Bignat to compare to
        * @param shift
        *            left shift of other before the comparison
        * @param start
        *            digits to skip at the beginning
        * @return true if this number is strictly less than the shifted
        *         {@code other}, false otherwise.
        */
        public boolean shift_lesser(Bignat other, short shift, short start) {
                short j;
    
            j = (short) (other.size + shift - this.size + start);
            short this_short, other_short;
            for (short i = start; i < this.size; i++, j++) {
                this_short = (short) (this.value[i] & digit_mask);
                if (j >= 0 && j < other.size) {
                    other_short = (short) (other.value[j] & digit_mask);
                }
                else {
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
         * Compares this and other bignat. 
         * @param other other value to compare with
         * @return true if this bignat is smaller, false if bigger or equal
         */
        public boolean smaller(Bignat other) {
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
        * @param other
        *            Bignat to compare with
        * @return true if this number is strictly lesser than {@code other}, false
        *         otherwise.
        */
        public boolean lesser(Bignat other) {
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
            
        /** Check if stored bignat is odd.
         * 
         * @return  true if odd, false if even
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
        * <P>
        * There are no direct size constraints, but if {@code quotient} is
        * non-null, it must be big enough for the quotient, otherwise an assertion
        * is thrown.
        * <P>
        * Uses schoolbook division inside and has O^2 complexity in the difference
        * of significant digits of the divident (in this number) and the divisor.
        * For numbers of equal size complexity is linear.
        * 
        * @param divisor
        *            must be non-zero
        * @param quotient
        *            gets the quotient if non-null
        */
        public void remainder_divide(Bignat divisor, Bignat quotient) {
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
         * @param other short value to add 
         */
        public void add(short other) {
            Util.setShort(bnh.tmp_array_short, (short) 0, other); // serialize other into array
            this.add_carry(bnh.tmp_array_short, (short) 0, (short) 2); // add as array
        }
    	
        /**
        * Addition with carry report. Adds other to this number. If this is too
        * small for the result (i.e., an overflow occurs) the method returns true.
        * Further, the result in {@code this} will then be the correct result of an
        * addition modulo the first number that does not fit into {@code this} (
        * {@code 2^(}{@link #digit_len}{@code * }{@link #size this.size}{@code )}),
        * i.e., only one leading 1 bit is missing. If there is no overflow the
        * method will return false.
        * <P>
        * 
        * It would be more natural to report the overflow with an
        * {@link javacard.framework.UserException}, however its
        * {@link javacard.framework.UserException#throwIt throwIt} method dies with
        * a null pointer exception when it runs in a host test frame...
        * <P>
        * 
        * Asserts that the size of other is not greater than the size of this.
        * 
        * @param other
        *            Bignat to add
        * @param otherOffset start offset within other buffer
        * @param otherLen length of other
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
         * @param other value to be added
         * @return true if carry happens, false otherwise
         */
        public boolean add_carry(Bignat other) {
            return add_carry(other.value, (short) 0, other.size);
        }
    
    
        /**
        * Addition. Adds other to this number. 
        * <P>
        * Same as {@link #times_add times_add}{@code (other, 1)} but without the
        * multiplication overhead.
        * <P>
        * Asserts that the size of other is not greater than the size of this.
        * 
        * @param other
        *            Bignat to add
        */
        public void add(Bignat other) {
            add_carry(other);
        }
    
        /**
         * Add other bignat to this bignat modulo {@code modulo} value. 
         * @param other value to add
         * @param modulo value of modulo to compute 
         */
        public void mod_add(Bignat other, Bignat modulo) { 
            short tmp_size = this.size;
            if (tmp_size < other.size) {
                tmp_size = other.size;
            }
            tmp_size++;
            bnh.fnc_mod_add_tmp.lock();
            bnh.fnc_mod_add_tmp.set_size(tmp_size); 
            bnh.fnc_mod_add_tmp.zero();
            bnh.fnc_mod_add_tmp.copy(this);
            bnh.fnc_mod_add_tmp.add(other);
            bnh.fnc_mod_add_tmp.mod(modulo);
            bnh.fnc_mod_add_tmp.shrink();
            this.clone(bnh.fnc_mod_add_tmp);
            bnh.fnc_mod_add_tmp.unlock();
        }
    
        /**
         * Substract other bignat from this bignat modulo {@code modulo} value.
         *
         * @param other value to substract
         * @param modulo value of modulo to apply
         */
        public void mod_sub(Bignat other, Bignat modulo) {
            if (other.lesser(this)) { // CTO
                this.subtract(other);
                this.mod(modulo);
            } else { //other>this (mod-other+this)
                bnh.fnc_mod_sub_tmpOther.lock();
                bnh.fnc_mod_sub_tmpOther.clone(other);
                bnh.fnc_mod_sub_tmpOther.mod(modulo);
    
                //fnc_mod_sub_tmpThis = new Bignat(this.length());
                bnh.fnc_mod_sub_tmpThis.lock();
                bnh.fnc_mod_sub_tmpThis.clone(this);
                bnh.fnc_mod_sub_tmpThis.mod(modulo);
    
                bnh.fnc_mod_sub_tmp.lock();
                bnh.fnc_mod_sub_tmp.clone(modulo);
                bnh.fnc_mod_sub_tmp.subtract(bnh.fnc_mod_sub_tmpOther);
                bnh.fnc_mod_sub_tmpOther.unlock();
                bnh.fnc_mod_sub_tmp.add(bnh.fnc_mod_sub_tmpThis); //this will never overflow as "other" is larger than "this"
                bnh.fnc_mod_sub_tmpThis.unlock();
                bnh.fnc_mod_sub_tmp.mod(modulo);
                bnh.fnc_mod_sub_tmp.shrink();
                this.clone(bnh.fnc_mod_sub_tmp);
                bnh.fnc_mod_sub_tmp.unlock();
            }
        }
    	
    	
        /**
         * Scaled addition. Add {@code mult * other} to this number. {@code mult}
         * must be below {@link #bignat_base}, that is, it must fit into one digit.
         * It is only declared as a short here to avoid negative numbers.
         * <P>
         * Asserts (overly restrictive) that this and other have the same size.
         * <P>
         * Same as {@link #times_add_shift times_add_shift}{@code (other, 0, mult)}
         * but without the shift overhead.
         * <P>
         * Used in multiplication.
         *
         * @param other Bignat to add
         * @param mult of short, factor to multiply {@code other} with before
         * addition. Must be less than {@link #bignat_base}.
         */
        public void times_add(Bignat other, short mult) {
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
         * <P>
         * {@code mult} must be less than {@link #bignat_base}, that is, it must fit
         * into one digit. It is only declared as a short here to avoid negative
         * numbers.
         * <P>
         * Asserts that the size of this is greater than or equal to
         * {@code other.size + shift + 1}.
         *
         * @param x Bignat to add
         * @param mult of short, factor to multiply {@code other} with before
         * addition. Must be less than {@link #bignat_base}.
         * @param shift number of digits to shift {@code other} to the left, before
         * addition.
         */
        public void times_add_shift(Bignat x, short shift, short mult) {
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
         * @param other value of divisor
         */
        public void divide(Bignat other) {
            bnh.fnc_divide_tmpThis.lock();
            bnh.fnc_divide_tmpThis.clone(this);
            bnh.fnc_divide_tmpThis.remainder_divide(other, this);
            this.clone(bnh.fnc_divide_tmpThis); 
            bnh.fnc_divide_tmpThis.unlock();
        }
    
        /**
         * Greatest common divisor of this bignat with other bignat. Result is
         * stored into this.
         *
         * @param other value of other bignat
         */
        public void gcd(Bignat other) {
            bnh.fnc_gcd_tmp.lock();
            bnh.fnc_gcd_tmpOther.lock();
    
            bnh.fnc_gcd_tmpOther.clone(other);
    
            // TODO: optimise?
            while (!other.is_zero()) {
                bnh.fnc_gcd_tmp.clone(bnh.fnc_gcd_tmpOther);
                this.mod(bnh.fnc_gcd_tmpOther);
                bnh.fnc_gcd_tmpOther.clone(this);
                this.clone(bnh.fnc_gcd_tmp);
            }
    
            bnh.fnc_gcd_tmp.unlock();
            bnh.fnc_gcd_tmpOther.unlock();
        }
    
        /**
         * Decides whether the arguments are coprime or not.
         *
         * @param a Bignat value
         * @param b Bignat value
         * @return true if coprime, false otherwise
         */
        public boolean is_coprime(Bignat a, Bignat b) {
            bnh.fnc_is_coprime_tmp.lock();
            bnh.fnc_is_coprime_tmp.clone(a);
    
            bnh.fnc_is_coprime_tmp.gcd(b);
            return bnh.fnc_is_coprime_tmp.same_value(Bignat_Helper.ONE);
        }
    
        /**
         * Computes base^exp and stores result into this bignat
         * @param base value of base
         * @param exp value of exponent
         */
        public void exponentiation(Bignat base, Bignat exp) {
            this.one();
            bnh.fnc_exponentiation_i.lock();
            bnh.fnc_exponentiation_i.set_size(exp.length());
            bnh.fnc_exponentiation_i.zero();
            bnh.fnc_exponentiation_tmp.lock();
            bnh.fnc_exponentiation_tmp.set_size((short) (2 * this.length()));
            for (; bnh.fnc_exponentiation_i.lesser(exp); bnh.fnc_exponentiation_i.increment_one()) { 
                bnh.fnc_exponentiation_tmp.mult(this, base);
                this.copy(bnh.fnc_exponentiation_tmp);
            }
            bnh.fnc_exponentiation_i.unlock();
            bnh.fnc_exponentiation_tmp.unlock();
        }
        
        /**
        * Multiplication. Automatically selects fastest available algorithm. 
        * Stores {@code x * y} in this. To ensure this is big
        * enough for the result it is asserted that the size of this is greater
        * than or equal to the sum of the sizes of {@code x} and {@code y}.
        * 
        * @param x
        *            first factor
        * @param y
        *            second factor
        */
        public void mult(Bignat x, Bignat y) {      
            if (!bnh.FLAG_FAST_MULT_VIA_RSA || x.length() < Bignat_Helper.FAST_MULT_VIA_RSA_TRESHOLD_LENGTH) {
            //if (!bnh.FLAG_FAST_MULT_VIA_RSA) {
                // If not supported, use slow multiplication
                // Use slow multiplication also when numbers are small => faster to do in software 
                mult_schoolbook(x, y);
            }
            else { 
                mult_rsa_trick(x, y, null, null);
            } 
        }        
    
        /** 
         * Slow schoolbook algorithm for multiplication
         * @param x first number to multiply
         * @param y second number to multiply
         */        
        public void mult_schoolbook(Bignat x, Bignat y) {            	
        	this.zero(); // important to keep, used in exponentiation()
            for (short i = (short) (y.size - 1); i >= 0; i--) {
                this.times_add_shift(x, (short) (y.size - 1 - i), (short) (y.value[i] & digit_mask));
            }
        }
        
        /**
         * Performs multiplication of two bignats x and y and stores result into
         * this. RSA engine is used to speedup operation.
         * @param x first value to multiply
         * @param y second value to multiply
         */
        public void mult_RSATrick(Bignat x, Bignat y) {
            mult_rsa_trick(x, y, null, null);
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
         * @param x first value to multiply
         * @param y second value to multiply
         * @param x_pow_2 if not null, array with precomputed value x^2 is expected
         * @param y_pow_2 if not null, array with precomputed value y^2 is expected
         */
        public void mult_rsa_trick(Bignat x, Bignat y, byte[] x_pow_2, byte[] y_pow_2) {
            short xOffset;
            short yOffset;
    
            bnh.lock(bnh.fnc_mult_resultArray1);
    
            // x+y
            Util.arrayFillNonAtomic(bnh.fnc_mult_resultArray1, (short) 0, (short) bnh.fnc_mult_resultArray1.length, (byte) 0);
            // We must copy bigger number first
            if (x.size > y.size) {
                // Copy x to the end of mult_resultArray
                xOffset = (short) (bnh.fnc_mult_resultArray1.length - x.length());
                Util.arrayCopyNonAtomic(x.value, (short) 0, bnh.fnc_mult_resultArray1, xOffset, x.length());
                if (add(bnh.fnc_mult_resultArray1, xOffset, x.size, y.value, (short) 0, y.size)) {
                    xOffset--;
                    bnh.fnc_mult_resultArray1[xOffset] = 0x01;
                }
            } else {
                // Copy x to the end of mult_resultArray
                yOffset = (short) (bnh.fnc_mult_resultArray1.length - y.length());
                Util.arrayCopyNonAtomic(y.value, (short) 0, bnh.fnc_mult_resultArray1, yOffset, y.length());
                if (add(bnh.fnc_mult_resultArray1, yOffset, y.size, x.value, (short) 0, x.size)) {
                    yOffset--;
                    bnh.fnc_mult_resultArray1[yOffset] = 0x01; // add carry if occured
                }
            }
    
            // ((x+y)^2)
            bnh.fnc_mult_cipher.doFinal(bnh.fnc_mult_resultArray1, (byte) 0, (short) bnh.fnc_mult_resultArray1.length, bnh.fnc_mult_resultArray1, (short) 0);
    
            // x^2
            bnh.lock(bnh.fnc_mult_resultArray2);
            if (x_pow_2 == null) {
                // x^2 is not precomputed
                Util.arrayFillNonAtomic(bnh.fnc_mult_resultArray2, (short) 0, (short) bnh.fnc_mult_resultArray2.length, (byte) 0);
                xOffset = (short) (bnh.fnc_mult_resultArray2.length - x.length());
                Util.arrayCopyNonAtomic(x.value, (short) 0, bnh.fnc_mult_resultArray2, xOffset, x.length());
                bnh.fnc_mult_cipher.doFinal(bnh.fnc_mult_resultArray2, (byte) 0, (short) bnh.fnc_mult_resultArray2.length, bnh.fnc_mult_resultArray2, (short) 0);
            } else {
                // x^2 is precomputed
                if ((short) x_pow_2.length != (short) bnh.fnc_mult_resultArray2.length) {
                    Util.arrayFillNonAtomic(bnh.fnc_mult_resultArray2, (short) 0, (short) bnh.fnc_mult_resultArray2.length, (byte) 0);
                    xOffset = (short) ((short) bnh.fnc_mult_resultArray2.length - (short) x_pow_2.length);
                } else {
                    xOffset = 0;
                }
                Util.arrayCopyNonAtomic(x_pow_2, (short) 0, bnh.fnc_mult_resultArray2, xOffset, (short) x_pow_2.length);
            }
            // ((x+y)^2) - x^2
            subtract(bnh.fnc_mult_resultArray1, (short) 0, (short) bnh.fnc_mult_resultArray1.length, bnh.fnc_mult_resultArray2, (short) 0, (short) bnh.fnc_mult_resultArray2.length);
    
            // y^2
            if (y_pow_2 == null) {
                // y^2 is not precomputed
                Util.arrayFillNonAtomic(bnh.fnc_mult_resultArray2, (short) 0, (short) bnh.fnc_mult_resultArray2.length, (byte) 0);
                yOffset = (short) (bnh.fnc_mult_resultArray2.length - y.length());
                Util.arrayCopyNonAtomic(y.value, (short) 0, bnh.fnc_mult_resultArray2, yOffset, y.length());
                bnh.fnc_mult_cipher.doFinal(bnh.fnc_mult_resultArray2, (byte) 0, (short) bnh.fnc_mult_resultArray2.length, bnh.fnc_mult_resultArray2, (short) 0);
            } else {
                // y^2 is precomputed
                if ((short) y_pow_2.length != (short) bnh.fnc_mult_resultArray2.length) {
                    Util.arrayFillNonAtomic(bnh.fnc_mult_resultArray2, (short) 0, (short) bnh.fnc_mult_resultArray2.length, (byte) 0);
                    yOffset = (short) ((short) bnh.fnc_mult_resultArray2.length - (short) y_pow_2.length);
                } else {
                    yOffset = 0;
                }
                Util.arrayCopyNonAtomic(y_pow_2, (short) 0, bnh.fnc_mult_resultArray2, yOffset, (short) y_pow_2.length);
            }
            
    
            // {(x+y)^2) - x^2} - y^2
            subtract(bnh.fnc_mult_resultArray1, (short) 0, (short) bnh.fnc_mult_resultArray1.length, bnh.fnc_mult_resultArray2, (short) 0, (short) bnh.fnc_mult_resultArray2.length);
    
            // we now have 2xy in mult_resultArray, divide it by 2 => shift by one bit and fill back into this
            short multOffset = (short) ((short) bnh.fnc_mult_resultArray1.length - 1);
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
                res = (short) (bnh.fnc_mult_resultArray1[multOffset] & 0xff);
                res = (short) (res >> 1);
                res2 = (short) (bnh.fnc_mult_resultArray1[(short) (multOffset - 1)] & 0xff);
                res2 = (short) (res2 << 7);
                this.value[i] = (byte) (short) (res | res2);
                multOffset--;
            }
            bnh.unlock(bnh.fnc_mult_resultArray1);
            bnh.unlock(bnh.fnc_mult_resultArray2);
        }    
    
        /**
         * Multiplication of bignats x and y computed by modulo {@code modulo}. 
         * The result is stored to this.
         * @param x first value to multiply
         * @param y second value to multiply
         * @param modulo value of modulo
         */
        public void mod_mult(Bignat x, Bignat y, Bignat modulo) {            	
            bnh.fnc_mod_mult_tmpThis.lock();
            bnh.fnc_mod_mult_tmpThis.resize_to_max(false);
            // Perform fast multiplication using RSA trick
            bnh.fnc_mod_mult_tmpThis.mult(x, y);        
            // Compute modulo 
            bnh.fnc_mod_mult_tmpThis.mod(modulo);
            bnh.fnc_mod_mult_tmpThis.shrink();
            this.clone(bnh.fnc_mod_mult_tmpThis);
            bnh.fnc_mod_mult_tmpThis.unlock();
        }
        // Potential speedup for  modular multiplication
        // Binomial theorem: (op1 + op2)^2 - (op1 - op2)^2 = 4 * op1 * op2 mod (mod)
        
        
    
        /**
         * One digit left shift.
         * <P>
         * Asserts that the first digit is zero.
         */
        public void shift_left() {
            // NOTE: assumes that overlapping src and dest arrays are properly handled by Util.arrayCopyNonAtomic
            Util.arrayCopyNonAtomic(this.value, (short) 1, this.value, (short) 0, (short) (size - 1)); 
            value[(short) (size - 1)] = 0;
        }
            
        /**
         * Optimized division by value two
         */    
        private void divide_by_2() {
            short tmp = 0;
            short tmp2 = 0;
            short carry = 0;
            for (short i = 0; i < this.size; i++) {
                tmp = (short) (this.value[i] & 0xff);
                tmp2 = tmp;
                tmp >>=1; // shift by 1 => divide by 2
                this.value[i] = (byte) (tmp | carry);
                carry = (short) (tmp2 & 0x01); // save lowest bit
                carry <<= 7; // shifted to highest position
            }
        }
            
        /**
         * Inefficient modular multiplication.
         *
         * This bignat is assigned to {@code x * y} modulo {@code mod}. Inefficient,
         * because it computes the modules with {@link #remainder_divide
         * remainder_divide} in each multiplication round. To avoid overflow the
         * first two digits of {@code x} and {@code mod} must be zero (which plays
         * nicely with the requirements for montgomery multiplication, see
         * {@link #montgomery_mult montgomery_mult}).
         * <P>
         * Asserts that {@code x} and {@code mod} have the same size. Argument
         * {@code y} can be arbitrary in size.
         * <P>
         * Included here to make it possible to compute the squared <a
         * href="package-summary.html#montgomery_factor">montgomery factor</a>,
         * which is needed to montgomerize numbers before montgomery multiplication.
         * Until now this has never been used, because the montgomery factors are
         * computed on the host and then installed on the card. Or numbers are
         * montgomerized on the host already.
         *
         * @param x first factor, first two digits must be zero
         * @param y second factor
         * @param mod modulus, first two digits must be zero
         */
        public void mod_mult_inefficient(Bignat x, Bignat y, Bignat mod) { 
            short len = 0;
            if (x.length() >= mod.length()) {
                len = x.length();
            } else {
                len = mod.length();
            }
    
            short magicAdd = 2;
            bnh.fnc_mult_mod_tmp_x.lock();
            bnh.fnc_mult_mod_tmp_x.set_size((short) (len + magicAdd));
            bnh.fnc_mult_mod_tmp_x.copy(x);
    
            bnh.fnc_mult_mod_tmp_mod.lock();
            bnh.fnc_mult_mod_tmp_mod.set_size((short) (len + magicAdd));
            bnh.fnc_mult_mod_tmp_mod.copy(mod);
    
            bnh.fnc_mult_mod_tmpThis.lock();
            bnh.fnc_mult_mod_tmpThis.set_size((short) (this.length() + magicAdd));
            bnh.fnc_mult_mod_tmpThis.zero();
            for (short i = 0; i < y.size; i++) {
                bnh.fnc_mult_mod_tmpThis.shift_left();
                bnh.fnc_mult_mod_tmpThis.times_add(bnh.fnc_mult_mod_tmp_x, (short) (y.value[i] & digit_mask));
                bnh.fnc_mult_mod_tmpThis.remainder_divide(bnh.fnc_mult_mod_tmp_mod, null);
            }
            bnh.fnc_mult_mod_tmp_x.unlock();
            bnh.fnc_mult_mod_tmp_mod.unlock();
    
            bnh.fnc_mult_mod_tmpThis.shrink();
            this.clone(bnh.fnc_mult_mod_tmpThis);
            bnh.fnc_mult_mod_tmpThis.unlock();
        }
    	
    
        //
        /**
         * Computes square root of provided bignat which MUST be prime using Tonelli
         * Shanks Algorithm. The result (one of the two roots) is stored to this. 
         * @param p value to compute square root from
         */
        public void sqrt_FP(Bignat p) {
            PM.check(PM.TRAP_BIGNAT_SQRT_1);
            //1. By factoring out powers of 2, find Q and S such that p-1=Q2^S p-1=Q*2^S and Q is odd
            bnh.fnc_sqrt_p_1.lock();
            bnh.fnc_sqrt_p_1.clone(p);
            PM.check(PM.TRAP_BIGNAT_SQRT_2);
            bnh.fnc_sqrt_p_1.decrement_one();
            PM.check(PM.TRAP_BIGNAT_SQRT_3);
    
            //Compute Q
            bnh.fnc_sqrt_Q.lock();
            bnh.fnc_sqrt_Q.clone(bnh.fnc_sqrt_p_1);
            bnh.fnc_sqrt_Q.divide_by_2(); //Q /= 2
            PM.check(PM.TRAP_BIGNAT_SQRT_4);
    
            //Compute S
            bnh.fnc_sqrt_S.lock();
            bnh.fnc_sqrt_S.set_size(p.length());
            bnh.fnc_sqrt_S.zero();
            bnh.fnc_sqrt_tmp.lock();
            bnh.fnc_sqrt_tmp.set_size(p.length());
            bnh.fnc_sqrt_tmp.zero();
    
            PM.check(PM.TRAP_BIGNAT_SQRT_5);
            while (bnh.fnc_sqrt_tmp.same_value(bnh.fnc_sqrt_Q)==false){
                bnh.fnc_sqrt_S.increment_one();
                bnh.fnc_sqrt_tmp.mod_mult(bnh.fnc_sqrt_S, bnh.fnc_sqrt_Q, p);
            }
            bnh.fnc_sqrt_tmp.unlock();
            PM.check(PM.TRAP_BIGNAT_SQRT_6);
            bnh.fnc_sqrt_S.unlock();
    
            //2. Find the first quadratic non-residue z by brute-force search
            bnh.fnc_sqrt_exp.lock();
            bnh.fnc_sqrt_exp.clone(bnh.fnc_sqrt_p_1);
            PM.check(PM.TRAP_BIGNAT_SQRT_7);
            bnh.fnc_sqrt_exp.divide_by_2();
            
            PM.check(PM.TRAP_BIGNAT_SQRT_8);
    
            bnh.fnc_sqrt_z.lock();
            bnh.fnc_sqrt_z.set_size(p.length());
            bnh.fnc_sqrt_z.one();
            bnh.fnc_sqrt_tmp.lock();
            bnh.fnc_sqrt_tmp.zero();
            bnh.fnc_sqrt_tmp.copy(Bignat_Helper.ONE);
    
            PM.check(PM.TRAP_BIGNAT_SQRT_9);
            while (bnh.fnc_sqrt_tmp.same_value(bnh.fnc_sqrt_p_1)==false) {
                bnh.fnc_sqrt_z.increment_one();
                bnh.fnc_sqrt_tmp.copy(bnh.fnc_sqrt_z);
                bnh.fnc_sqrt_tmp.mod_exp(bnh.fnc_sqrt_exp, p);		
            }
            PM.check(PM.TRAP_BIGNAT_SQRT_10);
            bnh.fnc_sqrt_p_1.unlock();
            bnh.fnc_sqrt_tmp.unlock();
            bnh.fnc_sqrt_z.unlock();
            bnh.fnc_sqrt_exp.copy(bnh.fnc_sqrt_Q);
            bnh.fnc_sqrt_Q.unlock();
            PM.check(PM.TRAP_BIGNAT_SQRT_11);
            bnh.fnc_sqrt_exp.increment_one();
            PM.check(PM.TRAP_BIGNAT_SQRT_12);
            bnh.fnc_sqrt_exp.divide_by_2();
            PM.check(PM.TRAP_BIGNAT_SQRT_13);
    
            this.mod(p);
            PM.check(PM.TRAP_BIGNAT_SQRT_14);
            this.mod_exp(bnh.fnc_sqrt_exp, p);
            PM.check(PM.TRAP_BIGNAT_SQRT_15);
            bnh.fnc_sqrt_exp.unlock();
        } // end void sqrt(Bignat p)	
    	
        
        /**
         * Computes and stores modulo of this bignat. 
         * @param modulo value of modulo
         */
        public void mod(Bignat modulo) {
            this.remainder_divide(modulo, null);
            // NOTE: attempt made to utilize crypto co-processor in pow2Mod_RSATrick_worksOnlyAbout30pp, but doesn't work for all inputs 
        }
        
            
    
        /** 
         * Computes inversion of this bignat taken modulo {@code modulo}. 
         * The result is stored into this.
         * @param modulo value of modulo
         */
        public void mod_inv(Bignat modulo) {
            bnh.fnc_mod_minus_2.lock();
            bnh.fnc_mod_minus_2.clone(modulo);
            bnh.fnc_mod_minus_2.decrement_one();
            bnh.fnc_mod_minus_2.decrement_one();
            
            mod_exp(bnh.fnc_mod_minus_2, modulo);
            bnh.fnc_mod_minus_2.unlock();
        }
        
        /**
         * Computes {@code res := this ** exponent mod modulo} and store results into this. 
         * Uses RSA engine to quickly compute this^exponent % modulo
         * @param exponent value of exponent
         * @param modulo value of modulo
         */
        public void mod_exp(Bignat exponent, Bignat modulo) {
            short tmp_size = (short)(bnh.MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8);
            bnh.fnc_mod_exp_modBN.lock();
            bnh.fnc_mod_exp_modBN.set_size(tmp_size);
    
            short len = n_mod_exp(tmp_size, this, exponent.as_byte_array(), exponent.length(), modulo, bnh.fnc_mod_exp_modBN.value, (short) 0);
            if (bnh.bIsSimulator) {
                // Decrypted length can be either tmp_size or less because of leading zeroes consumed by simulator engine implementation
                // Move obtained value into proper position with zeroes prepended
                if (len != tmp_size) {
                    bnh.lock(bnh.fnc_deep_resize_tmp);
                    Util.arrayFillNonAtomic(bnh.fnc_deep_resize_tmp, (short) 0, (short) bnh.fnc_deep_resize_tmp.length, (byte) 0);
                    Util.arrayCopyNonAtomic(bnh.fnc_mod_exp_modBN.value, (short) 0, bnh.fnc_deep_resize_tmp, (short) (tmp_size - len), len);
                    Util.arrayCopyNonAtomic(bnh.fnc_deep_resize_tmp, (short) 0, bnh.fnc_mod_exp_modBN.value, (short) 0, tmp_size);
                    bnh.unlock(bnh.fnc_deep_resize_tmp);
                }
            }
            else {
                // real cards should keep whole length of block, just check
                if (len != tmp_size) {
                    ISOException.throwIt(ReturnCodes.SW_ECPOINT_UNEXPECTED_KA_LEN);
                }
            }
            bnh.fnc_mod_exp_modBN.mod(modulo);
        	bnh.fnc_mod_exp_modBN.shrink();
        	this.clone(bnh.fnc_mod_exp_modBN);
            bnh.fnc_mod_exp_modBN.unlock();
        }
        
     
        public void mod_exp2(Bignat modulo) {
            mod_exp(Bignat_Helper.TWO, modulo);
            //this.pow2Mod_RSATrick(modulo);
    /*        
            short tmp_size = (short) (occ.bnHelper.MOD_RSA_LENGTH / 8);
            
            // Idea: a = this with prepended zeroes, b = this with appended zeroes, modulo with appended zeroes
            // Compute mult_RSATrick
            this.prependzeros(tmp_size, occ.bnHelper.helper_BN_A.as_byte_array(), (short) 0);
            occ.bnHelper.helper_BN_A.setSize(tmp_size);
            this.appendzeros(tmp_size, occ.bnHelper.helper_BN_B.as_byte_array(), (short) 0);
            occ.bnHelper.helper_BN_B.setSize(tmp_size);
    
            mult_RSATrick(occ.bnHelper.helper_BN_A, occ.bnHelper.helper_BN_B);
            
            // We will use prepared engine with exponent=2 and very large modulus (instead of provided modulus)
            // The reason is to avoid need for setting custom modulus and re-init RSA engine
            // Mod operation is computed later 
            occ.bnHelper.modPublicKey.setExponent(occ.bnHelper.CONST_TWO, (short) 0, (short) 1);
            occ.locker.lock(occ.bnHelper.fastResizeArray);
            modulo.appendzeros(tmp_size, occ.bnHelper.fastResizeArray, (short) 0);
            // NOTE: ideally, we would just set RSA engine modulus to our modulo. But smallest RSA key is 512 bit while 
            // our values are commonly smaller (e.g., 32B for 256b ECC). Prepending leading zeroes will cause 0xf105 (CryptoException.InvalidUse)
            //modulo.prependzeros(tmp_size, occ.bnHelper.fastResizeArray, (short) 0);
            occ.bnHelper.modPublicKey.setModulus(occ.bnHelper.fastResizeArray, (short) 0, tmp_size);
            occ.bnHelper.modCipher.init(occ.bnHelper.modPublicKey, Cipher.MODE_DECRYPT);
            this.prependzeros(tmp_size, occ.bnHelper.fastResizeArray, (short) 0);
            occ.bnHelper.modCipher.doFinal(occ.bnHelper.fastResizeArray, (byte) 0, tmp_size, occ.bnHelper.fastResizeArray, (short) 0);
            occ.locker.unlock(occ.bnHelper.fastResizeArray);
    
            // We used RSA engine with large modulo => some leading values will be zero (|this^2| <= 2*|this|)
            short startOffset = 0; // Find first nonzero value in resulting buffer
            while (occ.bnHelper.fastResizeArray[startOffset] == 0) {
                startOffset++;
            }
            short len = (short) (tmp_size - startOffset);
            this.setSize(len);
            this.from_byte_array(len, (short) 0, occ.bnHelper.fastResizeArray, startOffset);
            occ.locker.unlock(occ.bnHelper.fastResizeArray);
    */        
        }    
        /**
         * Calculates {@code res := base ** exp mod mod} using RSA engine. 
         * Requirements:
         * 1. Modulo must be either 521, 1024, 2048 or other lengths supported by RSA (see appendzeros() and mod() method)
         * 2. Base must have the same size as modulo (see prependzeros())
         * @param baseLen   length of base rounded to size of RSA engine
         * @param base      value of base (if size is not equal to baseLen then zeroes are appended)
         * @param exponent  array with exponent
         * @param exponentLen length of exponent
         * @param modulo    value of modulo 
         * @param resultArray array for the computed result
         * @param resultOffset start offset of resultArray
         */
        private short n_mod_exp(short baseLen, Bignat base, byte[] exponent, short exponentLen, Bignat modulo, byte[] resultArray, short resultOffset) {
            // Verify if pre-allocated engine match the required values
            if (bnh.fnc_NmodE_pubKey.getSize() < (short) (modulo.length() * 8)) {
                // attempt to perform modulu with higher or smaller than supported length - try change constant MODULO_ENGINE_MAX_LENGTH
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (bnh.fnc_NmodE_pubKey.getSize() < (short) (base.length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            // Potential problem: we are changing key value for publicKey already used before with occ.bnHelper.modCipher. 
            // Simulator and potentially some cards fail to initialize this new value properly (probably assuming that same key object will always have same value)
            // Fix (if problem occure): generate new key object: RSAPublicKey publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) (baseLen * 8), false);
    
            bnh.fnc_NmodE_pubKey.setExponent(exponent, (short) 0, exponentLen);
            bnh.lock(bnh.fnc_deep_resize_tmp);
            modulo.append_zeros(baseLen, bnh.fnc_deep_resize_tmp, (short) 0);
            bnh.fnc_NmodE_pubKey.setModulus(bnh.fnc_deep_resize_tmp, (short) 0, baseLen);
            bnh.fnc_NmodE_cipher.init(bnh.fnc_NmodE_pubKey, Cipher.MODE_DECRYPT);        
            base.prepend_zeros(baseLen, bnh.fnc_deep_resize_tmp, (short) 0);
            // BUGBUG: Check if input is not all zeroes (causes out-of-bound exception on some cards)
            short len = bnh.fnc_NmodE_cipher.doFinal(bnh.fnc_deep_resize_tmp, (short) 0, baseLen, resultArray, resultOffset); 
            bnh.unlock(bnh.fnc_deep_resize_tmp);
            return len;
        }
    
        /**
         * Negate current Bignat modulo provided modulus
         *
         * @param mod value of modulus
         */
        public void mod_negate(Bignat mod) {
            bnh.fnc_negate_tmp.lock();
            bnh.fnc_negate_tmp.set_size(mod.length());
            bnh.fnc_negate_tmp.copy(mod); //-y=mod-y
    
            if (this.lesser(mod)) { // y<mod
                bnh.fnc_negate_tmp.subtract(this);//-y=mod-y
                this.copy(bnh.fnc_negate_tmp);
            } else {// y>=mod
                this.mod(mod);//-y=y-mod
                bnh.fnc_negate_tmp.subtract(this);
                this.copy(bnh.fnc_negate_tmp);
            }
            bnh.fnc_negate_tmp.unlock();
        }
    
        /**
         * Shifts stored value to right by specified number of bytes. This operation equals to multiplication by value numBytes * 256.
         * @param numBytes number of bytes to shift
         */
        public void shift_bytes_right(short numBytes) {
            // Move whole content by numBytes offset
            bnh.lock(bnh.fnc_shift_bytes_right_tmp);
            Util.arrayCopyNonAtomic(this.value, (short) 0, bnh.fnc_shift_bytes_right_tmp, (short) 0, (short) (this.value.length));
            Util.arrayCopyNonAtomic(bnh.fnc_shift_bytes_right_tmp, (short) 0, this.value, numBytes, (short) ((short) (this.value.length) - numBytes));
            Util.arrayFillNonAtomic(this.value, (short) 0, numBytes, (byte) 0);
            bnh.unlock(bnh.fnc_shift_bytes_right_tmp);
        }
        
        /**
         * Allocates required underlying storage array with given maximum size and
         * allocator type (RAM or EEROM). Maximum size can be increased only by
         * future reallocation if allowed by ALLOW_RUNTIME_REALLOCATION flag
         *
         * @param maxSize maximum size of this Bignat
         * @param allocatorType memory allocator type. If
         * JCSystem.MEMORY_TYPE_PERSISTENT then memory is allocated in EEPROM. Use
         * JCSystem.CLEAR_ON_RESET or JCSystem.CLEAR_ON_DESELECT for allocation in
         * RAM with corresponding clearing behaviour.
         */
        private void allocate_storage_array(short maxSize, byte allocatorType) {
            this.size = maxSize;
            this.max_size = maxSize;
            this.allocatorType = allocatorType;
            this.value = bnh.allocateByteArray(this.max_size, allocatorType);
        }
        
        /**
         * Set content of Bignat internal array
         *
         * @param from_array_length available data in {@code from_array}
         * @param this_offset offset where data should be stored
         * @param from_array data array to deserialize from
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
         * Set content of Bignat internal array
         *
         * @param this_offset offset where data should be stored
         * @param from_array data array to deserialize from
         * @param from_array_length available data in {@code from_array}
         * @param from_array_offset offset in {@code from_array}
         * @return the number of shorts actually read, except for the case where
         * deserialization finished by reading precisely {@code len} shorts, in this
         * case {@code len + 1} is returned.
         */
        public short set_from_byte_array(short this_offset, byte[] from_array, short from_array_offset, short from_array_length) {
            return from_byte_array(from_array_length, this_offset, from_array, from_array_offset);
        }    
        
        /**
         * Set content of Bignat internal array
         *
         * @param from_array data array to deserialize from
         * @return the number of shorts actually read
         */
        public short from_byte_array(byte[] from_array) {
            return this.from_byte_array((short) from_array.length, (short) (this.value.length - from_array.length), from_array, (short) 0);
        }
    }
    
    
    /**
     *
     * @author Petr Svenda
     */
    public static class Bignat_Helper extends Base_Helper {
        /**
         * The size of speedup engine used for fast modulo exponent computation
         * (must be larger than biggest Bignat used)
         */
        public short MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
        /**
         * The size of speedup engine used for fast multiplication of large numbers
         * Must be larger than 2x biggest Bignat used
         */
        public short MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
        
        /**
         * If true, fast multiplication of large numbers via RSA engine can be used.
         * Is set automatically after successful allocation of required engines
         */
        public boolean FLAG_FAST_MULT_VIA_RSA = false;
        /**
         * Threshold length in bits of an operand after which speedup with RSA
         * multiplication is used. Schoolbook multiplication is used for shorter
         * operands
         */
        public static final short FAST_MULT_VIA_RSA_TRESHOLD_LENGTH = (short) 16;
        
        byte[] tmp_array_short = null;
        
        //
        // References to underlaying shared objects
        //
        byte[] fnc_mult_resultArray1 = null;
        byte[] fnc_deep_resize_tmp = null;
        byte[] fnc_mult_resultArray2 = null;
        byte[] fnc_same_value_array1 = null;
        byte[] fnc_same_value_hash = null;
        byte[] fnc_shift_bytes_right_tmp = null;
        
        // These Bignats are just pointing to some helper_BN_? so reasonable naming is preserved yet no need to actually allocated whole Bignat object
        Bignat fnc_mod_exp_modBN;
        
        Bignat fnc_mod_add_tmp;
        Bignat fnc_mod_sub_tmp;
        Bignat fnc_mod_sub_tmpOther;
        Bignat fnc_mod_sub_tmpThis;
    
        Bignat fnc_mod_mult_tmpThis;
    
        Bignat fnc_mult_mod_tmpThis;
        Bignat fnc_mult_mod_tmp_x;
        Bignat fnc_mult_mod_tmp_mod;
    
        Bignat fnc_divide_tmpThis;
    
        Bignat fnc_gcd_tmp;
        Bignat fnc_gcd_tmpOther;
    
        Bignat fnc_is_coprime_tmp;
    
        Bignat fnc_exponentiation_i;
        Bignat fnc_exponentiation_tmp;
    
        Bignat fnc_sqrt_p_1;
        Bignat fnc_sqrt_Q;
        Bignat fnc_sqrt_S;
        Bignat fnc_sqrt_tmp;
        Bignat fnc_sqrt_exp;
        Bignat fnc_sqrt_z;
    
        Bignat fnc_mod_minus_2;
    
        Bignat fnc_negate_tmp;
        
        Bignat fnc_int_add_tmpMag;
        Bignat fnc_int_multiply_mod;
        Bignat fnc_int_multiply_tmpThis;
        Bignat fnc_int_divide_tmpThis;
                
        RSAPublicKey fnc_NmodE_pubKey;
        Cipher fnc_NmodE_cipher;
        
        public static Bignat ONE;
        public static Bignat TWO;
        public static Bignat THREE;
    
        
        // Helper objects for fast multiplication of two large numbers (without modulo)
        KeyPair fnc_mult_keypair = null;
        RSAPublicKey fnc_mult_pubkey_pow2 = null;
        Cipher fnc_mult_cipher = null;
        MessageDigest hashEngine;
    
        static byte[] CONST_ONE = {0x01};
        static byte[] CONST_TWO = {0x02};
        
        public Bignat_Helper(ResourceManager resman) {
            super(resman);
        }
        
        void initialize(short modRSAEngineMaxBits, short multRSAEngineMaxBits) {
            MODULO_RSA_ENGINE_MAX_LENGTH_BITS = modRSAEngineMaxBits;
            MULT_RSA_ENGINE_MAX_LENGTH_BITS = multRSAEngineMaxBits;
            
            fnc_deep_resize_tmp = rm.helper_BN_array1;
            fnc_mult_resultArray1 = rm.helper_BN_array1;
            fnc_mult_resultArray2 = rm.helper_BN_array2;
    
            fnc_same_value_array1 = rm.helper_BN_array1;
            fnc_same_value_hash = rm.helper_BN_array2;
            
            fnc_shift_bytes_right_tmp = rm.helper_BN_array1;
            
            // BN below are just reassigned allocated helper_BN_? so that same helper_BN_? is not used in parallel (checked by lock() unlock())
            fnc_mod_add_tmp = rm.helper_BN_A;
    
            fnc_mod_sub_tmpThis = rm.helper_BN_A;
            fnc_mod_sub_tmp = rm.helper_BN_B;
            fnc_mod_sub_tmpOther = rm.helper_BN_C;
    
            fnc_mult_mod_tmpThis = rm.helper_BN_A;
            fnc_mult_mod_tmp_mod = rm.helper_BN_B;
            fnc_mult_mod_tmp_x = rm.helper_BN_C;
    
            fnc_exponentiation_tmp = rm.helper_BN_A;
            fnc_exponentiation_i = rm.helper_BN_B;
    
            fnc_mod_minus_2 = rm.helper_BN_B;
    
            fnc_gcd_tmp = rm.helper_BN_A;
            fnc_gcd_tmpOther = rm.helper_BN_B;
    
            fnc_is_coprime_tmp = rm.helper_BN_C; // is_coprime calls gcd internally
    
            fnc_negate_tmp = rm.helper_BN_B;
    
            fnc_sqrt_S = rm.helper_BN_A;
            fnc_sqrt_exp = rm.helper_BN_A;
            fnc_sqrt_p_1 = rm.helper_BN_B;
            fnc_sqrt_Q = rm.helper_BN_C;
            fnc_sqrt_tmp = rm.helper_BN_D;
            fnc_sqrt_z = rm.helper_BN_E;
    
            fnc_mod_mult_tmpThis = rm.helper_BN_E; // mod_mult is called from  fnc_sqrt => requires helper_BN_E not being locked in fnc_sqrt when mod_mult is called
    
            fnc_divide_tmpThis = rm.helper_BN_E; // divide is called from  fnc_sqrt => requires helper_BN_E not being locked  in fnc_sqrt when divide is called
    
            fnc_mod_exp_modBN = rm.helper_BN_F;  // mod_exp is called from  fnc_sqrt => requires helper_BN_F not being locked  in fnc_sqrt when mod_exp is called
    
            fnc_int_add_tmpMag = rm.helper_BN_A;
            fnc_int_multiply_mod = rm.helper_BN_A;
            fnc_int_multiply_tmpThis = rm.helper_BN_B;
            fnc_int_divide_tmpThis = rm.helper_BN_A;        
            
            
            // Allocate BN constants always in EEPROM (only reading)
            ONE = new Bignat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
            ONE.one();
            TWO = new Bignat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
            TWO.two();
            THREE = new Bignat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
            THREE.three();
    
            tmp_array_short = rm.memAlloc.allocateByteArray((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET); // only 2b RAM for faster add(short)
            fnc_NmodE_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            fnc_NmodE_pubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);
    
            // Speedup for fast multiplication
            fnc_mult_keypair = new KeyPair(KeyPair.ALG_RSA_CRT, MULT_RSA_ENGINE_MAX_LENGTH_BITS);
            fnc_mult_keypair.genKeyPair();
            fnc_mult_pubkey_pow2 = (RSAPublicKey) fnc_mult_keypair.getPublic();
            //mult_privkey_pow2 = (RSAPrivateCrtKey) mult_keypair.getPrivate();
            fnc_mult_pubkey_pow2.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
            fnc_mult_cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    
            hashEngine = rm.hashEngine;
    
            FLAG_FAST_MULT_VIA_RSA = false; // set true only if succesfully allocated and tested below
            try { // Subsequent code may fail on some real (e.g., Infineon CJTOP80K) cards - catch exception
                fnc_mult_cipher.init(fnc_mult_pubkey_pow2, Cipher.MODE_ENCRYPT);
                // Try operation - if doesn't work, exception SW_CANTALLOCATE_BIGNAT is emitted
                Util.arrayFillNonAtomic(fnc_mult_resultArray1, (short) 0, (short) fnc_mult_resultArray1.length, (byte) 6);
                fnc_mult_cipher.doFinal(fnc_mult_resultArray1, (short) 0, (short) fnc_mult_resultArray1.length, fnc_mult_resultArray1, (short) 0);
                FLAG_FAST_MULT_VIA_RSA = true;
            } catch (Exception ignored) {
            } // discard exception                
        }    
        
        /**
         * Erase all values stored in helper objects
         */
        void erase() {
            rm.erase();
            Util.arrayFillNonAtomic(tmp_array_short, (short) 0, (short) tmp_array_short.length, (byte) 0);
        }
    }
    
    
    /**
     * Configure itself to proper lengths and other parameters according to intended length of ECC
     * @author Petr Svenda
     */
    public static class ECConfig {
        /**
         * The size of speedup engine used for fast modulo exponent computation
         * (must be larger than biggest Bignat used)
         */
        public short MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
        /**
         * The size of speedup engine used for fast multiplication of large numbers
         * Must be larger than 2x biggest Bignat used
         */
        public short MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
        /**
         * The size of largest integer used in computations
         */
        public short MAX_BIGNAT_SIZE = (short) 65; // ((short) (MODULO_ENGINE_MAX_LENGTH_BITS / 8) + 1);
        /**
         * The size of largest ECC point used
         */
        public short MAX_POINT_SIZE = (short) 64;
        /**
         * The size of single coordinate of the largest ECC point used 
         */
        public short MAX_COORD_SIZE = (short) 32; // MAX_POINT_SIZE / 2
        
        
        public ResourceManager rm = null;
        /**
         * Helper structure containing all preallocated objects necessary for Bignat operations
         */
        public Bignat_Helper bnh = null;
        /**
         * Helper structure containing all preallocated objects necessary for ECPoint operations
         */
        public ECPoint_Helper ech = null;
    
        /**
         * Creates new control structure for requested bit length with all preallocated arrays and engines 
         * @param maxECLength maximum length of ECPoint objects supported. The provided value is used to 
         *      initialize properly underlying arrays and engines.  
         */
        public ECConfig(short maxECLength) {
            
            // Allocate helper objects for BN and EC
            // Note: due to circular references, we need to split object creation and actual alloaction and initailiztion later (initialize()) 
            rm = new ResourceManager();
            bnh = new Bignat_Helper(rm);
            ech = new ECPoint_Helper(rm);
    
            // Set proper lengths and other internal settings based on required ECC length
            if (maxECLength <= (short) 256) {
                setECC256Config();
            }
            else if (maxECLength <= (short) 384) {
                setECC384Config();
            } 
            else if (maxECLength <= (short) 512) {
                setECC512Config();
            }
            else {
                ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
            }
            
            // Allocate shared resources and initialize mapping between shared objects and helpers
            rm.initialize(MAX_POINT_SIZE, MAX_COORD_SIZE, MAX_BIGNAT_SIZE, MULT_RSA_ENGINE_MAX_LENGTH_BITS, bnh);
            bnh.initialize(MODULO_RSA_ENGINE_MAX_LENGTH_BITS, MULT_RSA_ENGINE_MAX_LENGTH_BITS);
            ech.initialize();
        }
        
        public void refreshAfterReset() {
            if (rm.locker != null) { 
                rm.locker.refreshAfterReset();
            }        
        }
        
        void reset() {
            bnh.FLAG_FAST_MULT_VIA_RSA = false;     
            ech.FLAG_FAST_EC_MULT_VIA_KA = false;   
        }
        
        public void setECC256Config() {
            reset();
            MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
            MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;        
            MAX_POINT_SIZE = (short) 64;
            computeDerivedLengths();
        }
        public void setECC384Config() {
            reset();
            MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
            MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
            MAX_POINT_SIZE = (short) 96;
            computeDerivedLengths();
        }
        public void setECC512Config() {
            reset();
            MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
            MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
            MAX_POINT_SIZE = (short) 128;
            computeDerivedLengths();
        }    
        public void setECC521Config() {
            reset();
            MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
            MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
            MAX_POINT_SIZE = (short) 129;
            computeDerivedLengths();
        }
        
        private void computeDerivedLengths() {
            MAX_BIGNAT_SIZE = (short) ((short) (bnh.MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8) + 1);
            MAX_COORD_SIZE = (short) (MAX_POINT_SIZE / 2);
        }
    
        /**
         * Unlocks all logically locked arrays and objects. Useful as recovery after premature end of some operation (e.g., due to exception)
         * when some objects remains locked.
         */
        void unlockAll() {
            rm.unlockAll();
            rm.locker.unlockAll();
        }
    }
    
    
    /**
     * 
     * @author Vasilios Mavroudis and Petr Svenda
     */
    public static class ECCurve {
        public final short KEY_LENGTH; //Bits
        public final short POINT_SIZE; //Bytes
        public final short COORD_SIZE; //Bytes
    
        //Parameters
        public byte[] p = null;
        public byte[] a = null;
        public byte[] b = null;
        public byte[] G = null;
        public byte[] r = null;
        
        public Bignat pBN;
        public Bignat aBN;
        public Bignat bBN;
        
        public KeyPair disposable_pair;
        public ECPrivateKey disposable_priv;
    
        
    
        /**
         * Creates new curve object from provided parameters. Either copy of provided
         * arrays is performed (bCopyArgs == true, input arrays can be reused later for other
         * purposes) or arguments are directly stored (bCopyArgs == false, usable for fixed static arrays) .
         * @param bCopyArgs if true, copy of arguments is created, otherwise reference is directly stored
         * @param p_arr array with p
         * @param a_arr array with a
         * @param b_arr array with b
         * @param G_arr array with base point G
         * @param r_arr array with r
         */
        public ECCurve(boolean bCopyArgs, byte[] p_arr, byte[] a_arr, byte[] b_arr, byte[] G_arr, byte[] r_arr) {
            //ECCurve_initialize(p_arr, a_arr, b_arr, G_arr, r_arr);
            this.KEY_LENGTH = (short) (p_arr.length * 8);
            this.POINT_SIZE = (short) G_arr.length;
            this.COORD_SIZE = (short) ((short) (G_arr.length - 1) / 2);
    
            if (bCopyArgs) {
                // Copy curve parameters into newly allocated arrays in EEPROM (will be only read, not written later => good performance even when in EEPROM)
                this.p = new byte[(short) p_arr.length];
                this.a = new byte[(short) a_arr.length];
                this.b = new byte[(short) b_arr.length];
                this.G = new byte[(short) G_arr.length];
                this.r = new byte[(short) r_arr.length];
    
                Util.arrayCopyNonAtomic(p_arr, (short) 0, p, (short) 0, (short) p.length);
                Util.arrayCopyNonAtomic(a_arr, (short) 0, a, (short) 0, (short) a.length);
                Util.arrayCopyNonAtomic(b_arr, (short) 0, b, (short) 0, (short) b.length);
                Util.arrayCopyNonAtomic(G_arr, (short) 0, G, (short) 0, (short) G.length);
                Util.arrayCopyNonAtomic(r_arr, (short) 0, r, (short) 0, (short) r.length);
            }
            else {
                // No allocation, store directly provided arrays 
                this.p = p_arr;
                this.a = a_arr;
                this.b = b_arr;
                this.G = G_arr;
                this.r = r_arr;
            }
    
            // We will not modify values of p/a/b during the lifetime of curve => allocate helper bignats directly from the array
            // Additionally, these Bignats will be only read from so Bignat_Helper can be null (saving need to pass as argument to ECCurve)
            this.pBN = new Bignat(this.p, null);
            this.aBN = new Bignat(this.a, null);
            this.bBN = new Bignat(this.b, null);
    
            this.disposable_pair = this.newKeyPair(null);
            this.disposable_priv = (ECPrivateKey) this.disposable_pair.getPrivate();
        }    
        
        /**
         * Refresh critical information stored in RAM for performance reasons after a card reset (RAM was cleared).
         */
        public void updateAfterReset() {
            this.pBN.from_byte_array(this.p);
            this.aBN.from_byte_array(this.a);
            this.bBN.from_byte_array(this.b);
        }
    	
        /**
         * Creates a new keyPair based on this curve parameters. KeyPair object is reused if provided. Fresh keyPair value is generated.
         * @param existingKeyPair existing KeyPair object which is reused if required. If null, new KeyPair is allocated
         * @return new or existing object with fresh key pair value
         */
        KeyPair newKeyPair(KeyPair existingKeyPair) {
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_1);
            ECPrivateKey privKey;
            ECPublicKey pubKey;
            if (existingKeyPair == null) { // Allocate if not supplied
                existingKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KEY_LENGTH);
            }
            
            // Some implementation will not return valid pub key until ecKeyPair.genKeyPair() is called
            // Other implementation will fail with exception if same is called => try catch and drop any exception 
            try {
                pubKey = (ECPublicKey) existingKeyPair.getPublic();
                if (pubKey == null) {
                    existingKeyPair.genKeyPair();
                }
            } catch (Exception e) {
            } // intentionally do nothing
            
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_2);
            privKey = (ECPrivateKey) existingKeyPair.getPrivate();
            pubKey = (ECPublicKey) existingKeyPair.getPublic();
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_3);
    
            // Set required values
            privKey.setFieldFP(p, (short) 0, (short) p.length);
            privKey.setA(a, (short) 0, (short) a.length);
            privKey.setB(b, (short) 0, (short) b.length);
            privKey.setG(G, (short) 0, (short) G.length);
            privKey.setR(r, (short) 0, (short) r.length);
            privKey.setK((short) 1);
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_4);
    
            pubKey.setFieldFP(p, (short) 0, (short) p.length);
            pubKey.setA(a, (short) 0, (short) a.length);
            pubKey.setB(b, (short) 0, (short) b.length);
            pubKey.setG(G, (short) 0, (short) G.length);
            pubKey.setR(r, (short) 0, (short) r.length);
            pubKey.setK((short) 1);
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_5);
    
            existingKeyPair.genKeyPair();
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_6);
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_7);
    
            return existingKeyPair;
        }
        
        public KeyPair newKeyPair_legacy(KeyPair existingKeyPair) {
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_1);
            ECPrivateKey privKey;
            ECPublicKey pubKey;
            if (existingKeyPair == null) {
                // We need to create required objects
                privKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_LENGTH, false);
                PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_2);
                pubKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KEY_LENGTH, false);
                PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_3);
            }
            else {
                // Obtain from object
                privKey = (ECPrivateKey) existingKeyPair.getPrivate();
                pubKey = (ECPublicKey) existingKeyPair.getPublic();
            }
            // Set required values
            privKey.setFieldFP(p, (short) 0, (short) p.length);
            privKey.setA(a, (short) 0, (short) a.length);
            privKey.setB(b, (short) 0, (short) b.length);
            privKey.setG(G, (short) 0, (short) G.length);
            privKey.setR(r, (short) 0, (short) r.length);
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_4);
    
            pubKey.setFieldFP(p, (short) 0, (short) p.length);
            pubKey.setA(a, (short) 0, (short) a.length);
            pubKey.setB(b, (short) 0, (short) b.length);
            pubKey.setG(G, (short) 0, (short) G.length);
            pubKey.setR(r, (short) 0, (short) r.length);
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_5);
    
            if (existingKeyPair == null) { // Allocate if not supplied
                existingKeyPair = new KeyPair(pubKey, privKey);
            }
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_6);
            existingKeyPair.genKeyPair();
            PM.check(PM.TRAP_ECCURVE_NEWKEYPAIR_7);
    
            return existingKeyPair;
        }
        
        
        /**
         * Converts provided Bignat into temporary EC private key object. No new 
         * allocation is performed, returned ECPrivateKey is overwritten by next call.
         * @param bn Bignat with new value
         * @return ECPrivateKey initialized with provided Bignat
         */
        public ECPrivateKey bignatAsPrivateKey(Bignat bn) {
            disposable_priv.setS(bn.as_byte_array(), (short) 0, bn.length());
            return disposable_priv;
        }
        
        /**
         * Set new G for this curve. Also updates all dependent key values.
         * @param newG buffer with new G
         * @param newGOffset start offset within newG
         * @param newGLen length of new G
         */
        public void setG(byte[] newG, short newGOffset, short newGLen) {
            Util.arrayCopyNonAtomic(newG, newGOffset, G, (short) 0, newGLen);
            this.disposable_pair = this.newKeyPair(this.disposable_pair);
            this.disposable_priv = (ECPrivateKey) this.disposable_pair.getPrivate();
            this.disposable_priv.setG(newG, newGOffset, newGLen);  
        }
    }
    
    
    /**
     * 
     * @author Vasilios Mavroudis and Petr Svenda
     */
    public static class ECPoint {	
        private final ECPoint_Helper ech;
    
        private ECPublicKey         thePoint;
        private KeyPair             thePointKeyPair;
        private final ECCurve       theCurve;
        
        /**
         * Creates new ECPoint object for provided {@code curve}. Random initial point value is generated. 
         * The point will use helper structures from provided ECPoint_Helper object.
         * @param curve point's elliptic curve
         * @param ech object with preallocated helper objects and memory arrays
         */
        public ECPoint(ECCurve curve, ECPoint_Helper ech) {
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
        public void getY(Bignat yCopy) {
            yCopy.set_size(this.getY(yCopy.as_byte_array(), (short) 0));
        }    
    	
    	
    
         
        /**
         * Doubles the current value of this point. 
         */
        public void makeDouble() {
            // doubling via add sometimes causes exception inside KeyAgreement engine
            // this.add(this);
            // Use bit slower, but more robust version via multiplication by 2
            this.multiplication(Bignat_Helper.TWO);
        }
    
        /**
         * Adds this (P) and provided (Q) point. Stores a resulting value into this point.
         * @param other point to be added to this.
         */
        public void add(ECPoint other) {
            PM.check(PM.TRAP_ECPOINT_ADD_1);
    
            boolean samePoint = this == other || isEqual(other);
    
            ech.lock(ech.uncompressed_point_arr1);
            this.thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
            ech.fnc_add_x_p.lock();
            ech.fnc_add_x_p.set_size(this.theCurve.COORD_SIZE);
            ech.fnc_add_x_p.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) 1);
            ech.fnc_add_y_p.lock();
            ech.fnc_add_y_p.set_size(this.theCurve.COORD_SIZE);
            ech.fnc_add_y_p.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
            ech.unlock(ech.uncompressed_point_arr1);
    
            PM.check(PM.TRAP_ECPOINT_ADD_2);
    
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
                ech.fnc_add_nominator.mod_exp(Bignat_Helper.TWO, this.theCurve.pBN);
                ech.fnc_add_nominator.mod_mult(ech.fnc_add_nominator, Bignat_Helper.THREE, this.theCurve.pBN);
                ech.fnc_add_nominator.mod_add(this.theCurve.aBN, this.theCurve.pBN);
                // (2y_p)
                ech.fnc_add_denominator.clone(ech.fnc_add_y_p);
                ech.fnc_add_denominator.mod_mult(ech.fnc_add_y_p, Bignat_Helper.TWO, this.theCurve.pBN);
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
    
                PM.check(PM.TRAP_ECPOINT_ADD_3);
                ech.fnc_add_nominator.mod(this.theCurve.pBN);
                PM.check(PM.TRAP_ECPOINT_ADD_4);
    
                ech.fnc_add_nominator.mod_sub(ech.fnc_add_y_p, this.theCurve.pBN);
    
                // (x_q-x_p)
                ech.fnc_add_denominator.clone(ech.fnc_add_x_q);
                ech.fnc_add_denominator.mod(this.theCurve.pBN);
                PM.check(PM.TRAP_ECPOINT_ADD_5);
                ech.fnc_add_denominator.mod_sub(ech.fnc_add_x_p, this.theCurve.pBN);
                ech.fnc_add_denominator.mod_inv(this.theCurve.pBN);        	
                PM.check(PM.TRAP_ECPOINT_ADD_6); 
            }
            
            ech.fnc_add_lambda.lock();
            ech.fnc_add_lambda.resize_to_max(false);
            ech.fnc_add_lambda.zero();
            ech.fnc_add_lambda.mod_mult(ech.fnc_add_nominator, ech.fnc_add_denominator, this.theCurve.pBN);
            ech.fnc_add_nominator.unlock();
            ech.fnc_add_denominator.unlock();
            PM.check(PM.TRAP_ECPOINT_ADD_7);
    
            // (x_p,y_p)+(x_q,y_q)=(x_r,y_r)
            // lambda=(y_q-y_p)/(x_q-x_p)
    
            //x_r=lambda^2-x_p-x_q
            ech.fnc_add_x_r.lock();
            if (samePoint) {
                short len = this.multiplication_x(Bignat_Helper.TWO, ech.fnc_add_x_r.as_byte_array(), (short) 0);
                ech.fnc_add_x_r.set_size(len); 
            } else {        
                ech.fnc_add_x_r.clone(ech.fnc_add_lambda);
                //m_occ.ecHelper.fnc_add_x_r.mod_exp(occ.bnHelper.TWO, this.TheCurve.pBN);
                ech.fnc_add_x_r.mod_exp2(this.theCurve.pBN);
                ech.fnc_add_x_r.mod_sub(ech.fnc_add_x_p, this.theCurve.pBN);
                ech.fnc_add_x_r.mod_sub(ech.fnc_add_x_q, this.theCurve.pBN);
                ech.fnc_add_x_q.unlock();                
                PM.check(PM.TRAP_ECPOINT_ADD_8); 
            }
            //y_r=lambda(x_p-x_r)-y_p        
            ech.fnc_add_y_r.lock();
            ech.fnc_add_y_r.clone(ech.fnc_add_x_p);
            ech.fnc_add_x_p.unlock();
            ech.fnc_add_y_r.mod_sub(ech.fnc_add_x_r, this.theCurve.pBN);
            PM.check(PM.TRAP_ECPOINT_ADD_9); 
            ech.fnc_add_y_r.mod_mult(ech.fnc_add_y_r, ech.fnc_add_lambda, this.theCurve.pBN);
            ech.fnc_add_lambda.unlock();
            PM.check(PM.TRAP_ECPOINT_ADD_10); 
            ech.fnc_add_y_r.mod_sub(ech.fnc_add_y_p, this.theCurve.pBN);
            ech.fnc_add_y_p.unlock();
            PM.check(PM.TRAP_ECPOINT_ADD_11);
    
            ech.lock(ech.uncompressed_point_arr1);
            ech.uncompressed_point_arr1[0] = (byte)0x04;
            // If x_r.length() and y_r.length() is smaller than this.TheCurve.COORD_SIZE due to leading zeroes which were shrinked before, then we must add these back
            ech.fnc_add_x_r.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) 1);
            ech.fnc_add_x_r.unlock();
            ech.fnc_add_y_r.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
            ech.fnc_add_y_r.unlock();
            PM.check(PM.TRAP_ECPOINT_ADD_12);
            this.setW(ech.uncompressed_point_arr1, (short) 0, this.theCurve.POINT_SIZE);
            ech.unlock(ech.uncompressed_point_arr1);
            PM.check(PM.TRAP_ECPOINT_ADD_13);
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
        public void multiplication(Bignat scalar) {
            PM.check(PM.TRAP_ECPOINT_MULT_1);
            
            ech.fnc_multiplication_x.lock();
            short len = this.multiplication_x(scalar, ech.fnc_multiplication_x.as_byte_array(), (short) 0);
            ech.fnc_multiplication_x.set_size(len); 
            PM.check(PM.TRAP_ECPOINT_MULT_2);
    
            //Y^2 = X^3 + XA + B = x(x^2+A)+B
            ech.fnc_multiplication_y_sq.lock();
            ech.fnc_multiplication_y_sq.clone(ech.fnc_multiplication_x);
            PM.check(PM.TRAP_ECPOINT_MULT_3);
            ech.fnc_multiplication_y_sq.mod_exp(Bignat_Helper.TWO, this.theCurve.pBN);
            PM.check(PM.TRAP_ECPOINT_MULT_4);
            ech.fnc_multiplication_y_sq.mod_add(this.theCurve.aBN, this.theCurve.pBN);
            PM.check(PM.TRAP_ECPOINT_MULT_5);
            ech.fnc_multiplication_y_sq.mod_mult(ech.fnc_multiplication_y_sq, ech.fnc_multiplication_x, this.theCurve.pBN);
            PM.check(PM.TRAP_ECPOINT_MULT_6);
            ech.fnc_multiplication_y_sq.mod_add(this.theCurve.bBN, this.theCurve.pBN);
            PM.check(PM.TRAP_ECPOINT_MULT_7);
            ech.fnc_multiplication_y1.lock();
            ech.fnc_multiplication_y1.clone(ech.fnc_multiplication_y_sq); 
            ech.fnc_multiplication_y_sq.unlock();
            PM.check(PM.TRAP_ECPOINT_MULT_8);
            ech.fnc_multiplication_y1.sqrt_FP(this.theCurve.pBN);
            PM.check(PM.TRAP_ECPOINT_MULT_9);
            
            // Construct public key with <x, y_1>
            ech.lock(ech.uncompressed_point_arr1);
            ech.uncompressed_point_arr1[0] = 0x04;
            ech.fnc_multiplication_x.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) 1);
            ech.fnc_multiplication_x.unlock();
            ech.fnc_multiplication_y1.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) (1 + theCurve.COORD_SIZE));
            this.setW(ech.uncompressed_point_arr1, (short) 0, theCurve.POINT_SIZE); //So that we can convert to pub key
            PM.check(PM.TRAP_ECPOINT_MULT_10);
    
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
            
            PM.check(PM.TRAP_ECPOINT_MULT_11);
    
            this.setW(ech.uncompressed_point_arr1, (short)0, theCurve.POINT_SIZE);
            ech.unlock(ech.uncompressed_point_arr1);
            
            PM.check(PM.TRAP_ECPOINT_MULT_12);
        }
    
        /**
         * Multiplies this point value with provided scalar and stores result into provided array.
         * No modification of this point is performed.
         * @param scalar value of scalar for multiplication
         * @param outBuffer output array for resulting value
         * @param outBufferOffset offset within output array
         * @return length of resulting value (in bytes)
         */
        public short multiplication_x(Bignat scalar, byte[] outBuffer, short outBufferOffset) {
            return multiplication_x_KA(scalar, outBuffer, outBufferOffset);
        }
        
        
        /**
         * Multiplies this point value with provided scalar and stores result into
         * provided array. No modification of this point is performed.
         * Native KeyAgreement engine is used.
         *
         * @param scalar value of scalar for multiplication
         * @param outBuffer output array for resulting value
         * @param outBufferOffset offset within output array
         * @return length of resulting value (in bytes)
         */
        private short multiplication_x_KA(Bignat scalar, byte[] outBuffer, short outBufferOffset) {
            // NOTE: potential problem on real cards (j2e) - when small scalar is used (e.g., Bignat.TWO), operation sometimes freezes
            PM.check(PM.TRAP_ECPOINT_MULT_X_1);
            theCurve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());
            PM.check(PM.TRAP_ECPOINT_MULT_X_2);
    
            ech.fnc_multiplication_x_keyAgreement.init(theCurve.disposable_priv);
            PM.check(PM.TRAP_ECPOINT_MULT_X_3);
    
            ech.lock(ech.uncompressed_point_arr1);
            short len = this.getW(ech.uncompressed_point_arr1, (short) 0); 
            PM.check(PM.TRAP_ECPOINT_MULT_X_4);
            len = ech.fnc_multiplication_x_keyAgreement.generateSecret(ech.uncompressed_point_arr1, (short) 0, len, outBuffer, outBufferOffset);
            ech.unlock(ech.uncompressed_point_arr1);
            PM.check(PM.TRAP_ECPOINT_MULT_X_5);
            // Return always length of whole coordinate X instead of len - some real cards returns shorter value equal to SHA-1 output size although PLAIN results is filled into buffer (GD60) 
            return this.theCurve.COORD_SIZE;
        }
    
        /**
         * Computes negation of this point.
         */
        public void negate() {
            PM.check(PM.TRAP_ECPOINT_NEGATE_1);
        	
            // Operation will dump point into uncompressed_point_arr, negate Y and restore back
            ech.fnc_negate_yBN.lock();
            ech.lock(ech.uncompressed_point_arr1);
            thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
            PM.check(PM.TRAP_ECPOINT_NEGATE_2);
            ech.fnc_negate_yBN.set_size(this.theCurve.COORD_SIZE);
            ech.fnc_negate_yBN.from_byte_array(this.theCurve.COORD_SIZE, (short) 0, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
            PM.check(PM.TRAP_ECPOINT_NEGATE_3);
        	ech.fnc_negate_yBN.mod_negate(this.theCurve.pBN);
            PM.check(PM.TRAP_ECPOINT_NEGATE_4);
            
            // Restore whole point back
            ech.fnc_negate_yBN.prepend_zeros(this.theCurve.COORD_SIZE, ech.uncompressed_point_arr1, (short) (1 + this.theCurve.COORD_SIZE));
            ech.fnc_negate_yBN.unlock();
            this.setW(ech.uncompressed_point_arr1, (short) 0, this.theCurve.POINT_SIZE);
            ech.unlock(ech.uncompressed_point_arr1);
            PM.check(PM.TRAP_ECPOINT_NEGATE_5);
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
        private void from_x(Bignat x) {
            //Y^2 = X^3 + XA + B = x(x^2+A)+B
            ech.fnc_from_x_y_sq.lock();
            ech.fnc_from_x_y_sq.clone(x);
            ech.fnc_from_x_y_sq.mod_exp(Bignat_Helper.TWO, this.theCurve.pBN);
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
    
    
    /**
     *
     * @author Petr Svenda
     */
    public static class ECPoint_Helper extends Base_Helper {
        // Selected constants missing from older JC API specs 
        public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN = (byte) 3;
        public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY = (byte) 6;
        public static final byte Signature_ALG_ECDSA_SHA_256 = (byte) 33;
    
        /**
         * If true, fast multiplication of ECPoints via KeyAgreement can be used. Is
         * set automatically after successful allocation of required engines
         */
        public boolean FLAG_FAST_EC_MULT_VIA_KA = false;
    
        byte[] uncompressed_point_arr1;
        byte[] fnc_isEqual_hashArray;
        byte[] fnc_multiplication_resultArray;
    
        // These Bignats are just pointing to some helperEC_BN_? so reasonable naming is preserved yet no need to actually allocated whole Bignat object
        Bignat fnc_add_x_r; // frequent write
        Bignat fnc_add_y_r; // frequent write
        Bignat fnc_add_x_p; // one init, then just read
        Bignat fnc_add_y_p; // one init, then just read
        Bignat fnc_add_x_q; // one init, then just read
        Bignat fnc_add_lambda; // write mod_mul (but only final result)
        Bignat fnc_add_nominator; // frequent write
        Bignat fnc_add_denominator; // frequent write
    
        Bignat fnc_multiplication_x; // result write
        Bignat fnc_multiplication_y_sq; // frequent write
        Bignat fnc_multiplication_scalar; // write once, read
        Bignat fnc_multiplication_y1; // mostly just read, write inside sqrt_FP
        Bignat fnc_multiplication_y2; // mostly just read, result write
        Bignat fnc_negate_yBN; // mostly just read, result write
    
        Bignat fnc_from_x_x;
        Bignat fnc_from_x_y_sq;
        Bignat fnc_from_x_y;
    
        Bignat fnc_is_y;
    
        KeyAgreement fnc_multiplication_x_keyAgreement;
        Signature    fnc_SignVerifyECDSA_signEngine; 
        MessageDigest fnc_isEqual_hashEngine;
    
        public ECPoint_Helper(ResourceManager rm) {
            super(rm);
    
            FLAG_FAST_EC_MULT_VIA_KA = false; // set true only if succesfully allocated and tested below
            try {
                //fnc_multiplication_x_keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DHC, false);
                //fnc_SignVerifyECDSA_signEngine = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
                //fnc_multiplication_x_keyAgreement = KeyAgreement.getInstance(Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY, false);
                fnc_multiplication_x_keyAgreement = KeyAgreement.getInstance(KeyAgreement_ALG_EC_SVDP_DH_PLAIN, false);
                fnc_SignVerifyECDSA_signEngine = Signature.getInstance(Signature_ALG_ECDSA_SHA_256, false);
                FLAG_FAST_EC_MULT_VIA_KA = true;
            } catch (Exception ignored) {
            } // Discard any exception
        }
    
        void initialize() {
            // Important: assignment of helper BNs is made according to two criteria:
            // 1. Correctness: same BN must not be assigned to overlapping operations (guarded by lock/unlock) 
            // 2. Memory tradeoff: we like to put as few BNs into RAM as possible. So most frequently used BNs for write should be in RAM
            //                      and at the same time we like to have as few BNs in RAM as possible. 
            // So think twice before changing the assignments!
            fnc_add_x_r = rm.helperEC_BN_B;
            fnc_add_y_r = rm.helperEC_BN_C;
            fnc_add_x_p = rm.helperEC_BN_D;
            fnc_add_y_p = rm.helperEC_BN_E;
            fnc_add_x_q = rm.helperEC_BN_F;
            fnc_add_nominator = rm.helperEC_BN_B;
            fnc_add_denominator = rm.helperEC_BN_C;
            fnc_add_lambda = rm.helperEC_BN_A;
    
            fnc_multiplication_scalar = rm.helperEC_BN_F;
            fnc_multiplication_x = rm.helperEC_BN_B;
            fnc_multiplication_y_sq = rm.helperEC_BN_C;
            fnc_multiplication_y1 = rm.helperEC_BN_D;
            fnc_multiplication_y2 = rm.helperEC_BN_B;
            fnc_multiplication_resultArray = rm.helper_BN_array1;
    
            fnc_negate_yBN = rm.helperEC_BN_C;
    
            Bignat fnc_from_x_x;
            Bignat fnc_from_x_y_sq;
            Bignat fnc_from_x_y;
    
            fnc_is_y = rm.helperEC_BN_C;
    
            fnc_isEqual_hashArray = rm.helper_hashArray;
            fnc_isEqual_hashEngine = rm.hashEngine;
    
            uncompressed_point_arr1 = rm.helper_uncompressed_point_arr1;
        }
    }
    
    
    /**
     * 
    * @author Vasilios Mavroudis and Petr Svenda
     */
    public static class Integer {
        private Bignat_Helper bnh;
    
        private Bignat magnitude;
        private byte sign;
        
    
        /**
         * Allocates integer with provided length and sets to zero. 
         * @param size 
         * @param bnh Bignat_Helper with all supporting objects
         */
        public Integer(short size, Bignat_Helper bnh) {
            allocate(size, (byte) 0, null, (byte) -1, bnh);
        }
    
        /**
         * Allocates integer from provided buffer and initialize by provided value.
         * Sign is expected as first byte of value.
         * @param value array with initial value
         * @param valueOffset start offset within   value
         * @param length length of array
         * @param bnh Bignat_Helper with all supporting objects
         */
        public Integer(byte[] value, short valueOffset, short length, Bignat_Helper bnh) {
            allocate(length, (value[valueOffset] == (byte) 0x00) ? (byte) 0 : (byte) 1, value, (short) (valueOffset + 1), bnh);
        }
    
        /**
         * Allocates integer from provided array with explicit sign. No sign is expected in provided array.
         *
         * @param sign  sign of integer
         * @param value array with initial value  
         * @param bnh Bignat_Helper with all supporting objects
         */
        public Integer(byte sign, byte[] value, Bignat_Helper bnh) {
            allocate((short) value.length, sign, value, (short) 0, bnh);
        }
    
        /**
         * Copy constructor of integer from other already existing value
         * @param other integer to copy from
         */
        public Integer(Integer other) {
            allocate(other.getSize(), other.getSign(), other.getMagnitude_b(), (short) 0, other.bnh);
        }
    
        /**
         * Creates integer from existing Bignat and provided sign. If required, 
         * copy is performed, otherwise bignat is used as magnitude.
         * @param sign  sign of integer
         * @param magnitude initial magnitude
         * @param bMakeCopy if true, magnitude is directly used (no copy). If false, new storage array is allocated.
         */
        public Integer(byte sign, Bignat magnitude, boolean bMakeCopy, Bignat_Helper bnh) {
            if (bMakeCopy) {
                // Copy from provided bignat
                allocate(magnitude.length(), sign, magnitude.as_byte_array(), (short) 0, bnh);
            }
            else {
                // Use directly provided Bignat as storage - no allocation
                initialize(sign, magnitude, bnh);
            }
        }
        
        /**
         * Initialize integer object with provided sign and already allocated Bignat
         * as magnitude
         *
         * @param sign sign of integer
         * @param bnStorage magnitude (object is directly used, no copy is
         * preformed)
         */
        private void initialize(byte sign, Bignat bnStorage, Bignat_Helper bnh) {
            this.sign = sign;
            this.magnitude = bnStorage;
            this.bnh = bnh;
        }
    
        /**
         * Allocates and initializes Integer.
         *
         * @param size length of integer
         * @param sign sign of integer
         * @param fromArray input array with initial value (copy of value is
         * performed)
         * @param fromArrayOffset start offset within fromArray
         */
        private void allocate(short size, byte sign, byte[] fromArray, short fromArrayOffset, Bignat_Helper bignatHelper) {
            this.bnh = bignatHelper;
            Bignat mag = new Bignat(size, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.bnh);
            if (fromArray != null) {
                mag.from_byte_array(size, (short) 0, fromArray, fromArrayOffset);
            }
            initialize(sign, mag, this.bnh);
        }
        
        /**
         * Clone value into this Integer from other Integer. Updates size of integer.
         * @param other other integer to copy from 
         */
        public void clone(Integer other) {
            this.sign = other.getSign();
            this.magnitude.copy(other.getMagnitude());
        }
    
        /** 
         * set this integer to zero
         */
        public void zero() {
            this.sign = (short) 0;
            this.magnitude.zero();
        }
    
        /**
         * Return sign of this integer
         * @return current sign
         */
        public byte getSign() {
            return this.sign;
        }
        /**
         * Set sign of this integer
         * @param s new sign
         */
        public void setSign(byte s) {
            this.sign = s;
        }
    
        /**
         * Return length (in bytes) of this integer
         * @return length of this integer
         */
        public short getSize() {
            return this.magnitude.length();
        }    
        /**
         * Set length of this integer
         * @param newSize new length
         */
        public void setSize(short newSize) {
            this.magnitude.set_size(newSize);
        }
    
        /**
         * Compute negation of this integer
         */
        public void negate() {
            if (this.isPositive()) {
                this.setSign((byte) 1);
            } else if (this.isNegative()) {
                this.setSign((byte) 0);
            }
        }
    
        /**
         * Returns internal array as byte array. No copy is performed so change of 
         * values in array also changes this integer
         * @return byte array with magnitude
         */
        public byte[] getMagnitude_b() {
            return this.magnitude.as_byte_array();
        }
    
        /**
         * Returns magnitude as Bignat. No copy is performed so change of Bignat also changes this integer
         *
         * @return Bignat representing magnitude
         */
        public Bignat getMagnitude() {
            return this.magnitude;
        }
    
        /**
         * Set magnitude of this integer from other one. Will not change this integer length. 
         * No sign is copied from other.
         * @param other other integer to copy from
         */
        public void setMagnitude(Integer other) {
            this.magnitude.copy(other.getMagnitude());
        }
    
        /**
         * Serializes this integer value into array. Sign is serialized as first byte
         * @param outBuffer output array
         * @param outBufferOffset start offset within output array
         * @return length of resulting serialized number including sign (number of bytes) 
         */
        public short toByteArray(byte[] outBuffer, short outBufferOffset) {
            //Store sign
            outBuffer[outBufferOffset] = sign;
            //Store magnitude
            Util.arrayCopyNonAtomic(this.getMagnitude_b(), (short) 0, outBuffer, (short) (outBufferOffset + 1), this.getSize());
            return (short) (this.getSize() + 1);
        }
        
        /**
         * Deserialize value of this integer from provided array including sign. 
         * Sign is expected to be as first byte
         * @param value array with value
         * @param valueOffset start offset within value
         * @param valueLength length of value
         */
        public void fromByteArray(byte[] value, short valueOffset, short valueLength) {
            //Store sign
            this.sign = value[valueOffset];
            //Store magnitude
            this.magnitude.from_byte_array((short) (valueLength - 1), (short) 0, value, (short) (valueOffset + 1));
        }
    
        /**
         * Return true if integer is negative.
         * @return true if integer is negative, false otherwise
         */
        public boolean isNegative() {
            return this.sign == 1;
        }
    
        /**
         * Return true if integer is positive.
         *
         * @return true if integer is positive, false otherwise
         */
        public boolean isPositive() {
            return this.sign == 0;
        }
    
        /**
         * Compares two integers. Return true, if this is smaller than other.
         * @param other other integer to compare
         * @return true, if this is strictly smaller than other. False otherwise.
         */
        public boolean lesser(Integer other) {
            if (this.sign == 1 && other.sign == 0) {
                return true;
            } else if (this.sign == 0 && other.sign == 1) {
                return false;
            } else if ((this.sign == 0 && other.sign == 0)) {
                return this.magnitude.lesser(other.magnitude);
            } else { //if ((this.sign == 1 && other.sign==1))
                return (!this.magnitude.lesser(other.magnitude));
            }
        }
    
        /**
         * Add other integer to this and store result into this.
         * @param other other integer to add 
         */
        public void add(Integer other) {
            if (this.isPositive() && other.isPositive()) { //this and other are (+)
                this.sign = 0;
                this.magnitude.add(other.magnitude);
            } else if (this.isNegative() && other.isNegative()) { //this and other are (-)
                this.sign = 1;
                this.magnitude.add(other.magnitude);
            } else {
                if (this.isPositive() && other.getMagnitude().lesser(this.getMagnitude())) { //this(+) is larger than other(-)
                    this.sign = 0;
                    this.magnitude.subtract(other.magnitude);
                } else if (this.isNegative() && other.getMagnitude().lesser(this.getMagnitude())) {	//this(-) has larger magnitude than other(+)
                    this.sign = 1;
                    this.magnitude.subtract(other.magnitude);
                } else if (this.isPositive() && this.getMagnitude().lesser(other.getMagnitude())) { //this(+) has smaller magnitude than other(-)
                    this.sign = 1;
                    bnh.fnc_int_add_tmpMag.lock();
                    bnh.fnc_int_add_tmpMag.clone(other.getMagnitude());
                    bnh.fnc_int_add_tmpMag.subtract(this.magnitude);
                    this.magnitude.copy(bnh.fnc_int_add_tmpMag);
                    bnh.fnc_int_add_tmpMag.unlock();
                } else if (this.isNegative() && this.getMagnitude().lesser(other.getMagnitude())) {  //this(-) has larger magnitude than other(+)
                    this.sign = 0;
                    bnh.fnc_int_add_tmpMag.lock();
                    bnh.fnc_int_add_tmpMag.clone(other.getMagnitude());
                    bnh.fnc_int_add_tmpMag.subtract(this.magnitude);
                    this.magnitude.copy(bnh.fnc_int_add_tmpMag);
                    bnh.fnc_int_add_tmpMag.unlock();
                } else if (this.getMagnitude().same_value(other.getMagnitude())) {  //this has opposite sign than other, and the same magnitude
                    this.sign = 0;
                    this.zero();
                }
            }
        }
    
        /**
         * Substract other integer from this and store result into this.
         *
         * @param other other integer to substract
         */
        public void subtract(Integer other) {
            other.negate(); // Potentially problematic - failure and exception in subsequent function will cause other to stay negated
            this.add(other);
            // Restore original sign for other
            other.negate();
        }
    
        /**
         * Multiply this and other integer and store result into this.
         *
         * @param other other integer to multiply
         */
        public void multiply(Integer other) {
            if (this.isPositive() && other.isNegative()) {
                this.setSign((byte) 1);
            } else if (this.isNegative() && other.isPositive()) {
                this.setSign((byte) 1);
            } else {
                this.setSign((byte) 0);
            }
    
            // Make mod BN as maximum value (positive, leading 0x80)
            bnh.fnc_int_multiply_mod.lock();
            bnh.fnc_int_multiply_mod.set_size(this.magnitude.length());
            bnh.fnc_int_multiply_mod.zero(); 
            bnh.fnc_int_multiply_mod.as_byte_array()[0] = (byte) 0x80;  // Max INT+1 Value 
    
            bnh.fnc_int_multiply_tmpThis.lock();
            bnh.fnc_int_multiply_tmpThis.set_size(this.magnitude.length());
            bnh.fnc_int_multiply_tmpThis.mod_mult(this.getMagnitude(), other.getMagnitude(), bnh.fnc_int_multiply_mod);
            this.magnitude.copy(bnh.fnc_int_multiply_tmpThis);
            bnh.fnc_int_multiply_mod.unlock();
            bnh.fnc_int_multiply_tmpThis.unlock();
        }
    
        /**
         * Divide this by other integer and store result into this.
         *
         * @param other divisor
         */
        public void divide(Integer other) {
            if (this.isPositive() && other.isNegative()) {
                this.setSign((byte) 1);
            } else if (this.isNegative() && other.isPositive()) {
                this.setSign((byte) 1);
            } else {
                this.setSign((byte) 0);
            }
    
            bnh.fnc_int_divide_tmpThis.lock();
            bnh.fnc_int_divide_tmpThis.clone(this.magnitude);
            bnh.fnc_int_divide_tmpThis.remainder_divide(other.getMagnitude(), this.magnitude);
            bnh.fnc_int_divide_tmpThis.unlock();
        }
    
        /**
         * Computes modulo of this by other integer and store result into this.
         *
         * @param other modulus
         */    
        public void modulo(Integer other) {
            this.magnitude.mod(other.getMagnitude());
        }
    }
    
    
    /**
     * The control point for unified allocation of arrays and objects with customable
     * specification of allocator type (RAM/EEPROM) for particular array. Allows for 
     * quick personalization and optimization of memory use when compiling for cards 
     * with more/less available memory. 
     * 
    * @author Petr Svenda
     */
    public static class ObjectAllocator {
        short allocatedInRAM = 0;
        short allocatedInEEPROM = 0;
        byte[] ALLOCATOR_TYPE_ARRAY = null;
        
        public static final byte BNH_helper_BN_array1    = 0;
        public static final byte BNH_helper_BN_array2    = 1;
        public static final byte BNH_helper_BN_A         = 2;
        public static final byte BNH_helper_BN_B         = 3;
        public static final byte BNH_helper_BN_C         = 4;
        public static final byte BNH_helper_BN_D         = 5;
        public static final byte BNH_helper_BN_E         = 6;
        public static final byte BNH_helper_BN_F         = 7;
        
        public static final byte ECPH_helperEC_BN_A      = 8;
        public static final byte ECPH_helperEC_BN_B      = 9;
        public static final byte ECPH_helperEC_BN_C      = 10;
        public static final byte ECPH_helperEC_BN_D      = 11;
        public static final byte ECPH_helperEC_BN_E      = 12;
        public static final byte ECPH_helperEC_BN_F      = 13;
        public static final byte ECPH_uncompressed_point_arr1 = 14;
        public static final byte ECPH_hashArray          = 15;
        
        public static final short ALLOCATOR_TYPE_ARRAY_LENGTH = (short) (ECPH_hashArray + 1);
        
        /**
         * Creates new allocator control object, resets performance counters
         */
        public ObjectAllocator() {
            ALLOCATOR_TYPE_ARRAY = new byte[ALLOCATOR_TYPE_ARRAY_LENGTH];
            setAllAllocatorsRAM();
            resetAllocatorCounters();
        }
        /**
         * All type of allocator for all object as EEPROM
         */
        public final void setAllAllocatorsEEPROM() {
            Util.arrayFillNonAtomic(ALLOCATOR_TYPE_ARRAY, (short) 0, (short) ALLOCATOR_TYPE_ARRAY.length, JCSystem.MEMORY_TYPE_PERSISTENT);
        }
        /**
         * All type of allocator for all object as RAM
         */
        public void setAllAllocatorsRAM() {
            Util.arrayFillNonAtomic(ALLOCATOR_TYPE_ARRAY, (short) 0, (short) ALLOCATOR_TYPE_ARRAY.length, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        }
        /**
         * All type of allocator for selected object as RAM (faster), rest EEPROM (saving RAM)
         * The current settings is heuristically obtained from measurements of performance of Bignat and ECPoint operations 
         */    
        public void setAllocatorsTradeoff() {
            // Set initial allocators into EEPROM
            setAllAllocatorsEEPROM();
            
            // Put only the most perfromance relevant ones into RAM
            ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_array1] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_array2] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_A] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_C] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_D] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_E] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BNH_helper_BN_F] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[ECPH_helperEC_BN_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[ECPH_helperEC_BN_C] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[ECPH_uncompressed_point_arr1] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        }   
    
        /**
         * Allocates new byte[] array with provided length either in RAM or EEPROM based on an allocator type.
         * Method updates internal counters of bytes allocated with specific allocator. Use {@code getAllocatedInRAM()} 
         * or {@code getAllocatedInEEPROM} for counters readout.
         * @param length    length of array
         * @param allocatorType type of allocator
         * @return allocated array 
         */
        public byte[] allocateByteArray(short length, byte allocatorType) {
            switch (allocatorType) {
                case JCSystem.MEMORY_TYPE_PERSISTENT:
                    allocatedInEEPROM += length;
                    return new byte[length];
                case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
                    allocatedInRAM += length;
                    return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_RESET);
                case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
                    allocatedInRAM += length;
                    return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
            }
            return null;
        }
    
        /**
         * Returns pre-set allocator type for provided object identified by unique objectAllocatorID
         * @param objectAllocatorID unique id of target object
         * @return allocator type
         */
        public byte getAllocatorType(short objectAllocatorID) {
            if (objectAllocatorID >= 0 && objectAllocatorID <= (short) ALLOCATOR_TYPE_ARRAY.length) {
                return ALLOCATOR_TYPE_ARRAY[objectAllocatorID];
            } else {
                ISOException.throwIt(ReturnCodes.SW_ALLOCATOR_INVALIDOBJID);
                return -1;
            }
        }    
        
        /**
         * Returns number of bytes allocated in RAM via {@code allocateByteArray()} since last reset of counters.
         * @return number of bytes allocated in RAM via this control object
         */
        public short getAllocatedInRAM() {
            return allocatedInRAM;
        }
        /**
         * Returns number of bytes allocated in EEPROM via {@code allocateByteArray()}
         * since last reset of counters.
         *
         * @return number of bytes allocated in EEPROM via this control object
         */
        public short getAllocatedInEEPROM() {
            return allocatedInEEPROM;
        }
        /**
         * Resets counters of allocated bytes in RAM and EEPROM
         */
        public final void resetAllocatorCounters() {
            allocatedInRAM = 0;
            allocatedInEEPROM = 0;
        }
    }
    
    
    /**
     *
    * @author Vasilios Mavroudis and Petr Svenda
     */
    public static class ObjectLocker {
        /**
         * Configuration flag controlling clearing of shared objects on lock as
         * prevention of unwanted leak of sensitive information from previous
         * operation. If true, object is erased once locked for use
         */
        private boolean ERASE_ON_LOCK = false;
        /**
         * Configuration flag controlling clearing of shared objects on lock as
         * prevention of unwanted leak of sensitive information to next 
         * operation. If true, object is erased once unlocked from use
         */
        private boolean ERASE_ON_UNLOCK = false;    
        
        /**
         * Configuration flag controlling clearing of shared objects on lock as
         * prevention of unwanted leak of sensitive information to next operation.
         * If true, object is erased once unlocked from use
         */
        private boolean PROFILE_LOCKED_OBJECTS = false;
        /**
         * Array of pointers to objects which will be guarded by locks. 
         * Every even value contains pointer to registered object. Subsequent index 
         * contains null if not locked, !null if locked, 
         * Stored in RAM for fast access.
         */
        private Object[] lockedObjects;
        /**
         * Copy of pointers to objects from lockedObjects in persistent memory to refresh after card reset.
         * Refreshed by call {@code refreshAfterReset()}
         */
        private Object[] lockedObjectsPersistent;
        
        /**
         * Array to hold state of lock for all other objects implemented as N x N array [0...N-1][N...2N-1]...[] 
         * where [0...N-1] contains the states of lock for all other objects than first object (lockedObjects[0]). 
         * If no other object is locked after series of operations, [0...N-1] will contain 0 on all indexes. 
         * All objects (lockedObjects[i]) which happened to be locked together with have 1 at [0...i...N-1]. 
         */
        public byte[] profileLockedObjects;
        /**
         * If true, locking is performed, otherwise relevant method just return without any operation performed
         */
        private boolean bLockingActive = true;
        
        public ObjectLocker(short numArrays) {
            initialize(numArrays, ERASE_ON_LOCK, ERASE_ON_UNLOCK);
        }
        public ObjectLocker(short numArrays, boolean bEraseOnLock, boolean bEraseOnUnlock) {
            initialize(numArrays, bEraseOnLock, bEraseOnUnlock);
        }
        private final void initialize(short numObjects, boolean bEraseOnLock, boolean bEraseOnUnlock) {
            lockedObjects = JCSystem.makeTransientObjectArray((short) (2 * numObjects), JCSystem.CLEAR_ON_RESET);
            lockedObjectsPersistent = new Object[(short) (2 * numObjects)];
            ERASE_ON_LOCK = bEraseOnLock;
            ERASE_ON_UNLOCK = bEraseOnUnlock;
            profileLockedObjects = new byte[(short) (numObjects * numObjects)]; 
            resetProfileLocks();
        }
        
        /**
         * Reset profile array with profile locks statistics.
         */
        public void resetProfileLocks() {
            Util.arrayFillNonAtomic(profileLockedObjects, (short) 0, (short) profileLockedObjects.length, (byte) 0);
        }
    
        /**
         * Register new object for lock guarding. 
         * @param objToLock object to be guarded
         * @return index to internal array where registered object is stored (if known, lock/unlock is faster)
         */
        public short registerLock(Object objToLock) {
            short i;
            for (i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[i] == null) {
                    // Free slot found
                    lockedObjects[i] = objToLock;
                    lockedObjects[(short) (i + 1)] = null; // null means array is unlocked
                    lockedObjectsPersistent[i] = objToLock; // Store same into persistent array as well
                    lockedObjectsPersistent[(short) (i + 1)] = null; 
                    return i; // Return index for potential speedup of locking
                }
            }
            ISOException.throwIt(ReturnCodes.SW_LOCK_NOFREESLOT);
            return -1;
        }
        /**
         * Locking array (placed in RAM) must be refreshed after card reset. Call this method during select()
         */
        public void refreshAfterReset() {
            for (short i = 0; i < (short) lockedObjects.length; i++) {
                lockedObjects[i] = lockedObjectsPersistent[i];
            }
        }
        
        /**
         * Controls if locking and unlocking is actually performed. The lock operations 
         * add some overhead, so it may be turned on/off as required. E.g., when developing 
         * new code or like to enjoy protection of automatic clearing of shared objects before/after lock
         * enable this feature. 
         * @param bLockActive if true, locking and unlocking is performed. If false, lock/unlock methods will return without any effect
         */
        public void setLockingActive(boolean bLockActive) {
            bLockingActive = bLockActive;
        }
        /**
         * Lock/reserve provided object for subsequent use. Used to protect corruption
         * of pre-allocated shared objects in different, potentially nested,
         * operations. Must be unlocked later on.
         *
         * @param objToLock array to be locked
         * @throws SW_ALREADYLOCKED if already locked (is already in use by
         * other operation)
         */
        public void lock(Object objToLock) {
            if (!bLockingActive) {
                return;
            }
            // Find object to lock
            short i;
            for (i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[i] != null && lockedObjects[i].equals(objToLock)) {
                    lock(objToLock, i);
                    break;
                }
            }
            // If reached here, required array was not found
            if (i == (short) lockedObjects.length) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
            }
        }
        public void lock(byte[] objToLock) {
            if (!bLockingActive) {
                return;
            }
            lock((Object) objToLock);
            if (ERASE_ON_LOCK) {
                Util.arrayFillNonAtomic(objToLock, (short) 0, (short) objToLock.length, (byte) 0);
            }
        }
        /**
         * Unlock/release object from use. Used to protect corruption of
         * pre-allocated objects used in different nested operations. Must
         * be locked before.
         *
         * @param objToUnlock object to unlock
         * @throws SW_NOTLOCKED_BIGNAT if was not locked before (inconsistence in
         * lock/unlock sequence)
         */
        
        public void unlock(Object objToUnlock) {
            if (!bLockingActive) {
                return;
            }
            // Find object to unlock
            short i;
            for (i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[i] != null && lockedObjects[i].equals(objToUnlock)) {
                    unlock(objToUnlock, i);
                    break;
                }
            }
            // If reached here, required array was not found
            if (i == (short) lockedObjects.length) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
            }
        }    
    
        public void unlock(byte[] objToUnlock) {
            if (!bLockingActive) {
                return;
            }
            unlock((Object) objToUnlock);
            if (ERASE_ON_UNLOCK) {
                Util.arrayFillNonAtomic(objToUnlock, (short) 0, (short) objToUnlock.length, (byte) 0);
            }
        }    
        
        /**
         * Unlocks all locked objects
         */
        public void unlockAll() {
            if (!bLockingActive) {
                return;
            }
            for (short i = 0; i < (short) lockedObjects.length; i += 2) {
                lockedObjects[(short) (i + 1)] = null;
            }
        }
        
        /**
         * Check if provided object is logically locked
         * @param objToUnlock object to be checked
         * @return true of array is logically locked, false otherwise 
         */
        
        public boolean isLocked(Object objToUnlock) {
            if (!bLockingActive) {
                return false;
            }
            // Find object to unlock
            short i;
            for (i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[i] != null && lockedObjects[i].equals(objToUnlock)) {
                    return lockedObjects[(short) (i + 1)] != null;
                }
            }
            // If reached here, required object was not found
            if (i == (short) lockedObjects.length) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
            }
            return false;
        }
        
        
        private void lock(Object objToLock, short lockIndex) {
            if (lockedObjects[lockIndex] != null && !lockedObjects[lockIndex].equals(objToLock)) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_MISMATCH);
            }
            // Next position in array signalizes logical lock (null == unlocked, !null == locked) 
            if (lockedObjects[(short) (lockIndex + 1)] == null) {
                lockedObjects[(short) (lockIndex + 1)] = objToLock; // lock logically by assigning object reference to [i + 1]
            } else {
                // this array is already locked, raise exception (incorrect sequence of locking and unlocking)
                ISOException.throwIt(ReturnCodes.SW_LOCK_ALREADYLOCKED);
            }
            if (PROFILE_LOCKED_OBJECTS) {
                // If enabled, check status of all other objects and mark these that are currently locked
                short profileLockOffset = (short) ((short) (lockIndex / 2) * (short) ((short) lockedObjects.length / 2)); // Obtain section of profileLockedObjects array relevant for current object
                
                for (short i = 0; i < (short) lockedObjects.length; i += 2) {
                    if (lockedObjects[(short) (i + 1)] != null) {
                        // Object at index i is locked, mark it to corresponding position in profileLockedObjects by setting value to 1
                        profileLockedObjects[(short) (profileLockOffset + (short) (i / 2))] = 1;
                    }
                }
            }
        }
        
        private void unlock(Object objToUnlock, short lockIndex) {
            if (lockedObjects[lockIndex] != null && !lockedObjects[lockIndex].equals(objToUnlock)) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_MISMATCH);
            }
            // Next position in array signalizes logical lock (null == unlocked, !null == locked) 
            if (lockedObjects[(short) (lockIndex + 1)].equals(objToUnlock)) {
                lockedObjects[(short) (lockIndex + 1)] = null; // lock logically by assigning object reference to [i + 1]
            } else {
                // this array is not locked, raise exception (incorrect sequence of locking and unlocking)
                ISOException.throwIt(ReturnCodes.SW_LOCK_NOTLOCKED);
            }
        }
    }
    
    public static class P512r1 {
    
        public final static short KEY_LENGTH = 512; //Bits
        public final static short POINT_SIZE = 129; //Bytes
        public final static short COORD_SIZE = 64; //Bytes
    
        public final static byte[] p = {(byte) 0xAA, (byte) 0xDD, (byte) 0x9D, (byte) 0xB8, (byte) 0xDB, (byte) 0xE9, (byte) 0xC4, (byte) 0x8B, (byte) 0x3F, (byte) 0xD4, (byte) 0xE6, (byte) 0xAE, (byte) 0x33, (byte) 0xC9, (byte) 0xFC, (byte) 0x07, (byte) 0xCB, (byte) 0x30, (byte) 0x8D, (byte) 0xB3, (byte) 0xB3, (byte) 0xC9, (byte) 0xD2, (byte) 0x0E, (byte) 0xD6, (byte) 0x63, (byte) 0x9C, (byte) 0xCA, (byte) 0x70, (byte) 0x33, (byte) 0x08, (byte) 0x71, (byte) 0x7D, (byte) 0x4D, (byte) 0x9B, (byte) 0x00, (byte) 0x9B, (byte) 0xC6, (byte) 0x68, (byte) 0x42, (byte) 0xAE, (byte) 0xCD, (byte) 0xA1, (byte) 0x2A, (byte) 0xE6, (byte) 0xA3, (byte) 0x80, (byte) 0xE6, (byte) 0x28, (byte) 0x81, (byte) 0xFF, (byte) 0x2F, (byte) 0x2D, (byte) 0x82, (byte) 0xC6, (byte) 0x85, (byte) 0x28, (byte) 0xAA, (byte) 0x60, (byte) 0x56, (byte) 0x58, (byte) 0x3A, (byte) 0x48, (byte) 0xF3};
    
        public final static byte[] a = {(byte) 0x78, (byte) 0x30, (byte) 0xA3, (byte) 0x31, (byte) 0x8B, (byte) 0x60, (byte) 0x3B, (byte) 0x89, (byte) 0xE2, (byte) 0x32, (byte) 0x71, (byte) 0x45, (byte) 0xAC, (byte) 0x23, (byte) 0x4C, (byte) 0xC5, (byte) 0x94, (byte) 0xCB, (byte) 0xDD, (byte) 0x8D, (byte) 0x3D, (byte) 0xF9, (byte) 0x16, (byte) 0x10, (byte) 0xA8, (byte) 0x34, (byte) 0x41, (byte) 0xCA, (byte) 0xEA, (byte) 0x98, (byte) 0x63, (byte) 0xBC, (byte) 0x2D, (byte) 0xED, (byte) 0x5D, (byte) 0x5A, (byte) 0xA8, (byte) 0x25, (byte) 0x3A, (byte) 0xA1, (byte) 0x0A, (byte) 0x2E, (byte) 0xF1, (byte) 0xC9, (byte) 0x8B, (byte) 0x9A, (byte) 0xC8, (byte) 0xB5, (byte) 0x7F, (byte) 0x11, (byte) 0x17, (byte) 0xA7, (byte) 0x2B, (byte) 0xF2, (byte) 0xC7, (byte) 0xB9, (byte) 0xE7, (byte) 0xC1, (byte) 0xAC, (byte) 0x4D, (byte) 0x77, (byte) 0xFC, (byte) 0x94, (byte) 0xCA};
    
        public final static byte[] b = {(byte) 0x3D, (byte) 0xF9, (byte) 0x16, (byte) 0x10, (byte) 0xA8, (byte) 0x34, (byte) 0x41, (byte) 0xCA, (byte) 0xEA, (byte) 0x98, (byte) 0x63, (byte) 0xBC, (byte) 0x2D, (byte) 0xED, (byte) 0x5D, (byte) 0x5A, (byte) 0xA8, (byte) 0x25, (byte) 0x3A, (byte) 0xA1, (byte) 0x0A, (byte) 0x2E, (byte) 0xF1, (byte) 0xC9, (byte) 0x8B, (byte) 0x9A, (byte) 0xC8, (byte) 0xB5, (byte) 0x7F, (byte) 0x11, (byte) 0x17, (byte) 0xA7, (byte) 0x2B, (byte) 0xF2, (byte) 0xC7, (byte) 0xB9, (byte) 0xE7, (byte) 0xC1, (byte) 0xAC, (byte) 0x4D, (byte) 0x77, (byte) 0xFC, (byte) 0x94, (byte) 0xCA, (byte) 0xDC, (byte) 0x08, (byte) 0x3E, (byte) 0x67, (byte) 0x98, (byte) 0x40, (byte) 0x50, (byte) 0xB7, (byte) 0x5E, (byte) 0xBA, (byte) 0xE5, (byte) 0xDD, (byte) 0x28, (byte) 0x09, (byte) 0xBD, (byte) 0x63, (byte) 0x80, (byte) 0x16, (byte) 0xF7, (byte) 0x23};
    
        public final static byte[] G = {(byte) 0x04, (byte) 0x81, (byte) 0xAE, (byte) 0xE4, (byte) 0xBD, (byte) 0xD8, (byte) 0x2E, (byte) 0xD9, (byte) 0x64, (byte) 0x5A, (byte) 0x21, (byte) 0x32, (byte) 0x2E, (byte) 0x9C, (byte) 0x4C, (byte) 0x6A, (byte) 0x93, (byte) 0x85, (byte) 0xED, (byte) 0x9F, (byte) 0x70, (byte) 0xB5, (byte) 0xD9, (byte) 0x16, (byte) 0xC1, (byte) 0xB4, (byte) 0x3B, (byte) 0x62, (byte) 0xEE, (byte) 0xF4, (byte) 0xD0, (byte) 0x09, (byte) 0x8E, (byte) 0xFF, (byte) 0x3B, (byte) 0x1F, (byte) 0x78, (byte) 0xE2, (byte) 0xD0, (byte) 0xD4, (byte) 0x8D, (byte) 0x50, (byte) 0xD1, (byte) 0x68, (byte) 0x7B, (byte) 0x93, (byte) 0xB9, (byte) 0x7D, (byte) 0x5F, (byte) 0x7C, (byte) 0x6D, (byte) 0x50, (byte) 0x47, (byte) 0x40, (byte) 0x6A, (byte) 0x5E, (byte) 0x68, (byte) 0x8B, (byte) 0x35, (byte) 0x22, (byte) 0x09, (byte) 0xBC, (byte) 0xB9, (byte) 0xF8, (byte) 0x22,
            (byte) 0x7D, (byte) 0xDE, (byte) 0x38, (byte) 0x5D, (byte) 0x56, (byte) 0x63, (byte) 0x32, (byte) 0xEC, (byte) 0xC0, (byte) 0xEA, (byte) 0xBF, (byte) 0xA9, (byte) 0xCF, (byte) 0x78, (byte) 0x22, (byte) 0xFD, (byte) 0xF2, (byte) 0x09, (byte) 0xF7, (byte) 0x00, (byte) 0x24, (byte) 0xA5, (byte) 0x7B, (byte) 0x1A, (byte) 0xA0, (byte) 0x00, (byte) 0xC5, (byte) 0x5B, (byte) 0x88, (byte) 0x1F, (byte) 0x81, (byte) 0x11, (byte) 0xB2, (byte) 0xDC, (byte) 0xDE, (byte) 0x49, (byte) 0x4A, (byte) 0x5F, (byte) 0x48, (byte) 0x5E, (byte) 0x5B, (byte) 0xCA, (byte) 0x4B, (byte) 0xD8, (byte) 0x8A, (byte) 0x27, (byte) 0x63, (byte) 0xAE, (byte) 0xD1, (byte) 0xCA, (byte) 0x2B, (byte) 0x2F, (byte) 0xA8, (byte) 0xF0, (byte) 0x54, (byte) 0x06, (byte) 0x78, (byte) 0xCD, (byte) 0x1E, (byte) 0x0F, (byte) 0x3A, (byte) 0xD8, (byte) 0x08, (byte) 0x92};
    
        public final static byte[] r = {(byte) 0xAA, (byte) 0xDD, (byte) 0x9D, (byte) 0xB8, (byte) 0xDB, (byte) 0xE9, (byte) 0xC4, (byte) 0x8B, (byte) 0x3F, (byte) 0xD4, (byte) 0xE6, (byte) 0xAE, (byte) 0x33, (byte) 0xC9, (byte) 0xFC, (byte) 0x07, (byte) 0xCB, (byte) 0x30, (byte) 0x8D, (byte) 0xB3, (byte) 0xB3, (byte) 0xC9, (byte) 0xD2, (byte) 0x0E, (byte) 0xD6, (byte) 0x63, (byte) 0x9C, (byte) 0xCA, (byte) 0x70, (byte) 0x33, (byte) 0x08, (byte) 0x70, (byte) 0x55, (byte) 0x3E, (byte) 0x5C, (byte) 0x41, (byte) 0x4C, (byte) 0xA9, (byte) 0x26, (byte) 0x19, (byte) 0x41, (byte) 0x86, (byte) 0x61, (byte) 0x19, (byte) 0x7F, (byte) 0xAC, (byte) 0x10, (byte) 0x47, (byte) 0x1D, (byte) 0xB1, (byte) 0xD3, (byte) 0x81, (byte) 0x08, (byte) 0x5D, (byte) 0xDA, (byte) 0xDD, (byte) 0xB5, (byte) 0x87, (byte) 0x96, (byte) 0x82, (byte) 0x9C, (byte) 0xA9, (byte) 0x00, (byte) 0x69};
    }
    
    
    /**
     * Utility class for performance profiling. Contains definition of performance trap 
     * constants and trap reaction method. 
    * @author Petr Svenda
     */
    public static class PM {
        public static short m_perfStop = -1; // Performace measurement stop indicator
    
        // Performance-related debugging response codes
        public static final short PERF_START        = (short) 0x0001;
                
        public static final short TRAP_UNDEFINED = (short) 0xffff;
    
        public static final short TRAP_EC_MUL = (short) 0x7780;
        public static final short TRAP_EC_MUL_1 = (short) (TRAP_EC_MUL + 1);
        public static final short TRAP_EC_MUL_2 = (short) (TRAP_EC_MUL + 2);
        public static final short TRAP_EC_MUL_3 = (short) (TRAP_EC_MUL + 3);
        public static final short TRAP_EC_MUL_4 = (short) (TRAP_EC_MUL + 4);
        public static final short TRAP_EC_MUL_5 = (short) (TRAP_EC_MUL + 5);
        public static final short TRAP_EC_MUL_6 = (short) (TRAP_EC_MUL + 6);
        public static final short TRAP_EC_MUL_COMPLETE = TRAP_EC_MUL;
    
        public static final short TRAP_EC_GEN = (short) 0x7770;
        public static final short TRAP_EC_GEN_1 = (short) (TRAP_EC_GEN + 1);
        public static final short TRAP_EC_GEN_2 = (short) (TRAP_EC_GEN + 2);
        public static final short TRAP_EC_GEN_3 = (short) (TRAP_EC_GEN + 3);
        public static final short TRAP_EC_GEN_COMPLETE = TRAP_EC_GEN;
        
        public static final short TRAP_EC_DBL = (short) 0x7760;
        public static final short TRAP_EC_DBL_1 = (short) (TRAP_EC_DBL + 1);
        public static final short TRAP_EC_DBL_2 = (short) (TRAP_EC_DBL + 2);
        public static final short TRAP_EC_DBL_3 = (short) (TRAP_EC_DBL + 3);
        public static final short TRAP_EC_DBL_4 = (short) (TRAP_EC_DBL + 4);
        public static final short TRAP_EC_DBL_COMPLETE = TRAP_EC_DBL;
    
        public static final short TRAP_EC_ADD = (short) 0x7750;
        public static final short TRAP_EC_ADD_1 = (short) (TRAP_EC_ADD + 1);
        public static final short TRAP_EC_ADD_2 = (short) (TRAP_EC_ADD + 2);
        public static final short TRAP_EC_ADD_3 = (short) (TRAP_EC_ADD + 3);
        public static final short TRAP_EC_ADD_4 = (short) (TRAP_EC_ADD + 4);
        public static final short TRAP_EC_ADD_5 = (short) (TRAP_EC_ADD + 5);
        public static final short TRAP_EC_ADD_COMPLETE = TRAP_EC_ADD;
    
        public static final short TRAP_BN_STR = (short) 0x7740;
        public static final short TRAP_BN_STR_1 = (short) (TRAP_BN_STR + 1);
        public static final short TRAP_BN_STR_2 = (short) (TRAP_BN_STR + 2);
        public static final short TRAP_BN_STR_3 = (short) (TRAP_BN_STR + 3);
        public static final short TRAP_BN_STR_COMPLETE = TRAP_BN_STR;
    
        public static final short TRAP_BN_ADD = (short) 0x7730;
        public static final short TRAP_BN_ADD_1 = (short) (TRAP_BN_ADD + 1);
        public static final short TRAP_BN_ADD_2 = (short) (TRAP_BN_ADD + 2);
        public static final short TRAP_BN_ADD_3 = (short) (TRAP_BN_ADD + 3);
        public static final short TRAP_BN_ADD_4 = (short) (TRAP_BN_ADD + 4);
        public static final short TRAP_BN_ADD_5 = (short) (TRAP_BN_ADD + 5);
        public static final short TRAP_BN_ADD_6 = (short) (TRAP_BN_ADD + 6);
        public static final short TRAP_BN_ADD_7 = (short) (TRAP_BN_ADD + 7);
        public static final short TRAP_BN_ADD_COMPLETE = TRAP_BN_ADD;
    
        public static final short TRAP_BN_SUB = (short) 0x7720;
        public static final short TRAP_BN_SUB_1 = (short) (TRAP_BN_SUB + 1);
        public static final short TRAP_BN_SUB_2 = (short) (TRAP_BN_SUB + 2);
        public static final short TRAP_BN_SUB_3 = (short) (TRAP_BN_SUB + 3);
        public static final short TRAP_BN_SUB_4 = (short) (TRAP_BN_SUB + 4);
        public static final short TRAP_BN_SUB_5 = (short) (TRAP_BN_SUB + 5);
        public static final short TRAP_BN_SUB_6 = (short) (TRAP_BN_SUB + 6);
        public static final short TRAP_BN_SUB_7 = (short) (TRAP_BN_SUB + 7);
        public static final short TRAP_BN_SUB_COMPLETE = TRAP_BN_SUB;
        
        public static final short TRAP_BN_MUL = (short) 0x7710;
        public static final short TRAP_BN_MUL_1 = (short) (TRAP_BN_MUL + 1);
        public static final short TRAP_BN_MUL_2 = (short) (TRAP_BN_MUL + 2);
        public static final short TRAP_BN_MUL_3 = (short) (TRAP_BN_MUL + 3);
        public static final short TRAP_BN_MUL_4 = (short) (TRAP_BN_MUL + 4);
        public static final short TRAP_BN_MUL_5 = (short) (TRAP_BN_MUL + 5);
        public static final short TRAP_BN_MUL_6 = (short) (TRAP_BN_MUL + 6);
        public static final short TRAP_BN_MUL_COMPLETE = TRAP_BN_MUL;
        
        public static final short TRAP_BN_EXP = (short) 0x7700;
        public static final short TRAP_BN_EXP_1 = (short) (TRAP_BN_EXP + 1);
        public static final short TRAP_BN_EXP_2 = (short) (TRAP_BN_EXP + 2);
        public static final short TRAP_BN_EXP_3 = (short) (TRAP_BN_EXP + 3);
        public static final short TRAP_BN_EXP_4 = (short) (TRAP_BN_EXP + 4);
        public static final short TRAP_BN_EXP_5 = (short) (TRAP_BN_EXP + 5);
        public static final short TRAP_BN_EXP_6 = (short) (TRAP_BN_EXP + 6);
        public static final short TRAP_BN_EXP_COMPLETE = TRAP_BN_EXP;
        
        public static final short TRAP_BN_MOD = (short) 0x76f0;
        public static final short TRAP_BN_MOD_1 = (short) (TRAP_BN_MOD + 1);
        public static final short TRAP_BN_MOD_2 = (short) (TRAP_BN_MOD + 2);
        public static final short TRAP_BN_MOD_3 = (short) (TRAP_BN_MOD + 3);
        public static final short TRAP_BN_MOD_4 = (short) (TRAP_BN_MOD + 4);
        public static final short TRAP_BN_MOD_5 = (short) (TRAP_BN_MOD + 5);
        public static final short TRAP_BN_MOD_COMPLETE = TRAP_BN_MOD;
        
        public static final short TRAP_BN_ADD_MOD = (short) 0x76e0;
        public static final short TRAP_BN_ADD_MOD_1 = (short) (TRAP_BN_ADD_MOD + 1);
        public static final short TRAP_BN_ADD_MOD_2 = (short) (TRAP_BN_ADD_MOD + 2);
        public static final short TRAP_BN_ADD_MOD_3 = (short) (TRAP_BN_ADD_MOD + 3);
        public static final short TRAP_BN_ADD_MOD_4 = (short) (TRAP_BN_ADD_MOD + 4);
        public static final short TRAP_BN_ADD_MOD_5 = (short) (TRAP_BN_ADD_MOD + 5);
        public static final short TRAP_BN_ADD_MOD_6 = (short) (TRAP_BN_ADD_MOD + 6);
        public static final short TRAP_BN_ADD_MOD_7 = (short) (TRAP_BN_ADD_MOD + 7);
        public static final short TRAP_BN_ADD_MOD_COMPLETE = TRAP_BN_ADD_MOD;
        
        public static final short TRAP_BN_SUB_MOD = (short) 0x76d0;
        public static final short TRAP_BN_SUB_MOD_1 = (short) (TRAP_BN_SUB_MOD + 1);
        public static final short TRAP_BN_SUB_MOD_2 = (short) (TRAP_BN_SUB_MOD + 2);
        public static final short TRAP_BN_SUB_MOD_3 = (short) (TRAP_BN_SUB_MOD + 3);
        public static final short TRAP_BN_SUB_MOD_4 = (short) (TRAP_BN_SUB_MOD + 4);
        public static final short TRAP_BN_SUB_MOD_5 = (short) (TRAP_BN_SUB_MOD + 5);
        public static final short TRAP_BN_SUB_MOD_6 = (short) (TRAP_BN_SUB_MOD + 6);
        public static final short TRAP_BN_SUB_MOD_COMPLETE = TRAP_BN_SUB_MOD;
        
        public static final short TRAP_BN_MUL_MOD = (short) 0x76c0;
        public static final short TRAP_BN_MUL_MOD_1 = (short) (TRAP_BN_MUL_MOD + 1);
        public static final short TRAP_BN_MUL_MOD_2 = (short) (TRAP_BN_MUL_MOD + 2);
        public static final short TRAP_BN_MUL_MOD_3 = (short) (TRAP_BN_MUL_MOD + 3);
        public static final short TRAP_BN_MUL_MOD_4 = (short) (TRAP_BN_MUL_MOD + 4);
        public static final short TRAP_BN_MUL_MOD_5 = (short) (TRAP_BN_MUL_MOD + 5);
        public static final short TRAP_BN_MUL_MOD_6 = (short) (TRAP_BN_MUL_MOD + 6);
        public static final short TRAP_BN_MUL_MOD_COMPLETE = TRAP_BN_MUL_MOD;
        
        public static final short TRAP_BN_EXP_MOD = (short) 0x76b0;
        public static final short TRAP_BN_EXP_MOD_1 = (short) (TRAP_BN_EXP_MOD + 1);
        public static final short TRAP_BN_EXP_MOD_2 = (short) (TRAP_BN_EXP_MOD + 2);
        public static final short TRAP_BN_EXP_MOD_3 = (short) (TRAP_BN_EXP_MOD + 3);
        public static final short TRAP_BN_EXP_MOD_4 = (short) (TRAP_BN_EXP_MOD + 4);
        public static final short TRAP_BN_EXP_MOD_5 = (short) (TRAP_BN_EXP_MOD + 5);
        public static final short TRAP_BN_EXP_MOD_6 = (short) (TRAP_BN_EXP_MOD + 6);
        public static final short TRAP_BN_EXP_MOD_COMPLETE = TRAP_BN_EXP_MOD;
        
        public static final short TRAP_BN_INV_MOD = (short) 0x76a0;
        public static final short TRAP_BN_INV_MOD_1 = (short) (TRAP_BN_INV_MOD + 1);
        public static final short TRAP_BN_INV_MOD_2 = (short) (TRAP_BN_INV_MOD + 2);
        public static final short TRAP_BN_INV_MOD_3 = (short) (TRAP_BN_INV_MOD + 3);
        public static final short TRAP_BN_INV_MOD_4 = (short) (TRAP_BN_INV_MOD + 4);
        public static final short TRAP_BN_INV_MOD_5 = (short) (TRAP_BN_INV_MOD + 5);
        public static final short TRAP_BN_INV_MOD_COMPLETE = TRAP_BN_INV_MOD;    
        
        public static final short TRAP_INT_STR = (short) 0x7690;
        public static final short TRAP_INT_STR_1 = (short) (TRAP_INT_STR + 1);
        public static final short TRAP_INT_STR_2 = (short) (TRAP_INT_STR + 2);
        public static final short TRAP_INT_STR_COMPLETE = TRAP_INT_STR;
    
        public static final short TRAP_INT_ADD = (short) 0x7680;
        public static final short TRAP_INT_ADD_1 = (short) (TRAP_INT_ADD + 1);
        public static final short TRAP_INT_ADD_2 = (short) (TRAP_INT_ADD + 2);
        public static final short TRAP_INT_ADD_3 = (short) (TRAP_INT_ADD + 3);
        public static final short TRAP_INT_ADD_4 = (short) (TRAP_INT_ADD + 4);
        public static final short TRAP_INT_ADD_COMPLETE = TRAP_INT_ADD;
    
        public static final short TRAP_INT_SUB = (short) 0x7670;
        public static final short TRAP_INT_SUB_1 = (short) (TRAP_INT_SUB + 1);
        public static final short TRAP_INT_SUB_2 = (short) (TRAP_INT_SUB + 2);
        public static final short TRAP_INT_SUB_3 = (short) (TRAP_INT_SUB + 3);
        public static final short TRAP_INT_SUB_4 = (short) (TRAP_INT_SUB + 4);
        public static final short TRAP_INT_SUB_COMPLETE = TRAP_INT_SUB;
    
        public static final short TRAP_INT_MUL = (short) 0x7660;
        public static final short TRAP_INT_MUL_1 = (short) (TRAP_INT_MUL + 1);
        public static final short TRAP_INT_MUL_2 = (short) (TRAP_INT_MUL + 2);
        public static final short TRAP_INT_MUL_3 = (short) (TRAP_INT_MUL + 3);
        public static final short TRAP_INT_MUL_4 = (short) (TRAP_INT_MUL + 4);
        public static final short TRAP_INT_MUL_COMPLETE = TRAP_INT_MUL;
    
        public static final short TRAP_INT_DIV = (short) 0x7650;
        public static final short TRAP_INT_DIV_1 = (short) (TRAP_INT_DIV + 1);
        public static final short TRAP_INT_DIV_2 = (short) (TRAP_INT_DIV + 2);
        public static final short TRAP_INT_DIV_3 = (short) (TRAP_INT_DIV + 3);
        public static final short TRAP_INT_DIV_4 = (short) (TRAP_INT_DIV + 4);
        public static final short TRAP_INT_DIV_COMPLETE = TRAP_INT_DIV;
    
        public static final short TRAP_INT_EXP = (short) 0x7640;
        public static final short TRAP_INT_EXP_1 = (short) (TRAP_INT_EXP + 1);
        public static final short TRAP_INT_EXP_2 = (short) (TRAP_INT_EXP + 2);
        public static final short TRAP_INT_EXP_3 = (short) (TRAP_INT_EXP + 3);
        public static final short TRAP_INT_EXP_4 = (short) (TRAP_INT_EXP + 4);
        public static final short TRAP_INT_EXP_COMPLETE = TRAP_INT_EXP;
    
        public static final short TRAP_INT_MOD = (short) 0x7630;
        public static final short TRAP_INT_MOD_1 = (short) (TRAP_INT_MOD + 1);
        public static final short TRAP_INT_MOD_2 = (short) (TRAP_INT_MOD + 2);
        public static final short TRAP_INT_MOD_3 = (short) (TRAP_INT_MOD + 3);
        public static final short TRAP_INT_MOD_4 = (short) (TRAP_INT_MOD + 4);
        public static final short TRAP_INT_MOD_COMPLETE = TRAP_INT_MOD;    
        
        public static final short TRAP_BN_POW2_MOD = (short) 0x7620;
        public static final short TRAP_BN_POW2_MOD_1 = (short) (TRAP_BN_POW2_MOD + 1);
        public static final short TRAP_BN_POW2_MOD_2 = (short) (TRAP_BN_POW2_MOD + 2);
        public static final short TRAP_BN_POW2_MOD_3 = (short) (TRAP_BN_POW2_MOD + 3);
        public static final short TRAP_BN_POW2_COMPLETE = TRAP_BN_POW2_MOD;
        
        
        // 7610-7600 unused
        
        public static final short TRAP_ECCURVE_NEWKEYPAIR = (short) 0x75f0;
        public static final short TRAP_ECCURVE_NEWKEYPAIR_1 = (short) (TRAP_ECCURVE_NEWKEYPAIR + 1);
        public static final short TRAP_ECCURVE_NEWKEYPAIR_2 = (short) (TRAP_ECCURVE_NEWKEYPAIR + 2);
        public static final short TRAP_ECCURVE_NEWKEYPAIR_3 = (short) (TRAP_ECCURVE_NEWKEYPAIR + 3);
        public static final short TRAP_ECCURVE_NEWKEYPAIR_4 = (short) (TRAP_ECCURVE_NEWKEYPAIR + 4);
        public static final short TRAP_ECCURVE_NEWKEYPAIR_5 = (short) (TRAP_ECCURVE_NEWKEYPAIR + 5);
        public static final short TRAP_ECCURVE_NEWKEYPAIR_6 = (short) (TRAP_ECCURVE_NEWKEYPAIR + 6);
        public static final short TRAP_ECCURVE_NEWKEYPAIR_7 = (short) (TRAP_ECCURVE_NEWKEYPAIR + 7);
        public static final short TRAP_ECCURVE_NEWKEYPAIR_COMPLETE = TRAP_ECCURVE_NEWKEYPAIR;
    
        public static final short TRAP_ECPOINT_ADD = (short) 0x75e0;
        public static final short TRAP_ECPOINT_ADD_1 = (short) (TRAP_ECPOINT_ADD + 1);
        public static final short TRAP_ECPOINT_ADD_2 = (short) (TRAP_ECPOINT_ADD + 2);
        public static final short TRAP_ECPOINT_ADD_3 = (short) (TRAP_ECPOINT_ADD + 3);
        public static final short TRAP_ECPOINT_ADD_4 = (short) (TRAP_ECPOINT_ADD + 4);
        public static final short TRAP_ECPOINT_ADD_5 = (short) (TRAP_ECPOINT_ADD + 5);
        public static final short TRAP_ECPOINT_ADD_6 = (short) (TRAP_ECPOINT_ADD + 6);
        public static final short TRAP_ECPOINT_ADD_7 = (short) (TRAP_ECPOINT_ADD + 7);
        public static final short TRAP_ECPOINT_ADD_8 = (short) (TRAP_ECPOINT_ADD + 8);
        public static final short TRAP_ECPOINT_ADD_9 = (short) (TRAP_ECPOINT_ADD + 9);
        public static final short TRAP_ECPOINT_ADD_10 = (short) (TRAP_ECPOINT_ADD + 10);
        public static final short TRAP_ECPOINT_ADD_11 = (short) (TRAP_ECPOINT_ADD + 11);
        public static final short TRAP_ECPOINT_ADD_12 = (short) (TRAP_ECPOINT_ADD + 12);
        public static final short TRAP_ECPOINT_ADD_13 = (short) (TRAP_ECPOINT_ADD + 13);
        public static final short TRAP_ECPOINT_ADD_COMPLETE = TRAP_ECPOINT_ADD;
    
        public static final short TRAP_ECPOINT_MULT = (short) 0x75d0;
        public static final short TRAP_ECPOINT_MULT_1 = (short) (TRAP_ECPOINT_MULT + 1);
        public static final short TRAP_ECPOINT_MULT_2 = (short) (TRAP_ECPOINT_MULT + 2);
        public static final short TRAP_ECPOINT_MULT_3 = (short) (TRAP_ECPOINT_MULT + 3);
        public static final short TRAP_ECPOINT_MULT_4 = (short) (TRAP_ECPOINT_MULT + 4);
        public static final short TRAP_ECPOINT_MULT_5 = (short) (TRAP_ECPOINT_MULT + 5);
        public static final short TRAP_ECPOINT_MULT_6 = (short) (TRAP_ECPOINT_MULT + 6);
        public static final short TRAP_ECPOINT_MULT_7 = (short) (TRAP_ECPOINT_MULT + 7);
        public static final short TRAP_ECPOINT_MULT_8 = (short) (TRAP_ECPOINT_MULT + 8);
        public static final short TRAP_ECPOINT_MULT_9 = (short) (TRAP_ECPOINT_MULT + 9);
        public static final short TRAP_ECPOINT_MULT_10 = (short) (TRAP_ECPOINT_MULT + 10);
        public static final short TRAP_ECPOINT_MULT_11 = (short) (TRAP_ECPOINT_MULT + 11);
        public static final short TRAP_ECPOINT_MULT_12 = (short) (TRAP_ECPOINT_MULT + 12);
        public static final short TRAP_ECPOINT_MULT_COMPLETE = TRAP_ECPOINT_MULT;    
        
        public static final short TRAP_ECPOINT_MULT_X = (short) 0x75c0;
        public static final short TRAP_ECPOINT_MULT_X_1 = (short) (TRAP_ECPOINT_MULT_X + 1);
        public static final short TRAP_ECPOINT_MULT_X_2 = (short) (TRAP_ECPOINT_MULT_X + 2);
        public static final short TRAP_ECPOINT_MULT_X_3 = (short) (TRAP_ECPOINT_MULT_X + 3);
        public static final short TRAP_ECPOINT_MULT_X_4 = (short) (TRAP_ECPOINT_MULT_X + 4);
        public static final short TRAP_ECPOINT_MULT_X_5 = (short) (TRAP_ECPOINT_MULT_X + 5);
        public static final short TRAP_ECPOINT_MULT_X_COMPLETE = TRAP_ECPOINT_MULT_X;
    
        public static final short TRAP_ECPOINT_NEGATE = (short) 0x75b0;
        public static final short TRAP_ECPOINT_NEGATE_1 = (short) (TRAP_ECPOINT_NEGATE + 1);
        public static final short TRAP_ECPOINT_NEGATE_2 = (short) (TRAP_ECPOINT_NEGATE + 2);
        public static final short TRAP_ECPOINT_NEGATE_3 = (short) (TRAP_ECPOINT_NEGATE + 3);
        public static final short TRAP_ECPOINT_NEGATE_4 = (short) (TRAP_ECPOINT_NEGATE + 4);
        public static final short TRAP_ECPOINT_NEGATE_5 = (short) (TRAP_ECPOINT_NEGATE + 5);
        public static final short TRAP_ECPOINT_NEGATE_COMPLETE = TRAP_ECPOINT_NEGATE;    
                
        public static final short TRAP_BIGNAT_SQRT = (short) 0x75a0;
        public static final short TRAP_BIGNAT_SQRT_1 = (short) (TRAP_BIGNAT_SQRT + 1);
        public static final short TRAP_BIGNAT_SQRT_2 = (short) (TRAP_BIGNAT_SQRT + 2);
        public static final short TRAP_BIGNAT_SQRT_3 = (short) (TRAP_BIGNAT_SQRT + 3);
        public static final short TRAP_BIGNAT_SQRT_4 = (short) (TRAP_BIGNAT_SQRT + 4);
        public static final short TRAP_BIGNAT_SQRT_5 = (short) (TRAP_BIGNAT_SQRT + 5);
        public static final short TRAP_BIGNAT_SQRT_6 = (short) (TRAP_BIGNAT_SQRT + 6);
        public static final short TRAP_BIGNAT_SQRT_7 = (short) (TRAP_BIGNAT_SQRT + 7);
        public static final short TRAP_BIGNAT_SQRT_8 = (short) (TRAP_BIGNAT_SQRT + 8);
        public static final short TRAP_BIGNAT_SQRT_9 = (short) (TRAP_BIGNAT_SQRT + 9);
        public static final short TRAP_BIGNAT_SQRT_10 = (short) (TRAP_BIGNAT_SQRT + 10);
        public static final short TRAP_BIGNAT_SQRT_11 = (short) (TRAP_BIGNAT_SQRT + 11);
        public static final short TRAP_BIGNAT_SQRT_12 = (short) (TRAP_BIGNAT_SQRT + 12);
        public static final short TRAP_BIGNAT_SQRT_13 = (short) (TRAP_BIGNAT_SQRT + 13);
        public static final short TRAP_BIGNAT_SQRT_14 = (short) (TRAP_BIGNAT_SQRT + 14);
        public static final short TRAP_BIGNAT_SQRT_15 = (short) (TRAP_BIGNAT_SQRT + 15);
        public static final short TRAP_BIGNAT_SQRT_COMPLETE = TRAP_BIGNAT_SQRT;
        
        
        public static final short TRAP_EC_SETCURVE = (short) 0x7590;
        public static final short TRAP_EC_SETCURVE_1 = (short) (TRAP_EC_SETCURVE + 1);
        public static final short TRAP_EC_SETCURVE_2 = (short) (TRAP_EC_SETCURVE + 2);
        public static final short TRAP_EC_SETCURVE_COMPLETE = TRAP_EC_SETCURVE;
    
        
        public static void check(short stopCondition) {
            if (PM.m_perfStop == stopCondition) {
                ISOException.throwIt(stopCondition);
            }
        }
    }
    
    
    /**
     *
     * @author Petr Svenda
     */
    public static class ResourceManager {
        /**
         * Object responsible for logical locking and unlocking of shared arrays and
         * objects
         */
        public ObjectLocker locker = null;
        /**
         * Object responsible for easy management of target placement (RAM/EEPROM)
         * fro allocated objects
         */
        public ObjectAllocator memAlloc = null;
        
        
        
        // Allocated arrays
        byte[] helper_BN_array1 = null;
        byte[] helper_BN_array2 = null;
        byte[] helper_uncompressed_point_arr1 = null;
        byte[] helper_hashArray = null;
        /**
         * Number of pre-allocated helper arrays
         */
        public static final byte NUM_HELPER_ARRAYS = 4;
    
        MessageDigest hashEngine;
        public static final byte NUM_SHARED_HELPER_OBJECTS = 1;
        
    
        // These Bignats helper_BN_? are allocated
        Bignat helper_BN_A;
        Bignat helper_BN_B;
        Bignat helper_BN_C;
        Bignat helper_BN_D;
        Bignat helper_BN_E;
        Bignat helper_BN_F;
    
        // These Bignats helperEC_BN_? are allocated
        Bignat helperEC_BN_A;
        Bignat helperEC_BN_B;
        Bignat helperEC_BN_C;
        Bignat helperEC_BN_D;
        Bignat helperEC_BN_E;
        Bignat helperEC_BN_F;
        
        public void initialize(short MAX_POINT_SIZE, short MAX_COORD_SIZE, short MAX_BIGNAT_SIZE, short MULT_RSA_ENGINE_MAX_LENGTH_BITS, Bignat_Helper bnh) {
            // Allocate long-term helper values
            locker = new ObjectLocker((short) (NUM_HELPER_ARRAYS + NUM_SHARED_HELPER_OBJECTS));
            //locker.setLockingActive(false); // if required, locking can be disabled
            memAlloc = new ObjectAllocator();
            memAlloc.setAllAllocatorsRAM();
            //if required, memory for helper objects and arrays can be in persistent memory to save RAM (or some tradeoff)       
            //ObjectAllocator.setAllAllocatorsEEPROM();  //ObjectAllocator.setAllocatorsTradeoff();
            
    
            // Multiplication speedup engines and arrays used by Bignat.mult_RSATrick()
            helper_BN_array1 = memAlloc.allocateByteArray((short) (MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_array1));
            locker.registerLock(helper_BN_array1);
            helper_BN_array2 = memAlloc.allocateByteArray((short) (MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_array2));
            locker.registerLock(helper_BN_array2);
            helper_uncompressed_point_arr1 = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.ECPH_uncompressed_point_arr1));
            locker.registerLock(helper_uncompressed_point_arr1);
            hashEngine = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            helper_hashArray = memAlloc.allocateByteArray(hashEngine.getLength(), memAlloc.getAllocatorType(ObjectAllocator.ECPH_hashArray));
            locker.registerLock(helper_hashArray);
            //locker.registerLock(hashEngine); // register hash engine to slightly speedup search for locked objects (hash engine used less frequently)
            
            
            helper_BN_A = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_A), bnh);
            helper_BN_B = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_B), bnh);
            helper_BN_C = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_C), bnh);
            helper_BN_D = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_D), bnh);
            helper_BN_E = new Bignat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_E), bnh);
            helper_BN_F = new Bignat((short) (MAX_BIGNAT_SIZE + 2), memAlloc.getAllocatorType(ObjectAllocator.BNH_helper_BN_F), bnh); // +2 is to correct for infrequent RSA result with two or more leading zeroes 
            
            helperEC_BN_A = new Bignat(MAX_POINT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_A), bnh);
            helperEC_BN_B = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_B), bnh);
            helperEC_BN_C = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_C), bnh);
            helperEC_BN_D = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_D), bnh);
            helperEC_BN_E = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_E), bnh);
            helperEC_BN_F = new Bignat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.ECPH_helperEC_BN_F), bnh);
            
            
        }
        
        /**
         * Erase all values stored in helper objects
         */
        void erase() {
            helper_BN_A.erase();
            helper_BN_B.erase();
            helper_BN_C.erase();
            helper_BN_D.erase();
            helper_BN_E.erase();
            helper_BN_F.erase();
            
            helperEC_BN_A.erase();
            helperEC_BN_B.erase();
            helperEC_BN_C.erase();
            helperEC_BN_D.erase();
            helperEC_BN_E.erase();
            helperEC_BN_F.erase();
            
    
            Util.arrayFillNonAtomic(helper_BN_array1, (short) 0, (short) helper_BN_array1.length, (byte) 0);
            Util.arrayFillNonAtomic(helper_BN_array2, (short) 0, (short) helper_BN_array2.length, (byte) 0);
            Util.arrayFillNonAtomic(helper_uncompressed_point_arr1, (short) 0, (short) helper_uncompressed_point_arr1.length, (byte) 0);
        }    
        
        /**
         * Unlocks all helper objects
         */
        public void unlockAll() {
            if (helper_BN_A.isLocked()) {
                helper_BN_A.unlock();
            }
            if (helper_BN_B.isLocked()) {
                helper_BN_B.unlock();
            }
            if (helper_BN_C.isLocked()) {
                helper_BN_C.unlock();
            }
            if (helper_BN_D.isLocked()) {
                helper_BN_D.unlock();
            }
            if (helper_BN_E.isLocked()) {
                helper_BN_E.unlock();
            }
            if (helper_BN_F.isLocked()) {
                helper_BN_F.unlock();
            }
    
            if (helperEC_BN_A.isLocked()) {
                helperEC_BN_A.unlock();
            }
            if (helperEC_BN_B.isLocked()) {
                helperEC_BN_B.unlock();
            }
            if (helperEC_BN_C.isLocked()) {
                helperEC_BN_C.unlock();
            }
            if (helperEC_BN_D.isLocked()) {
                helperEC_BN_D.unlock();
            }
            if (helperEC_BN_E.isLocked()) {
                helperEC_BN_E.unlock();
            }
            if (helperEC_BN_F.isLocked()) {
                helperEC_BN_F.unlock();
            }
            if (locker.isLocked(helper_uncompressed_point_arr1)) {
                locker.unlock(helper_uncompressed_point_arr1);
            }
            if (locker.isLocked(helper_hashArray)) {
                locker.unlock(helper_hashArray);
            }
            
        }    
    }
    
    /**
     *
    * @author Vasilios Mavroudis and Petr Svenda
     */
    public static class ReturnCodes {
        // Custom error response codes
        public static final short SW_BIGNAT_RESIZETOLONGER          = (short) 0x7000;
        public static final short SW_BIGNAT_REALLOCATIONNOTALLOWED  = (short) 0x7001;
        public static final short SW_BIGNAT_MODULOTOOLARGE          = (short) 0x7002;
        public static final short SW_BIGNAT_INVALIDCOPYOTHER        = (short) 0x7003;
        public static final short SW_BIGNAT_INVALIDRESIZE           = (short) 0x7004;
        public static final short SW_LOCK_ALREADYLOCKED             = (short) 0x7005;
        public static final short SW_LOCK_NOTLOCKED                 = (short) 0x7006;
        public static final short SW_LOCK_OBJECT_NOT_FOUND          = (short) 0x7007;
        public static final short SW_LOCK_NOFREESLOT                = (short) 0x7008;
        public static final short SW_LOCK_OBJECT_MISMATCH           = (short) 0x7009;
        public static final short SW_ECPOINT_INVALIDLENGTH          = (short) 0x700a;
        public static final short SW_ECPOINT_UNEXPECTED_KA_LEN      = (short) 0x700b;
        public static final short SW_ALLOCATOR_INVALIDOBJID         = (short) 0x700c;
        
        
        // Specific codes to propagate exceptions cought 
        // lower byte of exception is value as defined in JCSDK/api_classic/constant-values.htm
        public final static short SW_Exception                      = (short) 0xff01;
        public final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
        public final static short SW_ArithmeticException            = (short) 0xff03;
        public final static short SW_ArrayStoreException            = (short) 0xff04;
        public final static short SW_NullPointerException           = (short) 0xff05;
        public final static short SW_NegativeArraySizeException     = (short) 0xff06;
        public final static short SW_CryptoException_prefix         = (short) 0xf100;
        public final static short SW_SystemException_prefix         = (short) 0xf200;
        public final static short SW_PINException_prefix            = (short) 0xf300;
        public final static short SW_TransactionException_prefix    = (short) 0xf400;
        public final static short SW_CardRuntimeException_prefix    = (short) 0xf500;
    }
    
    public static class SecP256k1 {
    
        public final static short KEY_LENGTH = 256; // Bits
        public final static short POINT_SIZE = 65; // Bytes
        public final static short COORD_SIZE = 32; // Bytes
    
        public final static byte[] p = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
                (byte) 0xff, (byte) 0xff, (byte) 0xfc, (byte) 0x2f
        };
    
        public final static byte[] a = {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
    
        public final static byte[] b = {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07
        };
    
        public final static byte[] G = {
                (byte) 0x04,
                (byte) 0x79, (byte) 0xbe, (byte) 0x66, (byte) 0x7e,
                (byte) 0xf9, (byte) 0xdc, (byte) 0xbb, (byte) 0xac,
                (byte) 0x55, (byte) 0xa0, (byte) 0x62, (byte) 0x95,
                (byte) 0xce, (byte) 0x87, (byte) 0x0b, (byte) 0x07,
                (byte) 0x02, (byte) 0x9b, (byte) 0xfc, (byte) 0xdb,
                (byte) 0x2d, (byte) 0xce, (byte) 0x28, (byte) 0xd9,
                (byte) 0x59, (byte) 0xf2, (byte) 0x81, (byte) 0x5b,
                (byte) 0x16, (byte) 0xf8, (byte) 0x17, (byte) 0x98,
                (byte) 0x48, (byte) 0x3a, (byte) 0xda, (byte) 0x77,
                (byte) 0x26, (byte) 0xa3, (byte) 0xc4, (byte) 0x65,
                (byte) 0x5d, (byte) 0xa4, (byte) 0xfb, (byte) 0xfc,
                (byte) 0x0e, (byte) 0x11, (byte) 0x08, (byte) 0xa8,
                (byte) 0xfd, (byte) 0x17, (byte) 0xb4, (byte) 0x48,
                (byte) 0xa6, (byte) 0x85, (byte) 0x54, (byte) 0x19,
                (byte) 0x9c, (byte) 0x47, (byte) 0xd0, (byte) 0x8f,
                (byte) 0xfb, (byte) 0x10, (byte) 0xd4, (byte) 0xb8
        };
    
        public final static byte[] r = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
                (byte) 0xba, (byte) 0xae, (byte) 0xdc, (byte) 0xe6,
                (byte) 0xaf, (byte) 0x48, (byte) 0xa0, (byte) 0x3b,
                (byte) 0xbf, (byte) 0xd2, (byte) 0x5e, (byte) 0x8c,
                (byte) 0xd0, (byte) 0x36, (byte) 0x41, (byte) 0x41,
        };
    }
    
    public static class SecP256r1 {
    
        public final static short KEY_LENGTH = 256;//Bits
        public final static short POINT_SIZE = 65; //Bytes
        public final static short COORD_SIZE = 32; //Bytes
    
        public final static byte[] p = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
    
    
        public final static byte[] a = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc};
    
        public final static byte[] b = { 0x5a, (byte) 0xc6, 0x35, (byte) 0xd8, (byte) 0xaa, 0x3a,
                (byte) 0x93, (byte) 0xe7, (byte) 0xb3, (byte) 0xeb, (byte) 0xbd, 0x55, 0x76, (byte) 0x98,
                (byte) 0x86, (byte) 0xbc, 0x65, 0x1d, 0x06, (byte) 0xb0, (byte) 0xcc, 0x53, (byte) 0xb0,
                (byte) 0xf6, 0x3b, (byte) 0xce, 0x3c, 0x3e, 0x27, (byte) 0xd2, 0x60, 0x4b };
    
        public final static byte[] G = { 0x04, 0x6b, 0x17, (byte) 0xd1, (byte) 0xf2, (byte) 0xe1, 0x2c,
                0x42, 0x47, (byte) 0xf8, (byte) 0xbc, (byte) 0xe6, (byte) 0xe5, 0x63, (byte) 0xa4, 0x40,
                (byte) 0xf2, 0x77, 0x03, 0x7d, (byte) 0x81, 0x2d, (byte) 0xeb, 0x33, (byte) 0xa0, (byte) 0xf4,
                (byte) 0xa1, 0x39, 0x45, (byte) 0xd8, (byte) 0x98, (byte) 0xc2, (byte) 0x96, 0x4f, (byte) 0xe3,
                0x42, (byte) 0xe2, (byte) 0xfe, 0x1a, 0x7f, (byte) 0x9b, (byte) 0x8e, (byte) 0xe7, (byte) 0xeb,
                0x4a, 0x7c, 0x0f, (byte) 0x9e, 0x16, 0x2b, (byte) 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                (byte) 0xce, (byte) 0xcb, (byte) 0xb6, 0x40, 0x68, 0x37, (byte) 0xbf, 0x51, (byte) 0xf5 };
    
        public final static byte[] r = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00, 0x00,
                0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xbc, (byte) 0xe6, (byte) 0xfa, (byte) 0xad, (byte) 0xa7, 0x17, (byte) 0x9e,
                (byte) 0x84, (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2, (byte) 0xfc, 0x63, 0x25, 0x51 };
    }
}
