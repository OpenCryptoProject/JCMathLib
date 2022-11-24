package opencrypto.jcmathlib;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class Integer {
    private ResourceManager rm;
    private BigNat magnitude;
    private byte sign;

    /**
     * Allocates integer with provided length and sets to zero.
     *
     * @param size
     * @param bnh  Bignat_Helper with all supporting objects
     */
    public Integer(short size, ResourceManager rm) {
        allocate(size, (byte) 0, null, (byte) -1, rm);
    }

    /**
     * Allocates integer from provided buffer and initialize by provided value.
     * Sign is expected as first byte of value.
     *
     * @param value       array with initial value
     * @param valueOffset start offset within   value
     * @param length      length of array
     * @param bnh         BignatHelper with all supporting objects
     */
    public Integer(byte[] value, short valueOffset, short length, ResourceManager rm) {
        allocate(length, (value[valueOffset] == (byte) 0x00) ? (byte) 0 : (byte) 1, value, (short) (valueOffset + 1), rm);
    }

    /**
     * Allocates integer from provided array with explicit sign. No sign is expected in provided array.
     *
     * @param sign  sign of integer
     * @param value array with initial value
     * @param bnh   Bignat_Helper with all supporting objects
     */
    public Integer(byte sign, byte[] value, ResourceManager rm) {
        allocate((short) value.length, sign, value, (short) 0, rm);
    }

    /**
     * Copy constructor of integer from other already existing value
     *
     * @param other integer to copy from
     */
    public Integer(Integer other) {
        allocate(other.getSize(), other.getSign(), other.getMagnitude_b(), (short) 0, other.rm);
    }

    /**
     * Creates integer from existing Bignat and provided sign. If required,
     * copy is performed, otherwise BigNat is used as magnitude.
     *
     * @param sign      sign of integer
     * @param magnitude initial magnitude
     * @param copy      if true, magnitude is directly used (no copy). If false, new storage array is allocated.
     */
    public Integer(byte sign, BigNat magnitude, boolean copy, ResourceManager rm) {
        if (copy) {
            // Copy from provided BigNat
            allocate(magnitude.length(), sign, magnitude.as_byte_array(), (short) 0, rm);
        } else {
            // Use directly provided BigNat as storage - no allocation
            initialize(sign, magnitude, rm);
        }
    }

    /**
     * Initialize integer object with provided sign and already allocated Bignat
     * as magnitude
     *
     * @param sign      sign of integer
     * @param bnStorage magnitude (object is directly used, no copy is performed)
     */
    private void initialize(byte sign, BigNat bnStorage, ResourceManager rm) {
        this.sign = sign;
        this.magnitude = bnStorage;
        this.rm = rm;
    }

    /**
     * Allocates and initializes Integer.
     *
     * @param size            length of integer
     * @param sign            sign of integer
     * @param fromArray       input array with initial value (copy of value is
     *                        performed)
     * @param fromArrayOffset start offset within fromArray
     */
    private void allocate(short size, byte sign, byte[] fromArray, short fromArrayOffset, ResourceManager rm) {
        this.rm = rm;
        BigNat mag = new BigNat(size, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.rm);
        if (fromArray != null) {
            mag.from_byte_array(size, (short) 0, fromArray, fromArrayOffset);
        }
        initialize(sign, mag, this.rm);
    }

    /**
     * Clone value into this Integer from other Integer. Updates size of integer.
     *
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
     *
     * @return current sign
     */
    public byte getSign() {
        return this.sign;
    }

    /**
     * Set sign of this integer
     *
     * @param s new sign
     */
    public void setSign(byte s) {
        this.sign = s;
    }

    /**
     * Return length (in bytes) of this integer
     *
     * @return length of this integer
     */
    public short getSize() {
        return this.magnitude.length();
    }

    /**
     * Set length of this integer
     *
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
     *
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
    public BigNat getMagnitude() {
        return this.magnitude;
    }

    /**
     * Set magnitude of this integer from other one. Will not change this integer length.
     * No sign is copied from other.
     *
     * @param other other integer to copy from
     */
    public void setMagnitude(Integer other) {
        this.magnitude.copy(other.getMagnitude());
    }

    /**
     * Serializes this integer value into array. Sign is serialized as first byte
     *
     * @param outBuffer       output array
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
     *
     * @param value       array with value
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
     *
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
     *
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
     *
     * @param other other integer to add
     */
    public void add(Integer other) {
        BigNat tmp = rm.BN_A;

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
            } else if (this.isNegative() && other.getMagnitude().lesser(this.getMagnitude())) {    //this(-) has larger magnitude than other(+)
                this.sign = 1;
                this.magnitude.subtract(other.magnitude);
            } else if (this.isPositive() && this.getMagnitude().lesser(other.getMagnitude())) { //this(+) has smaller magnitude than other(-)
                this.sign = 1;
                tmp.lock();
                tmp.clone(other.getMagnitude());
                tmp.subtract(this.magnitude);
                this.magnitude.copy(tmp);
                tmp.unlock();
            } else if (this.isNegative() && this.getMagnitude().lesser(other.getMagnitude())) {  //this(-) has larger magnitude than other(+)
                this.sign = 0;
                tmp.lock();
                tmp.clone(other.getMagnitude());
                tmp.subtract(this.magnitude);
                this.magnitude.copy(tmp);
                tmp.unlock();
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
        BigNat mod = rm.BN_A;
        BigNat tmp = rm.BN_B;

        if (this.isPositive() && other.isNegative()) {
            this.setSign((byte) 1);
        } else if (this.isNegative() && other.isPositive()) {
            this.setSign((byte) 1);
        } else {
            this.setSign((byte) 0);
        }

        // Make mod BN as maximum value (positive, leading 0x80)
        mod.lock();
        mod.set_size(this.magnitude.length());
        mod.zero();
        mod.as_byte_array()[0] = (byte) 0x80;  // Max INT+1 Value

        tmp.lock();
        tmp.set_size(this.magnitude.length());
        tmp.mod_mult(this.getMagnitude(), other.getMagnitude(), mod);
        this.magnitude.copy(tmp);
        mod.unlock();
        tmp.unlock();
    }

    /**
     * Divide this by other integer and store result into this.
     *
     * @param other divisor
     */
    public void divide(Integer other) {
        BigNat tmp = rm.BN_A;

        if (this.isPositive() && other.isNegative()) {
            this.setSign((byte) 1);
        } else if (this.isNegative() && other.isPositive()) {
            this.setSign((byte) 1);
        } else {
            this.setSign((byte) 0);
        }

        tmp.lock();
        tmp.clone(this.magnitude);
        tmp.remainder_divide(other.getMagnitude(), this.magnitude);
        tmp.unlock();
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