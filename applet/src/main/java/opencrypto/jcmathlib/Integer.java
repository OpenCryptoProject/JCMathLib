package opencrypto.jcmathlib;

import javacard.framework.JCSystem;

/**
 * @author Vasilios Mavroudis and Petr Svenda, modified by Veronika Hanulikova
 */
public class Integer {
    private ResourceManager rm;
    private BigNat magnitude;
    private byte sign;

    /**
     * Allocates integer with provided length and sets to zero.
     *
     * @param size Integer size
     * @param rm ResourceManager with all supporting objects
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
     * @param rm          ResourceManager with all supporting objects
     */
    public Integer(byte[] value, short valueOffset, short length, ResourceManager rm) {
        allocate(length, (value[valueOffset] == (byte) 0x00) ? (byte) 0 : (byte) 1, value, (short) (valueOffset + 1), rm);
    }

    /**
     * Allocates integer from provided array with explicit sign. No sign is expected in provided array.
     *
     * @param sign  sign of integer
     * @param value array with initial value
     * @param rm    ResourceManager with all supporting objects
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
        rm.lock(rm.ARRAY_A);
        short len = magnitude.copyToByteArray(rm.ARRAY_A, (short) 0);
        allocate(len, other.getSign(), rm.ARRAY_A, (short) 0, other.rm);
        rm.unlock(rm.ARRAY_A);
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
            rm.lock(rm.ARRAY_A);
            short len = magnitude.copyToByteArray(rm.ARRAY_A, (short) 0);
            allocate(len, sign, rm.ARRAY_A, (short) 0, rm);
            rm.unlock(rm.ARRAY_A);
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
            mag.fromByteArray(fromArray, fromArrayOffset, size);
        }
        initialize(sign, mag, this.rm);
    }

    /**
     * Clone value into this Integer from other Integer. Updates size of integer.
     *
     * @param other other integer to copy from
     */
    public void ctClone(Integer other) {
        this.sign = other.getSign();
        this.magnitude.ctCopy(other.getMagnitude());
    }

    /**
     * set this integer to zero
     */
    public void ctZero() {
        this.sign = (short) 0;
        this.magnitude.ctZero();
    }

    public void ctZero(short maskOp) {
        this.sign = ConstantTime.ctSelect(maskOp, this.sign, (byte) 0);
        this.magnitude.ctZero(maskOp);
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
    public void ctSetSize(short newSize) {
        this.magnitude.ctSetSize(newSize);
    }

    /**
     * Compute negation of this integer
     */
    public void ctNegate() {
        short positive = this.ctIsPositive();
        short negative = this.ctIsNegative();
        byte oldSign = this.sign;
        byte newSign = (byte) ConstantTime.ctSelect(positive, (short) 1, oldSign);
        newSign = (byte) ConstantTime.ctSelect(negative, (short) 0, newSign);
        this.setSign(newSign);
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

    public void ctSetMagnitude(Integer other) {
        this.magnitude.ctCopy(other.getMagnitude());
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
        magnitude.copyToByteArray(outBuffer, (short) (outBufferOffset + 1));
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
        this.magnitude.fromByteArray(value, (short) (valueOffset + 1), (short) (valueLength - 1));
    }

    /**
     * Return true if integer is negative.
     *
     * @return 0xffff if integer is negative, 0x0000 otherwise
     */
    public short ctIsNegative() {
        return ConstantTime.ctEqual(this.sign, (short) 1);
    }

    /**
     * Return true if integer is positive.
     *
     * @return 0xffff if integer is negative, 0x0000 otherwise
     */
    public short ctIsPositive() {
        return ConstantTime.ctIsZero(this.sign);
    }

    /**
     * Compares two integers. Return true, if this is smaller than other.
     *
     * @param other other integer to compare
     * @return true, if this is strictly smaller than other. False otherwise.
     */
    public short ctLesser(Integer other) {
        // this.sign == 1 && other.sign == 0
        short thisNegativeOtherPositive = (short) (this.ctIsNegative() & other.ctIsPositive());
        // this.sign == 0 && other.sign == 1
        short thisPositiveOtherNegative = (short) (this.ctIsPositive() & other.ctIsNegative());
        // this.sign == 0 && other.sign == 0
        short bothPositive = (short) (this.ctIsPositive() & other.ctIsPositive());
        // this.sign == 1 && other.sign==1
        short bothNegative = (short) (this.ctIsNegative() & other.ctIsNegative());
        // only one actual comparison of the base
        short isLesser = this.magnitude.ctIsLesser(other.magnitude);
        // combine results together
        short result = ConstantTime.ctSelect(thisNegativeOtherPositive, (short) 0xffff, (short) 0);
        result = ConstantTime.ctSelect(thisPositiveOtherNegative, (short) 0, result);
        result = ConstantTime.ctSelect(bothPositive, isLesser, result);
        result = ConstantTime.ctSelect(bothNegative,  (short) (~isLesser), result);
        return result;
    }

    /**
     * Add other integer to this and store result into this.
     *
     * @param other other integer to add
     */
    public void ctAdd(Integer other) {
        BigNat tmp = rm.BN_A;

        short thisNegativeOtherPositive = (short) (this.ctIsNegative() & other.ctIsPositive()); // true
        short thisPositiveOtherNegative = (short) (this.ctIsPositive() & other.ctIsNegative()); // false
        short bothPositive = (short) (this.ctIsPositive() & other.ctIsPositive());
        short bothNegative = (short) (this.ctIsNegative() & other.ctIsNegative());
        short otherLesser = other.getMagnitude().ctIsLesser(this.getMagnitude());
        short thisLesser = this.getMagnitude().ctIsLesser(other.getMagnitude());
        short oppositeSignEqual = (short) ((thisPositiveOtherNegative | thisNegativeOtherPositive) & (~otherLesser & ~thisLesser));
        short thisPositiveLargerThanOtherNegative = (short) (thisPositiveOtherNegative & otherLesser);
        short thisNegativeLargerThanOtherPositive = (short) (thisNegativeOtherPositive & otherLesser);
        short thisPositiveSmallerThanOtherNegative = (short) (thisPositiveOtherNegative & thisLesser);
        short thisNegativeSmallerThanOtherPositive = (short) (thisNegativeOtherPositive & thisLesser);

        /* Set sign */
        byte newSign = ConstantTime.ctSelect((byte) (bothPositive | thisPositiveLargerThanOtherNegative | thisNegativeSmallerThanOtherPositive | oppositeSignEqual), (byte) 0, this.sign);
        newSign = ConstantTime.ctSelect((byte) (bothNegative | thisNegativeLargerThanOtherPositive | thisPositiveSmallerThanOtherNegative), (byte) 1,newSign);

        /* Perform subtraction or addition according the signs*/
        this.magnitude.ctAdd(other.magnitude, (short) (~bothNegative & ~bothPositive));
        this.magnitude.ctSubtract(other.magnitude, (short) (~thisNegativeLargerThanOtherPositive & ~thisPositiveLargerThanOtherNegative & ~oppositeSignEqual));

        /* Perform number switch according to signs */
        tmp.lock();
        tmp.ctClone(other.getMagnitude());
        tmp.ctSubtract(this.magnitude);
        this.magnitude.ctCopy(tmp, (short) (~thisNegativeSmallerThanOtherPositive & ~thisPositiveSmallerThanOtherNegative));
        tmp.unlock();

        setSign(newSign);
    }

    public void ctAddOptimized(Integer other) {
        BigNat tmp = rm.BN_A;

        short thisNegativeOtherPositive = (short) (this.ctIsNegative() & other.ctIsPositive()); // true
        short thisPositiveOtherNegative = (short) (this.ctIsPositive() & other.ctIsNegative()); // false
        short bothPositive = (short) (this.ctIsPositive() & other.ctIsPositive());
        short bothNegative = (short) (this.ctIsNegative() & other.ctIsNegative());
        short otherLesser = other.getMagnitude().ctIsLesser(this.getMagnitude());
        short thisLesser = this.getMagnitude().ctIsLesser(other.getMagnitude());
        short oppositeSignEqual = (short) ((thisPositiveOtherNegative | thisNegativeOtherPositive) & (~otherLesser & ~thisLesser));
        short thisPositiveLargerThanOtherNegative = (short) (thisPositiveOtherNegative & otherLesser);
        short thisNegativeLargerThanOtherPositive = (short) (thisNegativeOtherPositive & otherLesser);
        short thisPositiveSmallerThanOtherNegative = (short) (thisPositiveOtherNegative & thisLesser);
        short thisNegativeSmallerThanOtherPositive = (short) (thisNegativeOtherPositive & thisLesser);

        /* Set sign */
        byte newSign = ConstantTime.ctSelect((byte) (bothPositive | thisPositiveLargerThanOtherNegative | thisNegativeSmallerThanOtherPositive | oppositeSignEqual), (byte) 0, this.sign);
        newSign = ConstantTime.ctSelect((byte) (bothNegative | thisNegativeLargerThanOtherPositive | thisPositiveSmallerThanOtherNegative), (byte) 1,newSign);

        short opAdd = (short) (bothNegative | bothPositive);
        short opSub = (short) (thisNegativeLargerThanOtherPositive | thisPositiveLargerThanOtherNegative | oppositeSignEqual);
        short operation = (short) ((opAdd & (short) 0xFFFF) | ((opSub ^ (short) 0xFFFF) & (short) 0xFFFF));
        /* Remove one unneeded operation by compressing two ops into one cycle processing*/
        this.magnitude.ctAddSubtract(other.magnitude, operation, (short) (~opAdd & ~opSub));

        /* Perform number switch according to signs */
        tmp.lock();
        tmp.ctClone(other.getMagnitude());
        tmp.ctSubtract(this.magnitude);
        this.magnitude.ctCopy(tmp, (short) (~thisNegativeSmallerThanOtherPositive & ~thisPositiveSmallerThanOtherNegative));
        tmp.unlock();

        setSign(newSign);
    }

    /**
     * Substract other integer from this and store result into this.
     *
     * @param other other integer to substract
     */
    public void ctSubtract(Integer other) {
        other.ctNegate();
        this.ctAdd(other);
        other.ctNegate();
    }

    /**
     * Multiply this and other integer and store result into this.
     *
     * @param other other integer to multiply
     */
    public void ctMultiply(Integer other) {
        BigNat tmp = rm.BN_B;

        short thisPositiveOtherNegative = (short) (this.ctIsPositive() & other.ctIsNegative());
        short thisNegativeotherPositive = (short) (this.ctIsNegative() & other.ctIsPositive());
        byte newSign = ConstantTime.ctSelect((short) (thisPositiveOtherNegative & thisNegativeotherPositive), (byte) 1, (byte) 0);
        this.setSign(newSign);

        tmp.lock();
        tmp.ctClone(this.magnitude);
        tmp.ctMult(other.getMagnitude());
        this.magnitude.ctCopy(tmp);
        tmp.unlock();
    }

    /**
     * Divide this by other integer and store result into this.
     *
     * @param other divisor
     */
    public void ctDivide(Integer other) {
        BigNat tmp = rm.BN_A;

        short thisPositiveOtherNegative = (short) (this.ctIsPositive() & other.ctIsNegative());
        short thisNegativeotherPositive = (short) (this.ctIsNegative() & other.ctIsPositive());
        byte newSign = ConstantTime.ctSelect((short) (thisPositiveOtherNegative & thisNegativeotherPositive), (byte) 1, (byte) 0);
        this.setSign(newSign);

        tmp.lock();
        tmp.ctClone(this.magnitude);
        tmp.ctRemainderDivideOptimized(other.getMagnitude(), this.magnitude);
        tmp.unlock();
    }

    /**
     * Computes modulo of this by other integer and store result into this.
     *
     * @param other modulus
     */
    public void ctModulo(Integer other) {
        this.magnitude.ctMod(other.getMagnitude());
    }
}