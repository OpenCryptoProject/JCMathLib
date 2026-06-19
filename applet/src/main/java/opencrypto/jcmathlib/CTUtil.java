package opencrypto.jcmathlib;

/**
 * CTUtil class
 *
 * @author Veronika Hanulikova
 */
public class CTUtil {

    /**
     * Access to element of an array
     * @param array target array
     * @param length length of array
     * @param index index to be accessed
     * @return resulting byte, 0 if out of bounds
     */
    public static byte ctGet(byte[] array, short length, short index) {
        byte result = 0;
        for (short i = 0; i < length; i++) {
            byte mask = (byte) ConstantTime.ctEqual(i, index);
            result |= (array[i] & mask);
        }
        return result;
    }

    /**
     * Access to element of an array with boundary checking
     * @param array target array
     * @param length length of array
     * @param index index to be accessed
     * @return resulting byte, 0 if out of bounds
     */
    public static byte ctGetSafe(byte[] array, short length, short index) {
        byte result = 0;
        short problem = (short) (ConstantTime.ctIsNegative(index) | ConstantTime.ctGreaterOrEqual(index, length));
        if ((problem & (short) 0xffff) == (short) 0xffff)
            throw new ArrayIndexOutOfBoundsException();
        for (short i = 0; i < length; i++) {
            byte mask = (byte) ConstantTime.ctEqual(i, index);
            result |= (array[i] & mask);
        }
        return result;
    }

    /**
     * Set element in array
     * @param array target array
     * @param length length of array
     * @param index index to be accessed
     * @param value value to be set on given index
     */
    public static void ctSet(byte[] array, short length, short index, byte value) {
        for (short i = 0; i < length; i++) {
            byte mask = (byte) ConstantTime.ctEqual(i, index);
            array[i] = (byte) ((array[i] & ~mask) | (value & mask));
        }
    }

    /**
     * Set element in array, checking boundaries
     * @param array target array
     * @param length length of array
     * @param index index to be accessed
     * @param value value to be set on given index
     */
    public static void ctSetSafe(byte[] array, short length, short index, byte value) {
        short problem = (short) (ConstantTime.ctIsNegative(index) | ConstantTime.ctGreaterOrEqual(index, length));
        if ((problem & (short) 0xffff) == (short) 0xffff)
            throw new ArrayIndexOutOfBoundsException();
        for (short i = 0; i < length; i++) {
            byte mask = (byte) ConstantTime.ctEqual(i, index);
            array[i] = (byte) ((array[i] & ~mask) | (value & mask));
        }
    }

    /**
     * Get bit value on given position
     * @param array target array
     * @param length length of array
     * @param index index of bit position
     * @return bit value
     */
    public static byte ctGetBit(byte[] array, short length, short index) {
        short byteIndex = (short) (index >> 3); // bit / 8;
        short bitIndex = (short) (index & 7); // bit % 8
        byte result = array[(short)(length - 1 - byteIndex)];
        byte mask = (byte) (0x01 << bitIndex);
        result &= mask;
        result >>= bitIndex;
        return (byte) (result & 0x01);
    }

    /**
     * Set bit value on given position
     * @param array target array
     * @param length length of array
     * @param value value of bit to be set
     * @param index index of bit
     * @param maskOp if set to 0xffff, operation has no effect
     */
    public static void ctSetBit(byte[] array, short length, byte value, short index, short maskOp) {
        short byteIndex = (short) (index >> 3); // bit / 8;
        short bitIndex = (short) (index & 7); // bit % 8
        byte mask = (byte) (0x01 << bitIndex);
        short arrayIndex = (short) (length - 1 - byteIndex);
        array[arrayIndex] = (byte) ((array[arrayIndex] & ~mask) | (-value & mask) & ~maskOp);
    }

    /**
     * Set bit value on given position
     * @param array target array
     * @param length length of array
     * @param value value of bit to be set
     * @param index index of bit
     */
    public static void ctSetBit(byte[] array, short length, byte value, short index) {
        ctSetBit(array, length, value, index, (short) 0x00);
    }

    /**
     * Copies an array from the specified source array, beginning at the specified position, to the specified position of the destination array (non-atomically).
     * @param src source byte array
     * @param srcOff offset within source byte array to start copy from
     * @param dest destination byte array
     * @param destOff offset within destination byte array to start copy into
     * @param length byte length to be copied
     * @param maskOp perform blinded operation
     * @return  destOff+length
     * @implNote If srcOff or destOff or length parameter is negative an ArrayIndexOutOfBoundsException exception is thrown.
     * @implNote If srcOff+length is greater than src.length, the length of the src array a ArrayIndexOutOfBoundsException exception is thrown and no copy is performed.
     * @implNote If destOff+length is greater than dest.length, the length of the dest array an ArrayIndexOutOfBoundsException exception is thrown and no copy is performed.
     */
    public static short ctArrayCopyNonAtomic(byte[] src, short srcOff, byte[] dest, short destOff, short length, short maskOp) {
        if (src == null || dest == null)
            throw new NullPointerException();

        short error = (short) (ConstantTime.ctIsNegative(srcOff) | ConstantTime.ctIsNegative(destOff) | ConstantTime.ctIsNegative(length));
        error |= ConstantTime.ctGreater((short) (srcOff + length), (short) src.length)
                | ConstantTime.ctGreater((short) (destOff + length), (short) dest.length);
        if ((error & (short) 0xffff) == (short) 0xffff) {
            throw new ArrayIndexOutOfBoundsException();
        }

        short srcIndex = srcOff;
        for (short destIndex = 0; destIndex < dest.length; destIndex++) {
            short validDestRange = ConstantTime.ctGreaterOrEqual(destIndex, destOff); // after destination offset and before end of copied value
            validDestRange &= ConstantTime.ctLessThan(destIndex, (short) (destOff + length));
            short validSrcRange = ConstantTime.ctLessThan(srcIndex, (short) (src.length)); // before end of copied value
            short validSrcIndex = ConstantTime.ctSelect(validSrcRange, srcIndex, (short) 0);

            byte destValue = dest[destIndex]; // destination value can be read always
            byte srcValue = src[validSrcIndex];

            dest[destIndex] = ConstantTime.ctSelect((short) (validDestRange & validSrcRange & ~maskOp), srcValue, destValue);
            srcIndex += ConstantTime.ctSelect(validDestRange, (short) 1, (short) 0);
        }
        return (short) (destOff + length);
    }

    public static short ctArrayCopyNonAtomic(byte[] src, short srcOff, byte[] dest, short destOff, short length) {
        return ctArrayCopyNonAtomic(src, srcOff, dest, destOff, length, (short) 0x00);
    }

    /**
     * Fills the byte array (non-atomically) beginning at the specified position, for the specified length with the specified byte value.
     *
     * @param bArray the byte array
     * @param bOff offset within byte array to start filling bValue into
     * @param bLen byte length to be filled
     * @param bValue the value to fill the byte array with
     * @param maskOp perform blinded operation
     * @return bOff+bLen
     * @implNote If bOff or bLen parameter is negative an ArrayIndexOutOfBoundsException exception is thrown.
     * @implNote If bOff+bLen is greater than bArray.length, the length of the bArray array an ArrayIndexOutOfBoundsException exception is thrown.
     * @implNote If bArray parameter is null a NullPointerException exception is thrown.
     */
    public static short ctArrayFillNonAtomic(byte[] bArray, short bOff, short bLen, byte bValue, short maskOp) {
        if (bArray == null)
            throw new NullPointerException();
        short error = (short) (ConstantTime.ctIsNegative(bOff) | ConstantTime.ctIsNegative(bLen));
        error |= ConstantTime.ctGreater((short) (bOff + bLen), (short) bArray.length);
        if ((error & (short) 0xffff) == (short) 0xffff) {
            throw new ArrayIndexOutOfBoundsException();
        }

        for (short index = 0; index < bArray.length; index++) {
            short validIndex = ConstantTime.ctGreaterOrEqual(index, bOff);
            validIndex &= ConstantTime.ctLessThan(index, (short) (bOff + bLen));
            byte value = bArray[index];
            bArray[index] = ConstantTime.ctSelect((short) (validIndex & ~maskOp), bValue, value);
        }
        return (short) (bOff + bLen);
    }

    public static short ctArrayFillNonAtomic(byte[] bArray, short bOff, short bLen, byte bValue) {
        return ctArrayFillNonAtomic(bArray, bOff, bLen, bValue, (short) 0x00);
    }
}
