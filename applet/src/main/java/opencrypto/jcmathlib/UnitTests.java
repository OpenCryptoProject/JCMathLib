package opencrypto.jcmathlib;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.PINException;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;

/**
 * @author Vasilios Mavroudis and Petr Svenda and Antonin Dufka
 */
public class UnitTests extends Applet {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR; // TODO set your card

    public final static byte CLA_OC_UT = (byte) 0xB0;
    public final static byte INS_CLEANUP = (byte) 0x03;
    public final static byte INS_FREE_MEMORY = (byte) 0x06;
    public final static byte INS_GET_ALLOCATOR_STATS = (byte) 0x07;
    public final static byte INS_GET_PROFILE_LOCKS = (byte) 0x08;

    public final static byte INS_INT_STR = (byte) 0x09;
    public final static byte INS_INT_ADD = (byte) 0x10;
    public final static byte INS_INT_SUB = (byte) 0x11;
    public final static byte INS_INT_MUL = (byte) 0x12;
    public final static byte INS_INT_DIV = (byte) 0x13;
    public final static byte INS_INT_MOD = (byte) 0x15;

    public final static byte INS_BN_STR = (byte) 0x20;
    public final static byte INS_BN_ADD = (byte) 0x21;
    public final static byte INS_BN_SUB = (byte) 0x22;
    public final static byte INS_BN_MUL = (byte) 0x23;
    public final static byte INS_BN_SHIFT_RIGHT = (byte) 0x24;
    public final static byte INS_BN_MOD = (byte) 0x25;
    public final static byte INS_BN_SQ = (byte) 0x26;
    public final static byte INS_BN_MUL_SCHOOL = (byte) 0x27;

    public final static byte INS_BN_ADD_MOD = (byte) 0x30;
    public final static byte INS_BN_SUB_MOD = (byte) 0x31;
    public final static byte INS_BN_MUL_MOD = (byte) 0x32;
    public final static byte INS_BN_EXP_MOD = (byte) 0x33;
    public final static byte INS_BN_INV_MOD = (byte) 0x34;
    public final static byte INS_BN_SQ_MOD = (byte) 0x35;
    public final static byte INS_BN_SQRT_MOD = (byte) 0x36;

    public final static byte INS_EC_GEN = (byte) 0x40;
    public final static byte INS_EC_DBL = (byte) 0x41;
    public final static byte INS_EC_ADD = (byte) 0x42;
    public final static byte INS_EC_MUL = (byte) 0x43;
    public final static byte INS_EC_NEG = (byte) 0x44;
    public final static byte INS_EC_COMPARE = (byte) 0x46;
    public final static byte INS_EC_FROM_X = (byte) 0x47;
    public final static byte INS_EC_IS_Y_EVEN = (byte) 0x48;
    public final static byte INS_EC_MUL_ADD = (byte) 0x49;
    public final static byte INS_EC_ENCODE = (byte) 0x4a;

    boolean initialized = false;

    short[] memoryInfo;
    short memoryInfoOffset = 0;

    ResourceManager rm;
    ECCurve curve;
    ECPoint point1;
    ECPoint point2;

    byte[] customG;
    ECCurve customCurve;
    ECPoint customPoint;

    BigNat bn1;
    BigNat bn2;
    BigNat bn3;

    Integer int1;
    Integer int2;

    public UnitTests() {
        OperationSupport.getInstance().setCard(CARD_TYPE);
        if (!OperationSupport.getInstance().DEFERRED_INITIALIZATION) {
            initialize();
        }
    }

    public void initialize() {
        if (initialized) {
            return;
        }
        memoryInfo = new short[(short) (7 * 3)]; // Contains RAM and EEPROM memory required for basic library objects
        memoryInfoOffset = snapshotAvailableMemory((short) 1, memoryInfo, memoryInfoOffset);
        rm = new ResourceManager((short) 256);
        memoryInfoOffset = snapshotAvailableMemory((short) 2, memoryInfo, memoryInfoOffset);


        // Pre-allocate test objects (no new allocation for every tested operation)
        curve = new ECCurve(SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r, rm);
        memoryInfoOffset = snapshotAvailableMemory((short) 3, memoryInfo, memoryInfoOffset);
        customG = new byte[(short) SecP256r1.G.length];
        Util.arrayCopyNonAtomic(SecP256r1.G, (short) 0, customG, (short) 0, (short) SecP256r1.G.length);
        customCurve = new ECCurve(SecP256r1.p, SecP256r1.a, SecP256r1.b, customG, SecP256r1.r, rm);

        memoryInfoOffset = snapshotAvailableMemory((short) 5, memoryInfo, memoryInfoOffset);
        point1 = new ECPoint(curve);
        memoryInfoOffset = snapshotAvailableMemory((short) 6, memoryInfo, memoryInfoOffset);
        point2 = new ECPoint(curve);
        customPoint = new ECPoint(customCurve);

        // Testing BigNat objects used in tests
        memoryInfoOffset = snapshotAvailableMemory((short) 7, memoryInfo, memoryInfoOffset);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        bn1 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);
        memoryInfoOffset = snapshotAvailableMemory((short) 8, memoryInfo, memoryInfoOffset);
        bn2 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);
        bn3 = new BigNat(rm.MAX_BIGNAT_SIZE, memoryType, rm);

        short intLen = 4;
        int1 = new Integer(intLen, rm);
        int2 = new Integer(intLen, rm);
        initialized = true;
    }

    public static void install(byte[] ignoredArray, short ignoredOffset, byte ignoredLength) {
        new UnitTests().register();
    }

    public boolean select() {
        if (initialized) {
            updateAfterReset();
        }
        return true;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] apduBuffer = apdu.getBuffer();

        if (apduBuffer[ISO7816.OFFSET_CLA] != CLA_OC_UT) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Process Input
        short dataLen = apdu.setIncomingAndReceive(); // returns length of data field

        try {
            if(!initialized) {
                initialize();
            }

            switch (apduBuffer[ISO7816.OFFSET_INS]) {
                case INS_CLEANUP:
                    rm.unlockAll();
                    break;
                case INS_FREE_MEMORY:
                    if (CARD_TYPE != OperationSupport.SIMULATOR) {
                        JCSystem.requestObjectDeletion();
                    }
                    break;
                case INS_GET_ALLOCATOR_STATS:
                    short offset = 0;
                    Util.setShort(apduBuffer, offset, rm.memAlloc.getAllocatedInRAM());
                    offset += 2;
                    Util.setShort(apduBuffer, offset, rm.memAlloc.getAllocatedInEEPROM());
                    offset += 2;
                    for (short i = 0; i < (short) memoryInfo.length; i++) {
                        Util.setShort(apduBuffer, offset, memoryInfo[i]);
                        offset += 2;
                    }
                    apdu.setOutgoingAndSend((short) 0, offset);
                    break;
                case INS_GET_PROFILE_LOCKS:
                    Util.arrayCopyNonAtomic(rm.locker.profileLockedObjects, (short) 0, apduBuffer, (short) 0, (short) rm.locker.profileLockedObjects.length);
                    apdu.setOutgoingAndSend((short) 0, (short) rm.locker.profileLockedObjects.length);
                    break;

                case INS_EC_GEN:
                    testEcGen(apdu);
                    break;
                case INS_EC_DBL:
                    testEcDbl(apdu);
                    break;
                case INS_EC_ADD:
                    testEcAdd(apdu);
                    break;
                case INS_EC_MUL:
                    testEcMul(apdu);
                    break;
                case INS_EC_NEG:
                    testEcNeg(apdu);
                    break;
                case INS_EC_COMPARE:
                    testEcCompare(apdu);
                    break;
                case INS_EC_FROM_X:
                    testEcFromX(apdu);
                    break;
                case INS_EC_IS_Y_EVEN:
                    testEcIsYEven(apdu);
                    break;
                case INS_EC_MUL_ADD:
                    testEcMulAdd(apdu);
                    break;
                case INS_EC_ENCODE:
                    testEcEncode(apdu);
                    break;

                case INS_BN_STR:
                    testBnStr(apdu, dataLen);
                    break;
                case INS_BN_ADD:
                    testBnAdd(apdu, dataLen);
                    break;
                case INS_BN_SUB:
                    testBnSub(apdu, dataLen);
                    break;
                case INS_BN_MUL:
                    testBnMul(apdu, dataLen);
                    break;
                case INS_BN_SHIFT_RIGHT:
                    testBnShiftRight(apdu, dataLen);
                    break;
                case INS_BN_MUL_SCHOOL:
                    testBnMulSchool(apdu, dataLen);
                    break;
                case INS_BN_SQ:
                    testBnSq(apdu, dataLen);
                    break;
                case INS_BN_MOD:
                    testBnMod(apdu, dataLen);
                    break;

                case INS_BN_ADD_MOD:
                    testBnAddMod(apdu, dataLen);
                    break;
                case INS_BN_SUB_MOD:
                    testBnSubMod(apdu, dataLen);
                    break;
                case INS_BN_MUL_MOD:
                    testBnMulMod(apdu, dataLen);
                    break;
                case INS_BN_EXP_MOD:
                    testBnExpMod(apdu, dataLen);
                    break;
                case INS_BN_SQ_MOD:
                    testBnSqMod(apdu, dataLen);
                    break;
                case INS_BN_INV_MOD:
                    testBnInvMod(apdu, dataLen);
                    break;
                case INS_BN_SQRT_MOD:
                    testBnModSqrt(apdu, dataLen);
                    break;

                case INS_INT_STR:
                    testIntStr(apdu, dataLen);
                    break;
                case INS_INT_ADD:
                    testIntAdd(apdu, dataLen);
                    break;
                case INS_INT_SUB:
                    testIntSub(apdu, dataLen);
                    break;
                case INS_INT_MUL:
                    testIntMul(apdu, dataLen);
                    break;
                case INS_INT_DIV:
                    testIntDiv(apdu, dataLen);
                    break;
                case INS_INT_MOD:
                    testIntMod(apdu, dataLen);
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ReturnCodes.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(ReturnCodes.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(ReturnCodes.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(ReturnCodes.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(ReturnCodes.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (ReturnCodes.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (ReturnCodes.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (ReturnCodes.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (ReturnCodes.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (ReturnCodes.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(ReturnCodes.SW_Exception);
        }
    }


    final short snapshotAvailableMemory(short tag, short[] buffer, short bufferOffset) {
        buffer[bufferOffset] = tag;
        buffer[(short) (bufferOffset + 1)] = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        buffer[(short) (bufferOffset + 2)] = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
        return (short) (bufferOffset + 3);
    }


    void testEcGen(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        point1.randomize();

        short len = point1.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void updateAfterReset() {
        if (curve != null) {
            curve.updateAfterReset();
        }
        if (customCurve != null) {
            customCurve.updateAfterReset();
        }
        if (rm != null) {
            rm.refreshAfterReset();
            rm.unlockAll();
        }
    }

    void testEcDbl(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        customPoint.setW(apduBuffer, ISO7816.OFFSET_CDATA, customCurve.POINT_SIZE);
        customPoint.makeDouble();

        short len = customPoint.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testEcAdd(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        point1.setW(apduBuffer, ISO7816.OFFSET_CDATA, curve.POINT_SIZE);
        point2.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + curve.POINT_SIZE), curve.POINT_SIZE);
        point1.add(point2);

        short len = point1.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testEcMul(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        point1.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), curve.POINT_SIZE);
        point1.multiplication(bn1);

        short len = point1.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testEcMulAdd(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        point1.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), curve.POINT_SIZE);
        point2.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1 + curve.POINT_SIZE), curve.POINT_SIZE);
        point1.multAndAdd(bn1, point2);

        short len = point1.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testEcNeg(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        point1.setW(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        point1.negate();
        short len = point1.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }


    void testEcCompare(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        point1.setW(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        point2.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p2);
        apduBuffer[0] = 0;
        apduBuffer[1] = 0;
        apduBuffer[2] = 0;
        apduBuffer[3] = 0; // Tests expects big integer
        apduBuffer[4] = point1.isEqual(point2) ? (byte) 1 : (byte) 0;
        apdu.setOutgoingAndSend((short) 0, (short) 5);
    }


    void testEcFromX(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        point1.fromX(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        short len = point1.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }


    void testEcIsYEven(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        point1.setW(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        apduBuffer[0] = point1.isYEven() ? (byte) 1 : (byte) 0;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }


    void testEcEncode(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);
        boolean compressed = apduBuffer[ISO7816.OFFSET_P2] == 0x01;

        point1.decode(apduBuffer, ISO7816.OFFSET_CDATA, len);
        apdu.setOutgoingAndSend((short) 0, point1.encode(apduBuffer, (short) 0, compressed));
    }


    void testBnStr(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, dataLen);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnAdd(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);


        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), (short) (dataLen - p1));
        bn3.setSize((short) (p1 + 1));
        bn3.copy(bn1);
        bn3.add(bn2);
        short len = bn3.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnSub(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), (short) (dataLen - p1));
        bn3.setSize((short) (p1 + 1));
        bn3.copy(bn1);
        bn3.subtract(bn2);
        short len = bn3.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnMul(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), (short) (dataLen - p1));
        bn3.clone(bn1);
        bn3.mult(bn2);
        short len = bn3.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnSq(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, dataLen);
        bn1.sq();
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnShiftRight(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, dataLen);
        bn1.shiftRight(p1);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnMulSchool(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), (short) (dataLen - p1));
        boolean previous = OperationSupport.getInstance().RSA_SQ;
        OperationSupport.getInstance().RSA_SQ = false;
        bn3.clone(bn1);
        bn3.mult(bn2);
        OperationSupport.getInstance().RSA_SQ = previous;
        short len = bn3.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnMod(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), (short) (dataLen - p1));
        bn1.mod(bn2);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnAddMod(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p2);
        bn3.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1 + p2), (short) (dataLen - p1 - p2));
        bn1.modAdd(bn2, bn3);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnSubMod(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p2);
        bn3.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1 + p2), (short) (dataLen - p1 - p2));
        bn1.modSub(bn2, bn3);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnMulMod(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p2);
        bn3.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1 + p2), (short) (dataLen - p1 - p2));
        bn1.modMult(bn2, bn3);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnExpMod(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p2);
        bn3.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1 + p2), (short) (dataLen - p1 - p2));
        bn1.modExp(bn2, bn3);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnSqMod(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), (short) (dataLen - p1));
        bn1.modSq(bn2);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnInvMod(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), (short) (dataLen - p1));
        bn1.modInv(bn2);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testIntStr(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();

        int1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, dataLen);
        short len = int1.toByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testBnModSqrt(APDU apdu, short dataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        bn1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        bn2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), (short) (dataLen - p1));
        bn1.modSqrt(bn2);
        short len = bn1.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }


    void testIntAdd(APDU apdu, short ignoredDataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        int1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        int2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p1);

        int1.add(int2);
        short len = int1.toByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testIntSub(APDU apdu, short ignoredDataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        int1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        int2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p1);

        int1.subtract(int2);
        short len = int1.toByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testIntMul(APDU apdu, short ignoredDataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        int1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        int2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p1);

        int1.multiply(int2);
        short len = int1.toByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testIntDiv(APDU apdu, short ignoredDataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        int1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        int2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p1);

        int1.divide(int2);

        short len = int1.toByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void testIntMod(APDU apdu, short ignoredDataLen) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);

        int1.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, p1);
        int2.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + p1), p1);

        int1.modulo(int2);
        short len = int1.toByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
