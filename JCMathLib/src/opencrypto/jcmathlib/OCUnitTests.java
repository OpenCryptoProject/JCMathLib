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
 * 
* @author Vasilios Mavroudis and Petr Svenda
 */
public class OCUnitTests extends Applet {
    // Main instruction CLAss
    public final static byte CLA_OC_UT                  = (byte) 0xB0; // OpenCrypto Unit Tests

    // INStructions
    // Card Management
    public final static byte INS_SETUP                  = (byte) 0x01;
    public final static byte INS_STATUS                 = (byte) 0x02;
    public final static byte INS_CLEANUP                = (byte) 0x03;
    //public final static byte INS_TESTRSAMULT                    = (byte) 0x04;
    public final static byte INS_FREEMEMORY             = (byte) 0x06;
    public final static byte INS_GET_ALLOCATOR_STATS    = (byte) 0x07;
    public final static byte INS_GET_PROFILE_LOCKS      = (byte) 0x08;

    //BigNatural and BigInteger Operations
    public final static byte INS_INT_STR                = (byte) 0x09; 
    public final static byte INS_INT_ADD                = (byte) 0x10;
    public final static byte INS_INT_SUB                = (byte) 0x11;
    public final static byte INS_INT_MUL                = (byte) 0x12;
    public final static byte INS_INT_DIV                = (byte) 0x13;
    //public final static byte INS_INT_EXP				= (byte) 0x14;
    public final static byte INS_INT_MOD                = (byte) 0x15;

    public final static byte INS_BN_STR                 = (byte) 0x20;
    public final static byte INS_BN_ADD                 = (byte) 0x21;
    public final static byte INS_BN_SUB                 = (byte) 0x22;
    public final static byte INS_BN_MUL                 = (byte) 0x23;
    public final static byte INS_BN_EXP                 = (byte) 0x24;
    public final static byte INS_BN_MOD                 = (byte) 0x25;
    public final static byte INS_BN_SQRT                = (byte) 0x26;
    public final static byte INS_BN_MUL_SCHOOL          = (byte) 0x27;

    public final static byte INS_BN_ADD_MOD             = (byte) 0x30;
    public final static byte INS_BN_SUB_MOD             = (byte) 0x31;
    public final static byte INS_BN_MUL_MOD             = (byte) 0x32;
    public final static byte INS_BN_EXP_MOD             = (byte) 0x33;
    public final static byte INS_BN_INV_MOD             = (byte) 0x34;
    public final static byte INS_BN_POW2_MOD            = (byte) 0x35;

    //EC Operations
    public final static byte INS_EC_GEN                 = (byte) 0x40;
    public final static byte INS_EC_DBL                 = (byte) 0x41;
    public final static byte INS_EC_ADD                 = (byte) 0x42;
    public final static byte INS_EC_MUL                 = (byte) 0x43;
    public final static byte INS_EC_NEG                 = (byte) 0x44;
    public final static byte INS_EC_SETCURVE_G          = (byte) 0x45;
    public final static byte INS_EC_COMPARE             = (byte) 0x46;

    public final static byte INS_PERF_SETSTOP = (byte) 0xf5;
    
    
    static boolean bIsSimulator = false; 
    static boolean bTEST_256b_CURVE = true;
    static boolean bTEST_512b_CURVE = false;
    
    short[]         m_memoryInfo = null;
    short           m_memoryInfoOffset = 0;
    
    ECConfig        m_ecc = null;
    
    ECCurve         m_testCurve = null;

    ECPoint         m_testPoint1 = null;
    ECPoint         m_testPoint2 = null;
    
    byte[]          m_customG = null;
    ECCurve         m_testCurveCustom = null;
    ECPoint         m_testPointCustom = null;
    
    Bignat          m_testBN1;
    Bignat          m_testBN2;
    Bignat          m_testBN3;
    
    Integer         m_testINT1;
    Integer         m_testINT2;

    public OCUnitTests() {
        m_memoryInfo = new short[(short) (7 * 3)]; // Contains RAM and EEPROM memory required for basic library objects 
        m_memoryInfoOffset = snapshotAvailableMemory((short) 1, m_memoryInfo, m_memoryInfoOffset);
        if (bTEST_256b_CURVE) {
            m_ecc = new ECConfig((short) 256);
        }
        if (bTEST_512b_CURVE) {
            m_ecc = new ECConfig((short) 512);
        }
        m_memoryInfoOffset = snapshotAvailableMemory((short) 2, m_memoryInfo, m_memoryInfoOffset);
        

        // Pre-allocate test objects (no new allocation for every tested operation)
        if (bTEST_256b_CURVE) {
            m_testCurve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
            m_memoryInfoOffset = snapshotAvailableMemory((short) 3, m_memoryInfo, m_memoryInfoOffset);
            // m_testCurveCustom and m_testPointCustom will have G occasionally changed so we need separate ECCurve
            m_customG = new byte[(short) SecP256r1.G.length];
            Util.arrayCopyNonAtomic(SecP256r1.G, (short) 0, m_customG, (short) 0, (short) SecP256r1.G.length);
            m_testCurveCustom = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, m_customG, SecP256r1.r);
        }
        if (bTEST_512b_CURVE) {
            m_testCurve = new ECCurve(false, P512r1.p, P512r1.a, P512r1.b, P512r1.G, P512r1.r);
            // m_testCurveCustom and m_testPointCustom will have G occasionally changed so we need separate ECCurve
            m_customG = new byte[(short) P512r1.G.length];
            Util.arrayCopyNonAtomic(P512r1.G, (short) 0, m_customG, (short) 0, (short) P512r1.G.length);
            m_testCurveCustom = new ECCurve(false, P512r1.p, P512r1.a, P512r1.b, m_customG, P512r1.r);
        }
        
        m_memoryInfoOffset = snapshotAvailableMemory((short) 5, m_memoryInfo, m_memoryInfoOffset);
        m_testPoint1 = new ECPoint(m_testCurve, m_ecc.ech);
        m_memoryInfoOffset = snapshotAvailableMemory((short) 6, m_memoryInfo, m_memoryInfoOffset);
        m_testPoint2 = new ECPoint(m_testCurve, m_ecc.ech);
        m_testPointCustom = new ECPoint(m_testCurveCustom, m_ecc.ech);

        // Testing Bignat objects used in tests
        m_memoryInfoOffset = snapshotAvailableMemory((short) 7, m_memoryInfo, m_memoryInfoOffset);
        byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        m_testBN1 = new Bignat(m_ecc.MAX_BIGNAT_SIZE, memoryType, m_ecc.bnh);
        m_memoryInfoOffset = snapshotAvailableMemory((short) 8, m_memoryInfo, m_memoryInfoOffset);
        m_testBN2 = new Bignat(m_ecc.MAX_BIGNAT_SIZE, memoryType, m_ecc.bnh);
        m_testBN3 = new Bignat(m_ecc.MAX_BIGNAT_SIZE, memoryType, m_ecc.bnh);
        
        short intLen = 4;
        m_testINT1 = new Integer(intLen, m_ecc.bnh);
        m_testINT2 = new Integer(intLen, m_ecc.bnh);
    }
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        //new UnitTests().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        if (bLength == 0) {
            bIsSimulator = true;
        }
        new OCUnitTests().register();
    }

    public boolean select() {
        updateAfterReset();
        return true;
    }
    public void process(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        // Good practice: Return 9000 on SELECT
        if (selectingApplet()) {
            return;
        }

        // Check CLA byte
        if (apdubuf[ISO7816.OFFSET_CLA] != CLA_OC_UT) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Process Input
        short dataLen = apdu.setIncomingAndReceive(); // returns length of data field

        try {
            switch (apdubuf[ISO7816.OFFSET_INS]) {
                case INS_CLEANUP:
                    m_ecc.unlockAll();
                    break;
                case INS_FREEMEMORY:
                    if (!bIsSimulator) {
                        JCSystem.requestObjectDeletion();
                    }
                    break;
                case INS_PERF_SETSTOP:
                    PM.m_perfStop = Util.makeShort(apdubuf[ISO7816.OFFSET_CDATA], apdubuf[(short) (ISO7816.OFFSET_CDATA + 1)]);
                    break;
                case INS_GET_ALLOCATOR_STATS:
                    short offset = 0;
                    Util.setShort(apdubuf, offset, m_ecc.rm.memAlloc.getAllocatedInRAM());
                    offset += 2;
                    Util.setShort(apdubuf, offset, m_ecc.rm.memAlloc.getAllocatedInEEPROM());
                    offset += 2;
                    for (short i = 0; i < (short) m_memoryInfo.length; i++) {
                        Util.setShort(apdubuf, offset, m_memoryInfo[i]);
                        offset += 2;
                    }
                    apdu.setOutgoingAndSend((short) 0, offset);
                    break;
                case INS_GET_PROFILE_LOCKS:
                    Util.arrayCopyNonAtomic(m_ecc.rm.locker.profileLockedObjects, (short) 0, apdubuf, (short) 0, (short) m_ecc.rm.locker.profileLockedObjects.length);
                    apdu.setOutgoingAndSend((short) 0, (short) m_ecc.rm.locker.profileLockedObjects.length);
                    break;

                //==============================================================
                case INS_EC_GEN:
                    test_EC_GEN(apdu);
                    break;
                case INS_EC_SETCURVE_G:
                    test_EC_SETCURVE_G(apdu, dataLen);
                    break;
                case INS_EC_DBL:
                    test_EC_DBL(apdu);
                    break;

                case INS_EC_ADD:
                    test_EC_ADD(apdu);
                    break;

                case INS_EC_MUL:
                    test_EC_MUL(apdu);
                    break;

                case INS_EC_NEG:
                    test_EC_NEG(apdu);
                    break;

                case INS_EC_COMPARE:
                    test_EC_COMPARE(apdu);
                    break;

                //==============================================================
                case INS_BN_STR:
                    test_BN_STR(apdu, dataLen);
                    break;

                case INS_BN_ADD:
                    test_BN_ADD(apdu, dataLen);
                    break;

                case INS_BN_SUB:
                    test_BN_SUB(apdu, dataLen);
                    break;

                case INS_BN_MUL:
                    test_BN_MUL(apdu, dataLen, true);
                    break;
                case INS_BN_MUL_SCHOOL:
                    test_BN_MUL(apdu, dataLen, false);
                    break;

                case INS_BN_EXP:
                    test_BN_EXP(apdu, dataLen);
                    break;
                case INS_BN_SQRT:
                    test_BN_SQRT(apdu, dataLen);
                    break;

                case INS_BN_MOD:
                    test_BN_MOD(apdu, dataLen);
                    break;

                case INS_BN_ADD_MOD:
                    test_BN_ADD_MOD(apdu, dataLen);
                    break;

                case INS_BN_SUB_MOD:
                    test_BN_SUB_MOD(apdu, dataLen);
                    break;

                case INS_BN_MUL_MOD:
                    test_BN_MUL_MOD(apdu, dataLen);
                    break;

                case INS_BN_EXP_MOD:
                    test_BN_EXP_MOD(apdu, dataLen);
                    break;

                case INS_BN_POW2_MOD:
                    test_BN_POW2_MOD(apdu, dataLen);
                    break;

                case INS_BN_INV_MOD:
                    test_BN_INV_MOD(apdu, dataLen);
                    break;

                // ---------------------------------------
                case INS_INT_STR:
                    test_INT_STR(apdu, dataLen);
                    break;

                case INS_INT_ADD:
                    test_INT_ADD(apdu, dataLen);
                    break;

                case INS_INT_SUB:
                    test_INT_SUB(apdu, dataLen);
                    break;

                case INS_INT_MUL:
                    test_INT_MUL(apdu, dataLen);
                    break;

                case INS_INT_DIV:
                    test_INT_DIV(apdu, dataLen);
                    break;

                //case (byte) Configuration.INS_INT_EXP:
                //      test_INT_EXP(apdu, dataLen);
                //	break;
                case INS_INT_MOD:
                    test_INT_MOD(apdu, dataLen);
                    break;

                default:
                    // good practice: If you don't know the INStruction, say so:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            // Capture all reasonable exceptions and change into readable ones (instead of 0x6f00) 
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
    
    
    void test_EC_GEN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        PM.check(PM.TRAP_EC_GEN_1);
        m_testPoint1.randomize();
        PM.check(PM.TRAP_EC_GEN_2);

        short len = m_testPoint1.getW(apdubuf, (short) 0);
        PM.check(PM.TRAP_EC_GEN_3);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void updateAfterReset() {
        if (m_testCurve != null) { m_testCurve.updateAfterReset(); }
        if (m_testCurveCustom != null) {m_testCurveCustom.updateAfterReset(); }
        if (m_ecc != null) {
            m_ecc.refreshAfterReset(); 
            m_ecc.unlockAll();
        }
        if (m_ecc.bnh != null) {m_ecc.bnh.bIsSimulator = bIsSimulator; }
    }
    void test_EC_SETCURVE_G(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_customG, (short) 0, dataLen);
        PM.check(PM.TRAP_EC_SETCURVE_1);

        if (apdubuf[ISO7816.OFFSET_P2] == 1) { // If required, complete new custom curve and point is allocated
            m_testCurveCustom = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, m_customG, SecP256r1.r);
            m_testPointCustom = new ECPoint(m_testCurveCustom, m_ecc.ech);
            PM.check(PM.TRAP_EC_SETCURVE_2);
            // Release unused previous objects
            if (!bIsSimulator) {
                JCSystem.requestObjectDeletion();
            }
        }
        else {
            // Otherwise, only G is set and relevant objects are updated
            m_testCurveCustom.setG(apdubuf, (short) ISO7816.OFFSET_CDATA, m_testCurveCustom.POINT_SIZE);
            m_testPointCustom.updatePointObjects(); // After changing curve parameters, internal objects needs to be actualized
        }
   }
    
    void test_EC_DBL(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        PM.check(PM.TRAP_EC_DBL_1);
        m_testPointCustom.setW(apdubuf, (short) ISO7816.OFFSET_CDATA, m_testCurveCustom.POINT_SIZE);
        // NOTE: for doubling, curve G must be also set. Here we expect that test_EC_SETCURVE_G() was called before
        PM.check(PM.TRAP_EC_DBL_2);
        m_testPointCustom.makeDouble(); //G + G
        PM.check(PM.TRAP_EC_DBL_3);

        short len = m_testPointCustom.getW(apdubuf, (short) 0);
        PM.check(PM.TRAP_EC_DBL_4);
        apdu.setOutgoingAndSend((short) 0, len);
    }    
    
    void test_EC_ADD(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        PM.check(PM.TRAP_EC_ADD_1);
        m_testPoint1.setW(apdubuf, (short) ISO7816.OFFSET_CDATA, m_testCurve.POINT_SIZE);
        PM.check(PM.TRAP_EC_ADD_2);
        m_testPoint2.setW(apdubuf, (short) (ISO7816.OFFSET_CDATA + m_testCurve.POINT_SIZE), m_testCurve.POINT_SIZE);
        PM.check(PM.TRAP_EC_ADD_3);
        m_testPoint1.add(m_testPoint2);
        PM.check(PM.TRAP_EC_ADD_4);

        short len = m_testPoint1.getW(apdubuf, (short) 0);
        PM.check(PM.TRAP_EC_ADD_5);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_EC_MUL(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short p1_len = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_EC_MUL_1);
        Bignat scalar = m_testBN1;
        scalar.set_size(p1_len);
        scalar.from_byte_array(p1_len, (short) 0, apdubuf, ISO7816.OFFSET_CDATA);
        PM.check(PM.TRAP_EC_MUL_2);
        m_testPoint1.setW(apdubuf, (short) (ISO7816.OFFSET_CDATA + p1_len), m_testCurve.POINT_SIZE);
        PM.check(PM.TRAP_EC_MUL_3);
        m_testPoint1.multiplication(scalar);
        PM.check(PM.TRAP_EC_MUL_4);

        short len = m_testPoint1.getW(apdubuf, (short) 0);
        PM.check(PM.TRAP_EC_MUL_5);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_EC_NEG(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short p1_len = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        m_testPoint1.setW(apdubuf, ISO7816.OFFSET_CDATA, p1_len);
        m_testPoint1.negate();
        short len = m_testPoint1.getW(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }    
    
    
    void test_EC_COMPARE(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short p1_len = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        short p2_len = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        
        m_testPoint1.setW(apdubuf, (short) ISO7816.OFFSET_CDATA, p1_len);
        m_testPoint2.setW(apdubuf, (short) (ISO7816.OFFSET_CDATA + p1_len), p2_len);
        apdubuf[0] = 0; apdubuf[1] = 0; apdubuf[2] = 0; apdubuf[3] = 0; // Tests expects big integer
        apdubuf[4] = m_testPoint1.isEqual(m_testPoint2) ? (byte) 1 : (byte) 0;
        apdu.setOutgoingAndSend((short) 0, (short) 5);
    }            
    
    
    void test_BN_STR(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();

        PM.check(PM.TRAP_BN_STR_1);
        Bignat num = m_testBN1; 
        num.set_size(dataLen);
        PM.check(PM.TRAP_BN_STR_2);
        num.from_byte_array(dataLen, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        PM.check(PM.TRAP_BN_STR_3);
        short len = num.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void test_BN_ADD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_BN_ADD_1);
        Bignat num1 = m_testBN1;
        num1.set_size(p1);
        PM.check(PM.TRAP_BN_ADD_2);
        Bignat num2 = m_testBN2;
        num2.set_size((short) (dataLen - p1));
        PM.check(PM.TRAP_BN_ADD_3);
        Bignat sum = m_testBN3;
        sum.set_size((short) (p1 + 1));

        PM.check(PM.TRAP_BN_ADD_4);
        num1.from_byte_array(p1, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        num2.from_byte_array((short) (dataLen - p1), (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        PM.check(PM.TRAP_BN_ADD_5);
        sum.copy(num1);
        PM.check(PM.TRAP_BN_ADD_6);
        sum.add(num2);
        PM.check(PM.TRAP_BN_ADD_7);
        short len = sum.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);    
    }
                        
    void test_BN_SUB(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_BN_SUB_1);
        Bignat sub1 = m_testBN1;
        sub1.set_size(p1);
        PM.check(PM.TRAP_BN_SUB_2);
        Bignat sub2 = m_testBN2;
        sub2.set_size((short) (dataLen - p1));
        PM.check(PM.TRAP_BN_SUB_3);
        Bignat result = m_testBN3;
        result.set_size((short) (p1 + 1));
        PM.check(PM.TRAP_BN_SUB_4);
        sub1.from_byte_array(dataLen, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        sub2.from_byte_array(dataLen, (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        PM.check(PM.TRAP_BN_SUB_5);
        result.copy(sub1);
        PM.check(PM.TRAP_BN_SUB_6);
        result.subtract(sub2);
        PM.check(PM.TRAP_BN_SUB_7);
        short len = result.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }		
    
    void test_BN_MUL(APDU apdu, short dataLen, boolean bFastEngine) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_BN_MUL_1);    
        Bignat mul1 = m_testBN1;
        mul1.set_size(p1);
        PM.check(PM.TRAP_BN_MUL_2);
        Bignat mul2 = m_testBN2;
        mul2.set_size((short) (dataLen - p1));
        PM.check(PM.TRAP_BN_MUL_3);
        Bignat product = m_testBN3;
        product.set_size(dataLen);
        PM.check(PM.TRAP_BN_MUL_4);
        mul1.from_byte_array(p1, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        mul2.from_byte_array((short)(dataLen-p1), (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        PM.check(PM.TRAP_BN_MUL_5);
        if (bFastEngine && !bIsSimulator) {
            product.mult_rsa_trick(mul1, mul2, null, null);
        }
        else {
            product.mult_schoolbook(mul1, mul2);        
        }
        PM.check(PM.TRAP_BN_MUL_6);
        short len = product.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_BN_EXP(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apdubuf[ISO7816.OFFSET_P2] & 0x00FF);

        PM.check(PM.TRAP_BN_EXP_1);    
        Bignat base = m_testBN1;
        base.set_size(p1);
        PM.check(PM.TRAP_BN_EXP_2);
        Bignat exp = m_testBN2;
        exp.set_size((short) (dataLen - p1));
        PM.check(PM.TRAP_BN_EXP_3);
        Bignat res = m_testBN3;
        res.set_size((short) (m_ecc.MAX_BIGNAT_SIZE / 2));
        PM.check(PM.TRAP_BN_EXP_4);
        base.from_byte_array(p1, (short) 0, apdubuf, ISO7816.OFFSET_CDATA);
        exp.from_byte_array((short) (dataLen - p1), (short) 0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        PM.check(PM.TRAP_BN_EXP_5);
        res.exponentiation(base, exp);
        PM.check(PM.TRAP_BN_EXP_6);
        short len = res.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_BN_SQRT(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        Bignat num = m_testBN1;
        num.set_size(p1);
        num.from_byte_array(p1, p1, apdubuf, ISO7816.OFFSET_CDATA);
        Bignat num2 = m_testBN2;
        num2.clone(m_testCurve.pBN);
        num.sqrt_FP(num2);
        short len = num.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    
    void test_BN_MOD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_BN_MOD_1);
        Bignat num = m_testBN1;
        num.set_size(p1);
        PM.check(PM.TRAP_BN_MOD_2);
        Bignat mod = m_testBN2;
        mod.set_size((short) (dataLen - p1));
        PM.check(PM.TRAP_BN_MOD_3);
        num.from_byte_array(p1, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        mod.from_byte_array((short)(dataLen-p1), (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        PM.check(PM.TRAP_BN_MOD_4);
        num.mod(mod);
        PM.check(PM.TRAP_BN_MOD_5);
        short len = num.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_BN_ADD_MOD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apdubuf[ISO7816.OFFSET_P2] & 0x00FF);

        PM.check(PM.TRAP_BN_ADD_MOD_1);    
        Bignat num1 = m_testBN1;
        num1.set_size(p1);
        PM.check(PM.TRAP_BN_ADD_MOD_2);
        Bignat num2 = m_testBN2;
        num2.set_size(p2);
        PM.check(PM.TRAP_BN_ADD_MOD_3);
        Bignat mod = m_testBN3;
        mod.set_size((short) (dataLen - p1 - p2));
        PM.check(PM.TRAP_BN_ADD_MOD_4);
        num1.from_byte_array(p1, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        num2.from_byte_array(p2, (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        PM.check(PM.TRAP_BN_ADD_MOD_5);
        mod.from_byte_array((short)(dataLen-p1-p2), (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1+p2));
        PM.check(PM.TRAP_BN_ADD_MOD_6);
        num1.mod_add(num2, mod);
        PM.check(PM.TRAP_BN_ADD_MOD_7);
        short len = num1.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
        
    void test_BN_SUB_MOD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apdubuf[ISO7816.OFFSET_P2] & 0x00FF);

        PM.check(PM.TRAP_BN_SUB_MOD_1);    
        Bignat num1 = m_testBN1;
        num1.set_size(p1);
        PM.check(PM.TRAP_BN_SUB_MOD_2);
        Bignat num2 = m_testBN2;
        num2.set_size(p2);
        PM.check(PM.TRAP_BN_SUB_MOD_3);
        Bignat mod = m_testBN3;
        mod.set_size((short) (dataLen - p1 - p2));
        PM.check(PM.TRAP_BN_SUB_MOD_4);
        num1.from_byte_array(p1, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        num2.from_byte_array(p2, (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        mod.from_byte_array((short)(dataLen-p1-p2), (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1+p2));
        PM.check(PM.TRAP_BN_SUB_MOD_5);
        num1.mod_sub(num2, mod);
        PM.check(PM.TRAP_BN_SUB_MOD_6);
        short len = num1.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }			
    
    void test_BN_MUL_MOD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apdubuf[ISO7816.OFFSET_P2] & 0x00FF);

        PM.check(PM.TRAP_BN_MUL_MOD_1);    
        Bignat num1 = m_testBN1;
        num1.set_size(p1);
        PM.check(PM.TRAP_BN_MUL_MOD_2);
        Bignat num2 = m_testBN2;
        num2.set_size(p2);
        PM.check(PM.TRAP_BN_MUL_MOD_3);
        Bignat mod = m_testBN3;
        mod.set_size((short) (dataLen - p1 - p2));
        PM.check(PM.TRAP_BN_MUL_MOD_4);
        num1.from_byte_array(p1, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        num2.from_byte_array(p2, (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        mod.from_byte_array((short)(dataLen-p1-p2), (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1+p2));
        PM.check(PM.TRAP_BN_MUL_MOD_5);
        num1.mod_mult(num1, num2, mod);
        PM.check(PM.TRAP_BN_MUL_MOD_6);
        short len = num1.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_BN_EXP_MOD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apdubuf[ISO7816.OFFSET_P2] & 0x00FF);

        PM.check(PM.TRAP_BN_EXP_MOD_1);    
        Bignat num1 = m_testBN1;
        num1.set_size(p1);
        PM.check(PM.TRAP_BN_EXP_MOD_2);
        Bignat num2 = m_testBN2;
        num2.set_size(p2);
        PM.check(PM.TRAP_BN_EXP_MOD_3);
        Bignat mod = m_testBN3;
        mod.set_size((short) (dataLen - p1 - p2));
        PM.check(PM.TRAP_BN_EXP_MOD_4);
        num1.from_byte_array(p1, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        num2.from_byte_array(p2, (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        mod.from_byte_array((short)(dataLen-p1-p2), (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1+p2));
        PM.check(PM.TRAP_BN_EXP_MOD_5);
        num1.mod_exp(num2, mod);
        PM.check(PM.TRAP_BN_EXP_MOD_6);
        short len = num1.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_BN_POW2_MOD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        short p2 = (short) (apdubuf[ISO7816.OFFSET_P2] & 0x00FF);

        PM.check(PM.TRAP_BN_POW2_MOD_1);
        Bignat num1 = m_testBN1;
        num1.set_size(p1);
        Bignat mod = m_testBN3;
        mod.set_size((short) (dataLen - p1));
        num1.from_byte_array(p1, (short) 0, apdubuf, ISO7816.OFFSET_CDATA);
        mod.from_byte_array((short) (dataLen - p1), (short) 0, apdubuf, (short) (ISO7816.OFFSET_CDATA + p1));
        PM.check(PM.TRAP_BN_POW2_MOD_2);
        //num1.pow2Mod_RSATrick(mod);
        num1.mod_exp2(mod);
        PM.check(PM.TRAP_BN_POW2_MOD_3);
        short len = num1.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }    

    void test_BN_INV_MOD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_BN_INV_MOD_1);
        Bignat num1 = m_testBN1;
        num1.set_size(p1);
        PM.check(PM.TRAP_BN_INV_MOD_2);
        Bignat mod = m_testBN2;
        mod.set_size((short) (dataLen - p1));
        PM.check(PM.TRAP_BN_INV_MOD_3);
        num1.from_byte_array(p1, (short)0, apdubuf, ISO7816.OFFSET_CDATA);
        mod.from_byte_array((short)(dataLen-p1), (short)0, apdubuf, (short)(ISO7816.OFFSET_CDATA+p1));
        PM.check(PM.TRAP_BN_INV_MOD_4);
        num1.mod_inv(mod);
        PM.check(PM.TRAP_BN_INV_MOD_5);
        short len = num1.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    void test_INT_STR(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_INT_STR_1);
        //Integer num_int = new Integer(dataLen, (short) 0, apdubuf, ISO7816.OFFSET_CDATA);
        Integer num_int = m_testINT1;
        num_int.fromByteArray(apdubuf, ISO7816.OFFSET_CDATA, dataLen);
        PM.check(PM.TRAP_INT_STR_2);
        short len = num_int.toByteArray(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_INT_ADD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_INT_ADD_1);    
        //Integer num_add_1 = new Integer(dataLen, (short) 0, apdubuf, ISO7816.OFFSET_CDATA);
        Integer num_add_1 = m_testINT1;
        num_add_1.fromByteArray(apdubuf, ISO7816.OFFSET_CDATA, p1);
        PM.check(PM.TRAP_INT_ADD_2);
        //Integer num_add_2 = new Integer((short) (dataLen - p1), (short) 0, apdubuf, (short) (ISO7816.OFFSET_CDATA + p1));
        Integer num_add_2 = m_testINT2;
        num_add_2.fromByteArray(apdubuf, (short) (ISO7816.OFFSET_CDATA + p1), p1);
        PM.check(PM.TRAP_INT_ADD_3);
        num_add_1.add(num_add_2);
        PM.check(PM.TRAP_INT_ADD_4);
        short len = num_add_1.toByteArray(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_INT_SUB(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_INT_SUB_1);               
        Integer num_sub_1 = m_testINT1;
        num_sub_1.fromByteArray(apdubuf, ISO7816.OFFSET_CDATA, p1);
        Integer num_sub_2 = m_testINT2;
        num_sub_2.fromByteArray(apdubuf, (short) (ISO7816.OFFSET_CDATA + p1), p1);
        PM.check(PM.TRAP_INT_SUB_2);

        num_sub_1.subtract(num_sub_2);
        PM.check(PM.TRAP_INT_SUB_3);
        short len = num_sub_1.toByteArray(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_INT_MUL(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_INT_MUL_1);    
        Integer num_mul_1 = m_testINT1;
        num_mul_1.fromByteArray(apdubuf, ISO7816.OFFSET_CDATA, p1);
        Integer num_mul_2 = m_testINT2;
        num_mul_2.fromByteArray(apdubuf, (short) (ISO7816.OFFSET_CDATA + p1), p1);
        PM.check(PM.TRAP_INT_MUL_2);

        num_mul_1.multiply(num_mul_2);
        PM.check(PM.TRAP_INT_MUL_3);
        short len = num_mul_1.toByteArray(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_INT_DIV(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);

        PM.check(PM.TRAP_INT_DIV_1);    
        Integer num_div_1 = m_testINT1;
        num_div_1.fromByteArray(apdubuf, ISO7816.OFFSET_CDATA, p1);
        Integer num_div_2 = m_testINT2;
        num_div_2.fromByteArray(apdubuf, (short) (ISO7816.OFFSET_CDATA + p1), p1);
        PM.check(PM.TRAP_INT_DIV_2);

        num_div_1.divide(num_div_2);
        PM.check(PM.TRAP_INT_DIV_3);

        short len = num_div_1.toByteArray(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void test_INT_MOD(APDU apdu, short dataLen) {
        byte[] apdubuf = apdu.getBuffer();
        short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
        
        PM.check(PM.TRAP_INT_MOD_1);
        Integer num_mod_1 = m_testINT1;
        num_mod_1.fromByteArray(apdubuf, ISO7816.OFFSET_CDATA, p1);
        Integer num_mod_2 = m_testINT2;
        num_mod_2.fromByteArray(apdubuf, (short) (ISO7816.OFFSET_CDATA + p1), p1);
        PM.check(PM.TRAP_INT_MOD_2);

        num_mod_1.modulo(num_mod_2);
        PM.check(PM.TRAP_INT_MOD_3);
        short len = num_mod_1.toByteArray(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
