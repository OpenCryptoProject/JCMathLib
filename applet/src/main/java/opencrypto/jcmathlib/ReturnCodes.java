package opencrypto.jcmathlib;

/**
 *
* @author Vasilios Mavroudis and Petr Svenda
 */
public class ReturnCodes {
    // Custom error response codes
    public static final short SW_BIGNAT_RESIZETOLONGER          = (short) 0x7000;
    public static final short SW_BIGNAT_REALLOCATIONNOTALLOWED  = (short) 0x7001;
    public static final short SW_BIGNAT_MODULOTOOLARGE          = (short) 0x7002;
    public static final short SW_BIGNAT_INVALIDCOPYOTHER        = (short) 0x7003;
    public static final short SW_BIGNAT_INVALIDRESIZE           = (short) 0x7004;
    public static final short SW_BIGNAT_INVALIDMULT             = (short) 0x7005;
    public static final short SW_BIGNAT_INVALIDSQ               = (short) 0x7006;
    public static final short SW_LOCK_ALREADYLOCKED             = (short) 0x7010;
    public static final short SW_LOCK_NOTLOCKED                 = (short) 0x7011;
    public static final short SW_LOCK_OBJECT_NOT_FOUND          = (short) 0x7012;
    public static final short SW_LOCK_NOFREESLOT                = (short) 0x7013;
    public static final short SW_LOCK_OBJECT_MISMATCH           = (short) 0x7014;
    public static final short SW_ECPOINT_INVALIDLENGTH          = (short) 0x7020;
    public static final short SW_ECPOINT_UNEXPECTED_KA_LEN      = (short) 0x7021;
    public static final short SW_ECPOINT_INVALID                = (short) 0x7022;
    public static final short SW_ALLOCATOR_INVALIDOBJID         = (short) 0x7030;
    public static final short SW_OPERATION_NOT_SUPPORTED        = (short) 0x7040;

    
    // Specific codes to propagate exceptions caught
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
