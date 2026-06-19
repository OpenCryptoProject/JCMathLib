package opencrypto.jcmathlib;

/**
 * OperationSupport class
 *
 * @author Antonin Dufka, modified by Veronika Hanulikova
 */
public class OperationSupport {
    private static OperationSupport instance;

    public static final short SIMULATOR = 0x0000;   // jCardSim.org simulator
    public static final short JCOP21 = 0x0001;      // NXP J2E145G
    public static final short JCOP3_P60 = 0x0002;   // NXP JCOP3 J3H145 P60
    public static final short JCOP4_P71 = 0x0003;   // NXP JCOP4 J3Rxxx P71
    public static final short GD60 = 0x0004;        // G+D Sm@rtcafe 6.0
    public static final short GD70 = 0x0005;        // G+D Sm@rtcafe 7.0
    public static final short SECORA = 0x0006;      // Infineon Secora ID S

    public short MIN_RSA_BIT_LENGTH = 512;
    public short trueValue = (short) 0xffff;
    public short falseValue = (short) 0x0000;
    public short DEFERRED_INITIALIZATION = falseValue;

    public short RSA_EXP = trueValue;
    public short RSA_SQ = falseValue;
    public short RSA_PUB = falseValue;
    public short RSA_CHECK_ONE = falseValue;
    public short RSA_CHECK_EXP_ONE = falseValue;
    public short RSA_KEY_REFRESH = falseValue;
    public short RSA_PREPEND_ZEROS = falseValue;
    public short RSA_EXTRA_MOD = falseValue;
    public short RSA_RESIZE_MOD = trueValue;
    public short RSA_APPEND_MOD = falseValue;

    public short EC_HW_XY = falseValue;
    public short EC_HW_X = trueValue;
    public short EC_HW_ADD = falseValue;
    public short EC_SW_DOUBLE = falseValue;
    public short EC_PRECISE_BITLENGTH = trueValue;
    public short EC_SET_COFACTOR = falseValue;
    public short EC_GEN = trueValue;
    public short EC_HW_X_ECDSA = trueValue;

    private OperationSupport() {
    }

    public static OperationSupport getInstance() {
        if (OperationSupport.instance == null) OperationSupport.instance = new OperationSupport();
        return OperationSupport.instance;
    }

    public void setCard(short card_identifier) {
        switch (card_identifier) {
            case SIMULATOR:
                RSA_KEY_REFRESH = trueValue;
                RSA_PREPEND_ZEROS = trueValue;
                RSA_RESIZE_MOD = falseValue;
                EC_HW_XY = trueValue;
                EC_HW_ADD = trueValue;
                EC_SW_DOUBLE = trueValue;
                EC_PRECISE_BITLENGTH = falseValue;
                break;
            case JCOP21:
                RSA_PUB = trueValue;
                RSA_EXTRA_MOD = trueValue;
                RSA_APPEND_MOD = trueValue;
                EC_SW_DOUBLE = trueValue;
                RSA_SQ = trueValue;
                // EC_GEN = falseValue; // required by Wei25519
                // EC_HW_X_ECDSA = falseValue; // required by Wei25519
                break;
            case GD60:
                RSA_PUB = trueValue;
                RSA_EXTRA_MOD = trueValue;
                RSA_APPEND_MOD = trueValue;
                RSA_SQ = trueValue;
                break;
            case GD70:
                RSA_PUB = trueValue;
                RSA_CHECK_ONE = trueValue;
                RSA_EXTRA_MOD = trueValue;
                RSA_APPEND_MOD = trueValue;
                RSA_SQ = trueValue;
                break;
            case JCOP3_P60:
                DEFERRED_INITIALIZATION = trueValue;
                RSA_PUB = trueValue;
                EC_HW_XY = trueValue;
                EC_HW_ADD = trueValue;
                RSA_SQ = trueValue;
                break;
            case JCOP4_P71:
                DEFERRED_INITIALIZATION = trueValue;
                EC_HW_XY = trueValue;
                EC_HW_ADD = trueValue;
                RSA_SQ = trueValue;
                break;
            case SECORA:
                MIN_RSA_BIT_LENGTH = 1024;
                RSA_CHECK_EXP_ONE = trueValue;
                RSA_PUB = trueValue;
                RSA_EXTRA_MOD = trueValue;
                RSA_APPEND_MOD = trueValue;
                EC_HW_XY = trueValue;
                EC_PRECISE_BITLENGTH = falseValue;
                break;
            default:
                break;
        }
    }
}
