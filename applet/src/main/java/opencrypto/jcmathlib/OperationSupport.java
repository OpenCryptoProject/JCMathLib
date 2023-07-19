package opencrypto.jcmathlib;

/**
 * OperationSupport class
 *
 * @author Antonin Dufka
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
    public boolean DEFERRED_INITIALIZATION = false;

    public boolean RSA_EXP = true;
    public boolean RSA_SQ = true;
    public boolean RSA_PUB = false;
    public boolean RSA_CHECK_ONE = false;
    public boolean RSA_KEY_REFRESH = false;
    public boolean RSA_PREPEND_ZEROS = false;
    public boolean RSA_EXTRA_MOD = false;
    public boolean RSA_RESIZE_MOD = true;
    public boolean RSA_APPEND_MOD = false;

    public boolean EC_HW_XY = false;
    public boolean EC_HW_X = true;
    public boolean EC_HW_ADD = false;
    public boolean EC_SW_DOUBLE = false;

    private OperationSupport() {
    }

    public static OperationSupport getInstance() {
        if (OperationSupport.instance == null) OperationSupport.instance = new OperationSupport();
        return OperationSupport.instance;
    }

    public void setCard(short card_identifier) {
        switch (card_identifier) {
            case SIMULATOR:
                RSA_KEY_REFRESH = true;
                RSA_PREPEND_ZEROS = true;
                RSA_RESIZE_MOD = false;
                EC_HW_XY = true;
                EC_HW_ADD = true;
                EC_SW_DOUBLE = true;
                break;
            case JCOP21:
                RSA_PUB = true;
                RSA_EXTRA_MOD = true;
                RSA_APPEND_MOD = true;
                EC_SW_DOUBLE = true;
                break;
            case GD60:
                RSA_PUB = true;
                RSA_EXTRA_MOD = true;
                RSA_APPEND_MOD = true;
                break;
            case GD70:
                RSA_PUB = true;
                RSA_CHECK_ONE = true;
                RSA_EXTRA_MOD = true;
                RSA_APPEND_MOD = true;
                break;
            case JCOP3_P60:
                DEFERRED_INITIALIZATION = true;
                RSA_PUB = true;
                EC_HW_XY = true;
                EC_HW_ADD = true;
                break;
            case JCOP4_P71:
                DEFERRED_INITIALIZATION = true;
                EC_HW_XY = true;
                EC_HW_ADD = true;
                break;
            case SECORA:
                MIN_RSA_BIT_LENGTH = 1024;
                RSA_SQ = false;
                RSA_PUB = true;
                RSA_EXTRA_MOD = true;
                RSA_APPEND_MOD = true;
                EC_HW_XY = true;
                break;
            default:
                break;
        }
    }
}
