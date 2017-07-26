package opencrypto.jcmathlib;

import javacard.framework.ISOException;

/**
 * Utility class for performance profiling. Contains definition of performance trap 
 * constants and trap reaction method. 
* @author Petr Svenda
 */
public class PM {
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
