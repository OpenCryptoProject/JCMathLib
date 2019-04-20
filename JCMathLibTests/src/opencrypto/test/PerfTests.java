package opencrypto.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javacard.framework.ISO7816;
import javafx.util.Pair;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import opencrypto.jcmathlib.OCUnitTests;
import opencrypto.jcmathlib.PM;
import opencrypto.jcmathlib.SecP256r1;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
* @author Petr Svenda
 */
public class PerfTests {
    public static HashMap<Short, String> PERF_STOP_MAPPING = new HashMap<>();
    public static byte[] PERF_COMMAND = {OCUnitTests.CLA_OC_UT, OCUnitTests.INS_PERF_SETSTOP, 0, 0, 2, 0, 0};
    public static byte[] APDU_RESET = {(byte) 0xB0, (byte) 0x03, (byte) 0x00, (byte) 0x00};
    public static final byte[] PERF_COMMAND_NONE = {OCUnitTests.CLA_OC_UT, OCUnitTests.INS_PERF_SETSTOP, 0, 0, 2, 0, 0};
    
    static final String PERF_TRAP_CALL = "PM.check(PM.";
    static final String PERF_TRAP_CALL_END = ");";
    
    boolean MODIFY_SOURCE_FILES_BY_PERF = true;

    class PerfConfig {
        public String cardName = "noCardName";
        public FileOutputStream perfFile = null;
        public ArrayList<Pair<String, Long>> perfResultsSingleOp = new ArrayList<>();
        public ArrayList<String> perfResultsSubparts = new ArrayList<>();
        public HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw = new HashMap<>(); // hashmap with key being perf trap id, folowed by pair <prevTrapID, elapsedTimeFromPrev>
        public boolean bMeasurePerf = true;
        public short[] perfStops = null;
        public short perfStopComplete = -1;
        public ArrayList<String> failedPerfTraps = new ArrayList<>();
    }    

    PerfTests() {
        buildPerfMapping();        
    }
    
    void printOperationAverageTime(String opName, RunConfig runCfg, PerfConfig perfCfg) {
        if (runCfg.bMeasureOnlyTargetOp) {
            long avgOpTimeFirst = 0;
            long avgOpTimeSecond = 0;
            // Compute average for first stop
            
            System.out.println(String.format("Average time: %d", avgOpTimeSecond - avgOpTimeFirst));
        }
    }
    void RunPerformanceTests(RunConfig runCfg) throws Exception {
        PerfConfig cfg = new PerfConfig();
        cfg.cardName = "gd60";
        String experimentID = String.format("%d", System.currentTimeMillis());
        cfg.perfFile = new FileOutputStream(String.format("OC_PERF_log_%s.csv", experimentID));

        try {
            CardManager cardMngr = new CardManager(true, TestClient.OPENCRYPTO_UNITTEST_APPLET_AID);
            System.out.print("Connecting to card...");
            runCfg.testCardType = RunConfig.CARD_TYPE.JCARDSIMLOCAL;
            //runCfg.testCardType = RunConfig.CARD_TYPE.PHYSICAL;
            cardMngr.Connect(runCfg);
            System.out.println(" Done.");

            cardMngr.transmit(new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 
            cardMngr.transmit(new CommandAPDU(APDU_RESET));


            if (runCfg.bTestBN) {
                short[] PERFSTOPS_BigNatural_Addition = {PM.TRAP_BN_ADD_1, PM.TRAP_BN_ADD_2, PM.TRAP_BN_ADD_3, PM.TRAP_BN_ADD_4, PM.TRAP_BN_ADD_5, PM.TRAP_BN_ADD_6, PM.TRAP_BN_ADD_7, PM.TRAP_BN_ADD_COMPLETE};
                short[] PERFSTOPS_BigNatural_Addition_onlyTarget = {PM.TRAP_BN_ADD_6, PM.TRAP_BN_ADD_7};
                cfg.perfStops = runCfg.bMeasureOnlyTargetOp ? PERFSTOPS_BigNatural_Addition_onlyTarget : PERFSTOPS_BigNatural_Addition;
                cfg.perfStopComplete = PM.TRAP_BN_ADD_COMPLETE;
                long avgOpTime = 0;
                String opName = "BigNatural Addition: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength - 1);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(runCfg.bnBaseTestLength - 1);//Generate Int2
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_ADD, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    avgOpTime += PerfAnalyzeCommand(opName, cmd, cardMngr, cfg);
                }
                printOperationAverageTime(opName, runCfg, cfg);
                System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numRepeats));
                
                short[] PERFSTOPS_BigNatural_Subtraction = {PM.TRAP_BN_SUB_1, PM.TRAP_BN_SUB_2, PM.TRAP_BN_SUB_3, PM.TRAP_BN_SUB_4, PM.TRAP_BN_SUB_5, PM.TRAP_BN_SUB_6, PM.TRAP_BN_SUB_7, PM.TRAP_BN_SUB_COMPLETE};
                short[] PERFSTOPS_BigNatural_Subtraction_onlyTarget = {PM.TRAP_BN_SUB_6, PM.TRAP_BN_SUB_7};
                cfg.perfStops = runCfg.bMeasureOnlyTargetOp ? PERFSTOPS_BigNatural_Subtraction_onlyTarget : PERFSTOPS_BigNatural_Subtraction;
                cfg.perfStopComplete = PM.TRAP_BN_SUB_COMPLETE;
                avgOpTime = 0;
                opName = "BigNatural Subtraction: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(runCfg.bnBaseTestLength - 1);//Generate Int2
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_SUB, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    avgOpTime += PerfAnalyzeCommand(opName, cmd, cardMngr, cfg);
                }
                System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numRepeats));

                short[] PERFSTOPS_BigNatural_Multiplication = {PM.TRAP_BN_MUL_1, PM.TRAP_BN_MUL_2, PM.TRAP_BN_MUL_3, PM.TRAP_BN_MUL_4, PM.TRAP_BN_MUL_5, PM.TRAP_BN_MUL_6, PM.TRAP_BN_MUL_COMPLETE};
                short[] PERFSTOPS_BigNatural_Multiplication_onlyTarget = {PM.TRAP_BN_MUL_5, PM.TRAP_BN_MUL_6};
                cfg.perfStops = runCfg.bMeasureOnlyTargetOp ? PERFSTOPS_BigNatural_Multiplication_onlyTarget : PERFSTOPS_BigNatural_Multiplication;
                cfg.perfStopComplete = PM.TRAP_BN_MUL_COMPLETE;
                avgOpTime = 0;
                opName = "BigNatural Multiplication: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength / 2);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(runCfg.bnBaseTestLength / 2);//Generate Int2
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MUL, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    avgOpTime += PerfAnalyzeCommand(opName, cmd, cardMngr, cfg);
                }
                System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numRepeats));
                
                
                short[] PERFSTOPS_Bignat_sqrt = {PM.TRAP_BIGNAT_SQRT_1, PM.TRAP_BIGNAT_SQRT_2, PM.TRAP_BIGNAT_SQRT_3, PM.TRAP_BIGNAT_SQRT_4, PM.TRAP_BIGNAT_SQRT_5, PM.TRAP_BIGNAT_SQRT_6, PM.TRAP_BIGNAT_SQRT_7, PM.TRAP_BIGNAT_SQRT_8, PM.TRAP_BIGNAT_SQRT_9, PM.TRAP_BIGNAT_SQRT_10, PM.TRAP_BIGNAT_SQRT_11, PM.TRAP_BIGNAT_SQRT_12, PM.TRAP_BIGNAT_SQRT_13, PM.TRAP_BIGNAT_SQRT_14, PM.TRAP_BIGNAT_SQRT_15, PM.TRAP_BIGNAT_SQRT_COMPLETE};
                short[] PERFSTOPS_Bignat_sqrt_onlyTarget = {PM.TRAP_BIGNAT_SQRT_1, PM.TRAP_BIGNAT_SQRT_2, PM.TRAP_BIGNAT_SQRT_3, PM.TRAP_BIGNAT_SQRT_4, PM.TRAP_BIGNAT_SQRT_5, PM.TRAP_BIGNAT_SQRT_6, PM.TRAP_BIGNAT_SQRT_7, PM.TRAP_BIGNAT_SQRT_8, PM.TRAP_BIGNAT_SQRT_9, PM.TRAP_BIGNAT_SQRT_10, PM.TRAP_BIGNAT_SQRT_11, PM.TRAP_BIGNAT_SQRT_12, PM.TRAP_BIGNAT_SQRT_13, PM.TRAP_BIGNAT_SQRT_14, PM.TRAP_BIGNAT_SQRT_15, PM.TRAP_BIGNAT_SQRT_COMPLETE};
                cfg.perfStops = runCfg.bMeasureOnlyTargetOp ? PERFSTOPS_Bignat_sqrt_onlyTarget : PERFSTOPS_Bignat_sqrt;
                cfg.perfStopComplete = PM.TRAP_BIGNAT_SQRT_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num = Util.randomBigNat(runCfg.bnBaseTestLength);//Generate Int
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_SQRT, num.toByteArray().length, 0, num.toByteArray());
                    PerfAnalyzeCommand("Bignat_sqrt_FP: ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_BigNatural_Storage = {PM.TRAP_BN_STR_1, PM.TRAP_BN_STR_2, PM.TRAP_BN_STR_3, PM.TRAP_BN_STR_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Storage;
                cfg.perfStopComplete = PM.TRAP_BN_STR_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num = Util.randomBigNat(runCfg.bnBaseTestLength / 2);//Generate Int
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_STR, 0, 0, num.toByteArray());
                    PerfAnalyzeCommand("BigNatural Storage: ", cmd, cardMngr, cfg);
                }


                short[] PERFSTOPS_BigNatural_Exponentiation = {PM.TRAP_BN_EXP_1, PM.TRAP_BN_EXP_2, PM.TRAP_BN_EXP_3, PM.TRAP_BN_EXP_4, PM.TRAP_BN_EXP_5, PM.TRAP_BN_EXP_6, PM.TRAP_BN_EXP_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Exponentiation;
                cfg.perfStopComplete = PM.TRAP_BN_EXP_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = BigInteger.valueOf(14); //Generate Int1		
                    BigInteger num2 = BigInteger.valueOf(8); //Generate Int2
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_EXP, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    PerfAnalyzeCommand("BigNatural Exponentiation: ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_BigNatural_Modulo = {PM.TRAP_BN_MOD_1, PM.TRAP_BN_MOD_2, PM.TRAP_BN_MOD_3, PM.TRAP_BN_MOD_4, PM.TRAP_BN_MOD_5, PM.TRAP_BN_MOD_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Modulo;
                cfg.perfStopComplete = PM.TRAP_BN_MOD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(runCfg.bnBaseTestLength - 1);//Generate Int2
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MOD, (num1.toByteArray()).length, 0, Util.concat((num1.toByteArray()), (num2.toByteArray())));
                    PerfAnalyzeCommand("BigNatural Modulo: ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_BigNatural_Addition__Modulo_ = {PM.TRAP_BN_ADD_MOD_1, PM.TRAP_BN_ADD_MOD_2, PM.TRAP_BN_ADD_MOD_3, PM.TRAP_BN_ADD_MOD_4, PM.TRAP_BN_ADD_MOD_5, PM.TRAP_BN_ADD_MOD_6, PM.TRAP_BN_ADD_MOD_7, PM.TRAP_BN_ADD_MOD_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Addition__Modulo_;
                cfg.perfStopComplete = PM.TRAP_BN_ADD_MOD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(runCfg.bnBaseTestLength);//Generate Int2
                    BigInteger num3 = Util.randomBigNat(runCfg.bnBaseTestLength / 8);//Generate Int3
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_ADD_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
                    PerfAnalyzeCommand("BigNatural Addition (Modulo): ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_BigNatural_Subtraction__Modulo_ = {PM.TRAP_BN_SUB_MOD_1, PM.TRAP_BN_SUB_MOD_2, PM.TRAP_BN_SUB_MOD_3, PM.TRAP_BN_SUB_MOD_4, PM.TRAP_BN_SUB_MOD_5, PM.TRAP_BN_SUB_MOD_6, PM.TRAP_BN_SUB_MOD_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Subtraction__Modulo_;
                cfg.perfStopComplete = PM.TRAP_BN_SUB_MOD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength / 2);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(runCfg.bnBaseTestLength);//Generate Int2
                    BigInteger num3 = Util.randomBigNat(runCfg.bnBaseTestLength / 8);//Generate Int3
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_SUB_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
                    PerfAnalyzeCommand("BigNatural Subtraction (Modulo): ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_BigNatural_Multiplication__Modulo_ = {PM.TRAP_BN_MUL_MOD_1, PM.TRAP_BN_MUL_MOD_2, PM.TRAP_BN_MUL_MOD_3, PM.TRAP_BN_MUL_MOD_4, PM.TRAP_BN_MUL_MOD_5, PM.TRAP_BN_MUL_MOD_6, PM.TRAP_BN_MUL_MOD_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Multiplication__Modulo_;
                cfg.perfStopComplete = PM.TRAP_BN_MUL_MOD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength / 2);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(runCfg.bnBaseTestLength / 2);//Generate Int2
                    BigInteger num3 = Util.randomBigNat(runCfg.bnBaseTestLength / 8);//Generate Int3
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MUL_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
                    PerfAnalyzeCommand("BigNatural Multiplication (Modulo): ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_BigNatural_Exponentiation__Modulo_ = {PM.TRAP_BN_EXP_MOD_1, PM.TRAP_BN_EXP_MOD_2, PM.TRAP_BN_EXP_MOD_3, PM.TRAP_BN_EXP_MOD_4, PM.TRAP_BN_EXP_MOD_5, PM.TRAP_BN_EXP_MOD_6, PM.TRAP_BN_EXP_MOD_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Exponentiation__Modulo_;
                cfg.perfStopComplete = PM.TRAP_BN_EXP_MOD_COMPLETE;
                int power = 2;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength); //Generate Int1 (base)
                    BigInteger num2 = BigInteger.valueOf(power); //Generate Int2 (exp)
                    BigInteger num3 = Util.randomBigNat(runCfg.bnBaseTestLength);//Generate Int3 (mod)
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_EXP_MOD, Util.trimLeadingZeroes(num1.toByteArray()).length, Util.trimLeadingZeroes(num2.toByteArray()).length, Util.concat(Util.trimLeadingZeroes(num1.toByteArray()), Util.trimLeadingZeroes(num2.toByteArray()), Util.trimLeadingZeroes(num3.toByteArray())));
                    PerfAnalyzeCommand("BigNatural Exponentiation (Modulo): ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_BigNatural_Pow2__Modulo_ = {PM.TRAP_BN_POW2_MOD_1, PM.TRAP_BN_POW2_MOD_2, PM.TRAP_BN_POW2_MOD_3, PM.TRAP_BN_POW2_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Pow2__Modulo_;
                cfg.perfStopComplete = PM.TRAP_BN_POW2_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength); //Generate Int1 (base)
                    BigInteger mod = Util.randomBigNat(runCfg.bnBaseTestLength);//Generate Int3 (mod)
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_POW2_MOD, Util.trimLeadingZeroes(num1.toByteArray()).length, Util.trimLeadingZeroes(mod.toByteArray()).length, Util.concat(Util.trimLeadingZeroes(num1.toByteArray()), Util.trimLeadingZeroes(mod.toByteArray())));
                    PerfAnalyzeCommand("BigNatural Power2 (Modulo): ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_BigNatural_Inversion__Modulo_ = {PM.TRAP_BN_INV_MOD_1, PM.TRAP_BN_INV_MOD_2, PM.TRAP_BN_INV_MOD_3, PM.TRAP_BN_INV_MOD_4, PM.TRAP_BN_INV_MOD_5, PM.TRAP_BN_INV_MOD_COMPLETE};
                cfg.perfStops = PERFSTOPS_BigNatural_Inversion__Modulo_;
                cfg.perfStopComplete = PM.TRAP_BN_INV_MOD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    BigInteger num1 = Util.randomBigNat(runCfg.bnBaseTestLength + runCfg.bnBaseTestLength / 2); //Generate base
                    BigInteger num2 = new BigInteger(1, SecP256r1.p);//Generate mod
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_INV_MOD, Util.trimLeadingZeroes(num1.toByteArray()).length, 0, Util.concat(Util.trimLeadingZeroes(num1.toByteArray()), Util.trimLeadingZeroes(num2.toByteArray())));
                    PerfAnalyzeCommand("BigNatural Inversion (Modulo): ", cmd, cardMngr, cfg);        
                }

            }

            if (runCfg.bTestINT) {
                short[] PERFSTOPS_Integer_Storage = {PM.TRAP_INT_STR_1, PM.TRAP_INT_STR_2, PM.TRAP_INT_STR_COMPLETE};
                cfg.perfStops = PERFSTOPS_Integer_Storage;
                cfg.perfStopComplete = PM.TRAP_INT_STR_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    int num = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_STR, 0, 0, Util.IntToBytes(num));
                    PerfAnalyzeCommand("Integer Storage: ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_Integer_Addition = {PM.TRAP_INT_ADD_1, PM.TRAP_INT_ADD_2, PM.TRAP_INT_ADD_3, PM.TRAP_INT_ADD_4, PM.TRAP_INT_ADD_COMPLETE};
                cfg.perfStops = PERFSTOPS_Integer_Addition;
                cfg.perfStopComplete = PM.TRAP_INT_ADD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    int num_add_1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_add_2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);

                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_ADD, Util.IntToBytes(num_add_1).length, 0, Util.concat(Util.IntToBytes(num_add_1), Util.IntToBytes(num_add_2)));
                    PerfAnalyzeCommand("Integer Addition: ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_Integer_Subtraction = {PM.TRAP_INT_SUB_1, PM.TRAP_INT_SUB_2, PM.TRAP_INT_SUB_3, PM.TRAP_INT_SUB_COMPLETE};
                cfg.perfStops = PERFSTOPS_Integer_Subtraction;
                cfg.perfStopComplete = PM.TRAP_INT_SUB_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    int num_sub_1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_sub_2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_SUB, Util.IntToBytes(num_sub_1).length, 0, Util.concat(Util.IntToBytes(num_sub_1), Util.IntToBytes(num_sub_2)));
                    PerfAnalyzeCommand("Integer Subtraction: ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_Integer_Multiplication = {PM.TRAP_INT_MUL_1, PM.TRAP_INT_MUL_2, PM.TRAP_INT_MUL_3, PM.TRAP_INT_MUL_COMPLETE};
                cfg.perfStops = PERFSTOPS_Integer_Multiplication;
                cfg.perfStopComplete = PM.TRAP_INT_MUL_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    int num_mul_1 = ThreadLocalRandom.current().nextInt((int) (Math.sqrt(Integer.MIN_VALUE)), (int) (Math.sqrt(Integer.MAX_VALUE)));
                    int num_mul_2 = ThreadLocalRandom.current().nextInt((int) (Math.sqrt(Integer.MIN_VALUE)), (int) (Math.sqrt(Integer.MAX_VALUE)));
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_MUL, Util.IntToBytes(num_mul_1).length, 0, Util.concat(Util.IntToBytes(num_mul_1), Util.IntToBytes(num_mul_2)));
                    PerfAnalyzeCommand("Integer Multiplication: ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_Integer_Division = {PM.TRAP_INT_DIV_1, PM.TRAP_INT_DIV_2, PM.TRAP_INT_DIV_3, PM.TRAP_INT_DIV_COMPLETE};
                cfg.perfStops = PERFSTOPS_Integer_Division;
                cfg.perfStopComplete = PM.TRAP_INT_DIV_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    int num_div_1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_div_2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_DIV, Util.IntToBytes(num_div_1).length, 0, Util.concat(Util.IntToBytes(num_div_1), Util.IntToBytes(num_div_2)));
                    PerfAnalyzeCommand("Integer Division: ", cmd, cardMngr, cfg);
                }
    /*
                short[] PERFSTOPS_Integer_Exponentiation = {PerfMeasure.TRAP_INT_EXP_1, PerfMeasure.TRAP_INT_EXP_2, PerfMeasure.TRAP_INT_EXP_3, PerfMeasure.TRAP_INT_EXP_4, PerfMeasure.TRAP_INT_EXP_COMPLETE};
                cfg.perfStops = PERFSTOPS_Integer_Exponentiation;
                cfg.perfStopComplete = PerfMeasure.TRAP_INT_EXP_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    PerfAnalyzeCommand("Integer Exponentiation: ", cmd, cardMngr, cfg);
                }
    */
                short[] PERFSTOPS_Integer_Modulo = {PM.TRAP_INT_MOD_1, PM.TRAP_INT_MOD_2, PM.TRAP_INT_MOD_3, PM.TRAP_INT_MOD_COMPLETE};
                cfg.perfStops = PERFSTOPS_Integer_Modulo;
                cfg.perfStopComplete = PM.TRAP_INT_MOD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    int num_mod_1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_mod_2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_MOD, Util.IntToBytes(num_mod_1).length, 0, Util.concat(Util.IntToBytes(num_mod_1), Util.IntToBytes(num_mod_2)));
                    PerfAnalyzeCommand("Integer Modulo: ", cmd, cardMngr, cfg);
                }
            }

            if (runCfg.bTestECPoint) {
                // Details of ECPoint
                
/*                
                short[] PERFSTOPS_ECPoint_multiplication_double = {PerfMeasure.TRAP_ECPOINT_MULT_1, PerfMeasure.TRAP_ECPOINT_MULT_2, PerfMeasure.TRAP_ECPOINT_MULT_3, PerfMeasure.TRAP_ECPOINT_MULT_4, PerfMeasure.TRAP_ECPOINT_MULT_5, PerfMeasure.TRAP_ECPOINT_MULT_6, PerfMeasure.TRAP_ECPOINT_MULT_7, PerfMeasure.TRAP_ECPOINT_MULT_8, PerfMeasure.TRAP_ECPOINT_MULT_9, PerfMeasure.TRAP_ECPOINT_MULT_10, PerfMeasure.TRAP_ECPOINT_MULT_11, PerfMeasure.TRAP_ECPOINT_MULT_12, PerfMeasure.TRAP_ECPOINT_MULT_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPoint_multiplication_double;
                cfg.perfStopComplete = PerfMeasure.TRAP_ECPOINT_MULT_COMPLETE;
/**/
                /*
                short[] PERFSTOPS_ECPoint_multiplication_x2 = {PerfMeasure.TRAP_ECPOINT_MULT_X_1, PerfMeasure.TRAP_ECPOINT_MULT_X_2, PerfMeasure.TRAP_ECPOINT_MULT_X_3, PerfMeasure.TRAP_ECPOINT_MULT_X_4, PerfMeasure.TRAP_ECPOINT_MULT_X_5, PerfMeasure.TRAP_ECPOINT_MULT_X_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPoint_multiplication_x2;
                cfg.perfStopComplete = PerfMeasure.TRAP_ECPOINT_MULT_X_COMPLETE;
*/                
/*                
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    ECPoint pnt = Util.randECPoint();
                    System.out.println(String.format("Random ECPoint == G: %s", Util.toHex(pnt.getEncoded(false))));
                    // Set modified parameter G of the curve (our random point)    
                    cardMngr.transmit(new CommandAPDU(Configuration.CLA_MPC, Configuration.INS_EC_SETCURVE_G, 0, 0, pnt.getEncoded(false)));

                    CommandAPDU cmd = new CommandAPDU(Configuration.CLA_MPC, Configuration.INS_EC_DBL, 0, 0, pnt.getEncoded(false));
                    PerfAnalyzeCommand("ECPoint_double: ", cmd, cardMngr, cfg);
                }
*/
                short[] PERFSTOPS_ECPoint_multiplication = {PM.TRAP_ECPOINT_MULT_1, PM.TRAP_ECPOINT_MULT_2, PM.TRAP_ECPOINT_MULT_3, PM.TRAP_ECPOINT_MULT_4, PM.TRAP_ECPOINT_MULT_5, PM.TRAP_ECPOINT_MULT_6, PM.TRAP_ECPOINT_MULT_7, PM.TRAP_ECPOINT_MULT_8, PM.TRAP_ECPOINT_MULT_9, PM.TRAP_ECPOINT_MULT_10, PM.TRAP_ECPOINT_MULT_11, PM.TRAP_ECPOINT_MULT_12, PM.TRAP_ECPOINT_MULT_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPoint_multiplication;
                cfg.perfStopComplete = PM.TRAP_ECPOINT_MULT_COMPLETE;
                Security.addProvider(new BouncyCastleProvider());
                ECParameterSpec ecSpec2 = ECNamedCurveTable.getParameterSpec("secp256r1");
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    ECPoint pnt = ecSpec2.getG(); // Use standard G point
                    BigInteger scalar = Util.randomBigNat(runCfg.bnBaseTestLength);
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_MUL, scalar.toByteArray().length, 0, Util.concat(scalar.toByteArray(), pnt.getEncoded(false)));
                    PerfAnalyzeCommand("ECPoint_multiplication: ", cmd, cardMngr, cfg);
                }

                short[] PERFSTOPS_ECPoint_add = {PM.TRAP_ECPOINT_ADD_1, PM.TRAP_ECPOINT_ADD_2, PM.TRAP_ECPOINT_ADD_3, PM.TRAP_ECPOINT_ADD_4, PM.TRAP_ECPOINT_ADD_5, PM.TRAP_ECPOINT_ADD_6, PM.TRAP_ECPOINT_ADD_7, PM.TRAP_ECPOINT_ADD_8, PM.TRAP_ECPOINT_ADD_9, PM.TRAP_ECPOINT_ADD_10, PM.TRAP_ECPOINT_ADD_11, PM.TRAP_ECPOINT_ADD_12, PM.TRAP_ECPOINT_ADD_13, PM.TRAP_ECPOINT_ADD_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPoint_add;
                cfg.perfStopComplete = PM.TRAP_ECPOINT_ADD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    ECPoint pnt_1 = Util.randECPoint();
                    ECPoint pnt_2 = Util.randECPoint();
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_ADD, 0, 0, Util.concat(pnt_1.getEncoded(), pnt_2.getEncoded()));
                    //CommandAPDU cmd = new CommandAPDU(hexStringToByteArray("B041000041041D1D96E2B171DFCC457587259E28E597258BF86EA0CFCB97BB6FCE62E7539E2879F3FDE52075AACAD1BA7637F816B6145C01E646831C259409FB89309AB03FD9"));
                    PerfAnalyzeCommand("ECPoint_add: ", cmd, cardMngr, cfg);
                }

                // Details of ECCurve
    /*            
                 short[] PERFSTOPS_ECCurve_newKeyPair = {PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_1, PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_2, PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_3, PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_4, PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_5, PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_6, PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_7, PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_COMPLETE};
                 cfg.perfStops = PERFSTOPS_ECCurve_newKeyPair;
                 cfg.perfStopComplete = PerfMeasure.TRAP_ECCURVE_NEWKEYPAIR_COMPLETE;
                 for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                 CommandAPDU cmd = new CommandAPDU(Configuration.CLA_MPC, Configuration.INS_EC_GEN, 0, 0);
                 PerfAnalyzeCommand("ECCurve_newKeyPair: ", cmd, cardMngr, cfg);
                 }
                 */

                short[] PERFSTOPS_ECPoint_multiplication_x = {PM.TRAP_ECPOINT_MULT_X_1, PM.TRAP_ECPOINT_MULT_X_2, PM.TRAP_ECPOINT_MULT_X_3, PM.TRAP_ECPOINT_MULT_X_4, PM.TRAP_ECPOINT_MULT_X_5, PM.TRAP_ECPOINT_MULT_X_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPoint_multiplication_x;
                cfg.perfStopComplete = PM.TRAP_ECPOINT_MULT_X_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    ECPoint pnt = ecSpec2.getG(); // Use standard G point
                    BigInteger scalar = Util.randomBigNat(runCfg.bnBaseTestLength);
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_MUL, scalar.toByteArray().length, 0, Util.concat(scalar.toByteArray(), pnt.getEncoded(false)));
                    PerfAnalyzeCommand("ECPoint_multiplication_x: ", cmd, cardMngr, cfg);
                }


                short[] PERFSTOPS_ECPoint_negate = {PM.TRAP_ECPOINT_NEGATE_1, PM.TRAP_ECPOINT_NEGATE_2, PM.TRAP_ECPOINT_NEGATE_3, PM.TRAP_ECPOINT_NEGATE_4, PM.TRAP_ECPOINT_NEGATE_5, PM.TRAP_ECPOINT_NEGATE_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPoint_negate;
                cfg.perfStopComplete = PM.TRAP_ECPOINT_NEGATE_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    ECPoint pnt = Util.randECPoint();
                    ECPoint negPnt = pnt.negate();
                    CommandAPDU cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_NEG, pnt.getEncoded(false).length, 0, pnt.getEncoded(false));
                    PerfAnalyzeCommand("ECPoint_negate: ", cmd, cardMngr, cfg);
                }
            }

            if (runCfg.bTestEC) {
                short[] PERFSTOPS_ECPOINT_GEN = {PM.TRAP_EC_GEN_1, PM.TRAP_EC_GEN_2, PM.TRAP_EC_GEN_3, PM.TRAP_EC_GEN_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPOINT_GEN;
                cfg.perfStopComplete = PM.TRAP_EC_GEN_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    PerfAnalyzeCommand("EC Point Generation: ", new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_GEN, 0, 0), cardMngr, cfg);
                }

                short[] PERFSTOPS_ECPOINT_ADD = {PM.TRAP_EC_ADD_1, PM.TRAP_EC_ADD_2, PM.TRAP_EC_ADD_3, PM.TRAP_EC_ADD_4, PM.TRAP_EC_ADD_5, PM.TRAP_EC_ADD_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPOINT_ADD;
                cfg.perfStopComplete = PM.TRAP_EC_ADD_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    ECPoint pnt_1 = Util.randECPoint();
                    ECPoint pnt_2 = Util.randECPoint();
                    PerfAnalyzeCommand("EC Point Add: ", new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_ADD, 0, 0, Util.concat(pnt_1.getEncoded(), pnt_2.getEncoded())), cardMngr, cfg);
                }

                short[] PERFSTOPS_EC_scalar_point_multiplication = {PM.TRAP_EC_MUL_1, PM.TRAP_EC_MUL_2, PM.TRAP_EC_MUL_3, PM.TRAP_EC_MUL_4, PM.TRAP_EC_MUL_5, PM.TRAP_EC_MUL_COMPLETE};
                cfg.perfStops = PERFSTOPS_EC_scalar_point_multiplication;
                cfg.perfStopComplete = PM.TRAP_EC_MUL_COMPLETE;
                Security.addProvider(new BouncyCastleProvider());
                ECParameterSpec ecSpec2 = ECNamedCurveTable.getParameterSpec("secp256r1");
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    ECPoint base = ecSpec2.getG();
                    Random rnd = new Random();
                    BigInteger priv1 = new BigInteger(runCfg.bnBaseTestLength, rnd);
                    PerfAnalyzeCommand("EC scalar-point multiplication: ", new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_MUL, priv1.toByteArray().length, 0, Util.concat(priv1.toByteArray(), base.getEncoded(false))), cardMngr, cfg);
                }         
                
                short[] PERFSTOPS_ECPOINT_DOUBLE = {PM.TRAP_EC_DBL_1, PM.TRAP_EC_DBL_2, PM.TRAP_EC_DBL_3, PM.TRAP_EC_DBL_4, PM.TRAP_EC_DBL_COMPLETE};
                cfg.perfStops = PERFSTOPS_ECPOINT_DOUBLE;
                cfg.perfStopComplete = PM.TRAP_EC_DBL_COMPLETE;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    ECPoint pnt = Util.randECPoint();
                    System.out.println(String.format("Random ECPoint == G: %s", Util.toHex(pnt.getEncoded(false))));
                    // Set modified parameter G of the curve (our random point)    
                    cardMngr.transmit(new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_SETCURVE_G, 0, 0, pnt.getEncoded(false)));

                    PerfAnalyzeCommand("EC Point Double: ", new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_DBL, 0, 0, pnt.getEncoded()), cardMngr, cfg);
                }
            }

        
            System.out.println("\n-------------- Performance tests--------------\n\n");
            System.out.print("Disconnecting from card...");
            cardMngr.Disconnect(true); // Disconnect from the card
            System.out.println(" Done.");
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        if (cfg.failedPerfTraps.size() > 0) {
            System.out.println("#########################");
            System.out.println("!!! SOME PERFORMANCE TRAPS NOT REACHED !!!");
            System.out.println("#########################");
            for (String trap : cfg.failedPerfTraps) {
                System.out.println(trap);
            }
        } else {
            System.out.println("##########################");
            System.out.println("ALL PERFORMANCE TRAPS REACHED CORRECTLY");
            System.out.println("##########################");
        }       
        
        // Save performance traps into single file
        String perfFileName = String.format("TRAP_RAW_%s.csv", experimentID);
        SavePerformanceResults(cfg.perfResultsSubpartsRaw, perfFileName);
                
        // If required, modification of source code files is attempted
        if (MODIFY_SOURCE_FILES_BY_PERF) {
            String dirPath = "..\\!PerfSRC\\Lib\\";
            InsertPerfInfoIntoFiles(dirPath, cfg.cardName, experimentID, cfg.perfResultsSubpartsRaw);
        }
    }    
    
    static void SavePerformanceResults(HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw, String fileName) throws FileNotFoundException, IOException {
        // Save performance traps into single file
        FileOutputStream perfLog = new FileOutputStream(fileName);
        String output = "perfID, previous perfID, time difference between perfID and previous perfID (ms)\n";
        perfLog.write(output.getBytes());
        for (Short perfID : perfResultsSubpartsRaw.keySet()) {
            output = String.format("%d, %d, %d\n", perfID, perfResultsSubpartsRaw.get(perfID).getKey(), perfResultsSubpartsRaw.get(perfID).getValue());
            perfLog.write(output.getBytes());
        }
        perfLog.close();
    }
    
    static void LoadPerformanceResults(String fileName, HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw) throws FileNotFoundException, IOException {
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        String strLine;
        while ((strLine = br.readLine()) != null) {
            if (strLine.contains("perfID,")) {
                // skip header line
            }
            else {
                String[] cols = strLine.split(",");
                Short perfID = Short.parseShort(cols[0].trim());
                Short prevPerfID = Short.parseShort(cols[1].trim());
                Long elapsed = Long.parseLong(cols[2].trim());
                
                perfResultsSubpartsRaw.put(perfID, new Pair(prevPerfID, elapsed));
            }
        }
        br.close();
    }    
    
    static void testInsertPerfIntoFiles() throws IOException {
        String dirPath = "..\\!PerfSRC\\Lib\\";
        HashMap<Short, Pair<Short, Long>> results = new HashMap<>(); 
        results.put(PM.TRAP_EC_ADD_2, new Pair(PM.TRAP_EC_ADD_1, 37));
        results.put(PM.TRAP_EC_GEN_3, new Pair(PM.TRAP_EC_GEN_2, 123));
        results.put(PM.TRAP_EC_DBL_2, new Pair(PM.TRAP_EC_DBL_1, 567));

        String perfFileName = String.format("TRAP_RAW_123456.csv");
        SavePerformanceResults(results, perfFileName);
        HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw = new HashMap<>();
        LoadPerformanceResults(perfFileName, perfResultsSubpartsRaw);
        assert (perfResultsSubpartsRaw.size() == results.size());
        
        InsertPerfInfoIntoFiles(dirPath, "test", "123456", results);
    }
    
    long PerfAnalyzeCommand(String operationName, CommandAPDU cmd, CardManager cardMngr, PerfConfig cfg) throws CardException, IOException {
        System.out.println(operationName);
        short prevPerfStop = PM.PERF_START;
        long prevTransmitTime = 0;
        long lastFromPrevTime = 0;
        try {
            for (short perfStop : cfg.perfStops) {
                System.arraycopy(Util.shortToByteArray(perfStop), 0, PERF_COMMAND, ISO7816.OFFSET_CDATA, 2); // set required stop condition
                String operationNamePerf = String.format("%s_%s", operationName, getPerfStopName(perfStop));
                cardMngr.transmit(new CommandAPDU(PERF_COMMAND)); // set performance trap
                ResponseAPDU response = cardMngr.transmit(cmd); // execute target operation
                boolean bFailedToReachTrap = false;
                if (perfStop != cfg.perfStopComplete) { // Check expected error to be equal performance trap
                    if (response.getSW() != (perfStop & 0xffff)) {
                        // we have not reached expected performance trap
                        cfg.failedPerfTraps.add(getPerfStopName(perfStop));
                        bFailedToReachTrap = true;
                    }
                }
                writePerfLog(operationNamePerf, response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff), cardMngr.m_lastTransmitTime, cfg.perfResultsSingleOp, cfg.perfFile);
                long fromPrevTime = cardMngr.m_lastTransmitTime - prevTransmitTime;
                if (bFailedToReachTrap) {
                    cfg.perfResultsSubparts.add(String.format("[%s-%s], \tfailed to reach after %d ms (0x%x)", getPerfStopName(prevPerfStop), getPerfStopName(perfStop), cardMngr.m_lastTransmitTime, response.getSW()));
                }
                else {
                    cfg.perfResultsSubparts.add(String.format("[%s-%s], \t%d ms", getPerfStopName(prevPerfStop), getPerfStopName(perfStop), fromPrevTime));
                    cfg.perfResultsSubpartsRaw.put(perfStop, new Pair(prevPerfStop, fromPrevTime)); 
                    lastFromPrevTime = fromPrevTime;
                }

                prevPerfStop = perfStop;
                prevTransmitTime = cardMngr.m_lastTransmitTime;

                cardMngr.transmit(new CommandAPDU(APDU_RESET)); // free memory after command
            }
        }
        catch (Exception e) {
            // Print what we have measured so far
            for (String res : cfg.perfResultsSubparts) {
                System.out.println(res);
            }
            throw e;
        }
        // Print measured performance info
        for (String res : cfg.perfResultsSubparts) {
            System.out.println(res);
        }
        
        return lastFromPrevTime;
    }    
    
    
    static void writePerfLog(String operationName, boolean bResult, Long time, ArrayList<Pair<String, Long>> perfResults, FileOutputStream perfFile) throws IOException {
        perfResults.add(new Pair(operationName, time));
        perfFile.write(String.format("%s,%d,%s\n", operationName, time, bResult).getBytes());
        perfFile.flush();
    }
    
    
    static void InsertPerfInfoIntoFiles(String basePath, String cardName, String experimentID, HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw) throws FileNotFoundException, IOException {
        File dir = new File(basePath);
        String[] filesArray = dir.list();
        if ((filesArray != null) && (dir.isDirectory() == true)) {
            // make subdir for results
            String outputDir = String.format("%s\\perf\\%s\\", basePath, experimentID);
            new File(outputDir).mkdirs();

            for (String fileName : filesArray) {
                File dir2 = new File(basePath + fileName);
                if (!dir2.isDirectory()) {
                    InsertPerfInfoIntoFile(String.format("%s\\%s", basePath, fileName), cardName, experimentID, outputDir, perfResultsSubpartsRaw);
                }
            }
        }
    }
    
    static void InsertPerfInfoIntoFile(String filePath, String cardName, String experimentID, String outputDir, HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw) throws FileNotFoundException, IOException {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filePath));
            String basePath = filePath.substring(0, filePath.lastIndexOf("\\"));
            String fileName = filePath.substring(filePath.lastIndexOf("\\"));
            
            String fileNamePerf = String.format("%s\\%s", outputDir, fileName);
            FileOutputStream fileOut = new FileOutputStream(fileNamePerf);
            String strLine;
            String resLine;
            // For every line of program try to find perfromance trap. If found and perf. is available, then insert comment into code
            while ((strLine = br.readLine()) != null) {
                
                if (strLine.contains(PERF_TRAP_CALL)) {
                    int trapStart = strLine.indexOf(PERF_TRAP_CALL);
                    int trapEnd = strLine.indexOf(PERF_TRAP_CALL_END);
                    // We have perf. trap, now check if we also corresponding measurement
                    String perfTrapName = (String) strLine.substring(trapStart + PERF_TRAP_CALL.length(), trapEnd);
                    short perfID = getPerfStopFromName(perfTrapName);
                    
                    if (perfResultsSubpartsRaw.containsKey(perfID)) {
                        // We have measurement for this trap, add into comment section
                        resLine = String.format("%s // %d ms (%s,%s) %s", (String) strLine.substring(0, trapEnd + PERF_TRAP_CALL_END.length()), perfResultsSubpartsRaw.get(perfID).getValue(), cardName, experimentID, (String) strLine.subSequence(trapEnd + PERF_TRAP_CALL_END.length(), strLine.length()));
                    }
                    else {
                        resLine = strLine;
                    }
                }
                else {
                    resLine = strLine;
                }
                resLine += "\n";
                fileOut.write(resLine.getBytes());
            }
            
            fileOut.close();
        }
        catch(Exception e) {
            System.out.println(String.format("Failed to transform file %s ", filePath) + e);
        }
    }
    

    public static void buildPerfMapping() {
        PERF_STOP_MAPPING.put(PM.PERF_START, "PERF_START");
        //PERF_STOP_MAPPING.put(PerfMeasure.PERF_COMPLETE, "PERF_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_EC_GEN_1, "TRAP_EC_GEN_1");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_GEN_2, "TRAP_EC_GEN_2");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_GEN_3, "TRAP_EC_GEN_3");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_GEN_COMPLETE, "TRAP_EC_GEN_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_EC_DBL_1, "TRAP_EC_DBL_1");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_DBL_2, "TRAP_EC_DBL_2");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_DBL_3, "TRAP_EC_DBL_3");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_DBL_4, "TRAP_EC_DBL_4");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_DBL_COMPLETE, "TRAP_EC_DBL_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_EC_MUL_1, "TRAP_EC_MUL_1");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_MUL_2, "TRAP_EC_MUL_2");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_MUL_3, "TRAP_EC_MUL_3");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_MUL_4, "TRAP_EC_MUL_4");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_MUL_5, "TRAP_EC_MUL_5");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_MUL_6, "TRAP_EC_MUL_6");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_MUL_COMPLETE, "TRAP_EC_MUL_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_EC_ADD_1, "TRAP_EC_ADD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_ADD_2, "TRAP_EC_ADD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_ADD_3, "TRAP_EC_ADD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_ADD_4, "TRAP_EC_ADD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_ADD_5, "TRAP_EC_ADD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_ADD_COMPLETE, "TRAP_EC_ADD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_STR_1, "TRAP_BN_STR_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_STR_2, "TRAP_BN_STR_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_STR_3, "TRAP_BN_STR_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_STR_COMPLETE, "TRAP_BN_STR_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_1, "TRAP_BN_ADD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_2, "TRAP_BN_ADD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_3, "TRAP_BN_ADD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_4, "TRAP_BN_ADD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_5, "TRAP_BN_ADD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_6, "TRAP_BN_ADD_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_7, "TRAP_BN_ADD_7");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_COMPLETE, "TRAP_BN_ADD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_1, "TRAP_BN_SUB_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_2, "TRAP_BN_SUB_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_3, "TRAP_BN_SUB_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_4, "TRAP_BN_SUB_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_5, "TRAP_BN_SUB_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_6, "TRAP_BN_SUB_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_7, "TRAP_BN_SUB_7");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_COMPLETE, "TRAP_BN_SUB_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_1, "TRAP_BN_MUL_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_2, "TRAP_BN_MUL_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_3, "TRAP_BN_MUL_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_4, "TRAP_BN_MUL_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_5, "TRAP_BN_MUL_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_6, "TRAP_BN_MUL_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_COMPLETE, "TRAP_BN_MUL_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_1, "TRAP_BN_EXP_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_2, "TRAP_BN_EXP_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_3, "TRAP_BN_EXP_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_4, "TRAP_BN_EXP_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_5, "TRAP_BN_EXP_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_6, "TRAP_BN_EXP_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_COMPLETE, "TRAP_BN_EXP_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_MOD_1, "TRAP_BN_MOD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MOD_2, "TRAP_BN_MOD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MOD_3, "TRAP_BN_MOD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MOD_4, "TRAP_BN_MOD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MOD_5, "TRAP_BN_MOD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MOD_COMPLETE, "TRAP_BN_MOD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_MOD_1, "TRAP_BN_ADD_MOD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_MOD_2, "TRAP_BN_ADD_MOD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_MOD_3, "TRAP_BN_ADD_MOD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_MOD_4, "TRAP_BN_ADD_MOD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_MOD_5, "TRAP_BN_ADD_MOD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_MOD_6, "TRAP_BN_ADD_MOD_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_MOD_7, "TRAP_BN_ADD_MOD_7");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_ADD_MOD_COMPLETE, "TRAP_BN_ADD_MOD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_MOD_1, "TRAP_BN_SUB_MOD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_MOD_2, "TRAP_BN_SUB_MOD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_MOD_3, "TRAP_BN_SUB_MOD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_MOD_4, "TRAP_BN_SUB_MOD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_MOD_5, "TRAP_BN_SUB_MOD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_MOD_6, "TRAP_BN_SUB_MOD_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_SUB_MOD_COMPLETE, "TRAP_BN_SUB_MOD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_MOD_1, "TRAP_BN_MUL_MOD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_MOD_2, "TRAP_BN_MUL_MOD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_MOD_3, "TRAP_BN_MUL_MOD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_MOD_4, "TRAP_BN_MUL_MOD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_MOD_5, "TRAP_BN_MUL_MOD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_MOD_6, "TRAP_BN_MUL_MOD_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_MUL_MOD_COMPLETE, "TRAP_BN_MUL_MOD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_MOD_1, "TRAP_BN_EXP_MOD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_MOD_2, "TRAP_BN_EXP_MOD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_MOD_3, "TRAP_BN_EXP_MOD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_MOD_4, "TRAP_BN_EXP_MOD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_MOD_5, "TRAP_BN_EXP_MOD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_MOD_6, "TRAP_BN_EXP_MOD_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_EXP_MOD_COMPLETE, "TRAP_BN_EXP_MOD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_INV_MOD_1, "TRAP_BN_INV_MOD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_INV_MOD_2, "TRAP_BN_INV_MOD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_INV_MOD_3, "TRAP_BN_INV_MOD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_INV_MOD_4, "TRAP_BN_INV_MOD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_INV_MOD_5, "TRAP_BN_INV_MOD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_INV_MOD_COMPLETE, "TRAP_BN_INV_MOD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_INT_STR_1, "TRAP_INT_STR_1");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_STR_2, "TRAP_INT_STR_2");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_STR_COMPLETE, "TRAP_INT_STR_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_INT_ADD_1, "TRAP_INT_ADD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_ADD_2, "TRAP_INT_ADD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_ADD_3, "TRAP_INT_ADD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_ADD_4, "TRAP_INT_ADD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_ADD_COMPLETE, "TRAP_INT_ADD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_INT_SUB_1, "TRAP_INT_SUB_1");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_SUB_2, "TRAP_INT_SUB_2");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_SUB_3, "TRAP_INT_SUB_3");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_SUB_4, "TRAP_INT_SUB_4");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_SUB_COMPLETE, "TRAP_INT_SUB_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_INT_MUL_1, "TRAP_INT_MUL_1");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_MUL_2, "TRAP_INT_MUL_2");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_MUL_3, "TRAP_INT_MUL_3");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_MUL_4, "TRAP_INT_MUL_4");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_MUL_COMPLETE, "TRAP_INT_MUL_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_INT_DIV_1, "TRAP_INT_DIV_1");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_DIV_2, "TRAP_INT_DIV_2");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_DIV_3, "TRAP_INT_DIV_3");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_DIV_4, "TRAP_INT_DIV_4");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_DIV_COMPLETE, "TRAP_INT_DIV_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_INT_EXP_1, "TRAP_INT_EXP_1");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_EXP_2, "TRAP_INT_EXP_2");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_EXP_3, "TRAP_INT_EXP_3");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_EXP_4, "TRAP_INT_EXP_4");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_EXP_COMPLETE, "TRAP_INT_EXP_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_INT_MOD_1, "TRAP_INT_MOD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_MOD_2, "TRAP_INT_MOD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_MOD_3, "TRAP_INT_MOD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_MOD_4, "TRAP_INT_MOD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_INT_MOD_COMPLETE, "TRAP_INT_MOD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BN_POW2_MOD_1, "TRAP_BN_POW2_MOD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_POW2_MOD_2, "TRAP_BN_POW2_MOD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_POW2_MOD_3, "TRAP_BN_POW2_MOD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BN_POW2_COMPLETE, "TRAP_BN_POW2_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_ECCURVE_NEWKEYPAIR_1, "TRAP_ECCURVE_NEWKEYPAIR_1");
        PERF_STOP_MAPPING.put(PM.TRAP_ECCURVE_NEWKEYPAIR_2, "TRAP_ECCURVE_NEWKEYPAIR_2");
        PERF_STOP_MAPPING.put(PM.TRAP_ECCURVE_NEWKEYPAIR_3, "TRAP_ECCURVE_NEWKEYPAIR_3");
        PERF_STOP_MAPPING.put(PM.TRAP_ECCURVE_NEWKEYPAIR_4, "TRAP_ECCURVE_NEWKEYPAIR_4");
        PERF_STOP_MAPPING.put(PM.TRAP_ECCURVE_NEWKEYPAIR_5, "TRAP_ECCURVE_NEWKEYPAIR_5");
        PERF_STOP_MAPPING.put(PM.TRAP_ECCURVE_NEWKEYPAIR_6, "TRAP_ECCURVE_NEWKEYPAIR_6");
        PERF_STOP_MAPPING.put(PM.TRAP_ECCURVE_NEWKEYPAIR_7, "TRAP_ECCURVE_NEWKEYPAIR_7");
        PERF_STOP_MAPPING.put(PM.TRAP_ECCURVE_NEWKEYPAIR_COMPLETE, "TRAP_ECCURVE_NEWKEYPAIR_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_1, "TRAP_ECPOINT_ADD_1");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_2, "TRAP_ECPOINT_ADD_2");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_3, "TRAP_ECPOINT_ADD_3");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_4, "TRAP_ECPOINT_ADD_4");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_5, "TRAP_ECPOINT_ADD_5");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_6, "TRAP_ECPOINT_ADD_6");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_7, "TRAP_ECPOINT_ADD_7");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_8, "TRAP_ECPOINT_ADD_8");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_9, "TRAP_ECPOINT_ADD_9");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_10, "TRAP_ECPOINT_ADD_10");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_11, "TRAP_ECPOINT_ADD_11");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_12, "TRAP_ECPOINT_ADD_12");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_13, "TRAP_ECPOINT_ADD_13");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_ADD_COMPLETE, "TRAP_ECPOINT_ADD_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_1, "TRAP_ECPOINT_MULT_1");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_2, "TRAP_ECPOINT_MULT_2");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_3, "TRAP_ECPOINT_MULT_3");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_4, "TRAP_ECPOINT_MULT_4");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_5, "TRAP_ECPOINT_MULT_5");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_6, "TRAP_ECPOINT_MULT_6");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_7, "TRAP_ECPOINT_MULT_7");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_8, "TRAP_ECPOINT_MULT_8");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_9, "TRAP_ECPOINT_MULT_9");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_10, "TRAP_ECPOINT_MULT_10");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_11, "TRAP_ECPOINT_MULT_11");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_12, "TRAP_ECPOINT_MULT_12");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_COMPLETE, "TRAP_ECPOINT_MULT_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_X_1, "TRAP_ECPOINT_MULT_X_1");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_X_2, "TRAP_ECPOINT_MULT_X_2");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_X_3, "TRAP_ECPOINT_MULT_X_3");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_X_4, "TRAP_ECPOINT_MULT_X_4");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_X_5, "TRAP_ECPOINT_MULT_X_5");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_MULT_X_COMPLETE, "TRAP_ECPOINT_MULT_X_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_NEGATE_1, "TRAP_ECPOINT_NEGATE_1");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_NEGATE_2, "TRAP_ECPOINT_NEGATE_2");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_NEGATE_3, "TRAP_ECPOINT_NEGATE_3");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_NEGATE_4, "TRAP_ECPOINT_NEGATE_4");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_NEGATE_5, "TRAP_ECPOINT_NEGATE_5");
        PERF_STOP_MAPPING.put(PM.TRAP_ECPOINT_NEGATE_COMPLETE, "TRAP_ECPOINT_NEGATE_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_1, "TRAP_BIGNAT_SQRT_1");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_2, "TRAP_BIGNAT_SQRT_2");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_3, "TRAP_BIGNAT_SQRT_3");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_4, "TRAP_BIGNAT_SQRT_4");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_5, "TRAP_BIGNAT_SQRT_5");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_6, "TRAP_BIGNAT_SQRT_6");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_7, "TRAP_BIGNAT_SQRT_7");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_8, "TRAP_BIGNAT_SQRT_8");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_9, "TRAP_BIGNAT_SQRT_9");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_10, "TRAP_BIGNAT_SQRT_10");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_11, "TRAP_BIGNAT_SQRT_11");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_12, "TRAP_BIGNAT_SQRT_12");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_13, "TRAP_BIGNAT_SQRT_13");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_14, "TRAP_BIGNAT_SQRT_14");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_15, "TRAP_BIGNAT_SQRT_15");
        PERF_STOP_MAPPING.put(PM.TRAP_BIGNAT_SQRT_COMPLETE, "TRAP_BIGNAT_SQRT_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_EC_SETCURVE_1, "TRAP_EC_SETCURVE_1");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_SETCURVE_2, "TRAP_EC_SETCURVE_2");
        PERF_STOP_MAPPING.put(PM.TRAP_EC_SETCURVE_COMPLETE, "TRAP_EC_SETCURVE_COMPLETE");
    }

    public static String getPerfStopName(short stopID) {
        if (PERF_STOP_MAPPING.containsKey(stopID)) {
            return PERF_STOP_MAPPING.get(stopID);
        } else {
            assert (false);
            return "PERF_UNDEFINED";
        }
    }

    public static short getPerfStopFromName(String stopName) {
        for (Short stopID : PERF_STOP_MAPPING.keySet()) {
            if (PERF_STOP_MAPPING.get(stopID).equalsIgnoreCase(stopName)) {
                return stopID;
            }
        }
        assert (false);
        return PM.TRAP_UNDEFINED;
    }
    

}
