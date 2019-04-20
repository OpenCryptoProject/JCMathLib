package opencrypto.test;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

import javafx.util.Pair;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Security;
import java.util.HashMap;
import java.util.concurrent.ThreadLocalRandom;
import javacard.framework.ISO7816;
import opencrypto.jcmathlib.OCUnitTests;
import opencrypto.jcmathlib.SecP256r1;

/**
 * 
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class TestClient {
    public static boolean _FAIL_ON_ASSERT = false;
    public static int NUM_OP_REPEATS = 10;
    
    // Base length of test inputs (in bits) which corresponds to same length of ECC 
    // E.g., if you like to test 256b ECC, operations with 256b Bignat numbers are performed 
    // Important: applet is compiled with MAX_BIGNAT_SIZE constant which must be large enough to hold intermediate computations. 
    // MAX_BIGNAT_SIZE constant must be at least 2*(ECC_BASE_TEST_LENGTH / 8) + 1.
    public final static int BIGNAT_BASE_TEST_LENGTH = 256; 
    
    public static boolean _TEST_BN = false;
    public static boolean _TEST_INT = true;
    public static boolean _TEST_EC = false;
    
    public static boolean _MEASURE_PERF = false;
    public static boolean _MEASURE_PERF_ONLY_TARGET = false;
    


    static ArrayList<Pair<String, Long>> m_perfResults = new ArrayList<>();

    public static String format = "%-40s:%s%n\n-------------------------------------------------------------------------------\n";

    public static byte[] OPENCRYPTO_UNITTEST_APPLET_AID = {0x55, 0x6e, 0x69, 0x74, 0x54, 0x65, 0x73, 0x74, 0x73};
    public static byte[] APDU_CLEANUP = {OCUnitTests.CLA_OC_UT, OCUnitTests.INS_CLEANUP, (byte) 0x00, (byte) 0x00};
    public static byte[] APDU_GET_PROFILE_LOCKS = {OCUnitTests.CLA_OC_UT, OCUnitTests.INS_GET_PROFILE_LOCKS, (byte) 0x00, (byte) 0x00};


    public static void main(String[] args) throws Exception {
    	try {
            Integer targetReader = 0;
            if (args.length > 0) {
                targetReader = Integer.getInteger(args[0]);
            }

            PerfTests perfTests = new PerfTests();
            if (_MEASURE_PERF) {
                RunConfig runCfg = RunConfig.getConfig(_TEST_BN, _TEST_INT, _TEST_EC, NUM_OP_REPEATS, RunConfig.CARD_TYPE.PHYSICAL);
                runCfg.numRepeats = 1;
                runCfg.targetReaderIndex = targetReader;
                perfTests.RunPerformanceTests(runCfg);
            }
            else if (_MEASURE_PERF_ONLY_TARGET) {
                RunConfig runCfg = RunConfig.getConfig(_TEST_BN, _TEST_INT, _TEST_EC, NUM_OP_REPEATS, RunConfig.CARD_TYPE.PHYSICAL);
                runCfg.targetReaderIndex = targetReader;
                runCfg.bMeasureOnlyTargetOp = true;
                perfTests.RunPerformanceTests(runCfg);
            }
            else {
                RunConfig runCfg = RunConfig.getConfig(_TEST_BN, _TEST_INT, _TEST_EC, NUM_OP_REPEATS, RunConfig.CARD_TYPE.JCARDSIMLOCAL);
                runCfg.targetReaderIndex = targetReader;
                
                // First run debug operations on simulator and real card (if any)
/*              OpenCryptoFunctionalTests_debug(runCfg);
                runCfg.failedTestsList.clear();
                runCfg.testCardType = RunConfig.CARD_TYPE.PHYSICAL;
                OpenCryptoFunctionalTests_debug(runCfg);
                runCfg.failedTestsList.clear();
*/                
                // Run standard tests on simulator then real card (if any)
                //runCfg.testCardType = RunConfig.CARD_TYPE.JCARDSIMLOCAL;
                //OpenCryptoFunctionalTests(runCfg);
                //runCfg.failedTestsList.clear();
                runCfg.testCardType = RunConfig.CARD_TYPE.PHYSICAL;
                OpenCryptoFunctionalTests(runCfg);
                runCfg.failedTestsList.clear();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean OpenCryptoFunctionalTests(RunConfig runCfg) throws Exception {
        try {
            CardManager cardMngr = new CardManager(true, OPENCRYPTO_UNITTEST_APPLET_AID);

            System.out.print("Connecting to card...");
            if (!cardMngr.Connect(runCfg)) {
                return false;
            }
            System.out.println(" Done.");

            System.out.println("\n--------------Unit Tests--------------");

            CommandAPDU cmd;
            ResponseAPDU response;
            String operationName = "";
            boolean bResult = false;

            m_perfResults.clear();
            String logFileName = String.format("OC_PERF_log_%d.csv", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);

            cardMngr.transmit(new CommandAPDU(PerfTests.PERF_COMMAND_NONE));
            cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 

            // Obtain allocated bytes in RAM and EEPROM
            cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_GET_ALLOCATOR_STATS, 0, 0, 0);            
			response = cardMngr.transmit(cmd);
            byte[] data = response.getData();
			System.out.println("2a");			
            System.out.println(String.format("Data allocator: RAM = %d, EEPROM = %d", Util.getShort(data, (short) 0), Util.getShort(data, (short) 2)));
			System.out.println("2b");
            // Print memory snapshots from allocation
            for (int offset = 4; offset < data.length; offset += 6) {
                System.out.println(String.format("Tag '%d': RAM = %d, EEPROM = %d", Util.getShort(data, offset), Util.getShort(data, (short) (offset + 2)), Util.getShort(data, (short) (offset + 4))));
            }

            if (runCfg.bTestBN) {
                operationName = "BigNatural Storage: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_STR, 0, 0, num.toByteArray());
                    performCommand(operationName, cardMngr, cmd, num, perfFile, runCfg.failedTestsList);
                }

                operationName = "BigNatural Addition: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH - 1);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH - 1);//Generate Int2
                    BigInteger result = num1.add(num2); 
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_ADD, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList);
                }

                operationName = "BigNatural Subtraction: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH - 1);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH - 1);//Generate Int2
                    BigInteger result = num1.subtract(num2); 
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_SUB, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList);
                }

                operationName = "BigNatural Multiplication: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int2
                    BigInteger result = num1.multiply(num2); 
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MUL, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList);
                }

                operationName = "BigNatural Multiplication schoolbook: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int2
                    BigInteger result = num1.multiply(num2);
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MUL_SCHOOL, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList);
                }

                operationName = "BigNatural Exponentiation: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH / 4); //Generate Int1		
                    BigInteger num2 = BigInteger.valueOf(3); //Generate Int2
                    BigInteger result = num1.pow(3); 
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_EXP, num1.toByteArray().length, result.toByteArray().length, Util.concat(num1.toByteArray(), num2.toByteArray()));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList);
                }

                operationName = "BigNatural Modulo: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH - 1);//Generate Int2
                    BigInteger result = num1.mod(num2); 
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MOD, (num1.toByteArray()).length, 0, Util.concat((num1.toByteArray()), (num2.toByteArray())));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList, true);
                }
/*                
                operationName = "BigNatural sqrt_FP: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(256);//Generate Int1
                    BigInteger resSqrt = tonelli_shanks(num1, new BigInteger(1, SecP256r1.p));
                    cmd = new CommandAPDU(Configuration.CLA_MPC, Configuration.INS_BN_SQRT, (num1.toByteArray()).length, 0,num1.toByteArray());
                    performCommand(operationName, cardMngr, cmd, resSqrt, perfFile, true);
                }                
/**/
                operationName = "BigNatural Addition (Modulo): ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int2
                    BigInteger num3 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH / 8);//Generate Int3
                    BigInteger result = (num1.add(num2)).mod(num3);
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_ADD_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList, true);
                }

                operationName = "BigNatural Subtraction (Modulo): ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int2
                    BigInteger num3 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH / 8);//Generate Int3
                    BigInteger result = (num1.subtract(num2)).mod(num3);
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_SUB_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList, true);
                }

                operationName = "BigNatural Multiplication (Modulo): ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int1
                    BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int2
                    BigInteger num3 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH / 8);//Generate Int3
                    BigInteger result = (num1.multiply(num2)).mod(num3);
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MUL_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList, true);
                }

                operationName = "BigNatural Exponentiation (Modulo): ";
                int power = 2;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH); //Generate Int1 (base)
                    BigInteger num2 = BigInteger.valueOf(power); //Generate Int2 (exp)
                    BigInteger num3 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int3 (mod)
                    BigInteger result = (num1.modPow(num2, num3));
                    System.out.println(String.format("num1: %s", num1.toString(16)));
                    System.out.println(String.format("num2: %s", num2.toString(16)));
                    System.out.println(String.format("num3: %s", num3.toString(16)));

                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_EXP_MOD, Util.trimLeadingZeroes(num1.toByteArray()).length, Util.trimLeadingZeroes(num2.toByteArray()).length, Util.concat(Util.trimLeadingZeroes(num1.toByteArray()), Util.trimLeadingZeroes(num2.toByteArray()), Util.trimLeadingZeroes(num3.toByteArray())));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList, true);
                }
                
                operationName = "BigNatural Power2 (Modulo): ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH); //Generate Int1 (base)
                    BigInteger mod = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int3 (mod)
                    BigInteger result = (num1.modPow(BigInteger.valueOf(2), mod));

                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_POW2_MOD, Util.trimLeadingZeroes(num1.toByteArray()).length, Util.trimLeadingZeroes(mod.toByteArray()).length, Util.concat(Util.trimLeadingZeroes(num1.toByteArray()), Util.trimLeadingZeroes(mod.toByteArray())));
                    performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList, true);
                }

                operationName = "BigNatural Inversion (Modulo): ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH + BIGNAT_BASE_TEST_LENGTH / 2); //Generate base
                    BigInteger num2 = new BigInteger(1,SecP256r1.p);//Generate mod
                    BigInteger num3 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int3 (mod)
                    System.out.println(String.format("num1: %s", num1.toString(16)));
                    System.out.println(String.format("num2: %s", num2.toString(16)));
                    System.out.println(String.format("num3: %s", num3.toString(16)));
                    BigInteger result = num1.modInverse(num2).multiply(num1).mod(num3);
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_INV_MOD, Util.trimLeadingZeroes(num1.toByteArray()).length, 0, Util.concat(Util.trimLeadingZeroes(num1.toByteArray()), Util.trimLeadingZeroes(num2.toByteArray())));
                    response = cardMngr.transmit(cmd);
                    if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
                        BigInteger respInt = new BigInteger(1, response.getData()).multiply(num1).mod(num3);
                        bResult = result.compareTo(respInt) == 0;

                        if (!bResult) {
                            System.out.println(String.format("Expected: %s", result.toString(16)));
                            System.out.println(String.format("Obtained: %s", respInt.toString(16)));
                        }
                    } else {
                        bResult = false;
                        System.out.println(String.format("fail (0x%x)", response.getSW()));
                    }
                    logResponse(operationName, bResult, cardMngr.m_lastTransmitTime, perfFile, runCfg.failedTestsList);
                    if (!bResult) {
                        String failedAPDU = formatFailedAPDUCmd(cmd);
                        runCfg.failedTestsList.add(failedAPDU);
                    }

                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }
            }

            if (runCfg.bTestINT) {
                operationName = "Integer Storage: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    int num = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_STR, 0, 0, Util.IntToBytes(num));
                    response = cardMngr.transmit(cmd);
                    verifyAndLogResponse(operationName, response, cardMngr.m_lastTransmitTime, num, perfFile, runCfg.failedTestsList);
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }

                operationName = "Integer Addition: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    int num_add_1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_add_2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    //num_add_1 = Integer.MAX_VALUE;
                    //num_add_2 = Integer.MAX_VALUE;
                    int num_add = num_add_1 + num_add_2;

                    //System.out.println("op1   : " + bytesToHex(Util.IntToBytes(num_add_1)));
                    //System.out.println("op2   : " + bytesToHex(Util.IntToBytes(num_add_2)));
                    //System.out.println("result: " + bytesToHex(Util.IntToBytes(num_add)));
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_ADD, Util.IntToBytes(num_add_1).length, 0, Util.concat(Util.IntToBytes(num_add_1), Util.IntToBytes(num_add_2)));
                    response = cardMngr.transmit(cmd);
                    verifyAndLogResponse(operationName, response, cardMngr.m_lastTransmitTime, num_add, perfFile, runCfg.failedTestsList);
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }

                operationName = "Integer Subtraction: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    int num_sub_1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_sub_2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    //num_sub_1 = Integer.MAX_VALUE-1;
                    //num_sub_2 = Integer.MAX_VALUE;
                    int num_sub = num_sub_1 - num_sub_2;
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_SUB, Util.IntToBytes(num_sub_1).length, 0, Util.concat(Util.IntToBytes(num_sub_1), Util.IntToBytes(num_sub_2)));
                    response = cardMngr.transmit(cmd);
                    verifyAndLogResponse(operationName, response, cardMngr.m_lastTransmitTime, num_sub, perfFile, runCfg.failedTestsList);
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }

                operationName = "Integer Multiplication: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    int num_mul_1 = ThreadLocalRandom.current().nextInt((int) (Math.sqrt(Integer.MIN_VALUE)), (int) (Math.sqrt(Integer.MAX_VALUE)));
                    int num_mul_2 = ThreadLocalRandom.current().nextInt((int) (Math.sqrt(Integer.MIN_VALUE)), (int) (Math.sqrt(Integer.MAX_VALUE)));

                    //Avoid overflows
                    int num_mul = 0; //(java int may overflow!!)
                    while (num_mul == 0) {
                        try {
                            num_mul = Math.multiplyExact(num_mul_1, num_mul_2);
                            //num_mul = 6;
                        } catch (Exception e) { // or your specific exception
                        }

                    }
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_MUL, Util.IntToBytes(num_mul_1).length, 0, Util.concat(Util.IntToBytes(num_mul_1), Util.IntToBytes(num_mul_2)));
                    response = cardMngr.transmit(cmd);
                    verifyAndLogResponse(operationName, response, cardMngr.m_lastTransmitTime, num_mul, perfFile, runCfg.failedTestsList);
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }


                operationName = "Integer Division: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    int num_div_1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_div_2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_div = num_div_1 / num_div_2;
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_DIV, Util.IntToBytes(num_div_1).length, 0, Util.concat(Util.IntToBytes(num_div_1), Util.IntToBytes(num_div_2)));
                    response = cardMngr.transmit(cmd);
                    verifyAndLogResponse(operationName, response, cardMngr.m_lastTransmitTime, num_div, perfFile, runCfg.failedTestsList);
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }

                /*
                //14^8 is quite/very close to the max integer value
                System.out.print("Integer Exponentiation: ");
                int base = ThreadLocalRandom.current().nextInt(-14, 14);
                int exp = ThreadLocalRandom.current().nextInt(-8, 8);
                int num_exp = Math.pow(base, exp);
                cmd = new CommandAPDU(Configuration.CLA_MPC, Configuration.INS_INT_DIV, Util.IntToBytes(num_div_1).length, 0, Util.concat(Util.IntToBytes(num_div_1), Util.IntToBytes(num_div_2)));
                response = transmit(cmd);
                System.out.println(BytesToInt(response.getData())==num_div);			}
                */

                operationName = "Integer Modulo: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    int num_mod_1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_mod_2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
                    int num_mod = num_mod_1 % num_mod_2;
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_INT_MOD, Util.IntToBytes(num_mod_1).length, 0, Util.concat(Util.IntToBytes(num_mod_1), Util.IntToBytes(num_mod_2)));
                    response = cardMngr.transmit(cmd);
                    verifyAndLogResponse(operationName, response, cardMngr.m_lastTransmitTime, num_mod, perfFile, runCfg.failedTestsList);
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
               }
            }

            if (runCfg.bTestEC) {
                operationName = "EC Point Generation: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_GEN, 0, 0);
                    response = cardMngr.transmit(cmd);
                    PerfTests.writePerfLog(operationName, response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff), cardMngr.m_lastTransmitTime, m_perfResults, perfFile);
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }

                operationName = "EC Point Add: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    ECPoint pnt_1 = Util.randECPoint();
                    ECPoint pnt_2 = Util.randECPoint();
                    ECPoint pnt_sum = pnt_1.add(pnt_2);
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_ADD, 0, 0, Util.concat(pnt_1.getEncoded(false), pnt_2.getEncoded(false)));
                    response = cardMngr.transmit(cmd);

                    if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
                        bResult = Arrays.equals(pnt_sum.getEncoded(false), response.getData());

                        if (!bResult) {
                            System.out.println(String.format("Expected: %s", Util.toHex(pnt_sum.getEncoded(false))));
                            System.out.println(String.format("Obtained: %s", Util.toHex(response.getData())));
                        }
                    } else {
                        bResult = false;
                        System.out.println(String.format("fail (0x%x)", response.getSW()));
                    }

                    logResponse(operationName, bResult, cardMngr.m_lastTransmitTime, perfFile, runCfg.failedTestsList);
                    if (!bResult) {
                        String failedAPDU = formatFailedAPDUCmd(cmd);
                        runCfg.failedTestsList.add(failedAPDU);
                    }
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }

                operationName = "ECPoint Negation: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    ECPoint pnt = Util.randECPoint();
                    ECPoint negPnt = pnt.negate();
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_NEG, pnt.getEncoded(false).length, 0, pnt.getEncoded(false));
                    response = cardMngr.transmit(cmd);
                    bResult = verifyAndLogResponse(operationName, response, cardMngr.m_lastTransmitTime, negPnt, perfFile, runCfg.failedTestsList);
                    if (!bResult) {
                        String failedAPDU = formatFailedAPDUCmd(cmd);
                        runCfg.failedTestsList.add(failedAPDU);
                    }
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP));
                }

                operationName = "EC scalar_Point Multiplication: ";
                Security.addProvider(new BouncyCastleProvider());
                ECParameterSpec ecSpec2 = ECNamedCurveTable.getParameterSpec("secp256r1");
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    // NOTE: we will keep G same (standard), just keep changing the scalar. 
                    // If you want to test different G, INS_EC_SETCURVE_G must be called before same as for EC Point Double.  
                    ECPoint base = ecSpec2.getG();
                    BigInteger priv1 = Util.randomBigNat(256);
                    ECPoint pub = base.multiply(priv1);
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_MUL, priv1.toByteArray().length, 0, Util.concat(priv1.toByteArray(), base.getEncoded(false)));
                    response = cardMngr.transmit(cmd);
                    if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
                        bResult = Arrays.equals(pub.getEncoded(false), response.getData());
                        if (!bResult) {
                            System.out.println(String.format("Expected: %s", Util.toHex(pub.getEncoded(false))));
                            System.out.println(String.format("Obtained: %s", Util.toHex(response.getData())));
                        }
                    } else {
                        bResult = false;
                        System.out.println(String.format("fail (0x%x)", response.getSW()));
                    }
                    logResponse(operationName, bResult, cardMngr.m_lastTransmitTime, perfFile, runCfg.failedTestsList);
                    if (!bResult) {
                        String failedAPDU = formatFailedAPDUCmd(cmd);
                        runCfg.failedTestsList.add(failedAPDU);
                    }
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }

                operationName = "EC isEqual: ";
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    ECPoint pnt_1 = Util.randECPoint();
                    ECPoint pnt_2 = Util.randECPoint();
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_COMPARE, pnt_1.getEncoded(false).length, pnt_2.getEncoded(false).length, Util.concat(pnt_1.getEncoded(false), pnt_2.getEncoded(false)));
                    response = cardMngr.transmit(cmd);
                    bResult = verifyAndLogResponse(operationName, response, cardMngr.m_lastTransmitTime, 0, perfFile, runCfg.failedTestsList);
                    if (!bResult) {
                        String failedAPDU = formatFailedAPDUCmd(cmd);
                        runCfg.failedTestsList.add(failedAPDU);
                    }
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP));
                }
                
                operationName = "EC Point Double: ";
                Security.addProvider(new BouncyCastleProvider());
                //ECParameterSpec ecSpec2 = ECNamedCurveTable.getParameterSpec("secp256r1");
                boolean bSetRandomG = true;
                boolean bReallocateWholeCurve = false;
                for (int repeat = 0; repeat < runCfg.numRepeats; repeat++) {
                    System.out.println(String.format("%s (%d)", operationName, repeat));
                    ECPoint pnt;
                    if (bSetRandomG) {
                        pnt = Util.randECPoint();
                        System.out.println(String.format("Random ECPoint == G: %s", Util.toHex(pnt.getEncoded(false))));
                        // Set modified parameter G of the curve (our random point)    
                        cardMngr.transmit(new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_SETCURVE_G, pnt.getEncoded(false).length, bReallocateWholeCurve ? (byte) 1 : (byte) 0, pnt.getEncoded(false)));
                    } else {
                        pnt = ecSpec2.getG();
                    }

                    ECPoint doubled = pnt.add(pnt); // expected results
                    // Perform EC double operation    
                    cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_DBL, 0, 0, pnt.getEncoded(false));
                    try {
                        response = cardMngr.transmit(cmd);
                        if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
                            bResult = Arrays.equals(doubled.getEncoded(false), response.getData());
                            if (!bResult) {
                                System.out.println(String.format("Expected: %s", Util.toHex(doubled.getEncoded(false))));
                                System.out.println(String.format("Obtained: %s", Util.toHex(response.getData())));
                            }
                        } else {
                            bResult = false;
                            System.out.println(String.format("fail (0x%x)", response.getSW()));
                        }
                    } catch (Exception e) {
                        bResult = false;
                        e.printStackTrace();
                    }
                    logResponse(operationName, bResult, cardMngr.m_lastTransmitTime, perfFile, runCfg.failedTestsList);
                    if (!bResult) {
                        String failedAPDU = formatFailedAPDUCmd(cmd);
                        runCfg.failedTestsList.add(failedAPDU);
                    }
                    cardMngr.transmit(new CommandAPDU(APDU_CLEANUP)); 
                }                
            }

            System.out.println("\n--------------Unit Tests--------------\n\n");

            cardMngr.transmit(new CommandAPDU(APDU_GET_PROFILE_LOCKS));
            
            
            System.out.print("Disconnecting from card...");
            cardMngr.Disconnect(true);
            System.out.println(" Done.");

            if (runCfg.failedTestsList.size() > 0) {
                System.out.println("#########################");
                System.out.println("!!! SOME TESTS FAILED !!!");
                System.out.println("#########################");
                for (String test : runCfg.failedTestsList) {
                    System.out.println(test);
                }

                printFailedTestStats(runCfg);

            }
            else {
                System.out.println("##########################");
                System.out.println("ALL TESTS PASSED CORRECTLY");
                System.out.println("##########################");            
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }
    
    
    static void OpenCryptoFunctionalTests_debug(RunConfig runCfg) throws Exception {
        try {
            CardManager cardMngr = new CardManager(true, OPENCRYPTO_UNITTEST_APPLET_AID);
            System.out.print("Connecting to card...");
            cardMngr.Connect(runCfg);
            System.out.println(" Done.");

            m_perfResults.clear();

            cardMngr.transmit(new CommandAPDU(PerfTests.PERF_COMMAND_NONE));
            cardMngr.transmit(new CommandAPDU(APDU_CLEANUP));

            String logFileName = String.format("OC_PERF_log_%d.csv", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);

            CommandAPDU cmd;
            ResponseAPDU response;
            String operationName = "";
            boolean bResult = false;
            

            System.out.println("\n-------------- Problematic inputs tests --------------");
/*
            // TODO: add code for debugging
            operationName = "BigNatural Multiplication schoolbook: ";
            for (int repeat = 0; repeat < 10; repeat++) {
                System.out.println(String.format("%s (%d)", operationName, repeat));
                BigInteger num1 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int1
                BigInteger num2 = Util.randomBigNat(BIGNAT_BASE_TEST_LENGTH);//Generate Int2
                BigInteger result = num1.multiply(num2);
                cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MUL, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
                performCommand(operationName, cardMngr, cmd, result, perfFile, runCfg.failedTestsList);
            }
            int a=0;
/*            
            operationName = "EC Point Add: ";
            for (int repeat = 0; repeat < 1000000; repeat++) {
                System.out.println(String.format("%s (%d)", operationName, repeat));
                ECPoint pnt_1 = Util.randECPoint();
                ECPoint pnt_2 = Util.randECPoint();
                ECPoint pnt_sum = pnt_1.add(pnt_2);
                cmd = new CommandAPDU(Consts.CLA_OC_UT, Consts.INS_EC_ADD, 0, 0, Util.concat(pnt_1.getEncoded(false), pnt_2.getEncoded(false)));
                response = cardMngr.transmit(cmd);

                if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
                    byte[] x = pnt_sum.getXCoord().getEncoded();
                    byte[] y = pnt_sum.getYCoord().getEncoded();
                    x = pnt_sum.getEncoded(false);
                    bResult = Arrays.equals(pnt_sum.getEncoded(false), response.getData());

                    if (!bResult) {
                        System.out.println(String.format("Expected: %s", Util.toHex(pnt_sum.getEncoded(false))));
                        System.out.println(String.format("Obtained: %s", Util.toHex(response.getData())));
                    }
                } else {
                    bResult = false;
                    System.out.println(String.format("fail (0x%x)", response.getSW()));
                }    
            }
*/        
            
            System.out.println("\n-------------- Problematic inputs tests --------------\n\n");

            System.out.print("Disconnecting from card...");
            cardMngr.Disconnect(true);
            System.out.println(" Done.");

            if (runCfg.failedTestsList.size() > 0) {
                System.out.println("#########################");
                System.out.println("!!! SOME TESTS FAILED !!!");
                System.out.println("#########################");
                for (String test : runCfg.failedTestsList) {
                    System.out.println(test);
                }

                printFailedTestStats(runCfg);
            } else {
                System.out.println("##########################");
                System.out.println("ALL TESTS PASSED CORRECTLY");
                System.out.println("##########################");
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }    
    
    static HashMap<String, Integer> printFailedTestStats(RunConfig runCfg) {
        // Parse failed tests, output statistics
        HashMap<String, Integer> numFailsTest = new HashMap<>();
        for (String test : runCfg.failedTestsList) {
            if (!test.contains("failedCommand")) { // ignore output of apdu
                if (numFailsTest.containsKey(test)) {
                    Integer count = numFailsTest.get(test);
                    count++;
                    numFailsTest.replace(test, count);
                } else {
                    numFailsTest.put(test, 1);
                }
            }
        }

        System.out.println("\n***FAILED TESTS STATS***");
        for (String test : numFailsTest.keySet()) {
            System.out.println(String.format("%40s: %d / %d", test, numFailsTest.get(test), runCfg.numRepeats));
        }      
        System.out.println("************************\n");
        
        return numFailsTest;
    }

    
    interface CmdResultsComparator {
        public boolean compare(ResponseAPDU response);  
    }
    
    class ArrayMatchComparator implements CmdResultsComparator {
        ECPoint m_expected = null;
        ArrayMatchComparator(ECPoint expected) {
            this.m_expected = expected;
        }
        public boolean compare(ResponseAPDU response) {
            boolean bResult = false;
            if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
                bResult = Arrays.equals(m_expected.getEncoded(), response.getData());
            } else {
                bResult = false;
                System.out.println(String.format("fail (0x%x)", response.getSW()));
            }
            return bResult;
        }
    }
    
    static String formatFailedAPDUCmd(CommandAPDU failedCommand) {
        // If command corectness verification failed, then output for easy resend during debugging later
        byte[] failedcmd = failedCommand.getBytes();
        String failedAPDU = String.format("\tcardMngr.transmit(new CommandAPDU(hexStringToByteArray(\"%s\")));", Util.bytesToHex(failedcmd));
        failedAPDU += "\n\tstatic byte[] failedCommand = {";
        for (int i = 0; i < failedcmd.length; i++) {
            failedAPDU += String.format("(byte) 0x%x", failedcmd[i]);
            if (i != failedcmd.length - 1) {
                failedAPDU += ", ";
            }
        }
        failedAPDU += "};";
        failedAPDU += "\n\t";
        
        return failedAPDU;
    }
    static void performCommand(String operationName, CardManager cardManager, CommandAPDU command, BigInteger expectedResult, FileOutputStream perfFile, ArrayList<String> failedTestsList) throws CardException, IOException {
        performCommand(operationName, cardManager, command, expectedResult, perfFile, failedTestsList, false);
    }

    static void performCommand(String operationName, CardManager cardManager, CommandAPDU command, BigInteger expectedResult, FileOutputStream perfFile, ArrayList<String> failedTestsList, boolean bSigNum) throws CardException, IOException {
        ResponseAPDU response = cardManager.transmit(command);
        boolean bSuccess = false;
        
        if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
            byte[] data = response.getData();
            BigInteger respInt;
            if (bSigNum) { respInt = new BigInteger(1, data); } 
            else { respInt = new BigInteger(data); }

            bSuccess = expectedResult.compareTo(respInt) == 0;

            if (!bSuccess) {
                System.out.println(String.format("Expected: %s", expectedResult.toString(16)));
                System.out.println(String.format("Obtained: %s", respInt.toString(16)));
            }
        } else {
            System.out.println(String.format("fail (0x%x)", response.getSW()));
        }

        logResponse(operationName, bSuccess, cardManager.m_lastTransmitTime, perfFile, failedTestsList);

        if (!bSuccess) {
            String failedAPDU = formatFailedAPDUCmd(command);
            failedTestsList.add(failedAPDU);
        }

        cardManager.transmit(new CommandAPDU(APDU_CLEANUP)); 
    }
 
    static boolean verifyAndLogResponse(String operationName, ResponseAPDU response, Long lastTransmitTime, int expected, FileOutputStream perfFile, ArrayList<String> failedTestsList) throws IOException {
        boolean bResult = false;
        if (response.getSW () == (ISO7816.SW_NO_ERROR & 0xffff)) {
            bResult = Util.BytesToInt(response.getData()) == expected;
        }
        else {
            System.out.println(String.format("fail (0x%x)", response.getSW()));
        }
        logResponse(operationName, bResult, lastTransmitTime, perfFile, failedTestsList);
        return bResult;
    }
    static boolean verifyAndLogResponse(String operationName, ResponseAPDU response, Long lastTransmitTime, ECPoint expected, FileOutputStream perfFile, ArrayList<String> failedTestsList) throws IOException {
        boolean bResult = false;
        if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
            bResult = Arrays.equals(expected.getEncoded(false), response.getData());
            if (!bResult) {
                System.out.println(String.format("Expected: %s", Util.toHex(expected.getEncoded(false))));
                System.out.println(String.format("Obtained: %s", Util.toHex(response.getData())));
            }
        } else {
            bResult = false;
            System.out.println(String.format("fail (0x%x)", response.getSW()));
        }
        logResponse(operationName, bResult, lastTransmitTime, perfFile, failedTestsList);
        return bResult;
    }    
    
    static void logResponse(String operationName, boolean bResult, Long lastTransmitTime, FileOutputStream perfFile, ArrayList<String> failedTestsList) throws IOException {
        System.out.println(String.format("%s [%d ms]", bResult, lastTransmitTime));
        if (bResult == false && _FAIL_ON_ASSERT) {
            assert (bResult);
        }
        if (bResult == false) {
            // Add name of failed operation 
            failedTestsList.add(operationName);
        }
        PerfTests.writePerfLog(operationName, bResult, lastTransmitTime, m_perfResults, perfFile);
    }
    
}







