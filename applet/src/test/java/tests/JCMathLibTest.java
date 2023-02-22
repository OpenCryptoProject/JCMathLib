package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.ISO7816;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import opencrypto.jcmathlib.UnitTests;
import opencrypto.jcmathlib.SecP256r1;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * JCMathLib Unit Tests
 *
 * @author Petr Svenda and Antonin Dufka
 */
public class JCMathLibTest extends BaseTest {
    public static byte[] APDU_CLEANUP = {UnitTests.CLA_OC_UT, UnitTests.INS_CLEANUP, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    public static int BIGNAT_BIT_LENGTH = 256;

    public JCMathLibTest() throws Exception {
        this.setCardType(CardType.JCARDSIMLOCAL);
        this.setSimulateStateful(true);
        statefulCard = connect();
        statefulCard.transmit(new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_INITIALIZE, 0, 0));
    }

    @Test
    public void allocationInfo() throws Exception {
        // Obtain allocated bytes in RAM and EEPROM
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_GET_ALLOCATOR_STATS, 0, 0, new byte[1]);
        ResponseAPDU response = statefulCard.transmit(cmd);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, response.getSW());
        byte[] data = response.getData();
        System.out.printf("Data allocator: RAM = %d, EEPROM = %d%n", Util.getShort(data, (short) 0), Util.getShort(data, (short) 2));
        // Print memory snapshots from allocation
        for (int offset = 4; offset < data.length; offset += 6) {
            System.out.printf("Tag '%d': RAM = %d, EEPROM = %d%n", Util.getShort(data, offset), Util.getShort(data, (short) (offset + 2)), Util.getShort(data, (short) (offset + 4)));
        }
    }

    @Test
    public void eccGen() throws Exception {
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_GEN, 0, 0, new byte[1]);
        ResponseAPDU resp = statefulCard.transmit(cmd);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccAdd() throws Exception {
        ECPoint point1 = randECPoint();
        ECPoint point2 = randECPoint();
        ECPoint sum = point1.add(point2);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_ADD, 0, 0, Util.concat(point1.getEncoded(false), point2.getEncoded(false)));
        ResponseAPDU resp = statefulCard.transmit(cmd);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertArrayEquals(sum.getEncoded(false), resp.getData());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccNegation() throws Exception {
        CardManager cardMngr = connect();
        ECPoint point = randECPoint();
        ECPoint negated = point.negate();
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_NEG, point.getEncoded(false).length, 0, point.getEncoded(false));
        ResponseAPDU resp = cardMngr.transmit(cmd);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertArrayEquals(negated.getEncoded(false), resp.getData());
        cardMngr.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccMultiplyGenerator() throws Exception {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPoint point = ecSpec.getG();
        BigInteger scalar = randomBigNat(256);
        ECPoint result = point.multiply(scalar);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_MUL, scalar.toByteArray().length, 0, Util.concat(scalar.toByteArray(), point.getEncoded(false)));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertArrayEquals(result.getEncoded(false), resp.getData());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccMultiplyRandom() throws Exception {
        ECPoint point = randECPoint();
        BigInteger scalar = randomBigNat(256);
        ECPoint result = point.multiply(scalar);
        // Set modified parameter G of the curve (our random point)
        int rc = statefulCard.transmit(new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_SET_CURVE_G, point.getEncoded(false).length, 0, point.getEncoded(false))).getSW();
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, rc);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_MUL, scalar.toByteArray().length, 0, Util.concat(scalar.toByteArray(), point.getEncoded(false)));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertArrayEquals(result.getEncoded(false), resp.getData());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccIsEqual() throws Exception {
        ECPoint point1 = randECPoint();
        ECPoint point2 = randECPoint();
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_COMPARE, point1.getEncoded(false).length, point2.getEncoded(false).length, Util.concat(point1.getEncoded(false), point2.getEncoded(false)));
        ResponseAPDU resp = statefulCard.transmit(cmd);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccDoubleGenerator() throws Exception {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPoint point = ecSpec.getG();
        ECPoint doubled = point.add(point);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_DBL, 0, 0, point.getEncoded(false));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertArrayEquals(doubled.getEncoded(false), resp.getData());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccDoubleRandom() throws Exception {
        ECPoint point = randECPoint();
        ECPoint doubled = point.add(point);
        // Set modified parameter G of the curve (our random point)
        int rc = statefulCard.transmit(new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_SET_CURVE_G, point.getEncoded(false).length, 0, point.getEncoded(false))).getSW();
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, rc);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_DBL, 0, 0, point.getEncoded(false));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertArrayEquals(doubled.getEncoded(false), resp.getData());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccFromX() throws Exception {
        CardManager cardMngr = connect();
        ECPoint point = randECPoint();
        ECPoint negated = point.negate();
        byte[] xCoord = point.getXCoord().getEncoded();
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_FROM_X, xCoord.length, 0, xCoord);
        ResponseAPDU resp = cardMngr.transmit(cmd);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertTrue(Arrays.equals(point.getEncoded(false), resp.getData()) || Arrays.equals(negated.getEncoded(false), resp.getData()));
        cardMngr.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void eccIsYEven() throws Exception {
        CardManager cardMngr = connect();
        ECPoint point = randECPoint();
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_IS_Y_EVEN, point.getEncoded(false).length, 0, point.getEncoded(false));
        ResponseAPDU resp = cardMngr.transmit(cmd);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(point.getYCoord().toBigInteger().mod(BigInteger.valueOf(2)).intValue() == 0 ? 1 : 0, resp.getData()[0]);
        cardMngr.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatStorage() throws Exception {
        BigInteger num = randomBigNat(BIGNAT_BIT_LENGTH);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_STR, 0, 0, num.toByteArray());
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatAddition() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH - 1);
        BigInteger num2 = randomBigNat(BIGNAT_BIT_LENGTH - 1);
        BigInteger result = num1.add(num2);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_ADD, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatSubtraction() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH - 1);
        BigInteger num2 = randomBigNat(BIGNAT_BIT_LENGTH - 1);
        BigInteger result = num1.subtract(num2);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_SUB, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Disabled("Does not work in simulator")
    @Test
    public void bigNatMultiplication() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num2 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger result = num1.multiply(num2);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_MUL, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatMultiplicationSlow() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num2 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger result = num1.multiply(num2);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_MUL_SCHOOL, num1.toByteArray().length, 0, Util.concat(num1.toByteArray(), num2.toByteArray()));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatExponentiation() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH / 4);
        BigInteger num2 = BigInteger.valueOf(3);
        BigInteger result = num1.pow(3);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_EXP, num1.toByteArray().length, result.toByteArray().length, Util.concat(num1.toByteArray(), num2.toByteArray()));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatModulo() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num2 = randomBigNat(BIGNAT_BIT_LENGTH - 1);
        BigInteger result = num1.mod(num2);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_MOD, (num1.toByteArray()).length, 0, Util.concat((num1.toByteArray()), (num2.toByteArray())));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Disabled("Needs fix")
    @Test
    public void bigNatModSqrt() throws Exception {
        BigInteger num = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger result = tonelliShanks(num, new BigInteger(1, SecP256r1.p));
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_SQRT, (num.toByteArray()).length, 0, num.toByteArray());
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatModAdd() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num2 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num3 = randomBigNat(BIGNAT_BIT_LENGTH / 8);
        BigInteger result = (num1.add(num2)).mod(num3);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_ADD_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatModSub() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num2 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num3 = randomBigNat(BIGNAT_BIT_LENGTH / 8);
        BigInteger result = (num1.subtract(num2)).mod(num3);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_SUB_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatModMult() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num2 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num3 = randomBigNat(BIGNAT_BIT_LENGTH / 8);
        BigInteger result = (num1.multiply(num2)).mod(num3);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_MUL_MOD, (num1.toByteArray()).length, (num2.toByteArray()).length, Util.concat((num1.toByteArray()), (num2.toByteArray()), (num3.toByteArray())));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void bigNatModExp() throws Exception {
        // Test multiple configurations (to check for OperationSupport.RSA_KEY_REFRESH)
        for(int i = 0; i < 3; ++i) {
            BigInteger base = randomBigNat(256);
            BigInteger exp = randomBigNat(256);
            BigInteger mod = new BigInteger(1, SecP256r1.r);
            BigInteger result = (base.modPow(exp, mod));
            CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_EXP_MOD, Util.trimLeadingZeroes(base.toByteArray()).length, Util.trimLeadingZeroes(exp.toByteArray()).length, Util.concat(Util.trimLeadingZeroes(base.toByteArray()), Util.trimLeadingZeroes(exp.toByteArray()), Util.trimLeadingZeroes(mod.toByteArray())));
            ResponseAPDU resp = statefulCard.transmit(cmd);

            Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
            Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        }
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Disabled("Fails with the new simulator")
    @Test
    public void bigNatModSq() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger num2 = BigInteger.valueOf(2);
        BigInteger num3 = randomBigNat(BIGNAT_BIT_LENGTH / 8);
        BigInteger result = (num1.modPow(num2, num3));
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_SQ_MOD, Util.trimLeadingZeroes(num1.toByteArray()).length, Util.trimLeadingZeroes(num3.toByteArray()).length, Util.concat(Util.trimLeadingZeroes(num1.toByteArray()), Util.trimLeadingZeroes(num3.toByteArray())));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, new BigInteger(1, resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Disabled("Fails with the new simulator")
    @Test
    public void bigNatModInv() throws Exception {
        BigInteger num1 = randomBigNat(BIGNAT_BIT_LENGTH / 2 * 3);
        BigInteger num2 = new BigInteger(1, SecP256r1.p);
        BigInteger num3 = randomBigNat(BIGNAT_BIT_LENGTH);
        BigInteger result = num1.modInverse(num2).multiply(num1).mod(num3);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_INV_MOD, Util.trimLeadingZeroes(num1.toByteArray()).length, 0, Util.concat(Util.trimLeadingZeroes(num1.toByteArray()), Util.trimLeadingZeroes(num2.toByteArray())));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        BigInteger respResult = new BigInteger(1, resp.getData()).multiply(num1).mod(num3);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, respResult);
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void integerStorage() throws Exception {
        int num = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_INT_STR, 0, 0, intToBytes(num));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void integerAddition() throws Exception {
        int num1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        int num2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        int result = num1 + num2;
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_INT_ADD, intToBytes(num1).length, 0, Util.concat(intToBytes(num1), intToBytes(num2)));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, bytesToInt(resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void integerSubtraction() throws Exception {
        int num1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        int num2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        int result = num1 - num2;
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_INT_SUB, intToBytes(num1).length, 0, Util.concat(intToBytes(num1), intToBytes(num2)));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, bytesToInt(resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void integerMultiplication() throws Exception {
        int num1 = ThreadLocalRandom.current().nextInt(0, (int) (Math.sqrt(Integer.MAX_VALUE)));
        int num2 = ThreadLocalRandom.current().nextInt(0, (int) (Math.sqrt(Integer.MAX_VALUE)));
        int result = num1 * num2;
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_INT_MUL, intToBytes(num1).length, 0, Util.concat(intToBytes(num1), intToBytes(num2)));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, bytesToInt(resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void integerDivision() throws Exception {
        int num1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        int num2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        int result = num1 / num2;
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_INT_DIV, intToBytes(num1).length, 0, Util.concat(intToBytes(num1), intToBytes(num2)));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, bytesToInt(resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    @Test
    public void integerModulo() throws Exception {
        int num1 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        int num2 = ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
        int result = num1 % num2;
        CommandAPDU cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_INT_MOD, intToBytes(num1).length, 0, Util.concat(intToBytes(num1), intToBytes(num2)));
        ResponseAPDU resp = statefulCard.transmit(cmd);

        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, resp.getSW());
        Assertions.assertEquals(result, bytesToInt(resp.getData()));
        statefulCard.transmit(new CommandAPDU(APDU_CLEANUP));
    }

    public static BigInteger randomBigNat(int maxNumBitLength) {
        Random rnd = new Random();
        BigInteger aRandomBigInt;
        while (true) {
            do {
                aRandomBigInt = new BigInteger(maxNumBitLength, rnd);

            } while (aRandomBigInt.compareTo(new BigInteger("1")) < 1);

            if ((Util.trimLeadingZeroes(aRandomBigInt.toByteArray()).length != maxNumBitLength / 8) || (aRandomBigInt.toByteArray()).length != maxNumBitLength / 8) {
                // After serialization, number is longer or shorter - generate new one
            } else {
                // We have proper number
                return aRandomBigInt;
            }
        }
    }

    /* Takes as input an odd prime p and n < p and returns r
     * such that r * r = n [mod p]. */
    public static BigInteger tonelliShanks(BigInteger n, BigInteger p) {

        //1. By factoring out powers of 2, find Q and S such that p-1=Q2^S p-1=Q*2^S and Q is odd
        BigInteger p_1 = p.subtract(BigInteger.ONE);
        BigInteger S = BigInteger.ZERO;
        BigInteger Q = p_1;

        BigInteger two = BigInteger.valueOf(2);

        while (Q.mod(two).compareTo(BigInteger.ONE) != 0) { //while Q is not odd
            Q = Q.divide(two);
            //Q = p_1.divide(two.modPow(S, p));
            S = S.add(BigInteger.ONE);
        }

        //2. Find the first quadratic non-residue z by brute-force search
        BigInteger z = BigInteger.ONE;
        while (z.modPow(p_1.divide(BigInteger.valueOf(2)), p).compareTo(p_1) != 0) {
            z = z.add(BigInteger.ONE);
        }

        System.out.println("n (y^2)    : " + Util.bytesToHex(n.toByteArray()));
        System.out.println("Q          : " + Util.bytesToHex(Q.toByteArray()));
        System.out.println("S          : " + Util.bytesToHex(S.toByteArray()));

        BigInteger R = n.modPow(Q.add(BigInteger.ONE).divide(BigInteger.valueOf(2)), p);
        BigInteger c = z.modPow(Q, p);
        BigInteger t = n.modPow(Q, p);
        BigInteger M = S;

        while (t.compareTo(BigInteger.ONE) != 0) {
            BigInteger tt = t;
            BigInteger i = BigInteger.ZERO;
            while (tt.compareTo(BigInteger.ONE) != 0) {
                System.out.println("t    : " + tt.toString());
                tt = tt.multiply(tt).mod(p);
                i = i.add(BigInteger.ONE);
                //if (i.compareTo(m)==0) return BigInteger.ZERO;
            }

            BigInteger M_i_1 = M.subtract(i).subtract(BigInteger.ONE);
            System.out.println("M    : " + M.toString());
            System.out.println("i    : " + i.toString());
            System.out.println("M_i_1: " + M_i_1.toString());
            System.out.println("===================");
            BigInteger b = c.modPow(two.modPow(M_i_1, p_1), p);
            BigInteger b2 = b.multiply(b).mod(p);

            R = R.multiply(b).mod(p);
            c = b2;
            t = t.multiply(b2).mod(p);
            M = i;
        }

        if (R.multiply(R).mod(p).compareTo(n) == 0) {
            return R;
        } else {
            return BigInteger.ZERO;
        }
    }

    public static byte[] intToBytes(int val) {
        byte[] data = new byte[5];
        if (val < 0) {
            data[0] = 0x01;
        } else {
            data[0] = 0x00;
        }

        int unsigned = Math.abs(val);
        data[1] = (byte) (unsigned >>> 24);
        data[2] = (byte) (unsigned >>> 16);
        data[3] = (byte) (unsigned >>> 8);
        data[4] = (byte) unsigned;

        return data;
    }

    public static int bytesToInt(byte[] data) {
        int val = (data[1] << 24)
                | ((data[2] & 0xFF) << 16)
                | ((data[3] & 0xFF) << 8)
                | (data[4] & 0xFF);

        if (data[0] == 0x01) {
            val = val * -1;
        }

        return val;
    }

    /**
     * Utility function which will generate random valid ECPoint
     *
     * @return ECPoint
     */
    public static ECPoint randECPoint() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        ECParameterSpec ecSpec_named = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecSpec_named);
        KeyPair apair = kpg.generateKeyPair();
        ECPublicKey apub = (ECPublicKey) apair.getPublic();
        return apub.getQ();
    }

    @BeforeAll
    public static void setUpClass() {
    }

    @AfterAll
    public static void tearDownClass() {
    }

    @BeforeEach
    public void setUpMethod() {
    }

    @AfterEach
    public void tearDownMethod() {
    }
}
