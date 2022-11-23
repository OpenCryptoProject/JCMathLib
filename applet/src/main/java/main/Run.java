package main;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import opencrypto.jcmathlib.UnitTests;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class Run {
    public static void main(String[] args) throws Exception {
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("UnitTests".getBytes());
        simulator.installApplet(appletAID, UnitTests.class);

        simulator.selectApplet(appletAID);

        simulator.transmitCommand(new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_INITIALIZE, 0, 0));

        runBigNat(simulator);
        System.out.println();
        runECC(simulator);
    }

    /**
     * Demonstration of selected BigNat operations
     * @param card connected instance of CardSimulator
     */
    private static void runBigNat(CardSimulator card) {
        BigInteger num1 = new BigInteger("56C710A2984556420A71E5A898DCB0B9AC9EFF1A4FEA42A30E0BA3E2E483FC", 16);
        System.out.println("Number 1: ");
        System.out.println(Hex.toHexString(num1.toByteArray()));
        BigInteger num2 = new BigInteger("4304CE37282F03E5B41F2B50FEB3E6E65951018C9CE1B2682C634A0BA4E0CE", 16);
        System.out.println("Number 2: ");
        System.out.println(Hex.toHexString(num2.toByteArray()));

        CommandAPDU cmd;
        ResponseAPDU resp;
        System.out.println("BigNatural Addition: ");
        cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_ADD, num1.toByteArray().length, 0,
                concat(num1.toByteArray(), num2.toByteArray()));
        resp = card.transmitCommand(cmd);
        System.out.println(Hex.toHexString(resp.getData()));

        System.out.println("BigNatural Multiplication: ");
        cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_MUL, num1.toByteArray().length, 0,
                concat(num1.toByteArray(), num2.toByteArray()));
        resp = card.transmitCommand(cmd);
        System.out.println(Hex.toHexString(resp.getData()));

        System.out.println("BigNatural Modulo: ");
        cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_BN_MOD, num1.toByteArray().length, 0,
                concat(num1.toByteArray(), num2.toByteArray()));
        resp = card.transmitCommand(cmd);
        System.out.println(Hex.toHexString(resp.getData()));
    }

    /**
     * Demonstration of selected ECC operations
     * @param card connected instance of CardSimulator
     */
    private static void runECC(CardSimulator card) throws Exception {
        BigInteger num = new BigInteger("56C710A2984556420A71E5A898DCB0B9AC9EFF1A4FEA42A30E0BA3E2E483FC", 16);
        System.out.println("Scalar: ");
        System.out.println(Hex.toHexString(num.toByteArray()));
        ECPoint point1 = randECPoint();
        System.out.println("Point 1: ");
        System.out.println(Hex.toHexString(point1.getEncoded(false)));
        ECPoint point2 = randECPoint();
        System.out.println("Point 2: ");
        System.out.println(Hex.toHexString(point2.getEncoded(false)));
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPoint base = ecSpec.getG();

        CommandAPDU cmd;
        ResponseAPDU resp;
        System.out.println("EC Point Generation: ");
        cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_GEN, 0, 0);
        resp = card.transmitCommand(cmd);
        System.out.println(Hex.toHexString(resp.getData()));

        System.out.println("EC Point Add: ");
        cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_ADD, 0, 0,
                concat(point1.getEncoded(false), point2.getEncoded(false)));
        resp = card.transmitCommand(cmd);
        System.out.println(Hex.toHexString(resp.getData()));

        System.out.println("EC Scalar Multiplication: ");
        cmd = new CommandAPDU(UnitTests.CLA_OC_UT, UnitTests.INS_EC_MUL, num.toByteArray().length, 0,
                concat(num.toByteArray(), base.getEncoded(false)));
        resp = card.transmitCommand(cmd);
        System.out.println(Hex.toHexString(resp.getData()));
    }

    /**
     * Utility function which will generate random valid ECPoint
     * @return ECPoint
     */
    public static ECPoint randECPoint() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        ECParameterSpec ecSpec_named = ECNamedCurveTable.getParameterSpec("secp256r1"); // NIST P-256
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecSpec_named);
        KeyPair apair = kpg.generateKeyPair();
        ECPublicKey apub = (ECPublicKey) apair.getPublic();
        return apub.getQ();
    }

    /**
     * Concatenates two separate arrays into single bigger one
     * @param a first array
     * @param b second array
     * @return concatenated array
     */
    public static byte[] concat(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c = new byte[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

}