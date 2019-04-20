package opencrypto.examples;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import javax.smartcardio.CommandAPDU;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import opencrypto.jcmathlib.OCUnitTests;


/**
 * Simple example client to trigger selected Bignat and ECPoint on-card operations. For detailed testing please use JCMathLibTests client.
 * Requires bouncycastle (e.g., bcprov-jdk15on-157.jar) and jcardsim (e.g., jcardsim-3.0.5.jar) dependencies
 * @author Petr Svenda
 */
public class ExamplesClient {
    public static byte[] APPLET_AID = {0x55, 0x6e, 0x69, 0x74, 0x54, 0x65, 0x73, 0x74, 0x73};
    public static byte[] APDU_CLEANUP = {OCUnitTests.CLA_OC_UT, OCUnitTests.INS_CLEANUP, (byte) 0x00, (byte) 0x00};


    public static void main(String[] args) throws Exception {
        ExamplesClient client = new ExamplesClient();
        client.run();
    }

    public void run() {
        try {
            
            // Run on simulator -> only change CARD_TYPE.JCARDSIMLOCAL and set class of simulated applet
            // Test by placing breakpoint directly into opencrypto.jcmathlib.OCUnitTests.process() or any other method of interest
            CardConfig runCfg = CardConfig.getDefaultConfig();
			runCfg.testCardType = CardConfig.CARD_TYPE.JCARDSIMLOCAL;
			runCfg.appletToSimulate = OCUnitTests.class;
            runExamples(runCfg);

            // Run on real card -> only change CARD_TYPE.PHYSICAL
            // Applet must be uploaded before (gppro -install opcrypto.cap)
            // Breakpoints will not be triggered (we are on real card :))
			runCfg.testCardType = CardConfig.CARD_TYPE.PHYSICAL;
            runExamples(runCfg);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Demonstration of selected operations of Bignat and ECPoint. Notice that code 
     * is no different for simulator and real card (except for {@code CardConfig})
     * @param cardCfg configuration of target card to use (simulator / real card)
     * @return true if connected, false otherwise
     */
    boolean runExamples(CardConfig cardCfg) {
        try {

			CardManager cardMngr = new CardManager(true, APPLET_AID);

            // Connnect to card - simulator or real card is used based on cardCfg
            System.out.print("Connecting to card...");
            if (!cardMngr.Connect(cardCfg)) {
                System.out.println(" failed.");
                return false;
            }
            System.out.println(" done.");

			System.out.println("\n-------------- JCMathLib Operation Examples --------------");
			System.out.println("Info:");
			System.out.println("--> denotes data send to a card (hexadecimal)");
            System.out.println("<-- denotes data received from a card (hexadecimal) in the following format: response_data(xB) status(2B) (response_data_length) [operation_time_in_milliseconds]\n");
            
            
            // Example values to processed on card (fixed bignats, random ECPoints)
            BigInteger num1 = new BigInteger("56C710A2984556420A71E5A898DCB0B9AC9EFF1A4FEA42A30E0BA3E2E483FC", 16);
            BigInteger num2 = new BigInteger("4304CE37282F03E5B41F2B50FEB3E6E65951018C9CE1B2682C634A0BA4E0CE", 16);
            ECPoint pnt_1 = randECPoint();
            ECPoint pnt_2 = randECPoint();      
            Security.addProvider(new BouncyCastleProvider());
            ECParameterSpec ecSpec2 = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECPoint base = ecSpec2.getG();
            
            // APDU to be send to card
            CommandAPDU cmd;

            //
            // Selected Bignat operations 
            //
            System.out.println("BigNatural Addition: ");
            cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_ADD, num1.toByteArray().length, 0, 
                                  concat(num1.toByteArray(), num2.toByteArray()));
            cardMngr.transmit(cmd); // Notice: exatly same method is used both for simulator and real card 

            System.out.println("BigNatural Multiplication: ");
            cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MUL, num1.toByteArray().length, 0,
                                  concat(num1.toByteArray(), num2.toByteArray()));
            cardMngr.transmit(cmd);

            System.out.println("BigNatural Modulo: ");
            cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_BN_MOD, num1.toByteArray().length, 0,
                                  concat(num1.toByteArray(), num2.toByteArray()));
            cardMngr.transmit(cmd);

            
            //
            // Selected EC Point operations 
            //
            System.out.println("EC Point Generation: ");
            cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_GEN, 0, 0);
            cardMngr.transmit(cmd);

            System.out.println("EC Point Add: ");
            cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_ADD, 0, 0, 
                                  concat(pnt_1.getEncoded(false), pnt_2.getEncoded(false)));
            cardMngr.transmit(cmd);
            
            System.out.println("EC scalar_Point Multiplication: ");
            cmd = new CommandAPDU(OCUnitTests.CLA_OC_UT, OCUnitTests.INS_EC_MUL, num1.toByteArray().length, 0, 
                                  concat(num1.toByteArray(), base.getEncoded(false)));
            cardMngr.transmit(cmd);

            // Finalize and disconnect from card
            System.out.println("\n-------------- done --------------\n\n");
            System.out.print("Disconnecting from card...");
            cardMngr.Disconnect(true);
            System.out.println(" Done.");

        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }
    
    /**
     * Utility function which will generate random valid ECPoint
     * @return ECPoint
     * @throws Exception 
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







