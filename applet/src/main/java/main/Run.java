package main;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import opencrypto.jcmathlib.UnitTests;
import org.bouncycastle.util.encoders.Hex;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class Run {
    public static void main(String[] args) {
        String apduString;
        if (args.length < 1) {
            System.out.println("Sending auxiliary APDU to applet");
            apduString = "B02126004C0000000000000000870dcd5af5916e6a00002e93ca37f7106448939609160001d38c88000000f88a11447197374246619d7949c64faedee4fee515200000007197374246618e7949ce4f4ca4";
        } else {
            apduString = args[0];
            if (apduString.length() < 4) {
                System.err.println("Too short APDU");
            }
            System.out.println("Sending APDu provided by user");
        }

        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("Example".getBytes());
        simulator.installApplet(appletAID, UnitTests.class);

        simulator.selectApplet(appletAID);

        CommandAPDU commandAPDU = new CommandAPDU(Hex.decode(apduString));
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        System.out.printf("Command: %02x, P1: %02x, P2: %02x, DATA: %s\n", commandAPDU.getINS(), commandAPDU.getP1(), commandAPDU.getP2(), Hex.toHexString(commandAPDU.getData()));
        System.out.printf("Response: %02x %02x, DATA: %s\n", response.getSW1(), response.getSW2(), Hex.toHexString(response.getData()));
    }
}