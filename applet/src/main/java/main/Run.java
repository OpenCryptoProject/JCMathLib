package main;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import opencrypto.jcmathlib.Example;
import org.bouncycastle.util.encoders.Hex;
import javax.smartcardio.CommandAPDU;

public class Run {
    public static void main(String[] args) throws Exception {
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("Example".getBytes());
        simulator.installApplet(appletAID, Example.class);

        simulator.selectApplet(appletAID);

        System.out.println(Hex.toHexString(simulator.transmitCommand(new CommandAPDU(0, 0, 0, 0)).getData()));
    }
}