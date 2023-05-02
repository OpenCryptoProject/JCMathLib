package main;

import opencrypto.jcmathlib.Example;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.*;

public class RunExample {
    public static void main(String[] args){
        // 1. create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. install applet
        AID appletAID = AIDUtil.create("Example".getBytes());
        simulator.installApplet(appletAID, Example.class);

        // 3. select applet
        simulator.selectApplet(appletAID);

        // 4. send APDU
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x00, 0x00, 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        System.out.println(new String(response.getData()));
    }

}
