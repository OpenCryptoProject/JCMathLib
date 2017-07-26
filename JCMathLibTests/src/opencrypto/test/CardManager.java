package opencrypto.test;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.util.ArrayList;
import java.util.List;
import javacard.framework.AID;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/**
 *
* @author Petr Svenda
 */
public class CardManager {
    boolean     m_bDebug = false;
    byte[]      m_APPLET_AID = null;
    Long        m_lastTransmitTime = (long) 0;
    CommandAPDU m_lastCommand = null;
    CardChannel m_channel = null;
    
    public CardManager(boolean bDebug, byte[] appletAID) {
        this.m_bDebug = bDebug;
        this.m_APPLET_AID = appletAID;
    }
            
    // Card Logistics
    public boolean Connect(RunConfig runCfg) throws Exception {
        boolean bConnected = false;
        switch (runCfg.testCardType) {
            case PHYSICAL: {
                m_channel = ConnectPhysicalCard(runCfg.targetReaderIndex);
                break;
            }
            case JCOPSIM: {
                m_channel = ConnectJCOPSimulator(runCfg.targetReaderIndex);
                break;
            }
            case JCARDSIMLOCAL: {
                m_channel = ConnectJCardSimLocalSimulator(runCfg.appletToSimulate);
                break;
            }
            case JCARDSIMREMOTE: {
                m_channel = null; // Not implemented yet
                break;
            }
            default:
                m_channel = null;
                bConnected = false;
                
        }
        if (m_channel != null) {
            bConnected = true;
        }
        return bConnected;
    }
    
    public void Disconnect(boolean bReset) throws CardException {
        m_channel.getCard().disconnect(bReset); // Disconnect from the card
    }

    public CardChannel ConnectPhysicalCard(int targetReaderIndex) throws Exception {
        // JCOP Simulators
        System.out.print("Looking for physical cards... ");
        return connectToCardByTerminalFactory(TerminalFactory.getDefault(), targetReaderIndex);
    }

    public CardChannel ConnectJCOPSimulator(int targetReaderIndex) throws Exception {
        // JCOP Simulators
        System.out.print("Looking for JCOP simulators...");
        int[] ports = new int[]{8050};
        return connectToCardByTerminalFactory(TerminalFactory.getInstance("JcopEmulator", ports), targetReaderIndex);
    }

    private CardChannel ConnectJCardSimLocalSimulator(Class appletClass) throws Exception {
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        CAD cad = new CAD(System.getProperties());
        JavaxSmartCardInterface simulator = (JavaxSmartCardInterface) cad.getCardInterface();
        byte[] installData = new byte[0];
        AID appletAID = new AID(m_APPLET_AID, (short) 0, (byte) m_APPLET_AID.length);

        AID appletAIDRes = simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        simulator.selectApplet(appletAID);

        return new SimulatedCardChannelLocal(simulator);
    }

    private CardChannel connectToCardByTerminalFactory(TerminalFactory factory, int targetReaderIndex) throws CardException {
        List<CardTerminal> terminals = new ArrayList<>();

        boolean card_found = false;
        CardTerminal terminal = null;
        Card card = null;
        try {
            for (CardTerminal t : factory.terminals().list()) {
                terminals.add(t);
                if (t.isCardPresent()) {
                    card_found = true;
                }
            }
            System.out.println("Success.");
        } catch (Exception e) {
            System.out.println("Failed.");
        }

        if (card_found) {
            System.out.println("Cards found: " + terminals);

            terminal = terminals.get(targetReaderIndex); // Prioritize physical card over simulations

            System.out.print("Connecting...");
            card = terminal.connect("*"); // Connect with the card

            System.out.println(" Done.");

            System.out.print("Establishing channel...");
            m_channel = card.getBasicChannel();

            System.out.println(" Done.");

            // Select applet (mpcapplet)
            System.out.println("Smartcard: Selecting applet...");

            CommandAPDU cmd = new CommandAPDU(0x00, 0xa4, 0x04, 0x00, m_APPLET_AID);
            ResponseAPDU response = transmit(cmd);
        } else {
            System.out.print("Failed to find physical card.");
        }

        if (card != null) {
            return card.getBasicChannel();
        } else {
            return null;
        }
    }
    
    public ResponseAPDU transmit(CommandAPDU cmd)
            throws CardException {

        m_lastCommand = cmd;
        if (m_bDebug == true) {
            log(cmd);
        }

        long elapsed = -System.currentTimeMillis();
        ResponseAPDU response = m_channel.transmit(cmd);
        elapsed += System.currentTimeMillis();
        m_lastTransmitTime = elapsed;

        if (m_bDebug == true) {
            log(response, m_lastTransmitTime);
        }

        return response;
    }

    private void log(CommandAPDU cmd) {
        System.out.printf("--> %s\n", Util.toHex(cmd.getBytes()),
                cmd.getBytes().length);
    }

    private void log(ResponseAPDU response, long time) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("<-- %s %s (%d) [%d ms]\n", Util.toHex(data), swStr,
                    data.length, time);
        } else {
            System.out.printf("<-- %s [%d ms]\n", swStr, time);
        }
    }

    private void log(ResponseAPDU response) {
        log(response, 0);
    }

    private Card waitForCard(CardTerminals terminals)
            throws CardException {
        while (true) {
            for (CardTerminal ct : terminals
                    .list(CardTerminals.State.CARD_INSERTION)) {

                return ct.connect("*");
            }
            terminals.waitForChange();
        }
    }
    
}
