package opencrypto.examples;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.nio.ByteBuffer;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Proxy class turning JCardSim interface into standard javax.smartcardio  
 * @author Petr Svenda
 */
public class SimulatedCardChannelLocal extends CardChannel {
    JavaxSmartCardInterface m_simulator;
    SimulatedCard m_card;
    
    SimulatedCardChannelLocal (JavaxSmartCardInterface simulator) {
        m_simulator = simulator;
        m_card = new SimulatedCard();
    }

    @Override
    public Card getCard() {
        return m_card;
    }

    @Override
    public int getChannelNumber() {
        return 0;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU apdu) throws CardException {
        ResponseAPDU responseAPDU = null;

        try {
            responseAPDU = this.m_simulator.transmitCommand(apdu);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return responseAPDU;
    }

    @Override
    public int transmit(ByteBuffer bb, ByteBuffer bb1) throws CardException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void close() throws CardException {
        m_simulator.reset();
    }
}
