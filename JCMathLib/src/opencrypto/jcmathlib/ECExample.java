package opencrypto.jcmathlib;

import javacard.framework.APDU;
import javacard.framework.Applet;

/**
 * 
 * @author Petr Svenda
 */
public class ECExample extends Applet {
    ECConfig        ecc = null;
    ECCurve         curve = null;
    ECPoint         point1 = null;
    ECPoint         point2 = null;
    
    final static byte[] ECPOINT_TEST_VALUE = {(byte)0x04, (byte) 0x3B, (byte) 0xC1, (byte) 0x5B, (byte) 0xE5, (byte) 0xF7, (byte) 0x52, (byte) 0xB3, (byte) 0x27, (byte) 0x0D, (byte) 0xB0, (byte) 0xAE, (byte) 0xF2, (byte) 0xBC, (byte) 0xF0, (byte) 0xEC, (byte) 0xBD, (byte) 0xB5, (byte) 0x78, (byte) 0x8F, (byte) 0x88, (byte) 0xE6, (byte) 0x14, (byte) 0x32, (byte) 0x30, (byte) 0x68, (byte) 0xC4, (byte) 0xC4, (byte) 0x88, (byte) 0x6B, (byte) 0x43, (byte) 0x91, (byte) 0x4C, (byte) 0x22, (byte) 0xE1, (byte) 0x67, (byte) 0x68, (byte) 0x3B, (byte) 0x32, (byte) 0x95, (byte) 0x98, (byte) 0x31, (byte) 0x19, (byte) 0x6D, (byte) 0x41, (byte) 0x88, (byte) 0x0C, (byte) 0x9F, (byte) 0x8C, (byte) 0x59, (byte) 0x67, (byte) 0x60, (byte) 0x86, (byte) 0x1A, (byte) 0x86, (byte) 0xF8, (byte) 0x0D, (byte) 0x01, (byte) 0x46, (byte) 0x0C, (byte) 0xB5, (byte) 0x8D, (byte) 0x86, (byte) 0x6C, (byte) 0x09};
    final static byte[] SCALAR_TEST_VALUE = {(byte) 0xE8, (byte) 0x05, (byte) 0xE8, (byte) 0x02, (byte) 0xBF, (byte) 0xEC, (byte) 0xEE, (byte) 0x91, (byte) 0x9B, (byte) 0x3D, (byte) 0x3B, (byte) 0xD8, (byte) 0x3C, (byte) 0x7B, (byte) 0x52, (byte) 0xA5, (byte) 0xD5, (byte) 0x35, (byte) 0x4C, (byte) 0x4C, (byte) 0x06, (byte) 0x89, (byte) 0x80, (byte) 0x54, (byte) 0xB9, (byte) 0x76, (byte) 0xFA, (byte) 0xB1, (byte) 0xD3, (byte) 0x5A, (byte) 0x10, (byte) 0x91};

    public ECExample() {
        // Pre-allocate all helper structures
        ecc = new ECConfig((short) 256); 
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        point1 = new ECPoint(curve, ecc.ech);
        point2 = new ECPoint(curve, ecc.ech);
    }
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ECExample().register();
    }

    public boolean select() {
        ecc.refreshAfterReset();
        return true;
    }
    
    public void process(APDU apdu) {
        if (selectingApplet()) { return; }
        // NOTE: very simple EC usage example - no cla/ins, no communication with host...    
        point1.randomize(); // Generate first point at random
        point2.setW(ECPOINT_TEST_VALUE, (short) 0, (short) ECPOINT_TEST_VALUE.length); // Set second point to predefined value
        point1.add(point2); // Add two points together 
        point1.multiplication(SCALAR_TEST_VALUE, (short) 0, (short) SCALAR_TEST_VALUE.length); // Multiply point by large scalar
    }
}
