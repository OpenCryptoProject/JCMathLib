package opencrypto.jcmathlib;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.JCSystem;

/**
 * @author Petr Svenda
 */
public class Example extends Applet {
    ResourceManager rm;
    ECCurve curve;
    ECPoint point1, point2;
    BigNat scalar1, scalar2;
    boolean initialized = false;

    final static byte[] ECPOINT_TEST_VALUE = {
            (byte) 0x04,
            (byte) 0x3b, (byte) 0xc1, (byte) 0x5b, (byte) 0xe5,
            (byte) 0xf7, (byte) 0x52, (byte) 0xb3, (byte) 0x27,
            (byte) 0x0d, (byte) 0xb0, (byte) 0xae, (byte) 0xf2,
            (byte) 0xbc, (byte) 0xf0, (byte) 0xec, (byte) 0xbd,
            (byte) 0xb5, (byte) 0x78, (byte) 0x8f, (byte) 0x88,
            (byte) 0xe6, (byte) 0x14, (byte) 0x32, (byte) 0x30,
            (byte) 0x68, (byte) 0xc4, (byte) 0xc4, (byte) 0x88,
            (byte) 0x6b, (byte) 0x43, (byte) 0x91, (byte) 0x4c,
            (byte) 0x22, (byte) 0xe1, (byte) 0x67, (byte) 0x68,
            (byte) 0x3b, (byte) 0x32, (byte) 0x95, (byte) 0x98,
            (byte) 0x31, (byte) 0x19, (byte) 0x6d, (byte) 0x41,
            (byte) 0x88, (byte) 0x0c, (byte) 0x9f, (byte) 0x8c,
            (byte) 0x59, (byte) 0x67, (byte) 0x60, (byte) 0x86,
            (byte) 0x1a, (byte) 0x86, (byte) 0xf8, (byte) 0x0d,
            (byte) 0x01, (byte) 0x46, (byte) 0x0c, (byte) 0xb5,
            (byte) 0x8d, (byte) 0x86, (byte) 0x6c, (byte) 0x09
    };
    final static byte[] SCALAR_TEST_VALUE = {
            (byte) 0xe8, (byte) 0x05, (byte) 0xe8, (byte) 0x02,
            (byte) 0xbf, (byte) 0xec, (byte) 0xee, (byte) 0x91,
            (byte) 0x9b, (byte) 0x3d, (byte) 0x3b, (byte) 0xd8,
            (byte) 0x3c, (byte) 0x7b, (byte) 0x52, (byte) 0xa5,
            (byte) 0xd5, (byte) 0x35, (byte) 0x4c, (byte) 0x4c,
            (byte) 0x06, (byte) 0x89, (byte) 0x80, (byte) 0x54,
            (byte) 0xb9, (byte) 0x76, (byte) 0xfa, (byte) 0xb1,
            (byte) 0xd3, (byte) 0x5a, (byte) 0x10, (byte) 0x91
    };

    public Example() {
        OperationSupport.getInstance().setCard(OperationSupport.SIMULATOR); // TODO set your card
        if (!OperationSupport.getInstance().DEFERRED_INITIALIZATION) {
            initialize();
        }
    }

    public void initialize() {
        if (initialized) {
            return;
        }

        // Allocate resources for a required elliptic curve size (in bits)
        rm = new ResourceManager((short) 256);
        // Allocate SecP256r1 curve and two EC points on this curve
        curve = new ECCurve(SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r, rm);
        point1 = new ECPoint(curve);
        point2 = new ECPoint(curve);
        // Allocate two BigNats large enough to hold scalars of the elliptic curve
        scalar1 = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        scalar2 = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);

        initialized = true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Example().register();
    }

    public boolean select() {
        if (initialized) {
            rm.refreshAfterReset();
            curve.updateAfterReset();
        }
        return true;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        if (!initialized) {
            initialize();
        }

        point1.randomize(); // Generate the first point at random
        point2.setW(ECPOINT_TEST_VALUE, (short) 0, (short) ECPOINT_TEST_VALUE.length); // Set the second point to a predefined value
        point1.add(point2); // Add the second point to the first one

        scalar1.setValue((byte) 42); // Set the first scalar to 42
        scalar2.fromByteArray(SCALAR_TEST_VALUE, (short) 0, (short) SCALAR_TEST_VALUE.length); // Set the second scalar to a predefined value
        scalar1.modSq(curve.rBN); // Square the first scalar modulo curve order
        scalar1.modMult(scalar2, curve.rBN); // Multiply the two scalars modulo curve order

        point1.multiplication(scalar1); // Multiply the resulting point by the resulting scalar

        short len = point1.getW(apdu.getBuffer(), (short) 0); // Serialize the point to APDU buffer
        apdu.setOutgoingAndSend((short) 0, len); // Send the result to the host
    }
}
