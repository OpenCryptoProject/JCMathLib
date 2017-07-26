package opencrypto.test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import javacard.framework.ISO7816;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class Util {

    public static String toHex(byte[] bytes) {
        return toHex(bytes, 0, bytes.length);
    }

    public static String toHex(byte[] bytes, int offset, int len) {
        // StringBuilder buff = new StringBuilder();
        String result = "";

        for (int i = offset; i < offset + len; i++) {
            result += String.format("%02X", bytes[i]);
        }

        return result;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    
    /* Utils */
    public static short getShort(byte[] buffer, int offset) {
        return ByteBuffer.wrap(buffer, offset, 2).order(ByteOrder.BIG_ENDIAN).getShort();
    }

    public static short readShort(byte[] data, int offset) {
        return (short) (((data[offset] << 8)) | ((data[offset + 1] & 0xff)));
    }

    public static byte[] shortToByteArray(int s) {
        return new byte[]{(byte) ((s & 0xFF00) >> 8), (byte) (s & 0x00FF)};
    }
    
    
    public static byte[] joinArray(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        final byte[] result = new byte[length];

        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }

        return result;
    }

    public static byte[] trimLeadingZeroes(byte[] array) {
        short startOffset = 0;
        for (int i = 0; i < array.length; i++) {
            if (array[i] != 0) {
                break;
            } else {
                // still zero
                startOffset++;
            }
        }

        byte[] result = new byte[array.length - startOffset];
        System.arraycopy(array, startOffset, result, 0, array.length - startOffset);
        return result;
    }

    public static byte[] concat(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c = new byte[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

    public static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] tmp_conc = concat(a, b);
        return concat(tmp_conc, c);

    }
    
    
    public static ECPoint randECPoint() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        ECParameterSpec ecSpec_named = ECNamedCurveTable.getParameterSpec("secp256r1"); // NIST P-256
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecSpec_named);
        KeyPair apair = kpg.generateKeyPair();
        ECPublicKey apub = (ECPublicKey) apair.getPublic();
        return apub.getQ();
    }    
    
    public static byte[] IntToBytes(int val) {
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

    public static int BytesToInt(byte[] data) {
        int val = (data[1] << 24)
                | ((data[2] & 0xFF) << 16)
                | ((data[3] & 0xFF) << 8)
                | (data[4] & 0xFF);

        if (data[0] == 0x01) {
            val = val * -1;
        }

        return val;
    }    
    
    private static boolean checkSW(ResponseAPDU response) {
        if (response.getSW() != (ISO7816.SW_NO_ERROR & 0xffff)) {
            System.err.printf("Received error status: %02X.\n",
                    response.getSW());
            return false;
        }
        return true;
    }

    public static byte[] hexStringToByteArray(String s) {
        String sanitized = s.replace(" ", "");
        byte[] b = new byte[sanitized.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(sanitized.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }
    
    
    /**
     * *Math Stuff**
     */
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

    public static byte[] SerializeBigInteger(BigInteger BigInt) {

        int bnlen = BigInt.bitLength() / 8;

        byte[] large_int_b = new byte[bnlen];
        Arrays.fill(large_int_b, (byte) 0);
        int int_len = BigInt.toByteArray().length;
        if (int_len == bnlen) {
            large_int_b = BigInt.toByteArray();
        } else if (int_len > bnlen) {
            large_int_b = Arrays.copyOfRange(BigInt.toByteArray(), int_len
                    - bnlen, int_len);
        } else if (int_len < bnlen) {
            System.arraycopy(BigInt.toByteArray(), 0, large_int_b,
                    large_int_b.length - int_len, int_len);
        }

        return large_int_b;
    }

    public static long pow_mod(long x, long n, long p) {
        if (n == 0) {
            return 1;
        }
        if ((n & 1) == 1) {
            return (pow_mod(x, n - 1, p) * x) % p;
        }
        x = pow_mod(x, n / 2, p);
        return (x * x) % p;
    }

    /* Takes as input an odd prime p and n < p and returns r
     * such that r * r = n [mod p]. */
    public static BigInteger tonelli_shanks(BigInteger n, BigInteger p) {

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

    /* Takes as input an odd prime p and n < p and returns r
     * such that r * r = n [mod p]. */
    public static BigInteger tonellishanks(BigInteger n, BigInteger p) {
        //1. By factoring out powers of 2, find Q and S such that p-1=Q2^S p-1=Q*2^S and Q is odd
        BigInteger p_1 = p.subtract(BigInteger.ONE);
        BigInteger S = BigInteger.ZERO;
        BigInteger Q = p_1;

        BigInteger two = BigInteger.valueOf(2);

        System.out.println("p         : " + Util.bytesToHex(p.toByteArray()));
        System.out.println("p is prime: " + p.isProbablePrime(10));
        System.out.println("n         : " + Util.bytesToHex(n.toByteArray()));
        System.out.println("Q         : " + Util.bytesToHex(Q.toByteArray()));
        System.out.println("S         : " + Util.bytesToHex(S.toByteArray()));

        while (Q.mod(two).compareTo(BigInteger.ONE) != 0) { //while Q is not odd
            Q = p_1.divide(two.modPow(S, p));
            S = S.add(BigInteger.ONE);

        	//System.out.println("Iter n: " + bytesToHex(n.toByteArray()));
            //System.out.println("Iter Q: " + bytesToHex(Q.toByteArray()));
            //System.out.println("Iter S: " + bytesToHex(S.toByteArray()));
        }

    	//System.out.println("n: " + bytesToHex(n.toByteArray()));
        //System.out.println("Q: " + bytesToHex(Q.toByteArray()));
        //System.out.println("S: " + bytesToHex(S.toByteArray()));
        return n;
    }
    
    private static ECPoint ECPointDeSerialization(byte[] serialized_point,
            int offset, int pointLength, ECCurve curve) {

        byte[] x_b = new byte[pointLength / 2];
        byte[] y_b = new byte[pointLength / 2];

        // System.out.println("Serialized Point: " + toHex(serialized_point));
        // src -- This is the source array.
        // srcPos -- This is the starting position in the source array.
        // dest -- This is the destination array.
        // destPos -- This is the starting position in the destination data.
        // length -- This is the number of array elements to be copied.
        System.arraycopy(serialized_point, offset + 1, x_b, 0, pointLength / 2);
        BigInteger x = new BigInteger(bytesToHex(x_b), 16);
        // System.out.println("X:" + toHex(x_b));
        System.arraycopy(serialized_point, offset + (pointLength / 2 + 1), y_b, 0, pointLength / 2);
        BigInteger y = new BigInteger(bytesToHex(y_b), 16);
        // System.out.println("Y:" + toHex(y_b));

        ECPoint point = curve.createPoint(x, y);

        return point;
    }    
    
}
