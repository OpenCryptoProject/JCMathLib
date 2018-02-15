# JCMathLib

The JCMathLib is an open-source library for Java Card platform which provides objects and operations otherwise missing from standard Java Card API. Namely, we focus on adding support for low-level operations like addition or multiplication of points on elliptic curves in resource efficient way. As a bonus, we provide tooling for [shared memory management](https://github.com/OpenCryptoProject/JCMathLib/wiki/Main-components) and [performance optimization](https://github.com/OpenCryptoProject/JCProfiler).

The project comes in three parts:
* **JCMathLib** - the javacard library itself (on-card code)
* **JCMathLibExamples** - the simple testing Java client (PC-side client code with simple examples)
* **JCMathLibTests** - the client to thoroughly test all operations and measure performance (PC-side client)


## Quick taste
```java
package opencrypto.jcmathlib; 

 // ... in applet's constructor
 // Pre-allocate all helper structures
 ECConfig ecc = new ECConfig((short) 256); 
 // Pre-allocate standard SecP256r1 curve and two EC points on this curve
 ECCurve curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r, ecc);
 ECPoint point1 = new ECPoint(curve, ecc);
 ECPoint point2 = new ECPoint(curve, ecc);
    
 // ... in standard Java Card applet code
 // Generate first point at random
 point1.randomize(); 
 // Set second point to predefined value
 point2.setW(ECPOINT_TEST_VALUE, (short) 0, (short) ECPOINT_TEST_VALUE.length); 
 // Add two points together 
 point1.add(point2); 
 // Multiply point by large scalar
 point1.multiplication(SCALAR_TEST_VALUE, (short) 0, (short) SCALAR_TEST_VALUE.length); 
```

## FAQ
**Q:** Hold on, I thought elliptic curves are already supported on smart cards, right? <br>
**A:** Definitely not on each one. Take a look at [jcalgtest.org](https://jcalgtest.org) - out of 65 cards listed, only about 1/3 have some support. 

**Q:** I will just download some 3rd party implementation like Bouncy Castle and run it on a card. So why are you developing this library?<br>
**A:** Not that easy. The most Java Cards don't support *BigInteger* and usually not even *int* datatype. Even if you will change the code and finally compile, it will be impractically slow due to card's 40MHz CPU and 3KB RAM. That's why smart card manufacturers add dedicated coprocessor to speed up operations like modular multiplication (RSA) or elliptic curve point manipulation (ECC).

**Q:** So if there is cryptographic coprocessor, I can do decrypt, sign or run key establishment directly on the card, right?<br>
**A:** Yes, usually in the order of hundreds of milliseconds for asymmetric crypto. But if you like to build something fancier like multi-party secure communication protocols, blind signatures or attribute-based crypto which requires low-level operations, you are out of luck with standard Java Card API.

**Q:** ECPoint is not included in standard Java Card API? <br>
**A:** No, it is not supported. You can still get ECPoint operations you want via additional manufacturer proprietary API which usually means also signing NDA and get bound to a particular manufacturer.   

**Q:** How your library can provide ECPoint if the port from Bouncy Castle is not a viable option?<br>
**A:** We use card's fast co-processors in unintended ways (raw RSA for fast multiplication, ECDH KeyAgreement for point multiplication...)  and combine with software-only snippets to construct the required operations running as fast possible.   

**Q:** So you provide these missing operations in an efficient way. Are there any disadvantages with respect to a manufacturer's native implementation? <br>
**A:** We are slower if an operation requires computing lot of additional steps in a software-only manner. Also, native implementation is more resistant against side-channel and fault induction attacks.       

**Q:** Do you support ECPoint operations on cards which are complete without the EC support?  <br>
**A:** No, we need at least ECDH key agreement operation and new EC key pair generation supported on a target card. However, you can use fast operations with big numbers (Bignat, BigInteger - part of JCMathLib) even on cards without EC support. 

**Q:** Sounds good, how can I start to fiddle with the JCMathLibrary library?<br>
**A:** Buy [suitable](https://www.fi.muni.cz/~xsvenda/jcalgtest/) JavaCard for $10-20 with EC support ([buyers'guide](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/JavaCardBuyersGuide#javacard-buyers-guide-of-2015)), download this library source code, compile example project with [ant-javacard](https://github.com/martinpaljak/ant-javacard) and start playing. Don't forget to read [wiki](https://github.com/mavroudisv/JCMathLib/wiki) for examples and tutorials. 

## Advantages and potential drawbacks
**Advantages:**
  * Availability of low-level ECPoint operations (not included in standard javacard API) without a need to use a proprietary API (which usually requires signing a non-disclosure agreement).
  * Code portability between smart cards from different manufacturers. 
  * Possibility to use open-source simulator [JCardSim](https://jcardsim.org/) instead of vendor-specific one.
  
**Potential drawbacks (in comparison to vendor-specific API):**
  * Slower speed for some EC operations like addition or scalar multiplication (see [wiki](https://github.com/OpenCryptoProject/JCMathLib/wiki#performance-and-memory-overhead) for times measured on real cards
  * RAM memory overhead (about 1kB for fastest performance). Is configurable with an option to place all temporary objects in EEPROM (slower performance). 
  * Lower resilience against various side-channel and fault-induction attacks.

## Example applet, compilation, upload, and use

- Download ECExample project, open command line in project's root directory 
- Compile and convert example into ecexample.cap binary suitable for card ([ant-javacard](https://github.com/martinpaljak/ant-javacard) is used):
```
ant -f jcbuild.xml ecexample
```
(which results in output similar to this)
```
>ant -f jcbuild.xml ecexample
Buildfile: c:\OpenCrypto\ECExample\jcbuild.xml

ecexample:
 [javacard] JavaCard 2.x SDK detected in ext/java_card_kit-2_2_2
      [cap] Setting package name to opencrypto.jcmathlib
      [cap] Building CAP with 1 applet(s) from package opencrypto.jcmathlib
      [cap] opencrypto.jcmathlib.ECExample 556E69745465737473
  [compile] Compiling 15 source files to C:\Temp\classes71248306622090223590454623483186
      [cap] CAP saved to c:\OpenCrypto\ECExample\ecexample.cap

BUILD SUCCESSFUL
Total time: 3 seconds
```

- Upload ecexample.cap to your card using [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (if already installed, uninstall applet first using *-uninstall* switch)
```
gp -install ecexample.cap -v
```
(which results in output similar to this)
```
>gp -install ecexample.cap -v
Reader: Generic EMV Smartcard Reader 0
...
CAP file (v2.1) generated on Tue Jul 25 14:34:17 CEST 2017
By Sun Microsystems Inc. converter 1.3 with JDK 1.8.0_65 (Oracle Corporation)
Package: opencrypto.jcmathlib v0.0
Applet: ECExample with AID 556E69745465737473
Import: A0000000620001 v1.0
Import: A0000000620101 v1.3
Import: A0000000620102 v1.3
Import: A0000000620201 v1.3
Installing applet from package opencrypto.jcmathlib
```

- Trigger EC operations in process() method: 'gp -apdu '
```
gp --apdu 00a4040009556e69745465737473 --apdu 0b000000 -d
```
(which results in output similar to this)
```
>gp --apdu 00a4040009556e69745465737473 --apdu 0b000000 -d
# Detected readers from SunPCSC
[*] Generic EMV Smartcard Reader 0
SCardConnect("Generic EMV Smartcard Reader 0", T=*) -> T=1, 3BF91300008131FE454A434F503234325233A2
SCardBeginTransaction("Generic EMV Smartcard Reader 0")
A>> T=1 (4+0009) 00A40400 09 556E69745465737473
A<< (0000+2) (21ms) 9000
A>> T=1 (4+0000) 0B000000      <---------------- THIS COMMAND TRIGGERED OUR EC OPERATIONS!
A<< (0000+2) (8s378ms) 9000
...
SCardEndTransaction()
SCardDisconnect("Generic EMV Smartcard Reader 0", false)
```

The code below shows very simple applet demonstrating the use of ECPoint class and basic operations. Notice that memory allocation is happening only in applet's constructor. This is common (and good) practice within Java Card development.

```java
package opencrypto.jcmathlib;

public class ECExample extends javacard.framework.Applet {
    OCConfig        occ = null;
    ECCurve         curve = null;
    ECPoint         point1 = null;
    ECPoint         point2 = null;
    
    final static byte[] ECPOINT_TEST_VALUE = {(byte)0x04, (byte) 0x3B, (byte) 0xC1, (byte) 0x5B, (byte) 0xE5, (byte) 0xF7, (byte) 0x52, (byte) 0xB3, (byte) 0x27, (byte) 0x0D, (byte) 0xB0, (byte) 0xAE, (byte) 0xF2, (byte) 0xBC, (byte) 0xF0, (byte) 0xEC, (byte) 0xBD, (byte) 0xB5, (byte) 0x78, (byte) 0x8F, (byte) 0x88, (byte) 0xE6, (byte) 0x14, (byte) 0x32, (byte) 0x30, (byte) 0x68, (byte) 0xC4, (byte) 0xC4, (byte) 0x88, (byte) 0x6B, (byte) 0x43, (byte) 0x91, (byte) 0x4C, (byte) 0x22, (byte) 0xE1, (byte) 0x67, (byte) 0x68, (byte) 0x3B, (byte) 0x32, (byte) 0x95, (byte) 0x98, (byte) 0x31, (byte) 0x19, (byte) 0x6D, (byte) 0x41, (byte) 0x88, (byte) 0x0C, (byte) 0x9F, (byte) 0x8C, (byte) 0x59, (byte) 0x67, (byte) 0x60, (byte) 0x86, (byte) 0x1A, (byte) 0x86, (byte) 0xF8, (byte) 0x0D, (byte) 0x01, (byte) 0x46, (byte) 0x0C, (byte) 0xB5, (byte) 0x8D, (byte) 0x86, (byte) 0x6C, (byte) 0x09};

    final static byte[] SCALAR_TEST_VALUE = {(byte) 0xE8, (byte) 0x05, (byte) 0xE8, (byte) 0x02, (byte) 0xBF, (byte) 0xEC, (byte) 0xEE, (byte) 0x91, (byte) 0x9B, (byte) 0x3D, (byte) 0x3B, (byte) 0xD8, (byte) 0x3C, (byte) 0x7B, (byte) 0x52, (byte) 0xA5, (byte) 0xD5, (byte) 0x35, (byte) 0x4C, (byte) 0x4C, (byte) 0x06, (byte) 0x89, (byte) 0x80, (byte) 0x54, (byte) 0xB9, (byte) 0x76, (byte) 0xFA, (byte) 0xB1, (byte) 0xD3, (byte) 0x5A, (byte) 0x10, (byte) 0x91};


    public ECExample() {
        // Pre-allocate all helper structures
        occ = new OCConfig((short) 256); 
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r, occ);
        point1 = new ECPoint(curve, occ);
        point2 = new ECPoint(curve, occ);
    }
    // Installation of our applet
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ECExample().register();
    }
    public boolean select() {
        // Restore values which were cleared after card reset 
        occ.refreshAfterReset(); 
        return true;
    }
    
    // NOTE: very simple EC usage example - no cla/ins, no communication with host...    
    public void process(APDU apdu) {
        if (selectingApplet()) { return; } // Someone is going to use our applet!
        
        // Generate first point at random
        point1.randomize(); 
        // Set second point to predefined value
        point2.setW(ECPOINT_TEST_VALUE, (short) 0, (short) ECPOINT_TEST_VALUE.length); 
        // Add two points together 
        point1.add(point2); 
        // Multiply point by large scalar
        point1.multiplication(SCALAR_TEST_VALUE, (short) 0, (short) SCALAR_TEST_VALUE.length); 
    }
}
```


## Future work
* Additional optimizations and methods (remainder_divide is particular target)
* Support for other curves like Ed25519
* Long-term vision: support for easy transfer of the Bouncy Castle-enabled crypto code to Java Card environment
