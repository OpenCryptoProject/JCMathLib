[![MIT licensed](https://img.shields.io/github/license/OpenCryptoProject/JCMathLib)](https://github.com/OpenCryptoProject/JCMathLib/blob/master/LICENSE) 

<p align="center">
    <img src="README-rsrc/logo.png">
</p>

The JCMathLib is an open-source library for Java Card platform which provides objects and operations otherwise missing from standard Java Card API. Namely, we focus on adding support for low-level operations like addition or multiplication of points on elliptic curves in resource efficient way. As a bonus, we provide tooling for [shared memory management](https://github.com/OpenCryptoProject/JCMathLib/wiki/Main-components) and [performance optimization](https://github.com/OpenCryptoProject/JCProfiler).

If you want get into the math and the technical details explaining why things in JCMathLib work the way they do, you can find our paper here: https://arxiv.org/abs/1810.01662

If you want to cite this library:
```
@article{2020-jcmathlib-cybercert,
    Title = {JCMathLib: Wrapper Cryptographic Library for Transparent and Certifiable JavaCard Applets},
    Author = {Vasilios Mavroudis and Petr Svenda},
    Conference = {2020 IEEE European Symposium on Security and Privacy Workshops},
    Year = {2020},
    Pages = {89--96},
    Publisher = {IEEE},
}
```


### Project supporters
JCMathLib is kindly supported by: 
<p align="center"></br>
<a href="https://www.javacardos.com/javacardforum/?ws=opencryptojc"> <img src="README-rsrc/javacardos.png" width="300"></a>
</p>


## Running tests with simulator

```
./gradlew test
```

## Running tests on a physical smartcard

### Building applet for a physical smartcard

Set your card type in constructors of `OCUnitTests` and `ECExample` classes and then run the following command.

```
./gradlew buildJavaCard
```

### Installing the applet

Applet can be installed to using the following command.

```
./gradlew installJavaCard
```

Alternatively, you can use [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPLatformPro) and upload file `applet/build/javacard/unit_tests.cap`.

### Running tests

Change card type in constructor of JCMathLibTest to `CardType.PHYSICAL` and run the following command.

```
./gradlew test
```

If you have multiple readers connected to your device, you may need to adjust reader index (`runCfg.setTargetReaderIndex` in `BaseTest`).

## Example applet

The code below shows a very simple applet demonstrating the use of the ECPoint class and other basic operations. Notice that memory allocation is happening only in the applet's constructor. This is common (and good) Java Card development practice.

```java
package opencrypto.jcmathlib;

public class ECExample extends Applet {
    ECConfig        ecc = null;
    ECCurve         curve = null;
    ECPoint         point1 = null;
    ECPoint         point2 = null;

    final static byte[] ECPOINT_TEST_VALUE = {(byte)0x04, (byte) 0x3B, (byte) 0xC1, (byte) 0x5B, (byte) 0xE5, (byte) 0xF7, (byte) 0x52, (byte) 0xB3, (byte) 0x27, (byte) 0x0D, (byte) 0xB0, (byte) 0xAE, (byte) 0xF2, (byte) 0xBC, (byte) 0xF0, (byte) 0xEC, (byte) 0xBD, (byte) 0xB5, (byte) 0x78, (byte) 0x8F, (byte) 0x88, (byte) 0xE6, (byte) 0x14, (byte) 0x32, (byte) 0x30, (byte) 0x68, (byte) 0xC4, (byte) 0xC4, (byte) 0x88, (byte) 0x6B, (byte) 0x43, (byte) 0x91, (byte) 0x4C, (byte) 0x22, (byte) 0xE1, (byte) 0x67, (byte) 0x68, (byte) 0x3B, (byte) 0x32, (byte) 0x95, (byte) 0x98, (byte) 0x31, (byte) 0x19, (byte) 0x6D, (byte) 0x41, (byte) 0x88, (byte) 0x0C, (byte) 0x9F, (byte) 0x8C, (byte) 0x59, (byte) 0x67, (byte) 0x60, (byte) 0x86, (byte) 0x1A, (byte) 0x86, (byte) 0xF8, (byte) 0x0D, (byte) 0x01, (byte) 0x46, (byte) 0x0C, (byte) 0xB5, (byte) 0x8D, (byte) 0x86, (byte) 0x6C, (byte) 0x09};

    final static byte[] SCALAR_TEST_VALUE = {(byte) 0xE8, (byte) 0x05, (byte) 0xE8, (byte) 0x02, (byte) 0xBF, (byte) 0xEC, (byte) 0xEE, (byte) 0x91, (byte) 0x9B, (byte) 0x3D, (byte) 0x3B, (byte) 0xD8, (byte) 0x3C, (byte) 0x7B, (byte) 0x52, (byte) 0xA5, (byte) 0xD5, (byte) 0x35, (byte) 0x4C, (byte) 0x4C, (byte) 0x06, (byte) 0x89, (byte) 0x80, (byte) 0x54, (byte) 0xB9, (byte) 0x76, (byte) 0xFA, (byte) 0xB1, (byte) 0xD3, (byte) 0x5A, (byte) 0x10, (byte) 0x91};


    public ECExample() {
        // Set your card
        OperationSupport.getInstance().setCard(OperationSupport.SIMULATOR);
        // Pre-allocate all helper structures
        ecc = new ECConfig((short) 256); 
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        point1 = new ECPoint(curve, ecc.ech);
        point2 = new ECPoint(curve, ecc.ech);
    }
    // Installation of our applet
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ECExample().register();
    }
    public boolean select() {
        // Restore values which were cleared after card reset
        ecc.refreshAfterReset();
        return true;
    }

    // NOTE: very simple EC usage example - no cla/ins, no communication with host
    public void process(javacard.framework.APDU apdu) {
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

### Run example client with simulator

```
./gradlew run
```

## FAQ
**Q:** Hold on, I thought elliptic curves are already supported on smart cards, right? <br>
**A:** Definitely not on each one. Take a look at [jcalgtest.org](http://jcalgtest.org) - out of 65 cards listed, only about 1/3 have some support. 

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


## Future work
* Additional optimizations and methods (remainder_divide is particular target)
* Support for other curves like Ed25519
* Long-term vision: support for easy transfer of the Bouncy Castle-enabled crypto code to Java Card environment

### Happy users so far
(If you can't find yourself here, please let us know via [Issues](https://github.com/OpenCryptoProject/JCMathLib/issues))
  * [Myst](https://github.com/OpenCryptoProject/Myst): Secure Multiparty Key Generation, Signature and Decryption JavaCard applet and host application 
