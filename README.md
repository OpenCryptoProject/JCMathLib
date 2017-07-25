# JCMathLib

The JCMathLib is an open-source library for Java Card platform which provides objects and operations otherwise missing from standard Java Card API. Namely, we focus on adding support for low-level operations with elliptic curves like addition or multiplication of points on elliptic curves in resource efficient way. As a bonus, we provide shared memory management and performance optimization tooling.

## FAQ
**Q:** Hold on, I thought elliptic curves are already supported on smart cards, right? <br>
**A:** Definitely not on each one. Take a look at [jcalgtest.org](https://jcalgtest.org) - out of 65 cards listed, only about 1/3 have some support. 

**Q:** I will just download some 3rd party implementation like Bouncy Castle and run it on a card. So why are you developing this library?<br>
**A:** Not that easy. The most JavaCards don't support //int// datatype. And even if you will change the code and finally compile, it will be impractically slow on CPU with 40MHz CPU and 3KB RAM. That's why smart card manufacturers add dedicated coprocessor for operations like modular multiplication (RSA) or elliptic curve point operations (ECC).

**Q:** So if there is cryptographic coprocessor, I can do decrypt, sign or run key establishment directly on the card, right?<br>
**A:** Yes, usually in the order of hundreds of milliseconds for asymmetric crypto. But if you like to build some fancier like multi-party secure communication protocols, blind signatures or attribute-based crypto which requires low-level operations, you are usually out of luck.

**Q:** ECPoint is not included in standard Java Card API? <br>
**A:** No, it is not. You can still get operations you want via additional manufacturer proprietary API which usually means also signing NDA and also get bound to a particular manufacturer.   

**Q:** How your library can provide ECPoint if the port from Bouncy Castle is not a viable option?<br>
**A:** We use card's fast co-processors in unintended ways (raw RSA for fast multiplication, ECDH KeyAgreement for point multiplication...)  and combine with software-only implementation to provide the resulting operation.   

**Q:** So you provide these missing operations in an efficient way. Are there any disadvantages with respect to a manufacturer's native implementation? <br>
**A:** We are slower if an operation requires computing lot of additional steps in a software-only manner. Also, native implementation is more resistant against side-channel and fault induction attacks.       

**Q:** Do you support ECPoint operations on cards which are complete without EC support?  <br>
**A:** No, we need at least ECDH key agreement operation and new key pair generation supported on a target card. However, you can use fast operations with big numbers (Bignat, BigInteger) even on cards without EC support. 

**Q:** Sounds good, how can I start to fiddle with the JCMathLibrary library?<br>
**A:** Buy [suitable](https://www.fi.muni.cz/~xsvenda/jcalgtest/) JavaCard for $10-20 with EC support ([buyers'guide](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/JavaCardBuyersGuide#javacard-buyers-guide-of-2015)), download this library source code, compile example project with [ant-javacard](https://github.com/martinpaljak/ant-javacard) and start playing. Don't forget to read [wiki](https://github.com/mavroudisv/JCMathLib/wiki) for examples and tutorials. 

## Compilation, upload, and use

## Related projects
