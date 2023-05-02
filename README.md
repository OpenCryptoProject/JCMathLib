[![MIT licensed](https://img.shields.io/github/license/OpenCryptoProject/JCMathLib)](https://github.com/OpenCryptoProject/JCMathLib/blob/master/LICENSE) 

<p align="center">
    <img src=".github/resources/logo.png">
</p>

JCMathLib is an open-source library for the JavaCard platform that aims to enable low-level cryptographic computations
unavailable in the standard JavaCard API. In particular, it focuses on providing efficient modular arithmetic and
elliptic curve operations.

If you want to get into the technical details of JCMathLib, you can find them in this
paper: https://arxiv.org/abs/1810.01662.

## Table of Contents

- [Features and Limitations](#features-and-limitations)
- [Getting Started](#getting-started)
- [Integration With Your Applet](#integration-with-your-applet)
- [Community](#community)

## Features and Limitations

JCMathLib includes the following features:

- BigNat arithmetic including modular operations
- Elliptic curve point addition and multiplication
- Option to accelerate computation by utilizing `int` native type on smartcards that support it (
  branch `ints`)
- No dependencies on proprietary interfaces (only public JavaCard API)
- Selection of appropriate algorithm implementation based on the card's algorithm support (`OperationSupport`)
- Resource management (`ObjectAllocator`, `ObjectLocker`)
- Predefined common elliptic curves (`SecP256r1`, `SecP256k1`, `SecP512r1`)
- Tool for packaging JCMathLib into a single file for easy integration

Although higher-level cryptographic primitives and protocols can be constructed using JCMathLib, they are not included
in the library. In case you need a higher-level implementation, you may try looking for projects building on top
of JCMathLib (e.g., see [our users](#our-users)).

As JCMathLib is implemented for the JavaCard Platform and relies only on public JavaCard API, it is not as efficient
as a native implementation could be. This approach has a number of advantages, like easy portability and the possibility
to open-source code. However, it makes it much harder (if not impossible) to perform the operations in constant time,
and we do not aim to. The library is thus vulnerable to timing side-channel attacks and **is NOT suited for production
use**.

## Getting Started

Before using JCMathLib in your projects, you should test that it works properly on your smartcard. For that, you may
want to run UnitTests. If you plan to work only with a simulator, you can skip to the last step
of [the following section](#running-unit-tests).

### Running unit tests

Set your card type in the `UnitTests` class and also change the JavaCard API version in `applet/build.gradle` file if
you wish to run the code on cards with a JavaCard API version different from 3.0.5. Then you can build the applet by
running the following command.

```
./gradlew buildJavaCard
```

If the build completes successfully, you may install it on a card by running the following command. In case you
encounter some issues, you may want to try using [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)
directly and install the built cap file `applet/build/javacard/unit_tests.cap`.

```
./gradlew installJavaCard
```

If the installation completes successfully, you can run the tests. If the `UnitTests` contain your card type, the
following command will try to run the tests with a connected card. Otherwise, it will run the tests just in a simulator.

```
./gradlew test
```

If you have multiple readers connected to your device, you may need to adjust the reader
index (`runCfg.setTargetReaderIndex` in `BaseTest`).

### Example usage

For an example usage of the library, see the [`Example`](applet/src/main/java/opencrypto/jcmathlib/Example.java) applet.

## Integration With Your Applet

To enable easy integration of JCMathLib with your applet, we provide a Python script that bundles JCMathLib into a
single `.java` that can be included in your code.

The script provides the following interface, allowing to specify which parts of JCMathLib to include (to save memory).

```
$ python package.py -h
usage: package.py [-h] [-d DIR] [-k] [-c {SecP256k1,SecP256r1,SecP512r1} [{SecP256k1,SecP256r1,SecP512r1} ...]] [-p PACKAGE] [-o OUTPUT]

Package the JCMathLib library into a single file.

options:
  -h, --help            show this help message and exit
  -d DIR, --dir DIR     Directory to package
  -k, --keep-locks      Keep locks
  -c {SecP256k1,SecP256r1,SecP512r1} [{SecP256k1,SecP256r1,SecP512r1} ...], --curves {SecP256k1,SecP256r1,SecP512r1} [{SecP256k1,SecP256r1,SecP512r1} ...]
                        Curves to include
  -p PACKAGE, --package PACKAGE
                        Package name
  -o OUTPUT, --output OUTPUT
                        Output file
```

For example, to bundle JCMathLib for your applet `test` in which you use curve `SecP256k1`, use the following. The
output will be stored in `jcmathlib.java` file.

```
$ python package.py -p test -c SecP256k1 -o jcmathlib.java
```

## Community

JCMathLib is kindly supported by:

<p align="center">
<a href="https://www.javacardos.com/javacardforum/?ws=opencryptojc"><img src=".github/resources/javacardos.png" width="300"></a>
</p>

### How to contribute

We welcome all contributions, but we especially appreciate contributions in the following form:

- **Code improvements.** If you discover a bug or have an idea for improving the code, please, submit the change in a [Pull Request](https://github.com/OpenCryptoProject/JCMathLib/pulls).
- **Features.** If you wish certain feature was included in JCMathLib, let us know via [Issues](https://github.com/OpenCryptoProject/JCMathLib/issues) or implement it yourself and submit a [Pull Request](https://github.com/OpenCryptoProject/JCMathLib/pulls).
- **Testing on cards.** If you have a smart card model that is not yet included in JCMathLib and you manage to get it working, please, create a pull request with the corresponding `OperationSupport` configuration and include information about the smart card. Also consider submitting your card results to [JCAlgTest](https://jcalgtest.cz/).

### Our users
  * [Myst](https://github.com/OpenCryptoProject/Myst): Secure Multiparty Key Generation, Signature and Decryption JavaCard applet and host application 
  * [BioID](https://eprint.iacr.org/2019/894.pdf): a Privacy-Friendly Identity Document
  * [JCEd25519](https://github.com/dufkan/JCEd25519): a JavaCard implementation of Ed25519 signing

(If you can't find yourself here, please let us know via [Issues](https://github.com/OpenCryptoProject/JCMathLib/issues))
