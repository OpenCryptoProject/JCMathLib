[![MIT licensed](https://img.shields.io/github/license/OpenCryptoProject/JCMathLib)](https://github.com/OpenCryptoProject/JCMathLib/blob/master/LICENSE) 

<p align="center">
    <img src=".github/resources/logo.png">
</p>

JCMathLib is an open-source library for the JavaCard platform that aims to enable low-level cryptographic computations
unavailable in the standard JavaCard API. In particular, it focuses on providing efficient modular arithmetic and
elliptic curve operations.

If you want to get into the technical details of JCMathLib, you can find them in this
paper: https://arxiv.org/abs/1810.01662.

When citing our work, please use the following reference: 

```
@inproceedings{mavroudis2020jcmathlib,
  title={JCMathLib: wrapper cryptographic library for transparent and certifiable JavaCard applets},
  author={Mavroudis, Vasilios and Svenda, Petr},
  booktitle={2020 IEEE European Symposium on Security and Privacy Workshops (EuroS\&PW)},
  pages={89--96},
  year={2020},
  organization={IEEE}
}
```


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

Clone this repository:

```
git clone --recurse-submodules https://github.com/OpenCryptoProject/JCMathLib.git
```

For compilation for JavaCards, you need to obtain JavaCard SDKs, which are included as submodule. If you did not use `--recurse-submodules` in the previous command and your libs-sdks folder is empty, run:

```
git submodule update --init --recursive
```

Before using JCMathLib in your projects, you should test that it works properly on your smartcard. For that, you may want to run UnitTests. If you plan to work only with a simulator, you can skip to the last step of [the following section](#running-unit-tests).

### Running unit tests

1. Set your card type in the `JCMathLib/applet/src/main/java/opencrypto/jcmathlib/UnitTests` class. The supported options are listed in class `OperationSupport.{SIMULATOR, JCOP21, JCOP3_P60, JCOP4_P71, GD60, GD70, SECORA}`.

```java
public class UnitTests extends Applet {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR; // TODO set your card here
```

2. OPTIONAL (depending on card selected in step 1). Change the JavaCard API version in `applet/build.gradle` file if you wish to run the code on cards with a JavaCard API version different from 3.0.5.

```
// JC310b43 supports building also for lower versions (cap.targetsdk).
// If another SDK is selected, please comment the cap.targetsdk setting.
final def JC_SELECTED = JC310b43 <----
...
// JC310b43 supports compilation targeting for lower API versions.
// Here you can specify path to the SDK you want to use.
// Only JC304 and higher are supported for targeting.
// If JC310b43 is not used, targetsdk cannot be set.
targetsdk JC305  <----
```
If you would like to build for lower versions, comment out line with `targetsdk JC305` and set `final def JC_SELECTED = JC310b43` to other value like `final def JC_SELECTED = JC222`.

The list of settings is summarized here:
| Card | `OperationSupport` | `JC_SELECTED` | `targetsdk` | Notes |
| ---  | --- | --- | --- | --- |
| [jCardSim simulator](https://github.com/licel/jcardsim/) | SIMULATOR | -- | -- | (JavaCard API settings are ignored) |
| [NXP J2E145G](https://github.com/crocs-muni/jcalgtest_results/blob/main/javacard/Profiles/results/NXP_J2E145G_ICFabDate_2013_025_ALGSUPPORT__3b_f9_13_00_00_81_31_fe_45_4a_43_4f_50_32_34_32_52_33_a2_(provided_by_PetrS_and_Lukas_Malina).csv) | JCOP21 | JC303 | remove | |
| [NXP JCOP3 J3H145 P60](https://github.com/crocs-muni/jcalgtest_results/blob/main/javacard/Profiles/results/NXP_JCOP3_J3H145_SECID_P60_ALGSUPPORT__3b_11_95_80_(provided_by_Luka_Logar_and_Rowland_Watkins_and_PetrS).csv) | JCOP3_P60 | JC310b43 | JC304 | |
| [NXP JCOP4 J3Rxxx P71](https://github.com/crocs-muni/jcalgtest_results/blob/main/javacard/Profiles/results/NXP_JCOP4_J3R180_P71_ALGSUPPORT__3b_fa_18_00_ff_10_00_4a_54_61_78_43_6f_72_65_56_31_(provided_by_PetrS).csv) | JCOP4_P71 | JC310b43 | JC305 | |
| [G+D Sm@rtcafe 6.0](https://github.com/crocs-muni/jcalgtest_results/blob/main/javacard/Profiles/results/G%2BD_Smartcafe_6.0_80K_ICFabDate_2015_024_ALGSUPPORT__3b_fe_18_00_00_80_31_fe_45_53_43_45_36_30_2d_43_44_30_38_31_2d_6e_46_a9_(provided_by_PetrS).csv) | GD60 | JC303 | remove | |
| [G+D Sm@rtcafe 7.0](https://github.com/crocs-muni/jcalgtest_results/blob/main/javacard/Profiles/results/G%2BD_SmartCafe_7.0_215K_USB_Token_S_ALGSUPPORT__3b_f9_96_00_00_81_31_fe_45_53_43_45_37_20_0e_00_20_20_28_(provided_by_PetrS).csv) | GD70 | JC310b43 | JC304 | |
| [Infineon Secora ID S](https://github.com/crocs-muni/jcalgtest_results/blob/main/javacard/Profiles/results/Infineon_SECORA_ID_S_(SCP02_with_RSA2k_JC305_GP230_NOT_FOR_SALE_-_PROTOTYPE_ONLY)_ALGSUPPORT__3b_b8_97_00_c0_08_31_fe_45_ff_ff_13_57_30_50_23_00_6a_(provided_by_Thoth).csv) | SECORA | JC310b43 | JC305 | (may require AES256 GP keys) |

3. Build the applet by running the following command.

```
./gradlew buildJavaCard
```

4. If the build completes successfully, you may install it on a card by running the following command. In case you
encounter some issues, you may want to try using [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)
directly and install the built cap file `applet/build/javacard/unit_tests.cap`.

```
./gradlew installJavaCard
```

If the installation completes successfully, you can run the tests. If the `UnitTests` contain your card type, the
following command will try to run the tests with a connected card. Otherwise, it will run the tests just in a simulator.

```
./gradlew --rerun-tasks test
```

If you have multiple readers connected to your device, you may need to adjust the reader
index (`runCfg.setTargetReaderIndex` in `JCMathLib/applet/src/test/java/tests/BaseTest`).

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
  -c {SecP256k1,SecP256r1,SecP512r1,Wei25519} [{SecP256k1,SecP256r1,SecP512r1,Wei25519} ...], --curves {SecP256k1,SecP256r1,SecP512r1,Wei25519} [{SecP256k1,SecP256r1,SecP512r1,Wei25519} ...]
                        Curves to include
  -p PACKAGE, --package PACKAGE
                        Package name
  -o OUTPUT, --output OUTPUT
                        Output file
```

For example, to bundle JCMathLib for your applet `test` in which you use curve `SecP256r1`, use the following. The
output will be stored in `jcmathlib.java` file.

```
$ python package.py -p test -c SecP256r1 -o jcmathlib.java
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
