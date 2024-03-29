## Performance results 
The results presented are extracted from the unit tests execution; values shown are in milliseconds (ms). If the operation is **unsupported**, the `--` value is shown. The time measured starts with APDU send (triggering the target operation) and ends when the response is received, thus containing also data transmission and on-card data preparation overhead (the operation itself is somewhat faster). Consult the source code in UnitTests.java for target instruction (INS) to see all steps included in measurement.  

### Notes
  * Taisys SIMoME Vault does not support all JCMathLib operations and we do not know how to make full support
  * Infineon SECORA ID S can be likely optimized for faster performance, working on it
     

|	 Operation (time in ms) 	|	NXP JCOP4 J3R200 P71 (16.7.2023)	|	 NXP JCOP3 J3H145 P60 (16.7.2023)	|	Infineon SECORA ID S (16.7.2023)	|	GD Smartcafe 7.0 (16.7.2023)	|	Taisys SIMoME Vault (16.7.2023)	|
|	 --- 	|	 --- 	|	 --- 	|	 --- 	|	 --- 	|	 --- 	|
|	 bigNatAddition/INS_BN_ADD                          	|	27	|	38	|	26	|	18	|	55	|
|	 bigNatMod/INS_BN_MOD                               	|	47	|	49	|	61	|	43	|	67	|
|	 bigNatModAdd/INS_BN_ADD_MOD                        	|	45	|	57	|	54	|	32	|	66	|
|	 bigNatModExp/INS_BN_EXP_MOD                        	|	55	|	67	|	1677	|	537	|	--	|
|	 bigNatModInv/INS_BN_INV_MOD                        	|	58	|	72	|	1686	|	556	|	--	|
|	 bigNatModMult/INS_BN_MUL_MOD                       	|	180	|	233	|	1064	|	660	|	760	|
|	 bigNatModSq/INS_BN_SQ_MOD                          	|	65	|	75	|	1075	|	564	|	--	|
|	 bigNatModSqrt/INS_BN_SQRT_MOD                      	|	328	|	445	|	4722	|	1438	|	--	|
|	 bigNatModSub/INS_BN_SUB_MOD                        	|	45	|	75	|	55	|	45	|	54	|
|	 bigNatMultiplication/INS_BN_MUL                    	|	145	|	199	|	517	|	164	|	400	|
|	 bigNatMultiplicationSlow/INS_BN_MUL_SCHOOL         	|	340	|	590	|	540	|	461	|	769	|
|	 bigNatSetValue/INS_BN_SET_VALUE                    	|	19	|	21	|	31	|	17	|	18	|
|	 bigNatShiftRight/INS_BN_SHIFT_RIGHT                	|	21	|	29	|	22	|	14	|	46	|
|	 bigNatSq/INS_BN_SQ                                 	|	41	|	37	|	514	|	23	|	47	|
|	 bigNatStorage/INS_BN_STR                           	|	20	|	21	|	22	|	10	|	23	|
|	 bigNatSubtraction/INS_BN_SUB                       	|	40	|	51	|	51	|	30	|	54	|
|	 eccAdd/INS_EC_ADD                                  	|	86	|	250	|	5291	|	2723	|	--	|
|	 eccDoubleGenerator/INS_EC_DBL                      	|	60	|	201	|	182	|	3113	|	--	|
|	 eccDoubleRandom/INS_EC_DBL                         	|	64	|	202	|	179	|	3106	|	--	|
|	 eccEncode(compressed_in)/INS_EC_ENCODE             	|	576	|	797	|	6943	|	2718	|	--	|
|	 eccEncode(compressed_in_out)/INS_EC_ENCODE         	|	572	|	794	|	6944	|	2724	|	--	|
|	 eccEncode(compressed_out)/INS_EC_ENCODE            	|	25	|	25	|	32	|	14	|	60	|
|	 eccEncode(uncompressed_in_out)/INS_EC_ENCODE       	|	29	|	37	|	46	|	20	|	51	|
|	 eccFromX/INS_EC_FROM_X                             	|	604	|	773	|	6989	|	2737	|	--	|
|	 eccGen/INS_EC_GEN                                  	|	45	|	226	|	127	|	201	|	1244	|
|	 eccIsEqual/INS_EC_COMPARE                          	|	47	|	75	|	158	|	57	|	134	|
|	 eccIsYEven/INS_EC_IS_Y_EVEN                        	|	23	|	36	|	65	|	24	|	69	|
|	 eccMultRandomAndAdd/INS_EC_MUL_ADD                 	|	91	|	255	|	5441	|	5823	|	--	|
|	 eccMultiplyGenerator/INS_EC_MUL                    	|	73	|	209	|	211	|	3131	|	--	|
|	 eccMultiplyRandom/INS_EC_MUL                       	|	71	|	206	|	207	|	3110	|	--	|
|	 eccNegation/INS_EC_NEG                             	|	60	|	91	|	145	|	69	|	370	|
|	 integerAddition/INS_INT_ADD                        	|	12	|	22	|	18	|	14	|	28	|
|	 integerDivision/INS_INT_DIV                        	|	31	|	29	|	42	|	26	|	49	|
|	 integerModulo/INS_INT_MOD                          	|	14	|	18	|	26	|	14	|	27	|
|	 integerMultiplication/INS_INT_MUL                  	|	61	|	81	|	110	|	65	|	104	|
|	 integerStorage/INS_INT_STR                         	|	9	|	11	|	13	|	7	|	15	|
|	 integerSubtraction/INS_INT_SUB                     	|	20	|	41	|	61	|	20	|	31	|



