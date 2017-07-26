package opencrypto.test;

import java.util.ArrayList;
import opencrypto.jcmathlib.OCUnitTests;

/**
 *
 * @author Petr Svenda
 */
public class RunConfig {
    int targetReaderIndex = 0;
    public boolean bTestBN = true;
    public boolean bTestINT = true;
    public boolean bTestEC = true;
    public boolean bTestECPoint = true;
    public boolean bMeasureOnlyTargetOp = false;
    public int numRepeats = 1;
    public int bnBaseTestLength = 256;
    public ArrayList<String> failedTestsList = new ArrayList<>();
    public Class appletToSimulate;
    
    public enum CARD_TYPE {
        PHYSICAL, JCOPSIM, JCARDSIMLOCAL, JCARDSIMREMOTE
    }
    public CARD_TYPE testCardType = CARD_TYPE.PHYSICAL;
    
    public static RunConfig getDefaultConfig() {
        RunConfig runCfg = new RunConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.testCardType = CARD_TYPE.PHYSICAL;
        runCfg.appletToSimulate = OCUnitTests.class;
        
        return runCfg;
    }
    public static RunConfig getConfigSimulator() {
        RunConfig runCfg = new RunConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.testCardType = CARD_TYPE.JCARDSIMLOCAL;
        runCfg.bTestBN = false;
        runCfg.bTestINT = false;
        runCfg.bTestEC = false;
        runCfg.appletToSimulate = OCUnitTests.class;
        return runCfg;
    }
    public static RunConfig getConfig(boolean bTestBN, boolean bTestINT, boolean bTestEC, int numRepeats, CARD_TYPE cardType) {
        RunConfig runCfg = new RunConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.testCardType = cardType;
        runCfg.bTestBN = bTestBN;
        runCfg.bTestINT = bTestINT;
        runCfg.bTestEC = bTestEC;
        runCfg.numRepeats = numRepeats;
        runCfg.appletToSimulate = OCUnitTests.class;
        return runCfg;
    }
}
