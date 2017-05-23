package implementation;

import code.GuiException;
import x509.v3.CodeV3;

import java.io.File;
import java.util.Enumeration;
import java.util.List;

/**
 * Created by stevan on 5/23/17.
 */

public class MyCode extends CodeV3{

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        return null;
    }

    @Override
    public void resetLocalKeystore() {

    }

    @Override
    public int loadKeypair(String s) {
        return 0;
    }

    @Override
    public boolean saveKeypair(String s) {
        return false;
    }

    @Override
    public boolean removeKeypair(String s) {
        return false;
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean signCertificate(String s, String s1) {
        return false;
    }

    @Override
    public boolean importCertificate(File file, String s) {
        return false;
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        return false;
    }

    @Override
    public String getIssuer(String s) {
        return null;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String s) {
        return null;
    }

    @Override
    public int getRSAKeyLength(String s) {
        return 0;
    }

    @Override
    public List<String> getIssuers(String s) {
        return null;
    }

    @Override
    public boolean generateCSR(String s) {
        return false;
    }
}
