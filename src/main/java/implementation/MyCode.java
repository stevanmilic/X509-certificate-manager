package implementation;

import code.GuiException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import sun.security.ec.ECPrivateKeyImpl;
import x509.v3.CodeV3;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static implementation.GuiHelper.COUNTRY_OF_CITIZENSHIP_ID;
import static implementation.GuiHelper.PLACE_OF_BIRTH_ID;


/**
 * Created by stevan on 5/23/17.
 */

public class MyCode extends CodeV3 {

    private KeyStore keyStore;

    private static final int CERTIFICATE_POLICIES_ID = 3;
    private static final int SUBJECT_DIRECTORY_ATTRIBUTES_ID = 7;
    private static final int INHABIT_ANY_POLICY_ID = 13;


    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
        Security.addProvider(new BouncyCastleProvider());
        GuiHelper.setAccess(access);
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            if (keyStore != null) {
                return keyStore.aliases();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return Collections.emptyEnumeration();
    }

    @Override
    public void resetLocalKeystore() {
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Override
    public int loadKeypair(String s) {
        try {
            Key key = keyStore.getKey(s, new char[0]);
            if(key instanceof ECPrivateKeyImpl) {
                GuiHelper.setCertificatePublicKey((ECPrivateKeyImpl)key);
            }

            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(s);

            GuiHelper.setCertificateInfo(certificate);
            GuiHelper.setCertificateSubject(certificate.getSubjectX500Principal().getName());

            if (certificate.getSignature() == null) {
                //not signed
                return 0;
            }

            GuiHelper.setCertificateIssuer(certificate.getIssuerX500Principal().getName());
            GuiHelper.setCertificateExtensions(certificate);

            //certificate is self-signed -> trusted
            certificate.verify(certificate.getPublicKey());
            return 2;

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException | ParseException
                | NoSuchProviderException | CertificateException e) {
            e.printStackTrace();
            return -1;
        } catch (SignatureException | InvalidKeyException e) {
            //certificate is signed
            return 1;
        }
    }

    @Override
    public boolean saveKeypair(String s) {
        try {

            KeyPair keyPair = CertificateHelper.generateKeyPair(access.getPublicKeyAlgorithm(), access.getPublicKeyECCurve());

            X500Name issuer = CertificateHelper.buildName(
                    access.getSubjectCommonName(), access.getSubjectOrganization(), access.getSubjectOrganizationUnit(),
                    access.getSubjectLocality(), access.getSubjectState(), access.getSubjectCountry());
            BigInteger serialNumber = new BigInteger(access.getSerialNumber());

            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serialNumber, access.getNotBefore(), access.getNotAfter(), issuer, keyPair.getPublic());

            CertificateHelper.setCertificatePoliciesExtension(certificateBuilder, access.isCritical(CERTIFICATE_POLICIES_ID),
                    access.getAnyPolicy(), access.getCpsUri());

            CertificateHelper.setSubjectDirectoryExtension(certificateBuilder, access.isCritical(SUBJECT_DIRECTORY_ATTRIBUTES_ID),
                    access.getDateOfBirth(), access.getSubjectDirectoryAttribute(PLACE_OF_BIRTH_ID),
                    access.getSubjectDirectoryAttribute(COUNTRY_OF_CITIZENSHIP_ID), access.getGender());

            CertificateHelper.setInhabitAnyPolicyExtension(certificateBuilder, access.isCritical(INHABIT_ANY_POLICY_ID),
                    access.getInhibitAnyPolicy(), access.getSkipCerts());


            X509Certificate certificate = CertificateHelper.signCertificate(certificateBuilder, keyPair.getPrivate(),
                    access.getPublicKeySignatureAlgorithm());

            Certificate[] chain = {certificate};
            keyStore.setKeyEntry(s, keyPair.getPrivate(), new char[0], chain);

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException
                | OperatorCreationException | CertificateException | KeyStoreException | ParseException | IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean removeKeypair(String s) {
        try {
            keyStore.deleteEntry(s);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        try {
            KeyStore keyStoreImport = KeyStore.getInstance("PKCS12");
            keyStoreImport.load(new FileInputStream(s1), s2.toCharArray());

            Enumeration<String> enumeration = keyStoreImport.aliases();

            while(enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                keyStore.setKeyEntry(s, keyStoreImport.getKey(alias, s2.toCharArray()), new char[0], keyStoreImport
                        .getCertificateChain(alias));
            }


        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableKeyException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
        try {
            KeyStore keyStoreExport = KeyStore.getInstance("PKCS12");

            keyStoreExport.load(null, s2.toCharArray());
            keyStoreExport.setKeyEntry(s, keyStore.getKey(s, new char[0]), s2.toCharArray(), keyStore.getCertificateChain(s));

            OutputStream outputStream = new FileOutputStream(s1 + ".p12");
            keyStoreExport.store(outputStream, s2.toCharArray());
            outputStream.flush();
            outputStream.close();
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
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
