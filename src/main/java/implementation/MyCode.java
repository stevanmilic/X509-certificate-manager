package implementation;

import code.GuiException;
import implementation.exceptions.CriticalExtensionException;
import implementation.exceptions.NotCriticalExtensionException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import sun.security.ec.ECPrivateKeyImpl;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import x509.v3.CodeV3;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.*;

import static implementation.GuiHelper.*;


/**
 * Created by stevan on 5/23/17.
 */

public class MyCode extends CodeV3 {

    private KeyStore localKeyStore;
    private X509Certificate currentCertificate;
    private PKCS10CertificationRequest currentCertificationRequest;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
        Security.addProvider(new BouncyCastleProvider());
        GuiHelper.setAccess(access);
        try {
            localKeyStore = KeyStore.getInstance("PKCS12");
            localKeyStore.load(null, null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            if (localKeyStore != null) {
                return localKeyStore.aliases();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return Collections.emptyEnumeration();
    }

    @Override
    public void resetLocalKeystore() {
        try {
            localKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            localKeyStore.load(null, null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Override
    public int loadKeypair(String s) {
        try {
            Key key = localKeyStore.getKey(s, new char[0]);
            if (key instanceof ECPrivateKeyImpl) {
                GuiHelper.setCertificateECPublicKey((ECPrivateKeyImpl) key);
            } else if (key instanceof RSAPrivateKey) {
                GuiHelper.setCertificateRSAPublicKey((RSAPrivateKey) key);
            }

            X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(s);
            currentCertificate = certificate;

            GuiHelper.setCertificateInfo(certificate);
            GuiHelper.setCertificateSubject(certificate.getSubjectX500Principal().getName());

            GuiHelper.setCertificateIssuer(certificate.getIssuerX500Principal().getName());
            GuiHelper.setCertificateExtensions(certificate);

            certificate.checkValidity();

            if (localKeyStore.entryInstanceOf(s, KeyStore.TrustedCertificateEntry.class)) {
                //trusted certificate
                return 2;
            } else if (CertificateHelper.isSelfSigned(certificate) && certificate.getBasicConstraints() == -1) {
                //certificate is self signed and not CA
                return 0;
            } else {
                //certificate is signed or CA
                return 1;
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException | ParseException
                | CertificateException e) {
            e.printStackTrace();
            return -1;
        }
    }

    @Override
    public boolean saveKeypair(String s) {
        try {

            if (localKeyStore.containsAlias(s) || access.getVersion() == 0) {
                return false;
            }

            KeyPair keyPair;

            if (access.getPublicKeyAlgorithm().equals("EC")) {
                keyPair = CertificateHelper.generateECKeyPair(access.getPublicKeyECCurve());
            } else if (access.getPublicKeyAlgorithm().equals("RSA")) {
                keyPair = CertificateHelper.generateRSAKeyPair(access.getPublicKeyParameter());
            } else {
                return false;
            }

            X500Name issuer = CertificateHelper.buildName(
                    access.getSubjectCommonName(), access.getSubjectOrganization(), access.getSubjectOrganizationUnit(),
                    access.getSubjectLocality(), access.getSubjectState(), access.getSubjectCountry());
            BigInteger serialNumber = new BigInteger(access.getSerialNumber());

            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serialNumber, access.getNotBefore(), access.getNotAfter(), issuer /*subject */, keyPair.getPublic());

            CertificateHelper.setCertificatePoliciesExtension(certificateBuilder, access.isCritical(CERTIFICATE_POLICIES_ID),
                    access.getAnyPolicy(), access.getCpsUri());

            CertificateHelper.setSubjectDirectoryExtension(certificateBuilder, access.isCritical(SUBJECT_DIRECTORY_ATTRIBUTES_ID),
                    access.getDateOfBirth(), access.getSubjectDirectoryAttribute(PLACE_OF_BIRTH_ID),
                    access.getSubjectDirectoryAttribute(COUNTRY_OF_CITIZENSHIP_ID), access.getGender());

            CertificateHelper.setInhabitAnyPolicyExtension(certificateBuilder, access.isCritical(INHABIT_ANY_POLICY_ID),
                    access.getInhibitAnyPolicy(), access.getSkipCerts());


            X509Certificate certificate = CertificateHelper.signCertificate(certificateBuilder, keyPair.getPrivate(),
                    access.getPublicKeySignatureAlgorithm());

            Certificate[] certificateChain = {certificate};
            localKeyStore.setKeyEntry(s, keyPair.getPrivate(), new char[0], certificateChain);

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException
                | OperatorCreationException | CertificateException | KeyStoreException | ParseException | IOException
                | CriticalExtensionException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean removeKeypair(String s) {
        try {
            localKeyStore.deleteEntry(s);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        try {

            if (localKeyStore.containsAlias(s)) {
                return false;
            }

            KeyStore importKeyStore = KeyStore.getInstance("PKCS12");
            importKeyStore.load(new FileInputStream(s1), s2.toCharArray());

            Enumeration<String> enumeration = importKeyStore.aliases();

            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                localKeyStore.setKeyEntry(s, importKeyStore.getKey(alias, s2.toCharArray()), new char[0], importKeyStore
                        .getCertificateChain(alias));
            }

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableEntryException e) {
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
            keyStoreExport.setKeyEntry(s, localKeyStore.getKey(s, new char[0]), s2.toCharArray(), localKeyStore.getCertificateChain(s));

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
        try {
            Key issuerPrivateKey = localKeyStore.getKey(s, new char[0]);
            X509Certificate issuerCertificate = (X509Certificate) localKeyStore.getCertificate(s);

//            X500Name issuerName = new X500Name(issuerCertificate.getSubjectX500Principal().getName());
//            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuerName, new BigInteger(access.getSerialNumber()),
//                    access.getNotBefore(), access.getNotAfter(), currentCertificationRequest.getSubject(),
//                    currentCertificationRequest.getSubjectPublicKeyInfo());

            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuerCertificate.getSubjectX500Principal(),
                    currentCertificate.getSerialNumber(), currentCertificate.getNotBefore(),
                    currentCertificate.getNotAfter(), currentCertificate.getSubjectX500Principal(), currentCertificate.getPublicKey());


            Attribute[] attributes = currentCertificationRequest.getAttributes();
            if (attributes.length >= 1) {
                Attribute attribute = attributes[0];
                if (attribute.getAttrType() == PKCSObjectIdentifiers.pkcs_9_at_extensionRequest) {
                    Extensions extensions = (Extensions) attribute.getAttrValues().getObjectAt(0);
                    for (ASN1ObjectIdentifier extensionIdentifier : extensions.getExtensionOIDs()) {
                        certificateBuilder.addExtension(extensions.getExtension(extensionIdentifier));
                    }
                }
            }

            CertificateHelper.setAuthorityKeyIdentifierExtension(certificateBuilder, false, issuerCertificate);

            X509Certificate certificate = CertificateHelper.signCertificate(certificateBuilder, (PrivateKey) issuerPrivateKey, s1);

            String alias = localKeyStore.getCertificateAlias(currentCertificate);

            Certificate[] issuerCertificateChain = localKeyStore.getCertificateChain(s);
            Certificate[] certificateChain = new Certificate[issuerCertificateChain.length + 1];

            int i = 0;
            certificateChain[i++] = certificate;
            for (Certificate issuerCertificateInChain : issuerCertificateChain) {
                certificateChain[i++] = issuerCertificateInChain;
            }

            localKeyStore.setKeyEntry(alias, localKeyStore.getKey(alias, new char[0]), new char[0], certificateChain);

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException
                | OperatorCreationException | CertIOException | CriticalExtensionException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean importCertificate(File file, String s) {
        try {

            if (localKeyStore.containsAlias(s)) {
                return false;
            }

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(file));
            localKeyStore.setEntry(s, new KeyStore.TrustedCertificateEntry(certificate), null);
        } catch (CertificateException | FileNotFoundException | KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        try {
            if (i == 0) {
                OutputStream outputStream = new FileOutputStream(file);
                outputStream.write(currentCertificate.getEncoded());
                outputStream.flush();
                outputStream.close();
            } else {
                FileWriter fileWriter = new FileWriter(file);
                JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
                pemWriter.writeObject(currentCertificate);
            }
        } catch (CertificateEncodingException | IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public String getIssuer(String s) {
        try {
            X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(s);
            return certificate.getIssuerX500Principal().getName();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String s) {
        try {
            Key key = localKeyStore.getKey(s, new char[0]);
            return key.getAlgorithm();
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public int getRSAKeyLength(String s) {
        try {
            Key key = localKeyStore.getKey(s, new char[0]);
            if (key instanceof RSAPrivateKey) {
                RSAPrivateCrtKeyImpl rsaPrivateKey = (RSAPrivateCrtKeyImpl) key;
                return rsaPrivateKey.getModulus().bitLength();
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public List<String> getIssuers(String s) {
        List<String> issuers = new LinkedList<>();
        try {
            Enumeration<String> enumeration = localKeyStore.aliases();

            while (enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                if (alias.equals(s))
                    continue;
                Certificate[] certificateChain = localKeyStore.getCertificateChain(alias);
                if (certificateChain.length == 1) {
                    if (CertificateHelper.isCertificateAuthority((X509Certificate) certificateChain[0])) {
                        issuers.add(alias);
                    }
                } else {
                    boolean validChain = true;
                    if (!CertificateHelper.isCertificateAuthority((X509Certificate) certificateChain[0])) {
                        validChain = false;
                    }
                    for (int i = 0; i < certificateChain.length - 1 && validChain; i++) {
                        if (!((X509Certificate) certificateChain[i]).getIssuerX500Principal()
                                .equals(((X509Certificate) certificateChain[i + 1]).getSubjectX500Principal())
                                || !CertificateHelper.isCertificateAuthority((X509Certificate) certificateChain[i + 1])) {
                            validChain = false;
                        }
                    }
                    if (validChain) {
                        issuers.add(alias);
                    }
                }
            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
            issuers = Collections.emptyList();
        }
        return issuers;
    }

    @Override
    public boolean generateCSR(String s) {
        try {
            Key key = localKeyStore.getKey(s, new char[0]);
            X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(s);
            currentCertificationRequest = CertificateHelper.csrRequest((PrivateKey) key, certificate);
        } catch (KeyStoreException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | OperatorCreationException e) {
            e.printStackTrace();
            currentCertificationRequest = null;
            return false;
        }
        return true;
    }
}
