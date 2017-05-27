package implementation;

import sun.security.ec.ECPrivateKeyImpl;
import x509.v3.GuiV3;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.ParseException;

/**
 * Created by stevan on 5/27/17.
 */
class GuiHelper {

    static final int PLACE_OF_BIRTH_ID = 0;
    static final int COUNTRY_OF_CITIZENSHIP_ID = 1;

    private static GuiV3 access;

    static void setAccess(GuiV3 access) {
        GuiHelper.access = access;
    }

    static void setCertificatePublicKey(ECPrivateKeyImpl privateKey) {
        access.setPublicKeyAlgorithm(privateKey.getAlgorithm());
        access.setPublicKeyECCurve(privateKey.getParams().getCurve().toString());
    }

    static void setCertificateInfo(X509Certificate certificate) {
        access.setVersion(certificate.getVersion() - 1); //version 3 button
        access.setSerialNumber(String.valueOf(certificate.getSerialNumber()));
        access.setNotAfter(certificate.getNotAfter());
        access.setNotBefore(certificate.getNotBefore());
        access.setPublicKeySignatureAlgorithm(certificate.getSigAlgName());
        //access.setIssuerUniqueIdentifier(certificate.getIssuerUniqueID().toString());
    }

    static void setCertificateSubject(String subjectName) throws IOException {
        access.setSubject(subjectName);
    }

    static void setCertificateIssuer(String issuerName) throws IOException {
        access.setIssuer(issuerName);
    }

    static void setCertificateExtensions(X509Certificate certificate) throws IOException, ParseException {
        String cpsUri = CertificateHelper.getCertificatePoliciesExtension(certificate);
        if(!cpsUri.isEmpty()) {
            access.setAnyPolicy(true);
            access.setCpsUri(cpsUri);
        }
        String skipCerts = CertificateHelper.getInhabitAnyPolicyExtension(certificate);
        if(!skipCerts.isEmpty()) {
            access.setInhibitAnyPolicy(true);
            access.setSkipCerts(skipCerts);
        }
        String[] subjectDirectoryData = CertificateHelper.getSubjectDirectoryExtension(certificate);
        if(subjectDirectoryData != null) {
            access.setDateOfBirth(subjectDirectoryData[0]);
            access.setSubjectDirectoryAttribute(COUNTRY_OF_CITIZENSHIP_ID, subjectDirectoryData[1]);
            access.setSubjectDirectoryAttribute(PLACE_OF_BIRTH_ID, subjectDirectoryData[2]);
            access.setGender(subjectDirectoryData[3]);
        }
    }
}
