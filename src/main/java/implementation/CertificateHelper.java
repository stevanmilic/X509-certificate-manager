package implementation;

import implementation.exceptions.CriticalExtensionException;
import implementation.exceptions.NotCriticalExtensionException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Set;
import java.util.Vector;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

/**
 * Created by stevan on 5/25/17.
 */

class CertificateHelper {

    static KeyPair generateECKeyPair(String eccCurve) throws InvalidAlgorithmParameterException,
            NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
        ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(eccCurve);
        keyPairGenerator.initialize(parameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    static KeyPair generateRSAKeyPair(String keyLength) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(Integer.parseInt(keyLength));
        return keyPairGenerator.generateKeyPair();
    }

    static X500Name buildName(String commonName, String organization, String organizationUnit, String locality,
                              String state, String country) {

        X500NameBuilder nameBuilder = new X500NameBuilder();

        if (!commonName.isEmpty()) {
            nameBuilder.addRDN(BCStyle.CN, commonName);
        }
        if (!organizationUnit.isEmpty()) {
            nameBuilder.addRDN(BCStyle.OU, organizationUnit);
        }
        if (!organization.isEmpty()) {
            nameBuilder.addRDN(BCStyle.O, organization);
        }
        if (!locality.isEmpty()) {
            nameBuilder.addRDN(BCStyle.L, locality);
        }
        if (!state.isEmpty()) {
            nameBuilder.addRDN(BCStyle.ST, state);
        }
        if (!country.isEmpty()) {
            nameBuilder.addRDN(BCStyle.C, country);
        }

        return nameBuilder.build();
    }

    static void setSubjectDirectoryExtension(X509v3CertificateBuilder certificateBuilder, boolean isCritical,
                                             String dateOfBirth, String placeOfBirth, String countryOfCitizenship,
                                             String gender) throws IOException, ParseException, CriticalExtensionException {

        if (dateOfBirth.isEmpty() || placeOfBirth.isEmpty() || countryOfCitizenship.isEmpty() || gender.isEmpty()) {
            return;
        }

        if(isCritical) {
            throw new CriticalExtensionException(Extension.subjectDirectoryAttributes);
        }

        Vector<Attribute> attributes = new Vector<>();

        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
        Date dateOfBirthDate = simpleDateFormat.parse(dateOfBirth);

        attributes.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DERSet(new Time(dateOfBirthDate))));
        attributes.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DERSet(new DEROctetString(placeOfBirth.getBytes()))));
        attributes.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DERSet(new DEROctetString(countryOfCitizenship.getBytes()))));
        attributes.add(new Attribute(BCStyle.GENDER, new DERSet(new DEROctetString(gender.getBytes()))));

        SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes(attributes);
        certificateBuilder.addExtension(Extension.subjectDirectoryAttributes, isCritical, subjectDirectoryAttributes);
    }

    static void setInhabitAnyPolicyExtension(X509v3CertificateBuilder certificateBuilder,
                                             Boolean isCritical, boolean inhabitAnyPolicy, String skipCerts)
            throws IOException, NotCriticalExtensionException {
        if (inhabitAnyPolicy) {
            if(!isCritical) {
               throw new NotCriticalExtensionException(Extension.inhibitAnyPolicy);
            }
            ASN1Integer skipCertsInteger = new ASN1Integer(new BigInteger(skipCerts));
            certificateBuilder.addExtension(Extension.inhibitAnyPolicy, isCritical, skipCertsInteger);
        }
    }

    static void setCertificatePoliciesExtension(X509v3CertificateBuilder certificateBuilder, boolean isCritical,
                                                boolean anyPolicy, String cpsURI) throws IOException {
        if (anyPolicy) {
            PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(cpsURI);
            PolicyInformation policyInformation = new PolicyInformation(PolicyQualifierId.id_qt_cps,
                    new DERSequence(policyQualifierInfo));
            CertificatePolicies certificatePolicies = new CertificatePolicies(policyInformation);
            certificateBuilder.addExtension(Extension.certificatePolicies, isCritical, certificatePolicies);
        }
    }

    static void setAuthorityKeyIdentifierExtension(X509v3CertificateBuilder certificateBuilder, boolean isCritical,
                                                   X509Certificate caCertificate)
            throws NoSuchAlgorithmException, CertIOException, CriticalExtensionException {

        if(isCritical) {
            throw new CriticalExtensionException(Extension.authorityKeyIdentifier);
        }

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier subjectKeyIdentifier = extensionUtils.createSubjectKeyIdentifier(caCertificate.getPublicKey());
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        GeneralNames generalNames = new GeneralNames(new GeneralName(GeneralName.directoryName,
                caCertificate.getIssuerDN().getName()));
        AuthorityKeyIdentifier authorityKeyIdentifier = extensionUtils.createAuthorityKeyIdentifier(caCertificate.getPublicKey());
        authorityKeyIdentifier = new AuthorityKeyIdentifier(authorityKeyIdentifier.getKeyIdentifier(), generalNames,
                caCertificate.getSerialNumber());
        certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
    }

    static String getCertificatePoliciesExtension(X509Certificate certificate) throws IOException {
        byte[] certificatePoliciesBytes = certificate.getExtensionValue(Extension.certificatePolicies.toString());
        if (certificatePoliciesBytes != null) {
            CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(certificatePoliciesBytes));
            PolicyInformation[] policyInformations = certificatePolicies.getPolicyInformation();
            for (PolicyInformation policyInformation : policyInformations) {
                ASN1Sequence policyQualifiers = (ASN1Sequence) policyInformation.getPolicyQualifiers().getObjectAt(0);
                return policyQualifiers.getObjectAt(1).toString();
            }
        }
        return "";
    }

    static String getInhabitAnyPolicyExtension(X509Certificate certificate) throws IOException {
        byte[] inhabitAnyPolicyBytes = certificate.getExtensionValue(Extension.inhibitAnyPolicy.toString());
        if (inhabitAnyPolicyBytes != null) {
            ASN1Integer skipCertsInteger = (ASN1Integer) X509ExtensionUtil.fromExtensionValue(inhabitAnyPolicyBytes);
            return skipCertsInteger.getValue().toString();
        }
        return "";
    }

    static String[] getSubjectDirectoryExtension(X509Certificate certificate) throws IOException, ParseException {
        byte[] subjectDirectoryBytes = certificate.getExtensionValue(Extension.subjectDirectoryAttributes.toString());
        if (subjectDirectoryBytes != null) {
            String[] data = new String[4];
            SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(X509ExtensionUtil
                    .fromExtensionValue(subjectDirectoryBytes));
            Vector<Attribute> attributes = subjectDirectoryAttributes.getAttributes();
            for (Attribute attribute : attributes) {
                if (attribute.getAttrType().equals(BCStyle.DATE_OF_BIRTH)) {
                    ASN1UTCTime dateOfBirthTime = (ASN1UTCTime) attribute.getAttrValues().getObjectAt(0);
                    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
                    data[0] = simpleDateFormat.format(dateOfBirthTime.getDate());
                } else if (attribute.getAttrType().equals(BCStyle.PLACE_OF_BIRTH)) {
                    DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                    data[1] = new String(derOctetString.getOctets());
                } else if (attribute.getAttrType().equals(BCStyle.COUNTRY_OF_CITIZENSHIP)) {
                    DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                    data[2] = new String(derOctetString.getOctets());
                } else if (attribute.getAttrType().equals(BCStyle.GENDER)) {
                    DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                    data[3] = new String(derOctetString.getOctets());
                }
            }
            return data;
        }
        return null;
    }

    static boolean isSelfSigned(X509Certificate certificate) {
        //certificate is self-signed -> trusted
        try {
            certificate.verify(certificate.getPublicKey());
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    static X509Certificate signCertificate(X509v3CertificateBuilder certificateBuilder, PrivateKey privateKey,
                                           String signatureAlgorithm) throws CertificateException, OperatorCreationException {
        //new BcRSAContentSignerBuilder()
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(PROVIDER_NAME).build(privateKey);
        return new JcaX509CertificateConverter().setProvider(PROVIDER_NAME)
                .getCertificate(certificateBuilder.build(contentSigner));
    }

    static PKCS10CertificationRequest csrRequest(PrivateKey privateKey, X509Certificate certificate) throws IOException, OperatorCreationException {
        PKCS10CertificationRequestBuilder certificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder
                (certificate.getSubjectX500Principal(), certificate.getPublicKey());

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        byte[] certificatePoliciesBytes = certificate.getExtensionValue(Extension.certificatePolicies.toString());
        if(certificatePoliciesBytes != null) {
            CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(certificatePoliciesBytes));
            extensionsGenerator.addExtension(Extension.certificatePolicies, isExtensionCritical(Extension.certificatePolicies,
                    certificate.getCriticalExtensionOIDs()), certificatePolicies);
        }

        byte[] inhabitAnyPolicyBytes = certificate.getExtensionValue(Extension.inhibitAnyPolicy.toString());
        if (inhabitAnyPolicyBytes != null) {
            ASN1Integer skipCertsInteger = (ASN1Integer) X509ExtensionUtil.fromExtensionValue(inhabitAnyPolicyBytes);
            extensionsGenerator.addExtension(Extension.inhibitAnyPolicy, isExtensionCritical(Extension.inhibitAnyPolicy,
                    certificate.getCriticalExtensionOIDs()), skipCertsInteger);
        }


        byte[] subjectDirectoryBytes = certificate.getExtensionValue(Extension.subjectDirectoryAttributes.toString());
        if (subjectDirectoryBytes != null) {
            SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(X509ExtensionUtil
                    .fromExtensionValue(subjectDirectoryBytes));
            extensionsGenerator.addExtension(Extension.subjectDirectoryAttributes, isExtensionCritical(
                    Extension.subjectDirectoryAttributes, certificate.getCriticalExtensionOIDs()), subjectDirectoryAttributes);
        }

        if(!extensionsGenerator.isEmpty()) {
            certificationRequestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder(certificate.getSigAlgName())
                .setProvider(PROVIDER_NAME).build(privateKey);

        return certificationRequestBuilder.build(contentSigner);

    }

    static boolean isExtensionCritical(ASN1ObjectIdentifier extensionIdentifier, Set<String> criticalExtensionOIDs) {
        for(String extensionOID : criticalExtensionOIDs) {
            if(extensionOID.equals(extensionIdentifier.getId())) {
                return true;
            }
        }
        return false;
    }
}
