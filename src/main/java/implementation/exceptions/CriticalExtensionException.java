package implementation.exceptions;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Created by stevan on 5/30/17.
 */
public class CriticalExtensionException extends Exception{
    public CriticalExtensionException(ASN1ObjectIdentifier extensionIdentifier) {
        super("Extension with id " + extensionIdentifier.toString() + " cannot be critical!");
    }
}
