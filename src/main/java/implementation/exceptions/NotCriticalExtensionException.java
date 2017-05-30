package implementation.exceptions;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Created by stevan on 5/30/17.
 */
public class NotCriticalExtensionException extends  Exception{
    public NotCriticalExtensionException(ASN1ObjectIdentifier extensionIdentifier) {
       super("Extension with id " + extensionIdentifier.toString() + " must be critical!");
    }
}
