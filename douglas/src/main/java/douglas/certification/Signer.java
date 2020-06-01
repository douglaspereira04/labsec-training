package douglas.certification;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Signer {
	public static byte[] sign(byte[] data, PrivateKey prvk, String algorithm) throws NoSuchAlgorithmException, 
		InvalidKeyException, InvalidKeySpecException, SignatureException {
		Signature signer = Signature.getInstance(algorithm);
	    signer.initSign(prvk);
	    signer.update(data);
	    return Base64.getEncoder().encode(signer.sign());
	}
	
	public static boolean verify(byte[] data, PublicKey pubk, byte[] signature, String algorithm) throws CertificateException, 
		NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		
		Signature signer = Signature.getInstance(algorithm);
		signer.initVerify(pubk);
		signer.update(data);
		return signer.verify(Base64.getDecoder().decode(signature));
	}
}
