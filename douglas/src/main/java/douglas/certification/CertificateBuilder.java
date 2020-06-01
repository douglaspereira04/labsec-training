package douglas.certification;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateBuilder {
	
	private X500Name issuer = null;
	private X500Name subject = null;
	private PublicKey publicKey = null;
	private Date notBefore = null;
	private Date notAfter = null;
	private BigInteger serial = null;
	private JcaX509CertificateConverter converter;
	
	public CertificateBuilder(){
		this.converter = new JcaX509CertificateConverter();
		this.converter.setProvider(new BouncyCastleProvider());
	}
	
	public X509Certificate sign(PrivateKey prvk, String algorithm) throws CertificateException, 
		OperatorCreationException, NullPointerException {
		
	    JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
	    		this.issuer, this.serial, this.notBefore, this.notAfter, this.subject, this.publicKey);
	    ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(prvk);
	    X509CertificateHolder certHolder = certBuilder.build(signer);
	    return converter.getCertificate(certHolder);
	    
	}
	
	public X509Certificate build(String pem) throws CertificateException{
		byte[] pemBytes = pem.getBytes();
    	byte[] der = Base64.getDecoder().decode(pemBytes);
    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
    	return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(der));  
	}


	public X500Name getIssuer() {
		return issuer;
	}

	public void setIssuer(X500Name issuer) {
		this.issuer = issuer;
	}

	public X500Name getSubject() {
		return subject;
	}

	public void setSubject(X500Name subject) {
		this.subject = subject;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}
	
	public void setNotAfter(String date, String dateFormat) throws ParseException {
	    this.notAfter  = new SimpleDateFormat(dateFormat).parse(date);  
	}

	public BigInteger getSerial() {
		return serial;
	}

	public void setSerial(BigInteger serial) {
		this.serial = serial;
	}
	
	
}
