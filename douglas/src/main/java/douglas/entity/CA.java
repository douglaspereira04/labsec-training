package douglas.entity;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import douglas.certification.CertificateBuilder;


@Entity(name="CA")
public class CA {
	
	@Id
	//@GeneratedValue
	@Column(name="CA_ID", nullable=false, unique=true)
	private long id;
	
	@Column(name="CA_CERTIFICATE", nullable=false, columnDefinition="text")
	private String cert;
	
	@Column(name="CA_PRIVATE_KEY", nullable=false, columnDefinition="text")
	private String prvk;

	public CA() {
	}
	
	public CA(long id, String cert, String prvk) {
		super();
		this.id = id;
		this.cert = cert;
		this.prvk = prvk;
	}
	
	public CA(String cert, String prvk) {
		super();
		this.cert = cert;
		this.prvk = prvk;
	}
	
	public CA(X509Certificate cert, PrivateKey prvk) throws CertificateEncodingException {
		super();
		this.setCert(cert);
		this.setPrvk(prvk);
	}
	
	public CA(long id, X509Certificate cert, PrivateKey prvk) throws CertificateEncodingException {
		super();
		this.id = id;
		this.setCert(cert);
		this.setPrvk(prvk);
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getCertPem() {
		return cert;
	}

	public void setCertPem(String cert) {
		this.cert = cert;
	}

	public String getPrvkPem() {
		return prvk;
	}

	public void setPrvkPem(String prvk) {
		this.prvk = prvk;
	}
	
	public PrivateKey getPrvk() throws NoSuchAlgorithmException, InvalidKeySpecException {
	    byte[] prvKPemBytes = this.prvk.getBytes();
	    byte[] prvKDer = Base64.getDecoder().decode(prvKPemBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(new PKCS8EncodedKeySpec(prvKDer));
	}
	
	public void setPrvk(PrivateKey prvk) {
		byte[] prvKPemBytes = Base64.getEncoder().encode(prvk.getEncoded());
	    this.prvk = new String(prvKPemBytes);
	}
	
	public X509Certificate getCert() throws CertificateException{
    	return new CertificateBuilder().build(this.cert);
	}
	
	public void setCert(X509Certificate cert) throws CertificateEncodingException{
    	this.cert = new String(Base64.getEncoder().encode(cert.getEncoded()));
	}
	
	public X500Name getSubject() throws CertificateEncodingException, CertificateException {
		return new JcaX509CertificateHolder(this.getCert()).getSubject();
	}
	
}
