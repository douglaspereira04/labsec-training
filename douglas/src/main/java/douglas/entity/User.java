package douglas.entity;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

import douglas.certification.CertificateBuilder;
import douglas.certification.Signer;

@Entity(name="USER")
public class User {
	
	@Id
	@Column(name="USER_ID", nullable=false, unique=true)
	private String id;
	
	@Column(name="USER_PASS", nullable=false)
	private String pass;
	
	@ManyToOne(targetEntity = CA.class)
	@JoinColumn(name = "CA_ID")
	private CA ca;

	@Column(name="USER_CERTIFICATE", columnDefinition="TEXT")
	private String cert;
	
	@Column(name="USER_PRIVATE_KEY", columnDefinition="TEXT")
	private String prvk;
	
	public User() {
	}
	
	public User(String id, String pass) {
		super();
		this.id = id;
		this.pass = pass;
	}
	
	public User(String pass, CA ca, String cert, String prvk) {
		super();
		this.pass = pass;
		this.ca = ca;
		this.cert = cert;
		this.prvk = prvk;
	}
	
	public User(String id, String pass, CA ca, String cert, String prvk) {
		super();
		this.id = id;
		this.pass = pass;
		this.ca = ca;
		this.cert = cert;
		this.prvk = prvk;
	}


	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getPass() {
		return pass;
	}

	public void setPass(String pass) {
		this.pass = pass;
	}

	public CA getCa() {
		return ca;
	}

	public void setCa(CA ca) {
		this.ca = ca;
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
	
	public boolean isCertificated() {
		return this.cert != null;
	}

	public X509Certificate getCert() throws CertificateException{
    	return new CertificateBuilder().build(this.cert);
	}
	
	public void setCert(X509Certificate cert) throws CertificateEncodingException{
    	this.cert = new String(Base64.getEncoder().encode(cert.getEncoded()));
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
	
	public byte[] sign(byte[] data, String algorithm) throws NoSuchAlgorithmException, 
		InvalidKeyException, InvalidKeySpecException, SignatureException {
		 return Signer.sign(data, this.getPrvk(), algorithm);
	}
	
	public boolean verify(byte[] data, byte[] signature, String algorithm) throws CertificateException, 
		NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		return Signer.verify(data, this.getCert().getPublicKey(), signature, algorithm);
	}
	
}
