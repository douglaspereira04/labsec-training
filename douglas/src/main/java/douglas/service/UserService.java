package douglas.service;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.bouncycastle.asn1.x500.X500Name;

import douglas.entity.CA;
import douglas.entity.User;

@Path("user/")
public class UserService {
	
	@GET
	@Path("{auth}/")
	public String user(@PathParam("auth") String auth) {
		String[] userData = Service.authDecode(auth);
		return "<h1>"+userData[0]+"<br></h1>" + 
				"<form method='GET' action='certification/'>" + 
				"	<button type='submit'>Certificate</button><br>" + 
				"</form><br>" +
				"<form method='GET' action='sign/'>" + 
				"	<button type='submit'>Sign File</button><br>" + 
				"</form><br>" +
				"<form id='back_submit' method='GET' action='"+Service.root+"home/'>" + 
				"	<input type='submit' id='back_submit' value='Home'>" + 
				"</form><br>";
	}
	
	@GET
	@Path("{auth}/sign/")
	public String sign(@PathParam("auth") String auth) {
		return "<h1>Sign File<br></h1>" + 
				"<form id='sign_form' method='POST' action='submission/' enctype='multipart/form-data'>" + 
				"	File: <input type='file' name='file'><br>" +
				"	<input type='submit' value='Sign'><br>" + 
				"</form>" +
				"<form id='back_submit' method='GET' action='"+Service.root+"user/"+auth+"/'>" + 
				"	<input type='submit' id='back_submit' value='Home'>" + 
				"</form><br>";
	}
	
	@POST
	@Path("{auth}/sign/submission/")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public Response signSubmission(@PathParam("auth") String auth, Map<String, byte[]> form) {
		User user = null;
		byte[] signature = null;
		
		try {
			Response authResponse = Service.authenticateUser(auth);
			if (authResponse.getStatusInfo().getStatusCode() != Status.OK.getStatusCode())
				return authResponse;
			user = (User) authResponse.getEntity();
		
			if(user.getCertPem() == null || user.getPrvkPem() == null)
				return Response.status(Status.NOT_FOUND).entity("Uncertified user").build();
			
			if (form.get("file").length == 0) 
				return Response.status(Status.BAD_REQUEST).entity("No data to sign").build();
			
		    signature = user.sign(form.get("file"), "SHA256withRSA");
		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
		}
	    
		return Response.ok(new String(signature), MediaType.APPLICATION_OCTET_STREAM)
				.header("Content-Disposition", "attachment; filename=\"signature.txt\"").build();
	}
	
	@GET
	@Path("{auth}/certification/new/")
	public String newCertificate(@PathParam("auth") String auth) {
		return "<h1>Create Certificate<br></h1>" + 
				"<form id='cert_form' method='POST' action='submission/' enctype='multipart/form-data'>" + 
				"	CN: <input type='text' name='CN'><br>" + 
				"	ST: <input type='text' name='ST'><br>" + 
				"	O: <input type='text' name='O'><br>" + 
				"	OU: <input type='text' name='OU'><br>" +
				"	Not Before: <input type='text' name='before'><br>" +
				"	Not After: <input type='text' name='after'><br>" +
				"	Key Size: <input type='text' name='keysize'><br>" +
				"	<input type='submit' id='submit_cert' value='Create'><br>" + 
				"</form>";
	}
	
	@GET
	@Path("{auth}/certification/")
	public Response certification(@PathParam("auth") String auth) {
		User user = null;
		
		Response authResponse = Service.authenticateUser(auth);
		if (authResponse.getStatusInfo().getStatusCode() != Status.OK.getStatusCode())
			return authResponse;
		user = (User) authResponse.getEntity();
		
		if (user.getCertPem() != null)
			return Response.status(Status.TEMPORARY_REDIRECT).location(URI.create("user/"+auth+"/certification/downloads/")).build();
		
		return Response.status(Status.OK).entity(Service.proceed("Create Certificate","user/"+auth+"/certification/new/")).build();
	}
	
	@POST
	@Path("{auth}/certification/new/submission/")
	@Consumes("multipart/form-data")
	public Response certificationSubmission(@PathParam("auth") String auth, Map<String, String> form) {
		
		EntityManager em = null;
		int keySize = 0;
		String nameString = "";
		X509Certificate cert = null;
		KeyPairGenerator kpg = null;
		X500Name name = null;
		User user = null;
		CA ca = null;
		String id = null, pass = null;
		PrivateKey prvk = null;
		Date notBefore = null, notAfter = null;
		
		String[] userData = Service.authDecode(auth);
		try {
			keySize = Integer.parseInt(form.get("keysize"));
			form.remove("keysize");
			
			id = userData[0];
			pass = userData[1];
			
			notBefore =  new SimpleDateFormat("yyyy-mm-dd").parse(form.get("before")); 
			notAfter = new SimpleDateFormat("yyyy-mm-dd").parse(form.get("after")); 
			
			form.remove("before");
			form.remove("after");
			
			for (Map.Entry<String, String> entry : form.entrySet()) {
				nameString += entry.getKey() + "=" + entry.getValue() + ", ";
			}
			nameString = nameString.substring(0, nameString.length() - 2);
			name = new X500Name(nameString);
			
		}catch(Exception e) {
			return Response.status(Status.BAD_REQUEST).entity(Service.proceed(e.getMessage(), "user/"+auth+"/certification/new/")).build();
		}
		
		em = Service.emf.createEntityManager();
		try {
			em.getTransaction().begin();
			
			user = em.find(User.class, id);
			if (user == null || !user.getPass().equals(pass))
				return Response.status(Status.NOT_FOUND).entity(Service.proceed("Wrong ID or Password", "user/"+auth+"/certification/new/")).build();
			
			if (user.isCertificated())
				return Response.status(Status.FORBIDDEN).entity("Already certificated").build();
			
			ca = em.find(CA.class, (long)1);
			if (ca == null)
				return Response.status(Status.NOT_FOUND).entity(Service.proceed("No CA Found", "user/"+auth+"/certification/new/")).build();
			
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(keySize);
			KeyPair kp = kpg.genKeyPair();
			prvk = kp.getPrivate();
			PublicKey pubk = kp.getPublic();
			
		    Service.cb.setIssuer(ca.getSubject());
		    Service.cb.setSubject(name);
		    Service.cb.setPublicKey(pubk);
		    Service.cb.setNotBefore(notBefore);
		    Service.cb.setNotAfter(notAfter);
		    Service.cb.setSerial(new BigInteger(String.valueOf(new Date().getTime())));
		
		    cert = Service.cb.sign(prvk, "SHA256withRSA");
	    	user.setCert(cert);
	    	
	    	user.setCa(ca);
		    user.setPrvk(prvk);

			em.getTransaction().commit();
			
			return Response.status(Status.OK).entity(Service.proceed("Certificado criado","user/"+auth+"/certification/")).build();
		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
		} finally {
			if (em.getTransaction().isActive())
				em.getTransaction().rollback();
			em.close();
		}
	    
	}
	
	@GET
	@Path("{auth}/certification/downloads/")
	public String downloadCertification(@PathParam("auth") String auth) {
		String[] userData = Service.authDecode(auth);
		return "<h1>"+userData[0]+"<br></h1>" + 
				"<form method='GET' action='"+Service.root+"certificate/'>" + 
				"	<input type='hidden' name='user' value='"+userData[0]+"'>"+ 
				"	<button type='submit'>Certificate</button><br>" + 
				"</form><br>" +
				"<form method='GET' action='privatekey/'>" +
				"	<button type='submit'>Private Key</button><br>" + 
				"</form><br>" +
				"<form method='GET' action='"+Service.root+"user/"+auth+"/'>" +
				"	<button type='submit'>Return</button><br>" + 
				"</form><br>";
	}
	
	@GET
	@Path("{auth}/certification/downloads/privatekey/")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public Response privateKey(@PathParam("auth") String auth) {
	
		String result = "";
		User user;
		Response response;
		
		response = Service.authenticateUser(auth);	
		if (response.getStatusInfo().getStatusCode() != Status.OK.getStatusCode())
			return response;
		user = (User) response.getEntity();
		
		if (user.getPrvkPem() == null)
			return Response.status(Status.NOT_FOUND).entity(Service.proceed("No Private Key Found", "")).build();
		
		result += "-----BEGIN RSA PRIVATE KEY-----";
		result += user.getPrvkPem();
		result += "-----END RSA PRIVATE KEY-----";
		return Response.ok(result, MediaType.APPLICATION_OCTET_STREAM)
				.header("Content-Disposition", "attachment; filename=\"pk.key.pem\"" ).build();

	}
	
}
