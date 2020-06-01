package douglas.service;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityExistsException;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import javax.persistence.PersistenceException;
import javax.persistence.Query;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.bouncycastle.asn1.x500.X500Name;


import douglas.certification.CertificateBuilder;
import douglas.certification.Signer;
import douglas.entity.CA;
import douglas.entity.User;



@Path("/")
public class Service {
	
	static CertificateBuilder cb = new CertificateBuilder();
	static EntityManagerFactory emf = Persistence.createEntityManagerFactory("douglaspu");
	static String root = "/douglas/service/";
	static String proceed(String message, String action) {
		return  ""+message+"<br> "+
				"<form id='form' action='"+root+""+action+"'>" + 
				"	<input type='submit' id='form' value='Proceed'><br>" + 
				"</form>";
	}
			
	
	@GET
	public Response initialize() {
		EntityManager em = emf.createEntityManager();		
		
		try {
			em.getTransaction().begin();
			Query query = em.createQuery("SELECT COUNT(CA_ID) FROM CA");
			if((long)query.getSingleResult() > 0)
				return Response.status(Status.TEMPORARY_REDIRECT).location(URI.create("home/")).build();
			else
				return Response.status(Status.TEMPORARY_REDIRECT).location(URI.create("new-ca/")).build();
		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
		}finally {
			em.getTransaction().commit();
			em.close();
		}

	}

	@GET
	@Path("new-ca/")
	public String CA() {
		return "<h1>Create CA<br></h1>" + 
				"<form id='ca_form' method='POST' action='submission/' enctype='multipart/form-data'>" + 
				"	CN: <input type='text' name='CN'><br>" + 
				"	ST: <input type='text' name='ST'><br>" + 
				"	O: <input type='text' name='O'><br>" + 
				"	OU: <input type='text' name='OU'><br>" +
				"	Not Before: <input type='text' name='before'><br>" +
				"	Not After: <input type='text' name='after'><br>" +
				"	Key Size: <input type='text' name='keysize'><br>" +
				"	<input type='submit' id='submit_ca' value='Create'><br>" + 
				"</form>";
	}

	@GET
	@Path("home/")
	public String home() {
		return "<h1>Sign In<br></h1>" + 
				"<form id='sign_form' method='POST' action='signin' enctype='multipart/form-data'>" + 
				"	ID: <input type='text' name='id'><br>" + 
				"	Password: <input type='password' name='password'><br>" + 
				"	<input type='submit' id='submit_sign' value='Sign In'><br>" + 
				"</form><br>" +
				"<h1>Log In<br></h1>" + 
				"<form id='log_form' method='POST' action='login' enctype='multipart/form-data'>" + 
				"	ID: <input type='text' name='id'><br>" + 
				"	Password: <input type='password' name='password'><br>" + 
				"	<input type='submit' id='submit_Log' value='Log In'><br>" + 
				"</form>" + 
				"<form id='getcert_form' method='GET' action='"+root+"certificate/'>" + 
				"	<input type='text' name='user' placeholder='Username'>&nbsp" +
				"	<input type='submit' id='getcert_submit' value='Download Certificate'><br>" + 
				"</form>" + 
				"<form id='verify_form' method='GET' action='"+root+"verify/'>" + 
				"	<input type='submit' id='go_verify' value='Verify Signature'><br>" + 
				"</form>" + 
				"<form id='display_form' method='GET' action='"+root+"users/'>" + 
				"	<input type='submit' id='display_submit' value='Display Users'><br>" + 
				"</form>";
	}
	
	@POST
	@Path("new-ca/submission/")
	@Consumes("multipart/form-data")
	public Response caSubmission(Map<String, String> form) {
		EntityManager em = null;
		int keySize;
		String nameString = "";
		X509Certificate cert = null;
		KeyPairGenerator kpg = null;
		X500Name name = null;
		CA ca = null;
		PrivateKey prvk = null;
		Date notBefore = null, notAfter = null;
		
		try {
			keySize = Integer.parseInt(form.get("keysize"));
			form.remove("keysize");

			notBefore =  new SimpleDateFormat("yyyy-mm-dd").parse(form.get("before")); 
			notAfter = new SimpleDateFormat("yyyy-mm-dd").parse(form.get("after")); 
			
			form.remove("before");
			form.remove("after");
			
			for (Map.Entry<String, String> entry : form.entrySet()) {
				nameString += entry.getKey() + "=" + entry.getValue() + ", ";
			}
			nameString = nameString.substring(0, nameString.length() - 2);
			name = new X500Name(nameString);
			
		} catch (Exception e) {
			return Response.status(Status.BAD_REQUEST).entity(proceed(e.getMessage(), "")).build();
		}

		try {
			em = emf.createEntityManager();
			Query query = em.createQuery("SELECT COUNT(CA_ID) FROM CA");		
			
			em.getTransaction().begin();
			if((long)query.getSingleResult() > 0)
				return Response.status(Status.FORBIDDEN).entity("CA already exists").build();
			em.getTransaction().commit();
			
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(keySize);
			KeyPair kp = kpg.genKeyPair();
			prvk = kp.getPrivate();
			PublicKey pubk = kp.getPublic();

			cb.setIssuer(name);
			cb.setSubject(name);
			cb.setPublicKey(pubk);
		    Service.cb.setNotBefore(notBefore);
		    Service.cb.setNotAfter(notAfter);
			cb.setSerial(new BigInteger("0"));
			
		    cert = cb.sign(prvk, "SHA256withRSA");

		    em.getTransaction().begin();
	    	ca = new CA((long)1 ,cert, prvk);
			em.persist(ca);
			em.getTransaction().commit();
			
		} catch(EntityExistsException e) {
			return Response.status(Status.FORBIDDEN).entity(proceed("CA already exists", "")).build();
		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
		} finally {
			if (em.getTransaction().isActive())
				em.getTransaction().rollback();
			em.close();
		}

		return Response.status(Status.OK).entity(proceed("CA created","")).build();
		
	}
	
	@POST
	@Path("home/signin")
	@Consumes("multipart/form-data")
	public Response signUser(Map<String, String> form) {
		EntityManager em = emf.createEntityManager();
		User user;
		
		try {
			user = new User(form.get("id"), form.get("password"));
		}catch (NullPointerException e) {
			return Response.status(Status.BAD_REQUEST).entity(proceed("Request Error", "")).build();
		}
		
		try {
			em.getTransaction().begin();
			em.persist(user);
			em.getTransaction().commit();
		}catch(PersistenceException e) {
			return Response.status(Status.FORBIDDEN).entity(proceed("Unavailable ID", "")).build();
		}catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
		}finally {
			if (em.getTransaction().isActive())
				em.getTransaction().rollback();
			em.close();
		}

		return Response.status(Status.OK).entity(proceed("Registered", "")).build();
	}
	
	@POST
	@Path("home/login")
	@Consumes("multipart/form-data")
	public Response logUser(Map<String, String> form) {
		EntityManager em = emf.createEntityManager();
		String auth;
		
		try {
			em.getTransaction().begin();
			Query query = em.createQuery("SELECT COUNT(USER_ID) FROM USER WHERE USER_ID=:id AND USER_PASS=:pass");
			query.setParameter("id", form.get("id"));
			query.setParameter("pass", form.get("password"));
			long count = (long) query.getSingleResult();
			em.getTransaction().commit();
			
			if(count < 1)
				return Response.status(Status.NOT_FOUND).entity(proceed("Wrong ID or Password", "")).build();
			
			auth = authEncode(form.get("id"), form.get("password"));
			
		}catch (NullPointerException e) {
			return Response.status(Status.BAD_REQUEST).entity(proceed("Request Error", "")).build();
		}catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
		}finally {
			if (em.getTransaction().isActive())
				em.getTransaction().rollback();
			em.close();
		}
		
		return Response.status(Status.OK).entity(proceed("authenticator: "+ auth,"user/"+auth+"/")).build();
	}
	
	@GET
	@Path("certificate/")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public Response certificate(@QueryParam("user") String id) {
	
		String result = "";
		User user;
		Response response;
		
		response = findUser(id);	
		if (response.getStatusInfo().getStatusCode() != Status.OK.getStatusCode())
			return response;
		user = (User) response.getEntity();
		
		if (user.getCertPem() == null)
			return Response.status(Status.NOT_FOUND).entity(proceed("No Private Key Found", "")).build();
		
		result += "-----BEGIN CERTIFICATE-----";
		result += user.getCertPem();
		result += "-----END CERTIFICATE-----";
		return Response.ok(result, MediaType.APPLICATION_OCTET_STREAM)
				.header("Content-Disposition", "attachment; filename=\"certificate.pem\"" ).build();
	}
	
	@GET
	@Path("verify/")
	public String verify() {
		return "<h1>Verify Signature<br></h1>" + 
				"<form id='sign_form' method='POST' action='submission/' enctype='multipart/form-data'>" + 
				"	User: <input type='text' name='user'><br>" +
				"	Certificate: <input type='file' name='cert'> -> When defined, \"User\" field is ignored<br>" +
				"	File: <input type='file' name='file'><br>" +
				"	Signature: <input type='file' name='signature'><br>" +
				"	<input type='submit' value='Verify'><br>" + 
				"</form>";
	}
	
	@POST
	@Path("verify/submission/")
	public Response verifySubmission(Map<String, byte[]> form) {
		User user = null;
		boolean verified = false;
		Response findResponse;
		try {
			
			if (form.get("cert").length > 0) {
				String pem = new String(form.get("cert")).substring(27);
				pem = pem.substring(0, pem.length()-25);
		    	verified = Signer.verify(form.get("file"), cb.build(pem).getPublicKey(),form.get("signature"), "SHA256withRSA");
			}else {
				findResponse = findUser(new String(form.get("user")));
				if (findResponse.getStatusInfo().getStatusCode() != Status.OK.getStatusCode())
					return findResponse;
				user = (User) findResponse.getEntity();
				
				if(user.getCertPem() == null || user.getPrvkPem() == null)
					return Response.status(Status.NOT_FOUND).entity(proceed("Uncertified user",
							"verify/")).build();
				
		    	verified = user.verify(form.get("file"), form.get("signature"), "SHA256withRSA");
			}
			
		} catch (NullPointerException | CertificateException e) {
			return Response.status(Status.BAD_REQUEST)
					.entity(proceed(e.getMessage(), "verify/")).build();
		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR)
					.entity(proceed(e.getMessage(), "verify/")).build();
		}
		
		return Response.status(Status.OK)
				.entity(proceed(verified ? "Valid" : "Invalid", "verify/")).build();
	}
	
	@GET
	@Path("users/")
	public Response displayUsers() {
		List<String> userList;
		String result = "";
		String line = 	"<form id='getcert_form' method='GET' action='"+root+"certificate/'>" + 
						"	<span>%s</span>&nbsp"+
						"	<input type='hidden' name='user' value='%s'>" +
						"	<input type='submit' id='getcert_submit' value='Download Certificate'>" + 
						"</form><br>";
		
		EntityManager em = emf.createEntityManager();		
		
		try {
			em.getTransaction().begin();
			Query query = em.createQuery("SELECT id FROM USER");
			userList = query.getResultList();
			em.getTransaction().commit();
		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
		}finally {
			if (em.getTransaction().isActive())
				em.getTransaction().rollback();
			em.close();
		}
		
		for ( String user : userList ) {
			result += String.format(line, user, user);
		}
		
		result += "<form id='back_submit' method='GET' action='"+root+"home/'>" + 
					"	<input type='submit' id='back_submit' value='Home'>" + 
					"</form><br>";

		return Response.status(Status.OK).entity(result).build();
	}
	
	public static String authEncode(String id, String pass) {
		return new String(Base64.getEncoder().encode((id+":"+pass).getBytes()));
	}
	
	public static String[] authDecode(String encoded) {
		String auth = new String(Base64.getDecoder().decode(encoded));
		return auth.split(":");
	}
	
	public static Response authenticateUser(String auth) {
		String[] userData = authDecode(auth);
		User user;
		String id = userData[0];
		String pass = userData[1];
		
		Response findResponse = findUser(id);
		
		if (findResponse.getStatus() != Status.OK.getStatusCode())
			return findResponse;
		user = (User) findResponse.getEntity();
		
		try {
			if(!user.getPass().equals(pass))
				return Response.status(Status.NOT_FOUND).entity(proceed("Wrong ID or Password", "")).build();
		} catch (NullPointerException e) {
			return Response.status(Status.BAD_REQUEST).entity(e.getMessage()).build();
		}
		return Response.status(Status.OK).entity(user).build();
	}
	
	public static Response findUser(String id) {
		User user;
		EntityManager em = emf.createEntityManager();
		
		try {
			em.getTransaction().begin();
			user = em.find(User.class, id);
			em.getTransaction().commit();
			
			if(user == null)
				return Response.status(Status.NOT_FOUND).entity(proceed("No user found", "")).build();
		} catch (Exception e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
		} finally {
			if(em.getTransaction().isActive())
				em.getTransaction().rollback();
			em.close();
		}
		
		return Response.status(Status.OK).entity(user).build();
	}
	
	
}
