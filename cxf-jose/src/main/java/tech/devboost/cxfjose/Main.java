package tech.devboost.cxfjose;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.cxf.rs.security.jose.jwa.ContentAlgorithm;
import org.apache.cxf.rs.security.jose.jwa.KeyAlgorithm;
import org.apache.cxf.rs.security.jose.jwa.SignatureAlgorithm;
import org.apache.cxf.rs.security.jose.jwe.JweUtils;
import org.apache.cxf.rs.security.jose.jws.JwsUtils;

public class Main {

	private static PublicKey PUBLIC_KEY;
	private static PrivateKey PRIVATE_KEY;
	private static String MESSAGE;

	static {
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			PUBLIC_KEY = kp.getPublic();
			PRIVATE_KEY = kp.getPrivate();
		} catch (NoSuchAlgorithmException exc) {
			throw new RuntimeException(exc);
		}

		MESSAGE = "Hello JW*";
	}

	public static void main(String[] args) throws Exception {

		String signed = jws(MESSAGE);
		String encrypted = jwe(signed);
		System.out.println("Signed: " + signed);
		System.out.println("Encrypted: " + encrypted);

		byte[] decryptedByte = JweUtils.decrypt(PRIVATE_KEY, KeyAlgorithm.RSA_OAEP_256, ContentAlgorithm.A128GCM,
				encrypted);
		String decrypted = new String(decryptedByte, "utf-8");
		System.out.println("Decrypted: " + decrypted);

		String verified = JwsUtils.verify(PUBLIC_KEY, SignatureAlgorithm.RS512, decrypted);
		System.out.println("Verified: " + verified);
	}

	private static String jwe(String message) throws Exception {
		return JweUtils.encrypt(PUBLIC_KEY, KeyAlgorithm.RSA_OAEP_256, ContentAlgorithm.A128GCM, message.getBytes());
	}

	private static String jws(String message) {
		return JwsUtils.sign(PRIVATE_KEY, SignatureAlgorithm.RS512, message);
	}
}
