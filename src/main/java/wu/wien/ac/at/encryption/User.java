package wu.wien.ac.at.encryption;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class User {

	private Key privateRSAKey;
	private Key publicRSAKey;
	private String passphrase;

	public User() {
		generateRSAKeys();
	}

	public User(String pwd) {
		passphrase = pwd;
		generateRSAKeys();
	}

	public Key getPrivateRSAKey() {
		return privateRSAKey;
	}

	public Key getPublicRSAKey() {
		return publicRSAKey;
	}

	public String getPassphrase() {
		return passphrase;
	}

	public void setPassphrase(String pwd) {
		passphrase = pwd;
	}

	/**
	 * Generates and saves RSA public/private keys
	 * 
	 * @param privatPath
	 * @param publicPath
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void generateRSAKeys() {

		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");

			kpg.initialize(2048);
			KeyPair keyPair = kpg.genKeyPair();
			this.privateRSAKey = keyPair.getPrivate();
			this.publicRSAKey = keyPair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// // Public Key sichern
		// X509EncodedKeySpec x509EncodedKeySpec = new
		// X509EncodedKeySpec(publicRSAKey.getEncoded());
		// FileOutputStream fos = new FileOutputStream(publicPath);
		// fos.write(x509EncodedKeySpec.getEncoded());
		// fos.close();
		//
		// // Private Key sichern
		// PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new
		// PKCS8EncodedKeySpec(privateRSAKey.getEncoded());
		// fos = new FileOutputStream(privatPath);
		// fos.write(pkcs8EncodedKeySpec.getEncoded());
		// fos.close();
	}
}
