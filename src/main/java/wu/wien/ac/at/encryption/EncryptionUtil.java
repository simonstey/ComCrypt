package wu.wien.ac.at.encryption;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.engines.HVEIP08KEMEngine;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.generators.HVEIP08ParametersGenerator;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08EncryptionParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08KeyGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08MasterSecretKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08Parameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08PublicKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08SecretKeyGenerationParameters;
import it.unisa.dia.gas.crypto.kem.KeyEncapsulationMechanism;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

/**
 * @author Simon Steyskal
 * 
 * Info: certain methods adapted from http://stackoverflow.com/a/10128606
 */

public class EncryptionUtil {

	public final static int AES_Key_Size = 256;
	public static final int MAX_FILE_BUF = 1024;
	public static final String METHOD_RSA = "RSA/ECB/PKCS1Padding";
	public final String METHOD_AES = "AES";
	public static final String A = "A";
	public static final String B = "B";
	public static final String C = "C";
	public static final String D = "D";
	public static final int totalNumberOfPartitions = 11;
	public static PairingParameters parameters;
	private Key privateRSAKey = null;
	private Key publicRSAKey = null;
	private Key AESKey = null;
	private KeyPair keyPair;
	private HashMap<Integer, HashSet<String>> combinationsPerGraph = new HashMap<Integer, HashSet<String>>();

	/**
	 * @param privRSAKeyPath
	 * @param pubRSAKeyPath
	 * @param AESKeyPath
	 * @throws Exception
	 */
	public EncryptionUtil(String privRSAKeyPath, String pubRSAKeyPath, String AESKeyPath) throws Exception {
		generateRSAKeys(privRSAKeyPath, pubRSAKeyPath);
	}

	/**
	 * 
	 */
	public EncryptionUtil() {

	}

	/**
	 * @param partitions
	 * @return
	 */
	public HashSet<String> getPartsForPartitions(String[] partitions) {
		HashSet<String> partsForGraph = new HashSet<String>();

		if (!combinationsPerGraph.isEmpty()) {
			for (int i = 0; i < partitions.length; i++)
				partsForGraph.addAll(combinationsPerGraph.get(Integer.valueOf(partitions[i]) - 1));
		}

		return partsForGraph;
	}

	// ++++++++++++++++++++++++++++++++++++++++++++++
	// Generating & Saving AES/RSA Keys
	// ++++++++++++++++++++++++++++++++++++++++++++++

	/**
	 * Generates and saves RSA public/private keys
	 * 
	 * @param privatPath
	 * @param publicPath
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public void generateRSAKeys(String privatPath, String publicPath)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		this.keyPair = kpg.genKeyPair();
		this.privateRSAKey = keyPair.getPrivate();
		this.publicRSAKey = keyPair.getPublic();

		// Public Key sichern
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicRSAKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(publicPath);
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();

		// Private Key sichern
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateRSAKey.getEncoded());
		fos = new FileOutputStream(privatPath);
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}

	/**
	 * Generates and saves an AES key
	 * 
	 * @param path
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public void generateAndSaveAESKey(String path) throws NoSuchAlgorithmException, IOException {

		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(AES_Key_Size);
		this.AESKey = keygen.generateKey();

		byte[] bytes = AESKey.getEncoded();
		System.out.println(bytes.length);
		FileOutputStream keyfos = new FileOutputStream(path);
		keyfos.write(bytes);
		keyfos.close();
	}

	/**
	 * Generates and saves an AES key
	 * 
	 * @param path
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static SecretKey generateAESKey() {
		KeyGenerator keygen;
		try {
			keygen = KeyGenerator.getInstance("AES");

			keygen.init(AES_Key_Size);
			return keygen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Loads an AES key
	 * 
	 * @param path
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public Key loadAESKey(String path) throws NoSuchAlgorithmException, IOException {
		return (new SecretKeySpec(Files.readAllBytes(new File(path).toPath()), 0, AES_Key_Size / 8, "AES"));
	}

	// ++++++++++++++++++++++++++++++++++++++++++++++
	// Encrypting/Decrypting an entire file
	// ++++++++++++++++++++++++++++++++++++++++++++++

	public static byte[] encryptKeyStoreEntry(String input, Key key) {
		return encrypt(input.getBytes(), key, METHOD_RSA);
	}

	public static byte[] decryptKeyStoreEntry(String input, Key key) {
		return decrypt(input.getBytes(), key, METHOD_RSA);
	}
	
	public static AsymmetricCipherKeyPair setup(HVEIP08Parameters hveParameters, String keyPath) throws IOException {
        HVEKeyPairGenerator generator = new HVEKeyPairGenerator();
        generator.init(new HVEIP08KeyGenerationParameters(new SecureRandom(), hveParameters));

        return generator.generateKeyPair(keyPath);
    }
	
	public static AsymmetricCipherKeyPair setupLoad(HVEIP08Parameters hveParameters, String keyPath) throws IOException {
        HVEKeyPairGenerator generator = new HVEKeyPairGenerator();
        generator.init(new HVEIP08KeyGenerationParameters(new SecureRandom(), hveParameters));

        return generator.loadKeyPair(keyPath);
    }
    
    public static int[] createFileVector(int n, String fileName) {
//    	String filename = FilenameUtils.getBaseName(fileName);
		long filenameL = Long.parseLong(fileName, 10);
		int[] result = new int[n];
		BitSet bs2 = BitSet.valueOf(new long[] { filenameL });

		for(int i = 0; i < result.length; i++){
			if(bs2.get(i))
				result[i] = 1;
			else
				result[i] = 0;
		}
		
		return result;
   }
    
    public static int[] createKeyVector(int n, String[] partitions) {
    	int[] result = new int[n];
    	Arrays.fill(result,0);
    	
    	for (int i = 0; i < partitions.length; i++) {
			result[Integer.parseInt(partitions[i]) - 1] = -1;
		}
        return result;
   }

    public static int[][] createMatchingVectors(int n) {
    	 int[][] result = new int[2][n];
         Random random = new Random();
         for (int i = 0; i < n; i++) {
             result[0][i] = -1;
             result[1][i] = random.nextInt(2);
         }
         return result;
    }
	
    public static CipherParameters keyGen(CipherParameters privateKey, int... pattern) {
	        HVESecretKeyGenerator generator = new HVESecretKeyGenerator();
	        generator.init(new HVEIP08SecretKeyGenerationParameters(
	                (HVEIP08MasterSecretKeyParameters) privateKey, pattern)
	        );

	        return generator.generateKey();
	    }
	
    public static HVEIP08Parameters genBinaryParam(int n, String propertiesPath) {
        HVEIP08ParametersGenerator generator = new HVEIP08ParametersGenerator();
        
//        parameters = PairingFactory.getInstance().loadParameters(Paths.get(propertiesPath,"a_181_603.properties").toString());
        
		PairingFactory.getInstance().setUsePBCWhenPossible(false);

		int rBits = 160;
		int qBits = 512;
		TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);

		parameters = pg.generate();
		// save pairing parameters
		writeFile(propertiesPath + "/pairing.properties", parameters.toString().getBytes());
        
        generator.init(n, parameters);

        return generator.generateParameters();
    }
    public static HVEIP08Parameters loadBinaryParam(int n, String propertiesPath) {
    	HVEIP08ParametersGenerator generator = new HVEIP08ParametersGenerator();
    	
    	PairingFactory.getInstance().setUsePBCWhenPossible(false);
        parameters = PairingFactory.getInstance().loadParameters(Paths.get(propertiesPath,"pairing.properties").toString());
    	
    	generator.init(n, parameters);
    	
    	return generator.generateParameters();
    }
   
	
    public static byte[] getRawKey(byte[] seed) throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		kgen.init(128, sr); // 192 and 256 bits may not be available
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		return raw;
	}
	
   
	
	/**
	 * Pass two file objects representing the actual input (cleartext) and
	 * output file to be encrypted.
	 * 
	 * @param input
	 *            - the cleartext file to be encrypted
	 * @param output
	 *            - the encrypted data file
	 * @param encMethod
	 *            - the encryption method to be used
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public static void encryptFile(File input, File output, CipherParameters pubKey, int n, String compressionApproach)//int... attributes)
			throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
		FileInputStream fin;
		FileOutputStream fout;
		long totalread = 0;
		int nread = 0;
		byte[] inbuf = new byte[MAX_FILE_BUF];
		// create parent directory
		new File(output.getParent()).mkdirs();

		String filename = FilenameUtils.getBaseName(input.getName());
		String extension = FilenameUtils.getExtension(input.getName());
		
		switch (compressionApproach) {
		case "A":
			filename = Math.pow(2, (Double.parseDouble(filename)-1))+"";
			filename = filename.split("\\.")[0];
			break;
		case "C":
			if (extension.equals("bt")){
				filename = Math.pow(2, (Double.parseDouble(filename)-1))+"";
				filename = filename.split("\\.")[0];
			} else {
				filename = FilenameUtils.getBaseName(input.getName());
			}
			break;
		default :
			filename = FilenameUtils.getBaseName(input.getName());
			break;
		}
		
		
		/* ipBuf = AESSeed(=M) + [c1 + c2] */
		byte[][] ipBuf = encaps(pubKey,createFileVector(n,filename));
		
		byte[] raw = getRawKey(ipBuf[0]);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		
		Cipher encrypt_cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		
		byte [] iv = new byte[encrypt_cipher.getBlockSize()];
        for(int i=0;i<iv.length;i++)iv[i] = 0;
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
		
		
		encrypt_cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

		fout = new FileOutputStream(output);
		fin = new FileInputStream(input);
		
		if (ipBuf[1] != null)
			fout.write(ipBuf[1]);

		while ((nread = fin.read(inbuf)) > 0) {
			totalread += nread;

			// create a buffer to write with the exact number of bytes read.
			// Otherwise a short read fills inbuf with 0x0
			// and results in full blocks of MAX_FILE_BUF being written.
			byte[] trimbuf = new byte[nread];
			for (int i = 0; i < nread; i++)
				trimbuf[i] = inbuf[i];

			// encrypt the buffer using the cipher obtained previously
			byte[] tmp = encrypt_cipher.update(trimbuf);

			// I don't think this should happen, but just in case..
			if (tmp != null)
				fout.write(tmp);
		}

		// finalize the encryption since we've done it in blocks of MAX_FILE_BUF
		byte[] finalbuf = encrypt_cipher.doFinal();
		if (finalbuf != null)
			fout.write(finalbuf);

		fout.flush();
		fin.close();
		fout.close();
		fout.close();
	}

	/**
	 * Read from the encrypted file (input) and turn the cipher back into
	 * cleartext. Write the cleartext buffer back out to disk as (output) File.
	 * 
	 * @param input
	 *            - File object representing encrypted data on disk
	 * @param output
	 *            - File object of cleartext data to write out after decrypting
	 * @param decMethod
	 *            - the decryption method to be used
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException 
	 * @throws InvalidCipherTextException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public static void decryptFile(File input, File output, KeyEncapsulationMechanism kem) throws IllegalBlockSizeException,
			BadPaddingException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidCipherTextException, InvalidAlgorithmParameterException {
		FileInputStream fin;
		FileOutputStream fout;
		CipherInputStream cin;
		long totalread = 0;
		int nread = 0;
		byte[] inbuf = new byte[MAX_FILE_BUF];
		byte[] ctbuf = new byte[kem.getInputBlockSize()];
		
		fout = new FileOutputStream(output);
		fin = new FileInputStream(input);
		
		int	ctSize =fin.read(ctbuf);
		totalread += ctSize;

		// create a buffer to write with the exact number of bytes read.
		// Otherwise a short read fills inbuf with 0x0
		byte[] ct = new byte[ctSize];
		for (int i = 0; i < ctSize; i++)
			ct[i] = ctbuf[i];

		
		byte[] raw = kem.processBlock(ct, 0, ct.length);

		byte[] keySeed = getRawKey(raw);
		SecretKeySpec skeySpec = new SecretKeySpec(keySeed, "AES");
		
		Cipher decrypt_cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		
		byte [] iv = new byte[decrypt_cipher.getBlockSize()];
        for(int i=0;i<iv.length;i++)iv[i] = 0;
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
		
		decrypt_cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);

		
		
		// creating a decoding stream from the FileInputStream
		cin = new CipherInputStream(fin, decrypt_cipher);
		
		while ((nread = cin.read(inbuf)) >= 0) {
			totalread += nread;

			// create a buffer to write with the exact number of bytes read.
			// Otherwise a short read fills inbuf with 0x0
			byte[] trimbuf = new byte[nread];
			for (int i = 0; i < nread; i++)
				trimbuf[i] = inbuf[i];

			// write out the size-adjusted buffer
			fout.write(trimbuf);
		}
		
		fout.flush();
		cin.close();
		fin.close();
		fout.close();
	}
	
	public static int[] copyFromLongArray(long[] source, int n) {
		int[] dest = new int[n];
	    for(int i=0; i<source.length; i++) {
	        dest[i] = (int) source[i];
	    }
	    return dest;
	}
	
	public static byte[][] encaps(CipherParameters publicKey, int... attributes) {
        try {
            KeyEncapsulationMechanism kem = new HVEIP08KEMEngine();
            kem.init(true, new HVEIP08EncryptionParameters((HVEIP08PublicKeyParameters) publicKey, attributes));

            byte[] ciphertext = kem.processBlock(new byte[0], 0, 0);

            assertNotNull(ciphertext);
            assertNotSame(0, ciphertext.length);

            byte[] key = Arrays.copyOfRange(ciphertext, 0, kem.getKeyBlockSize());
            byte[] ct = Arrays.copyOfRange(ciphertext, kem.getKeyBlockSize(), ciphertext.length);

            return new byte[][]{key, ct};
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
        return null;
    }

	/**
	 * Pass two file objects representing the actual input (cleartext) and
	 * output file to be encrypted.
	 * 
	 * @param input
	 *            - the cleartext file to be encrypted
	 * @param output
	 *            - the encrypted data file
	 * @param encMethod
	 *            - the encryption method to be used
	 * @throws IOException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 */
	public static void encryptFile(File input, File output, String encMethod, Key key)
			throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException {
		FileInputStream fin;
		FileOutputStream fout;
		long totalread = 0;
		int nread = 0;
		byte[] inbuf = new byte[MAX_FILE_BUF];
		// create parent directory
		new File(output.getParent()).mkdirs();
		Cipher encrypt_cipher = Cipher.getInstance(encMethod);
		encrypt_cipher.init(Cipher.ENCRYPT_MODE, key);

		fout = new FileOutputStream(output);
		fin = new FileInputStream(input);

		while ((nread = fin.read(inbuf)) > 0) {
			totalread += nread;

			// create a buffer to write with the exact number of bytes read.
			// Otherwise a short read fills inbuf with 0x0
			// and results in full blocks of MAX_FILE_BUF being written.
			byte[] trimbuf = new byte[nread];
			for (int i = 0; i < nread; i++)
				trimbuf[i] = inbuf[i];

			// encrypt the buffer using the cipher obtained previously
			byte[] tmp = encrypt_cipher.update(trimbuf);

			// I don't think this should happen, but just in case..
			if (tmp != null)
				fout.write(tmp);
		}

		// finalize the encryption since we've done it in blocks of MAX_FILE_BUF
		byte[] finalbuf = encrypt_cipher.doFinal();
		if (finalbuf != null)
			fout.write(finalbuf);

		fout.flush();
		fin.close();
		fout.close();
		fout.close();
	}

	/**
	 * @param masterPW
	 * @param masterPath
	 * @param outputPath
	 * @param partitions
	 * @return
	 */
	public KeyStore generateKeyStoreFileForGraphs(String masterPW, String masterPath, String outputPath,
			String... partitions) {
		HashSet<String> requiredPartsForPartitions = getPartsForPartitions(partitions);

		try {
			KeyStore outputKeystore = KeyStore.getInstance("JCEKS");
			outputKeystore.load(null, null);

			KeyStore masterKeyStore = KeyStore.getInstance("JCEKS");
			masterKeyStore.load(new FileInputStream(masterPath), "master".toCharArray());

			for (String s : requiredPartsForPartitions) {
				PasswordProtection keyPassword = new PasswordProtection(s.toCharArray());
				KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) masterKeyStore.getEntry(s, keyPassword);

				outputKeystore.setEntry(s, entry, keyPassword);
			}
			outputKeystore.store(new FileOutputStream(outputPath), masterPW.toCharArray());
			return outputKeystore;
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException
				| UnrecoverableEntryException e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Read from the encrypted file (input) and turn the cipher back into
	 * cleartext. Write the cleartext buffer back out to disk as (output) File.
	 * 
	 * @param input
	 *            - File object representing encrypted data on disk
	 * @param output
	 *            - File object of cleartext data to write out after decrypting
	 * @param decMethod
	 *            - the decryption method to be used
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 */
	public static void decryptFile(File input, File output, String decMethod, Key key) throws IllegalBlockSizeException,
			BadPaddingException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		FileInputStream fin;
		FileOutputStream fout;
		CipherInputStream cin;
		long totalread = 0;
		int nread = 0;
		byte[] inbuf = new byte[MAX_FILE_BUF];

		Cipher decrypt_cipher = Cipher.getInstance(decMethod);
		decrypt_cipher.init(Cipher.DECRYPT_MODE, key);

		fout = new FileOutputStream(output);
		fin = new FileInputStream(input);

		// creating a decoding stream from the FileInputStream
		cin = new CipherInputStream(fin, decrypt_cipher);

		while ((nread = cin.read(inbuf)) > 0) {
			totalread += nread;

			// create a buffer to write with the exact number of bytes read.
			// Otherwise a short read fills inbuf with 0x0
			byte[] trimbuf = new byte[nread];
			for (int i = 0; i < nread; i++)
				trimbuf[i] = inbuf[i];

			// write out the size-adjusted buffer
			fout.write(trimbuf);
		}

		fout.flush();
		cin.close();
		fin.close();
		fout.close();
	}

	// ++++++++++++++++++++++++++++++++++++++++++++++
	// Encrypting/Decrypting a single line of text
	// ++++++++++++++++++++++++++++++++++++++++++++++

	/**
	 * Encrypts and returns a single string using specified encryption method
	 * 
	 * @param text
	 *            - string to be encrypted
	 * @param encMethod
	 *            - encryption method that has to be used
	 * @return encString - encrypted string
	 */
	public static byte[] encrypt(byte[] data, Key key, String encMethod) {

		Cipher encrypt_cipher;
		try {
			encrypt_cipher = Cipher.getInstance(encMethod);
			
			encrypt_cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encrypted = encrypt_cipher.doFinal(data);
			return encrypted;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Decrypts and returns a single encrypted string using specified encryption
	 * method
	 * 
	 * @param encString
	 *            - string to be decrypted
	 * @param decMethod
	 *            - decryption method that has to be used
	 * @return decString - decrypted string
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] crypted, Key key, String decMethod) {
		Cipher decrypt_cipher;
		try {
			decrypt_cipher = Cipher.getInstance(decMethod);
			decrypt_cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] cipherData = decrypt_cipher.doFinal(crypted);
			return cipherData;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// ++++++++++++++++++++++++++++++
	// Digest Methods
	// ++++++++++++++++++++++++++++++

	/**
	 * Generate the checksum of a file based on provided digest method
	 * 
	 * @param filename
	 *            - path to file the checksum has to be created for
	 * @param digestMethod
	 *            - digest method that has to be used
	 * @return checksum
	 * @throws Exception
	 */
	public static byte[] createChecksum(String filename, String digestMethod) throws Exception {
		InputStream fis = new FileInputStream(filename);

		byte[] buffer = new byte[1024];
		MessageDigest complete = MessageDigest.getInstance(digestMethod);
		int numRead;

		do {
			numRead = fis.read(buffer);
			if (numRead > 0) {
				complete.update(buffer, 0, numRead);
			}
		} while (numRead != -1);

		fis.close();
		return complete.digest();
	}

	/**
	 * Returns the checksum of a file based on provided digest method
	 * 
	 * @param filename
	 *            - path to file the checksum has to be created for
	 * @param digestMethod
	 *            - digest method that has to be used
	 * @return checksum
	 * @throws Exception
	 */
	public static String getSHAChecksum(String filename, String digestMethod) throws Exception {
		byte[] b = createChecksum(filename, digestMethod);
		String result = "";

		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}

	/**
	 * Returns the checksum of a file based on provided digest method
	 * 
	 * @param filename
	 *            - path to file the checksum has to be created for
	 * @param digestMethod
	 *            - digest method that has to be used
	 * @return checksum
	 * @throws Exception
	 */
	public String getSHAChecksum(byte[] b, String digestMethod) throws Exception {
		MessageDigest md = MessageDigest.getInstance(digestMethod);
		md.update(b);

		byte byteData[] = md.digest();

		// convert the byte to hex format method 1
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < byteData.length; i++) {
			sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
		}

		return sb.toString();
	}

	/**
	 * @param b1
	 * @param b2
	 * @return
	 */
	public byte[] bitwiseXOR(byte[] b1, byte[] b2) {
		byte[] returnArray = new byte[AES_Key_Size / 8];

		int i = 0;
		for (byte b : b1)
			returnArray[i] = (byte) (b ^ b2[i++]);

		return returnArray;
	}

	// ++++++++++++++++++++++++++++++
	// Getter und Setter
	// ++++++++++++++++++++++++++++++

	/**
	 * @return the privateRSAKey
	 */
	public Key getPrivateRSAKey() {
		return privateRSAKey;
	}

	/**
	 * @param privateRSAKey
	 *            the privateRSAKey to set
	 */
	public void setPrivateRSAKey(Key privateRSAKey) {
		this.privateRSAKey = privateRSAKey;
	}

	/**
	 * @return the publicRSAKey
	 */
	public Key getPublicRSAKey() {
		return publicRSAKey;
	}

	/**
	 * @param publicRSAKey
	 *            the publicRSAKey to set
	 */
	public void setPublicRSAKey(Key publicRSAKey) {
		this.publicRSAKey = publicRSAKey;
	}

	/**
	 * @return the aESKey
	 */
	public Key getAESKey() {
		return AESKey;
	}

	/**
	 * @param aESKey
	 *            the aESKey to set
	 */
	public void setAESKey(Key aESKey) {
		AESKey = aESKey;
	}
	
	/* read byte[] from inputfile */
	public static byte[] readFile(String inputfile) {
		InputStream is;
		try {
			is = new FileInputStream(inputfile);

		int size = is.available();
		byte[] content = new byte[size];

		is.read(content);

		is.close();
		return content;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
return null;
	}

	/* write byte[] into outputfile */
	public static void writeFile(String outputfile, byte[] b) {
		OutputStream os;
		try {
			os = new FileOutputStream(outputfile);

		os.write(b);
		os.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}