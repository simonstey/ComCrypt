package comenc;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.BitSet;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.engines.HVEIP08KEMEngine;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.generators.HVEIP08KeyPairGenerator;
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
import wu.wien.ac.at.encryption.HVEKeyPairGenerator;
import wu.wien.ac.at.encryption.HVESecretKeyGenerator;


public class HVETest {

	public final static int AES_Key_Size = 256;
	public static final int MAX_FILE_BUF = 1024;
	public static PairingParameters parameters;
	
	public HVETest() {
		// TODO Auto-generated constructor stub
	}
	

	
	public static void main(String[] args) throws Exception {
//		long filenameL = Long.parseLong("9", 10);
//		int[] result = new int[12];
//		
//		
//		BitSet bs2 = BitSet.valueOf(new long[] { filenameL });
//
//		for(int i = 0; i < result.length; i++){
//			if(bs2.get(i))
//				result[i] = 1;
//			else
//				result[i] = 0;
//		}
//
//        System.out.println(result.length);
//        for(int i = 0; i < result.length;i++){
//        	System.out.println(i+": "+result[i]);
//        }
		
		Security.addProvider(new BouncyCastleProvider());
		 int n = 12;
		    AsymmetricCipherKeyPair keyPair = setupLoad(genBinaryParam(n),"");

//		    int[][] vectors = createMatchingVectors(n);
//		    
//		    try {
//				encryptFile(new File("src/test/resources/1.dic"),new File("src/test/resources/1.edic"), keyPair.getPublic(), n);
//			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
//					| NoSuchPaddingException | NoSuchProviderException | IOException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//		    
//		    System.out.println("Encrypted file!");
////		    
//            KeyEncapsulationMechanism kem = new HVEIP08KEMEngine();
//
//            String[] partitions = {"2","1"};
//            
//            CipherParameters cpm = keyGen(keyPair.getPrivate(), createKeyVector(n,partitions));
//            
//            kem.init(false, cpm);
//            
//            System.out.println("initialized kem");
//            
//            try {
//				decryptFile(new File("src/test/resources/1.edic"),new File("src/test/resources/1_2.dic"), kem);
//            } catch (BadPaddingException | IOException e) {
//				System.out.println("not permitted to decrypt file!");
//            } catch (InvalidKeyException | IllegalBlockSizeException | NoSuchAlgorithmException
//					| NoSuchPaddingException | NoSuchProviderException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}

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
    	String filename = FilenameUtils.getBaseName(fileName);
		long filenameL = Long.parseLong(filename, 10);
		
		int[] result = bits2Ints(BitSet.valueOf(new long[] { filenameL }),n);
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

    protected static int[][] createMatchingVectors(int n) {
    	 int[][] result = new int[2][n];
         Random random = new Random();
         for (int i = 0; i < n; i++) {
             result[0][i] = -1;
             result[1][i] = random.nextInt(2);
         }
         return result;
    }
	
	 protected static CipherParameters keyGen(CipherParameters privateKey, int... pattern) {
	        HVESecretKeyGenerator generator = new HVESecretKeyGenerator();
	        generator.init(new HVEIP08SecretKeyGenerationParameters(
	                (HVEIP08MasterSecretKeyParameters) privateKey, pattern)
	        );

	        return generator.generateKey();
	    }
	
    protected static HVEIP08Parameters genBinaryParam(int n) {
        HVEIP08ParametersGenerator generator = new HVEIP08ParametersGenerator();
        
        PairingFactory.getInstance().setUsePBCWhenPossible(false);
        parameters = PairingFactory.getInstance().loadParameters("a_181_603.properties");
        
        generator.init(n, parameters);

        return generator.generateParameters();
    }
   
	
	private static byte[] getRawKey(byte[] seed) throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		kgen.init(128, sr); // 192 and 256 bits may not be available
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		return raw;
	}
	
	  static int[] bits2Ints(BitSet bs,int n) {
		    int[] temp = new int[n];
//		    int[] temp = new int[bs.size() / 32];

		    for (int i = 0; i < temp.length; i++)
		      for (int j = 0; j < 32; j++)
		        if (bs.get(i * 32 + j))
		          temp[i] |= 1 << j;

		    return temp;
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
	public static void encryptFile(File input, File output, CipherParameters pubKey, int n)//int... attributes)
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
		long filenameL = Long.parseLong(filename, 10);
		
//		int[] fileAttributes = bits2Ints(BitSet.valueOf(new long[] { filenameL }),n);
		
		/* ipBuf = AESSeed(=M) + [c1 + c2] */
		byte[][] ipBuf = encaps(pubKey,createFileVector(n,input.getName()));
		
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
		
		System.out.println("size kem.getKeyBlockSize(): "+kem.getKeyBlockSize());
		System.out.println("size kem.getInputBlockSize(): "+kem.getInputBlockSize());
		System.out.println("size kem.getOutputBlockSize(): "+kem.getOutputBlockSize());
		
		fout = new FileOutputStream(output);
		fin = new FileInputStream(input);
		
		System.out.println("bytes in fin: "+fin.available());
System.out.println("starting to read file header");
		
		int	ctSize =fin.read(ctbuf);
		totalread += ctSize;

		// create a buffer to write with the exact number of bytes read.
		// Otherwise a short read fills inbuf with 0x0
		byte[] ct = new byte[ctSize];
		for (int i = 0; i < ctSize; i++)
			ct[i] = ctbuf[i];

		
		
System.out.println("finished reading file header");

		byte[] raw = kem.processBlock(ct, 0, ct.length);

		byte[] keySeed = getRawKey(raw);
		SecretKeySpec skeySpec = new SecretKeySpec(keySeed, "AES");
		System.out.println("starting decryption");
		Cipher decrypt_cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		
		byte [] iv = new byte[decrypt_cipher.getBlockSize()];
        for(int i=0;i<iv.length;i++)iv[i] = 0;
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
		
		decrypt_cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);

		
		
		// creating a decoding stream from the FileInputStream
		cin = new CipherInputStream(fin, decrypt_cipher);
		System.out.println("bytes in fin: "+fin.available());

		
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
		
		System.out.println("finished decryption");
		fout.flush();
		cin.close();
		fin.close();
		fout.close();
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
}
