/**
 * 
 */
package wu.wien.ac.at.encryption;

import static java.nio.file.StandardCopyOption.COPY_ATTRIBUTES;

import java.io.IOException;
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.crypto.CipherParameters;

/**
 * @author Simon Steyskal
 * 
 * Info: Partially adapted from http://stackoverflow.com/a/35292625
 *
 */
public class EncryptFileVisitorHVE extends SimpleFileVisitor<Path> {

	private int files;
	private int dirs;
	private int n;
	private final Path source;
	private final Path target;
	private final CipherParameters pubKey;
	private final String compressionApproach;
	/**
	 * @param source
	 * @param target
	 */
	public EncryptFileVisitorHVE(Path source, Path target, CipherParameters pubKey, int n, String compressionApproach) {
		this.source = source;
		this.target = target;
		this.pubKey = pubKey;
		this.n = n;
		this.compressionApproach = compressionApproach;
	}


	/**
	 * Count of all files found within this visitor.
	 *
	 * @return Count of files found.
	 */
	public int getFiles() {
		return files;
	}

	/**
	 * Count of all directories found within this visitor.
	 *
	 * @return Count of directories found.
	 */
	public int getDirs() {
		return dirs;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
		files++;
		Path newFile = target.resolve(source.relativize(file));
		String filename = file.getFileName().toString();
		String extension =  FilenameUtils.getExtension(filename);
		String eFilename = FilenameUtils.getBaseName(filename) + ".e" + extension;

		

		
		    try {
		    	EncryptionUtil.encryptFile(file.toFile(), newFile.resolveSibling(eFilename).toFile(), pubKey, n, compressionApproach);
			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
					| NoSuchPaddingException | NoSuchProviderException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
		

//		if (method.equals("encrypt")) {
//			SecretKey tmpKey = EncryptionUtil.generateAESKey();
//		
//			try {
//
//				// store the secret key
//				KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(tmpKey);
//				PasswordProtection keyPassword = new PasswordProtection(eFilename.toCharArray());
//				try {
//					keyStore.setEntry(eFilename, keyStoreEntry, keyPassword);
//				} catch (KeyStoreException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//
//				EncryptionUtil.encryptFile(file.toFile(), newFile.resolveSibling(eFilename).toFile(), "AES", tmpKey);
//			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
//					| NoSuchPaddingException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
		return FileVisitResult.CONTINUE;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
		// before visiting entries in a directory we copy the directory
		// (okay if directory already exists).
		CopyOption[] options = new CopyOption[] { COPY_ATTRIBUTES };
		Path newdir = target.resolve(source.relativize(dir));

		try {
			Files.copy(dir, newdir, options);
		} catch (FileAlreadyExistsException x) {
			// ignore
		} catch (IOException x) {
			System.err.format("Unable to create: %s: %s%n", newdir, x);
			return FileVisitResult.SKIP_SUBTREE;
		}

		return FileVisitResult.CONTINUE;
	}

}
