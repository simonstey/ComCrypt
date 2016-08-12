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
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.io.FilenameUtils;

/**
 * @author Simon Steyskal
 * 
 * Info: Partially adapted from http://stackoverflow.com/a/35292625
 *
 */
public class EncryptFileVisitor extends SimpleFileVisitor<Path> {

	private int files;
	private int dirs;
	private final Path source;
	private final Path target;
	private KeyStore keyStore;
	/**
	 * @param source
	 * @param target
	 */
	public EncryptFileVisitor(Path source, Path target) {
		this.source = source;
		this.target = target;
	}

	/**
	 * @param source
	 * @param target
	 * @param keyStore
	 */
	public EncryptFileVisitor(Path source, Path target, KeyStore keyStore) {
		this.source = source;
		this.keyStore = keyStore;
		this.target = target;
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

		Path newFile = target.resolve(source.relativize(file));

//		if (method.equals("encrypt")) {
			SecretKey tmpKey = EncryptionUtil.generateAESKey();
			files++;
			try {
				String filename = file.getFileName().toString();
				String eFilename = FilenameUtils.getBaseName(filename) + ".e" + FilenameUtils.getExtension(filename);

				// store the secret key
				KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(tmpKey);
				PasswordProtection keyPassword = new PasswordProtection(eFilename.toCharArray());
				try {
					keyStore.setEntry(eFilename, keyStoreEntry, keyPassword);
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				EncryptionUtil.encryptFile(file.toFile(), newFile.resolveSibling(eFilename).toFile(), "AES", tmpKey);
			} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
					| NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
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
