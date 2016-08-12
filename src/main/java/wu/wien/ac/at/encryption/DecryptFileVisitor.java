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
import java.security.UnrecoverableEntryException;
import java.util.BitSet;

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
public class DecryptFileVisitor extends SimpleFileVisitor<Path> {

	private int files;
	private int dirs;
	private final Path source;
	private final Path target;
	private String compressionApproach;
	private KeyStore masterKeyStore;
	private KeyStore slaveKeyStore;
	private String[] partitions;
	private static final String A = "A";
	private static final String B = "B";
	private static final String C = "C";
	private static final String D = "D";
	private User decryptingUser = new User();

	/**
	 * @param source
	 * @param target
	 * @param masterKeyStore
	 * @param slaveKeyStore
	 * @param compressionApproach
	 * @param partitions
	 */
	public DecryptFileVisitor(Path source, Path target, KeyStore masterKeyStore, KeyStore slaveKeyStore,
			String compressionApproach, String[] partitions, String username) {
		this.source = source;
		this.masterKeyStore = masterKeyStore;
		this.slaveKeyStore = slaveKeyStore;
		this.target = target;
		this.compressionApproach = compressionApproach;
		this.partitions = partitions;
		decryptingUser.setPassphrase(username);
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
		if (FilenameUtils.getExtension(file.getFileName().toString()).equals("edic")
				|| FilenameUtils.getExtension(file.getFileName().toString()).equals("ebt")) {
			fileSelector(file);
		} else if (FilenameUtils.getExtension(file.getFileName().toString()).equals("ehdt")) {
			fileSelector(file);
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

	/**
	 * @param file
	 */
	public void fileSelector(Path file) {
		String filename = FilenameUtils.getBaseName(file.getFileName().toString());
		long filenameL = Long.parseLong(filename, 10);

		switch (compressionApproach) {
		case A:
			for (int i = 0; i < partitions.length; i++) {
				if (filename.equals(partitions[i])) {
					decryptFiles(file);
				}
			}
			break;
		case B:
			for (int i = 0; i < partitions.length; i++) {
				if (BitSet.valueOf(new long[] { filenameL }).get(Integer.parseInt(partitions[i]) - 1)) {
					decryptFiles(file);
				}
			}
			break;
		case C:
			for (int i = 0; i < partitions.length; i++) {
				if (file.getParent().endsWith("dictionaries")
						&& BitSet.valueOf(new long[] { filenameL }).get(Integer.parseInt(partitions[i]) - 1)) {
					decryptFiles(file);
				} else if (file.getParent().endsWith("triples") && filename.equals(partitions[i])) {
					decryptFiles(file);
				}
			}
			break;
		case D:
			for (int i = 0; i < partitions.length; i++) {
				if (BitSet.valueOf(new long[] { filenameL }).get(Integer.parseInt(partitions[i]) - 1)) {
					decryptFiles(file);
				}
			}
			break;
		}
	}

	/**
	 * @param file
	 */
	private void decryptFiles(Path file) {
		files++;
		Path newFile = target.resolve(source.relativize(file));
		String filename = file.getFileName().toString();
		try {
			String eFilename = filename.replace(".e", ".");

			PasswordProtection keyPassword = new PasswordProtection(EncryptionUtil
					.encryptKeyStoreEntry(filename, decryptingUser.getPublicRSAKey()).toString().toCharArray());

			KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) masterKeyStore.getEntry(filename,
					new PasswordProtection(filename.toCharArray()));
			slaveKeyStore.setEntry(filename, entry, keyPassword);
			SecretKey keyFound = entry.getSecretKey();

			EncryptionUtil.decryptFile(file.toFile(), newFile.resolveSibling(eFilename).toFile(), "AES", keyFound);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
				| NoSuchPaddingException | UnrecoverableEntryException | KeyStoreException | IOException e) {
			e.printStackTrace();
		}
	}

}
