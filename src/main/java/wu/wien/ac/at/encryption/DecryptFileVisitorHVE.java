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
import java.util.BitSet;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;

import infobiz.wu.ac.at.comcrypt.crypto.cpabe.Cpabe;
import it.unisa.dia.gas.crypto.kem.KeyEncapsulationMechanism;

/**
 * @author Simon Steyskal
 * 
 * Info: Partially adapted from http://stackoverflow.com/a/35292625
 *
 */
public class DecryptFileVisitorHVE extends SimpleFileVisitor<Path> {

	private int files;
	private int dirs;
	private final Path source;
	private final Path target;
	private String compressionApproach;
	private String keyPath;
	private KeyEncapsulationMechanism kem;
	private String[] partitions;
	private static final String A = "A";
	private static final String B = "B";
	private static final String C = "C";
	private static final String D = "D";
	private Cpabe cp;
	private User decryptingUser = new User();

	/**
	 * @param source
	 * @param target
	 * @param masterKeyStore
	 * @param slaveKeyStore
	 * @param compressionApproach
	 * @param partitions
	 */
	public DecryptFileVisitorHVE(Path source, Path target, String keyPath,
			String compressionApproach, String[] partitions, String username) {
		this.source = source;
		this.keyPath = keyPath;
		this.target = target;
		this.compressionApproach = compressionApproach;
		this.partitions = partitions;
		decryptingUser.setPassphrase(username);
		this.cp = new Cpabe();
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

			cp.dec(keyPath, keyPath, file.toString(), newFile.resolveSibling(eFilename).toString());
		
//			EncryptionUtil.decryptFile(file.toFile(), newFile.resolveSibling(eFilename).toFile(), kem);
		}	catch (BadPaddingException e) {
				System.out.println("Not allowed to decrypt "+filename+"!");
		} 	catch (IOException e) {
			System.out.println("Not allowed to decrypt "+filename+"!");
		} catch (InvalidKeyException | IllegalBlockSizeException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
