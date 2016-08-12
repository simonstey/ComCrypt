package wu.wien.ac.at.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import org.apache.commons.io.FileUtils;

import wu.wien.ac.at.encryption.DecryptFileVisitor;
import wu.wien.ac.at.encryption.EncryptFileVisitor;

/**
 * @author Simon Steyskal
 */
public class ComCryption {

	private static String inputPath;
	private static String outputPath;
	private static String keystorePath;
	private static String compressionApproach;
	private static String username;
	private static String[] partitions;
	private static String method;
	private static int numberOfRuns;

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		inputPath = System.getProperty("inPath");
		outputPath = System.getProperty("outPath");
		keystorePath = System.getProperty("keyPath");
		numberOfRuns = Integer.valueOf(System.getProperty("runs"));
		method = System.getProperty("method");
	
		if (method.equals("decrypt")) {
			compressionApproach = System.getProperty("approach");
			username = System.getProperty("user");
			partitions = System.getProperty("partitions").split(" ");
			averageTest(() -> decryptFiles());
		} else {
			averageTest(() -> encryptFiles());
		}

	}

	/**
	 * Performs an averaging test against each method.
	 *
	 * Note: For the most un-biasing test, run only one test per execution. This
	 * will ensure that prior tests are less likely to have influence on your
	 * test results.
	 *
	 * To further un-bias the tests, run a priming test first with a count of 1
	 * and disregard it's result.
	 */
	public static void averageTest() {
		if (method.equals("decrypt")) {
			averageTest(numberOfRuns, () -> decryptFiles());
		} else {
			averageTest(numberOfRuns, () -> encryptFiles());
		}
	}

	/**
	 * 
	 */
	public static void encryptFiles() {
		System.out.println("Starting to encrypt all files in: " + inputPath);
		System.out.println("Encrypted files will be stored in: " + outputPath);

		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(null, null);

			EncryptFileVisitor visitor = new EncryptFileVisitor(Paths.get(inputPath).normalize().toAbsolutePath(),
					Paths.get(outputPath).normalize().toAbsolutePath(), keyStore);

			Files.walkFileTree(Paths.get(inputPath).normalize().toAbsolutePath(), visitor);
			System.out.format("Number of processed files: %d.\n", visitor.getFiles());
			keyStore.store(new FileOutputStream(keystorePath), "master".toCharArray());
		} catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * 
	 */
	public static void decryptFiles() {
		System.out.println("Starting to decrypt files for partitions: " + Arrays.asList(partitions));
		System.out.println("Decrypted files will be stored in: " + outputPath);

		try {
			KeyStore outputKeystore = KeyStore.getInstance("JCEKS");

			outputKeystore.load(null, null);

			KeyStore masterKeyStore = KeyStore.getInstance("JCEKS");
			masterKeyStore.load(new FileInputStream(keystorePath), "master".toCharArray());

			Path normalizedInPath = Paths.get(inputPath).normalize().toAbsolutePath();
			Path normalizedOutPath = Paths.get(outputPath).normalize().toAbsolutePath();

			DecryptFileVisitor visitor = new DecryptFileVisitor(normalizedInPath, normalizedOutPath, masterKeyStore,
					outputKeystore, compressionApproach, partitions, username);
			Files.walkFileTree(Paths.get(inputPath).normalize().toAbsolutePath(), visitor);
			outputKeystore.store(new FileOutputStream(outputPath + "/" + username + ".ejks"), username.toCharArray());

			System.out.println("----------------------");
			System.out.println("Successfully created keystore containing all keys used for decrypting requested partitions in " + outputPath + "/" + username + ".ejks");
			System.out.println("Keystore " + username + ".ejks is encrypted using " + username + "'s public RSA key");
			System.out.println("----------------------");
			System.out.format("Number of processed files: %d.\n", visitor.getFiles());
			System.out.println("----------------------");
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Used to perform a timed average of a repeated set of runs.
	 *
	 * @param count
	 *            Amount of times to run {@code r}.
	 * @param r
	 *            {@link Runnable} object to perform tests against.
	 */
	public static void averageTest(int count, Runnable r) {
		Duration total = Duration.ZERO;
		for (int i = 0; i < count; i++) {
			try {
				FileUtils.deleteDirectory(new File(outputPath));
				(new File(outputPath)).mkdirs();
				System.out.println("deleted folders for new run: " + outputPath);
			} catch (IOException e) {
				e.printStackTrace();
			}

			total = total.plus(time(() -> r.run()));

		}
		System.out.format("Average duration: %sms\n", total.dividedBy(count).toMillis());
		System.out.format("Overall duration: " + total.toMillis() + "ms\n");

	}
	
	/**
	 * Used to perform a timed average of a repeated set of runs.
	 *
	 * @param r
	 *            {@link Runnable} object to perform tests against.
	 */
	public static void averageTest(Runnable r) {
		Instant start = Instant.now();
		r.run();
		Duration dur = Duration.between(start, Instant.now());

		System.out.format("Completed in: %sms%n", dur.toMillis());
	}

	/**
	 * Times a {@link Runnable} instance.
	 *
	 * @param r
	 *            {@link Runnable} object to time.
	 * @return {@link Duration} object containing run-time length.
	 */
	public static Duration time(Runnable r) {
		Instant start = Instant.now();
		r.run();
		Duration dur = Duration.between(start, Instant.now());

		System.out.format("Completed in: %sms%n", dur.toMillis());
		return dur;
	}

}
