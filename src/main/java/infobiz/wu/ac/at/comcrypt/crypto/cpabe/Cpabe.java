package infobiz.wu.ac.at.comcrypt.crypto.cpabe;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

import infobiz.wu.ac.at.comcrypt.crypto.cpabe.policy.LangPolicy;

public class Cpabe {

	/**
	 * @param args
	 * @author Junwei Wang(wakemecn@gmail.com)
	 */

	public void setup(String keystorePath) {
		byte[] pub_byte, msk_byte;
		BswabePub pub = new BswabePub();
		BswabeMsk msk = new BswabeMsk();
		Bswabe.setup(pub, msk);

		/* store BswabePub into mskfile */
		pub_byte = SerializeUtils.serializeBswabePub(pub);
		Common.spitFile(Paths.get(keystorePath,"mPub.key").toString(), pub_byte);

		/* store BswabeMsk into mskfile */
		msk_byte = SerializeUtils.serializeBswabeMsk(msk);
		Common.spitFile(Paths.get(keystorePath,"mSec.key").toString(), msk_byte);
	}

	public void keygen(String keystorePath, String prvPath,
			String attr_str) throws NoSuchAlgorithmException, IOException {
		BswabePub pub;
		BswabeMsk msk;
		byte[] pub_byte, msk_byte, prv_byte;

		/* get BswabePub from pubfile */
		pub_byte = Common.suckFile(Paths.get(keystorePath,"mPub.key").toString());
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		/* get BswabeMsk from mskfile */
		msk_byte = Common.suckFile(Paths.get(keystorePath,"mSec.key").toString());
		msk = SerializeUtils.unserializeBswabeMsk(pub, msk_byte);

		String[] attr_arr = LangPolicy.parseAttribute(attr_str);
		BswabePrv prv = Bswabe.keygen(pub, msk, attr_arr);

		/* store BswabePrv into prvfile */
		prv_byte = SerializeUtils.serializeBswabePrv(prv);
		Common.spitFile(Paths.get(prvPath,"pSec.key").toString(), prv_byte);
	}
	
	public byte[][] encaps(String pubPath, String policy) throws Exception {
		BswabePub pub;
		BswabeCph cph;
		BswabeCphKey keyCph;
		byte[] cphBuf;

		byte[] pub_byte;
		Element m;

		/* get BswabePub from pubfile */
		pub_byte = Common.suckFile(Paths.get(pubPath,"mPub.key").toString());
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		keyCph = Bswabe.enc(pub, policy);
		cph = keyCph.cph;
		m = keyCph.key;
		System.err.println("m = " + m.toString());

		if (cph == null) {
			System.out.println("Error happed in enc");
			System.exit(0);
		}

		cphBuf = SerializeUtils.bswabeCphSerialize(cph);

		return new byte[][] {m.toBytes(), cphBuf};
//		
//		/* read file to encrypted */
//		plt = Common.suckFile(inputfile);
//		aesBuf = AESCoder.encrypt(m.toBytes(), plt);
//		// PrintArr("element: ", m.toBytes());
//		Common.writeCpabeFile(encfile, cphBuf, aesBuf);
	}

	public void enc(String pubPath, String policy, String inputfile,
			String encfile) throws Exception {
		BswabePub pub;
		BswabeCph cph;
		BswabeCphKey keyCph;
		byte[] plt;
		byte[] cphBuf;
		byte[] aesBuf;
		byte[] pub_byte;
		Element m;

		/* get BswabePub from pubfile */
		pub_byte = Common.suckFile(Paths.get(pubPath,"mPub.key").toString());
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		keyCph = Bswabe.enc(pub, policy);
		cph = keyCph.cph;
		m = keyCph.key;
//		System.err.println("m = " + m.toString());

		if (cph == null) {
			System.out.println("Error happed in enc");
			System.exit(0);
		}

		cphBuf = SerializeUtils.bswabeCphSerialize(cph);

		/* read file to encrypted */
		plt = Common.suckFile(inputfile);
		aesBuf = AESCoder.encrypt(m.toBytes(), plt);
		// PrintArr("element: ", m.toBytes());
		Common.writeCpabeFile(encfile, cphBuf, aesBuf);
	}

	public void dec(String pubPath, String prvPath, String encfile,
			String decfile) throws Exception {
		byte[] aesBuf, cphBuf;
		byte[] plt;
		byte[] prv_byte;
		byte[] pub_byte;
		byte[][] tmp;
		BswabeCph cph;
		BswabePrv prv;
		BswabePub pub;

		/* get BswabePub from pubfile */
		pub_byte = Common.suckFile(Paths.get(pubPath,"mPub.key").toString());
		pub = SerializeUtils.unserializeBswabePub(pub_byte);

		/* read ciphertext */
		tmp = Common.readCpabeFile(encfile);
		aesBuf = tmp[0];
		cphBuf = tmp[1];
		cph = SerializeUtils.bswabeCphUnserialize(pub, cphBuf);

		/* get BswabePrv form prvfile */
		prv_byte = Common.suckFile(Paths.get(prvPath,"pSec.key").toString());
		prv = SerializeUtils.unserializeBswabePrv(pub, prv_byte);

		BswabeElementBoolean beb = Bswabe.dec(pub, prv, cph);
//		System.err.println("e = " + beb.e.toString());
		if (beb.b) {
			plt = AESCoder.decrypt(beb.e.toBytes(), aesBuf);
			Common.spitFile(decfile, plt);
		} 
	}

}
