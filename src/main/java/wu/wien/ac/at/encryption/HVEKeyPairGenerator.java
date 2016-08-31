package wu.wien.ac.at.encryption;

import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08KeyGenerationParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08MasterSecretKeyParameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08Parameters;
import it.unisa.dia.gas.crypto.jpbc.fe.hve.ip08.params.HVEIP08PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPow;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class HVEKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
	private HVEIP08KeyGenerationParameters param;

	@Override
	public void init(KeyGenerationParameters param) {
		this.param = (HVEIP08KeyGenerationParameters) param;
	}

	public HVEIP08PublicKeyParameters loadPubKey(Pairing p, PairingParameters params, String pubKeyPath)
			throws IOException {
		PairingStreamReader pubStreamParser = new PairingStreamReader(p, pubKeyPath);

		try {

			Element g = pubStreamParser.readElement("G1");

			int[] attributeLengths = pubStreamParser.readInts();
			HVEIP08Parameters hveParameters = new HVEIP08Parameters(params, g, attributeLengths);
			Element Y = pubStreamParser.readElement("GT");
			List<List<Element>> Ts = new ArrayList<List<Element>>();
			List<List<Element>> Vs = new ArrayList<List<Element>>();
			int n = pubStreamParser.readInt();
			for (int i = 0; i < n; i++) {
				int attributeNum = pubStreamParser.readInt();
				List<Element> tList = new ArrayList<Element>(attributeNum);
				List<Element> vList = new ArrayList<Element>(attributeNum);
				for (int j = 0; j < attributeNum; j++) {
					tList.add(pubStreamParser.readElement("G1"));
					vList.add(pubStreamParser.readElement("G1"));
				}
				Ts.add(tList);
				Vs.add(vList);
			}
			pubStreamParser.close();

			return new HVEIP08PublicKeyParameters(hveParameters, Y, Ts, Vs);
		} catch (EOFException e) {

		}

		return null;
	}

	public HVEIP08MasterSecretKeyParameters loadMskKey(Pairing p, PairingParameters params, String privKeyPath)
			throws IOException {
		PairingStreamReader privStreamParser = new PairingStreamReader(p, privKeyPath);
		try {
		Element g = privStreamParser.readElement("G1");
		int[] attributeLengths = privStreamParser.readInts();
		HVEIP08Parameters hveParameters = new HVEIP08Parameters(params, g, attributeLengths);

		Element Y = privStreamParser.readElement("Zr");
		List<List<Element>> Ts = new ArrayList<List<Element>>();
		List<List<Element>> Vs = new ArrayList<List<Element>>();
		int n = privStreamParser.readInt();
		for (int i = 0; i < n; i++) {
			int attributeNum = privStreamParser.readInt();
			List<Element> tList = new ArrayList<Element>(attributeNum);
			List<Element> vList = new ArrayList<Element>(attributeNum);
			for (int j = 0; j < attributeNum; j++) {
				tList.add(privStreamParser.readElement("Zr"));
				vList.add(privStreamParser.readElement("Zr"));
			}
			Ts.add(tList);
			Vs.add(vList);
		}
		System.out.println("before closing");
		privStreamParser.close();
		return new HVEIP08MasterSecretKeyParameters(hveParameters, Y, Ts, Vs);
	} catch (EOFException e) {
		System.out.println("Fired");
	}
		System.out.println("returning 0");
	return null;
	}

	public AsymmetricCipherKeyPair loadKeyPair(String keyPath) {
		// IPLOSTW10Parameters parameters = param.getParameters();

		Path path = Paths.get(keyPath, "pairing.properties");
		byte[] data;
		try {
			data = Files.readAllBytes(path);

			// this.powG = g.getElementPowPreProcessing();

			PairingParameters params = new PropertiesParameters().load(new ByteArrayInputStream(data));
			Pairing p = PairingFactory.getPairing(params);

			Path pubPath = Paths.get(keyPath, "pub.key");
			Path privPath = Paths.get(keyPath, "privMaster.key");

			HVEIP08MasterSecretKeyParameters hveSk = loadMskKey(p, params, privPath.toString());
			HVEIP08PublicKeyParameters hvePk = loadPubKey(p, params, pubPath.toString());
			
			return new AsymmetricCipherKeyPair(hvePk, hveSk);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public AsymmetricCipherKeyPair generateKeyPair(String keyPath) throws IOException {
		HVEIP08Parameters parameters = param.getParameters();
		parameters.preProcess();

		Pairing pairing = PairingFactory.getPairing(parameters.getParameters());
		Element g = parameters.getG();
		ElementPow powG = parameters.getElementPowG();
		int n = parameters.getN();

		// Init Y
		Element y = pairing.getZr().newElement().setToRandom();
		Element Y = pairing.pairing(g, g).powZn(y);

		// Init
		List<List<Element>> T = new ArrayList<List<Element>>(n);
		List<List<Element>> t = new ArrayList<List<Element>>(n);

		List<List<Element>> V = new ArrayList<List<Element>>(n);
		List<List<Element>> v = new ArrayList<List<Element>>(n);

		for (int i = 0; i < n; i++) {

			int howMany = parameters.getAttributeNumAt(i);
			List<Element> T_i = new ArrayList<Element>();
			List<Element> t_i = new ArrayList<Element>();

			List<Element> V_i = new ArrayList<Element>();
			List<Element> v_i = new ArrayList<Element>();

			for (int j = 0; j < howMany; j++) {
				Element t_j = pairing.getZr().newElement().setToRandom();
				T_i.add(powG.powZn(t_j).getImmutable());
				t_i.add(t_j.getImmutable());

				Element v_j = pairing.getZr().newElement().setToRandom();
				V_i.add(powG.powZn(v_j).getImmutable());
				v_i.add(v_j.getImmutable());
			}

			T.add(T_i);
			t.add(t_i);

			V.add(V_i);
			v.add(v_i);
		}

		HVEIP08PublicKeyParameters hvePub = new HVEIP08PublicKeyParameters(parameters, Y.getImmutable(), T, V);
		HVEIP08MasterSecretKeyParameters hveSk = new HVEIP08MasterSecretKeyParameters(parameters, y.getImmutable(), t,
				v);

		PairingStreamWriter pubOS = new PairingStreamWriter(pairing, Paths.get(keyPath, "pub.key").toString());
		// --- write common part
		pubOS.writeElement(hvePub.getParameters().getG());
		pubOS.writeInts(hvePub.getParameters().getAttributeLengths());
		// --- write public key
		pubOS.writeElement(hvePub.getY());
		pubOS.writeInt(hvePub.getParameters().getN());
		for (int i = 0; i < hvePub.getParameters().getN(); i++) {
			pubOS.writeInt(hvePub.getParameters().getAttributeNumAt(i));
			for (int j = 0; j < hvePub.getParameters().getAttributeNumAt(i); j++) {
				pubOS.writeElement(hvePub.getTAt(i, j));
				pubOS.writeElement(hvePub.getVAt(i, j));
			}
		}
		pubOS.save();
		pubOS.close();

		PairingStreamWriter privOS = new PairingStreamWriter(pairing,  Paths.get(keyPath, "privMaster.key").toString());

		privOS.writeElement(hveSk.getParameters().getG());
		privOS.writeInts(hveSk.getParameters().getAttributeLengths());
		// --- write public key
		privOS.writeElement(hveSk.getY());
		privOS.writeInt(hveSk.getParameters().getN());
		for (int i = 0; i < hveSk.getParameters().getN(); i++) {
			privOS.writeInt(hveSk.getParameters().getAttributeNumAt(i));
			for (int j = 0; j < hveSk.getParameters().getAttributeNumAt(i); j++) {
				privOS.writeElement(hveSk.getTAt(i, j));
				privOS.writeElement(hveSk.getVAt(i, j));
			}
		}
		privOS.save();
		privOS.close();
		return new AsymmetricCipherKeyPair(hvePub, hveSk);
	}

	@Override
	public AsymmetricCipherKeyPair generateKeyPair() {
		// TODO Auto-generated method stub
		return null;
	}

}