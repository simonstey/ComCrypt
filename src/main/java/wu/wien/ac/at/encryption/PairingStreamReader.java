package wu.wien.ac.at.encryption;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;


public class PairingStreamReader implements ObjectInput {

    private ObjectInput objectInput;

    private Pairing pairing;

    public PairingStreamReader(Pairing pairing, String filePath) {
        this.pairing = pairing;
        
        FileInputStream fin = null;
    	try{
    		fin = new FileInputStream(filePath);
    		objectInput = new ObjectInputStream(fin);
    	} catch (Exception ex) {
    	    ex.printStackTrace();
    	}

    }



    @Override
	public Object readObject() throws IOException, ClassNotFoundException {
        return objectInput.readObject();
    }

    @Override
	public int read() throws IOException {
        return objectInput.read();
    }

    @Override
	public int read(byte[] b) throws IOException {
        return objectInput.read(b);
    }

    @Override
	public int read(byte[] b, int off, int len) throws IOException {
        return objectInput.read(b, off, len);
    }

    @Override
	public long skip(long n) throws IOException {
        return objectInput.skip(n);
    }

    @Override
	public int available() throws IOException {
        return objectInput.available();
    }

    @Override
	public void close() throws IOException {
        objectInput.close();
    }

    @Override
	public void readFully(byte[] b) throws IOException {
        objectInput.readFully(b);
    }

    @Override
	public void readFully(byte[] b, int off, int len) throws IOException {
        objectInput.readFully(b, off, len);
    }

    @Override
	public int skipBytes(int n) throws IOException {
        return objectInput.skipBytes(n);
    }

    @Override
	public boolean readBoolean() throws IOException {
        return objectInput.readBoolean();
    }

    @Override
	public byte readByte() throws IOException {
        return objectInput.readByte();
    }

    @Override
	public int readUnsignedByte() throws IOException {
        return objectInput.readUnsignedByte();
    }

    @Override
	public short readShort() throws IOException {
        return objectInput.readShort();
    }

    @Override
	public int readUnsignedShort() throws IOException {
        return objectInput.readUnsignedShort();
    }

    @Override
	public char readChar() throws IOException {
        return objectInput.readChar();
    }

    @Override
	public int readInt() throws IOException {
        return objectInput.readInt();
    }

    @Override
	public long readLong() throws IOException {
        return objectInput.readLong();
    }

    @Override
	public float readFloat() throws IOException {
        return objectInput.readFloat();
    }

    @Override
	public double readDouble() throws IOException {
        return objectInput.readDouble();
    }

    @Override
	public String readLine() throws IOException {
        return objectInput.readLine();
    }

    @Override
	public String readUTF() throws IOException {
        return objectInput.readUTF();
    }


    public Pairing getPairing() {
        return pairing;
    }

    public Field readField() throws IOException {
        Field identifier = getPairing().getFieldAt(readInt());
       
        return identifier;
        
//        switch (identifier) {
//            case G1:
//                return pairing.getG1();
//            case G2:
//                return pairing.getG2();
//            case GT:
//                return pairing.getGT();
//            case Zr:
//                return pairing.getZr();
//            default:
//                throw new IllegalArgumentException("Illegal Field Identifier.");
//        }
    }


    public Element readElement(Field fieldIdentifier) throws IOException {
        Element e = fieldIdentifier.newElement();
//        switch (fieldIdentifier) {
//            case G1:
//                e = pairing.getG1().newElement();
//                break;
//            case G2:
//                e = pairing.getG2().newElement();
//                break;
//            case GT:
//                e = pairing.getGT().newElement();
//                break;
//            case Zr:
//                e = pairing.getZr().newElement();
//                break;
//            default:
//                throw new IllegalArgumentException("Invalid Field Type.");
//        }

        byte[] buffer = new byte[readInt()];
        readFully(buffer);
        e.setFromBytes(buffer);

        return e;
    }
    
    public Element readElement(String fieldIdentifier) throws IOException {
    	 Element e;

        switch (fieldIdentifier) {
            case "G1":
                e = pairing.getG1().newElement();
                break;
            case "G2":
                e = pairing.getG2().newElement();
                break;
            case "GT":
                e = pairing.getGT().newElement();
                break;
            case "Zr":
                e = pairing.getZr().newElement();
                break;
            default:
                throw new IllegalArgumentException("Invalid Field Type.");
        }

        byte[] buffer = new byte[readInt()];
        readFully(buffer);
        e.setFromBytes(buffer);

        return e;
    }

    public Element[] readElements(Field identifier) throws IOException{
        int num = readInt();
        Element[] elements = new Element[num];
        for (int i = 0; i < num; i++) {
            elements[i] = readElement(identifier);
        }

        return elements;
    }

//    public PairingPreProcessing readPairingPreProcessing() throws IOException {
//        int size = readInt();
//        byte[] buffer = new byte[size];
//        readFully(buffer);
//
//        return getPairing().pairing(buffer, 0);
//    }
//
//    public ElementPowPreProcessing readElementPowPreProcessing() throws IOException {
//        // Read field identifier
//        Field field = readField();
//
//        // read the preprocessing information
//        int size = readInt();
//        byte[] buffer = new byte[size];
//        readFully(buffer);
//
//        return field.pow(buffer, 0);
//    }

    public int[] readInts() throws IOException {
        int num = readInt();

        int[] elements = new int[num];
        for (int i = 0; i < num; i++) {
            elements[i] = readInt();
        }

        return elements;
    }

    public byte[] readBytes() throws IOException {
        int length = readInt();
        byte[] buffer = new byte[length];
        readFully(buffer);

        return buffer;
}


}
