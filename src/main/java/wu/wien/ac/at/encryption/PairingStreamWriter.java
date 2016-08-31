package wu.wien.ac.at.encryption;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;


public class PairingStreamWriter implements ObjectOutput {
    private ObjectOutput dos;

    private Pairing pairing;

    public PairingStreamWriter(Pairing pairing, String filePath) {
        this.pairing = pairing;
        
    	FileOutputStream fout = null;
    	try{
    	     fout = new FileOutputStream(filePath);
    	     dos = new ObjectOutputStream(fout);
    	} catch (Exception ex) {
    	    ex.printStackTrace();
    	}

    }


    public void write(String s) throws IOException {
        dos.writeUTF(s);
    }

    public void write(Element element) throws IOException {
        dos.write(element.toBytes());
    }

    @Override
	public void writeInt(int value) throws IOException {
        dos.writeInt(value);
    }
    
    public void writeInts(int[] ints) throws IOException {
        if (ints == null) {
        	writeInt(0);
        } else {
        	writeInt(ints.length);
            for (int anInt : ints) writeInt(anInt);
        }
}
    
    public Pairing getPairing() {
        return pairing;
    }
    
    public void writePairingFieldIndex(Field field) throws IOException {
        int index = getPairing().getFieldIndex(field);
        if (index == -1)
            throw new IllegalArgumentException("The field does not belong to the current pairing instance.");
        writeInt(index);
    }


    public void writeElement(Element element) throws IOException {
        if (element == null)
            writeInt(0);
        else {
            byte[] bytes = element.toBytes();
            writeInt(bytes.length);
            write(bytes);
        }
    }

    public void writeElements(Element[] elements) throws IOException {
        if (elements == null)
            writeInt(0);
        else {
            writeInt(elements.length);
            for (Element e : elements)
            	writeElement(e);
//            writeElement(e);
        }
    }


    @Override
	public void write(byte[] bytes) throws IOException {
//    	writeInt(bytes.length);
        dos.write(bytes);
    }

//    public byte[] toBytes() {
//        return baos.toByteArray();
//    }
    
    public void save() throws IOException {
    	
    	    if(dos != null){
    	    	dos.close();
    	    }
    	
    }

	@Override
	public void writeBoolean(boolean arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeByte(int arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeBytes(String arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeChar(int arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeChars(String arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeDouble(double arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeFloat(float arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeLong(long arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeShort(int arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeUTF(String arg0) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void close() throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void flush() throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void write(int b) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void writeObject(Object obj) throws IOException {
		// TODO Auto-generated method stub
		
	}

}
