package lv.uee.gluu.dto;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

public class ByteDataInputStream extends DataInputStream {
    public ByteDataInputStream(byte[] data) {
        super(new ByteArrayInputStream(data));
    }

    public byte[] read(int numberOfBytes) throws IOException {
        byte[] readBytes = new byte[numberOfBytes];
        this.readFully(readBytes);
        return readBytes;
    }

    public byte[] readAll() throws IOException {
        byte[] readBytes = new byte[this.available()];
        this.readFully(readBytes);
        return readBytes;
    }

    public byte readSigned() throws IOException {
        return this.readByte();
    }

    public int readUnsigned() throws IOException {
        return this.readUnsignedByte();
    }
}