package de.cotech.hw.fido2.internal.cbor_java.encoder;

import java.io.OutputStream;

import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.DoublePrecisionFloat;

public class DoublePrecisionFloatEncoder extends AbstractEncoder<DoublePrecisionFloat> {

	public DoublePrecisionFloatEncoder(CborEncoder encoder, OutputStream outputStream) {
		super(encoder, outputStream);
	}

	@Override
	public void encode(DoublePrecisionFloat dataItem) throws CborException {
		write((7 << 5) | 27);
		long bits = Double.doubleToRawLongBits(dataItem.getValue());
		write((int) ((bits >> 56) & 0xFF));
		write((int) ((bits >> 48) & 0xFF));
		write((int) ((bits >> 40) & 0xFF));
		write((int) ((bits >> 32) & 0xFF));
		write((int) ((bits >> 24) & 0xFF));
		write((int) ((bits >> 16) & 0xFF));
		write((int) ((bits >> 8) & 0xFF));
		write((int) ((bits >> 0) & 0xFF));
	}

}
