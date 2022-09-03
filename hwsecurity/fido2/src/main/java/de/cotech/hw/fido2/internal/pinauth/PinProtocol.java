package de.cotech.hw.fido2.internal.pinauth;

import java.io.IOException;

import de.cotech.hw.fido2.internal.Fido2AppletConnection;

public interface PinProtocol {
    PinToken clientPinAuthenticate(
            Fido2AppletConnection fido2AppletConnection, String pin, boolean lastAttemptOk) throws IOException;

    int version();

    byte[] authenticate(PinToken pinToken, byte[] data);

    byte[] encrypt(PinToken pinToken, byte[] data);

    byte[] decrypt(PinToken pinToken, byte[] data) throws IOException;

    byte[] calculatePinAuth(PinToken pinToken, byte[] data);
}
