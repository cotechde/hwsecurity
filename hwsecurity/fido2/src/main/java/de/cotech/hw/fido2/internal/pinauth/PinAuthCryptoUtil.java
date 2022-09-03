/*
 * Copyright (C) 2018-2021 Confidential Technologies GmbH
 *
 * You can purchase a commercial license at https://hwsecurity.dev.
 * Buying such a license is mandatory as soon as you develop commercial
 * activities involving this program without disclosing the source code
 * of your own applications.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.cotech.hw.fido2.internal.pinauth;


import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import androidx.annotation.Keep;
import androidx.annotation.VisibleForTesting;

import de.cotech.hw.fido2.exceptions.FidoClientPinTooShortException;
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers.CoseAlg;
import de.cotech.hw.fido2.internal.cose.CosePublicKeyUtils;
import de.cotech.hw.fido2.internal.crypto.P256;
import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.HashUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class PinAuthCryptoUtil {

    private static final byte ZERO_BYTE = 0;

    /**
     * CTAP2 pinAuth, used for authentication of operations based on pinToken.
     * https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN
     */
    public byte[] calculatePinAuth(byte[] pinToken, byte[] clientDataHash) {
        return hmacSha256Left16Bytes(pinToken, clientDataHash);
    }

    public byte[] authenticate(byte[] secret, byte[] data) {
        return hmacSha256Left16Bytes(secret, data);
    }

    /**
     * Leftmost 16 bytes of an HMAC-SHA-256 operation.
     */
    private byte[] hmacSha256Left16Bytes(byte[] secret, byte[] data) {
        return Arrays.copyOfRange(hmacSha256(secret, data), 0, 16);
    }

    /**
     * Simple HMAC-SHA-256.
     */
    private byte[] hmacSha256(byte[] secret, byte[] data) {
        try {
            Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
            hmacSHA256.init(new SecretKeySpec(secret, "HmacSHA256"));
            return hmacSHA256.doFinal(data);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] encrypt(byte[] sharedSecret, byte[] data) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(getIv());
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] decrypt(byte[] sharedSecret, byte[] data) throws IOException {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[16]);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(data);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new IOException("Error decrypting data from authenticator", e);
        }
    }

    public byte[] calculatePinHashEnc(byte[] sharedSecret, String pin) throws IOException {
        byte[] pinHash = calculatePinHash(pin);
        return encrypt(sharedSecret, pinHash);
    }

    @Keep
    private byte[] getIv() {
        // IV=0 as per CTAP2 specification
        // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#settingNewPin
        // Workaround to prevent warnings in Google Play Dev Console:
        // https://support.google.com/faqs/answer/9450925?hl=en
        byte[] iv = new byte[16];
        Arrays.fill(iv, ZERO_BYTE);
        return iv;
    }

    @VisibleForTesting
    byte[] calculatePinHash(String pin) throws IOException {
        if (pin.length() < 4) {
            throw new FidoClientPinTooShortException();
        }
        return Arrays.copyOfRange(HashUtil.sha256(pin.getBytes()), 0, 16);
    }

    byte[] padPin(String pin) throws IOException {
        if (pin.length() < 4) {
            throw new FidoClientPinTooShortException();
        }
        byte[] pinBytes = pin.getBytes(Charset.forName("UTF-8"));
        if (pinBytes.length > 63) {
            throw new IOException("PIN UTF-8 encoding must not exceed 63 bytes length!");
        }
        byte[] result = new byte[64];
        System.arraycopy(pinBytes, 0, result, 0, pinBytes.length);
        return result;
    }

    public byte[] decryptPinToken(byte[] sharedSecret, byte[] pinTokenEnc) throws IOException {
        try {
            return decrypt(sharedSecret, pinTokenEnc);
        } catch (IOException e) {
            throw new IOException("Error decrypting pinToken from authenticator", e);
        }
    }

    public KeyPair generatePlatformKeyPair() {
        try {
            return P256.newKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] cosePublicKeyFromPublicKey(PublicKey publicKey) throws IOException {
        return CosePublicKeyUtils.encodex962PublicKeyAsCose(P256.serializePublicKey(publicKey), CoseAlg.ECDH_ES_w_HKDF_256);
    }

    public PublicKey publicKeyFromCosePublicKey(byte[] cosePublicKey) throws IOException {
        try {
            byte[] authenticatorKeyAgreementX962Key = CosePublicKeyUtils.encodeCosePublicKeyAsX962(cosePublicKey);
            return P256.deserializePublicKey(authenticatorKeyAgreementX962Key);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Missing ECDH algorithm in crypto provider! This is a build system bug, perhaps proguard stripped the crypto provider.", e);
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed decoding authenticator public key", e);
        }
    }

    public byte[] generateSharedSecret(
            PrivateKey platformPrivateKey,
            PublicKey authenticatorPublicKey
    ) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(platformPrivateKey);
            ka.doPhase(authenticatorPublicKey, true);

            return HashUtil.sha256(ka.generateSecret());
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Invalid key used for ECDH. This is a bug, perhaps a PrivateKey or PublicKey from a different provider was used?", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Missing ECDH algorithm in crypto provider! This is a build system bug, perhaps proguard stripped the crypto provider.", e);
        }
    }
}
