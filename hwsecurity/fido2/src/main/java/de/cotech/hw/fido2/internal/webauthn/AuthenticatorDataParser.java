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

package de.cotech.hw.fido2.internal.webauthn;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import de.cotech.hw.fido2.domain.create.AuthenticatorData;
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.domain.create.AttestedCredentialData;
import de.cotech.hw.fido2.internal.cbor.CborUtils;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;


public class AuthenticatorDataParser {
    private static final int LENGTH_RPIDHASH = 32;
    private static final int TOTAL_LENGTH_HEADER = LENGTH_RPIDHASH + 1 + 4;

    private static final int LENGTH_AAGUID = 16;

    public AuthenticatorData fromBytes(byte[] bytes) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(bytes).duplicate();
        buf.order(ByteOrder.BIG_ENDIAN);

        byte[] rpIdHash = new byte[LENGTH_RPIDHASH];
        buf.get(rpIdHash);
        byte flags = buf.get();
        int sigCounter = buf.getInt();

        AttestedCredentialData attestedCredentialData = null;
        Map extensionData = null;

        boolean hasAttestedCredentialData = (flags & AuthenticatorData.FLAG_ATTESTED_CREDENTIAL_DATA) != 0;
        if (hasAttestedCredentialData) {
            attestedCredentialData = parseAttestedCredentialData(buf);
        }

        boolean hasExtensionData = (flags & AuthenticatorData.FLAG_EXTENSION_DATA) != 0;
        if (hasExtensionData) {
            extensionData = parseExtensionData(buf);
        }

        return AuthenticatorData.create(
                rpIdHash, flags, sigCounter, attestedCredentialData, extensionData);
    }

    public byte[] toBytes(AuthenticatorData authenticatorData) {
        byte[] attestedCredentialData = serializeAttestedCredentialData(authenticatorData.attestedCredentialData());

        byte[] extensionData = null;

        if (authenticatorData.hasExtensionData()) {
            try {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                new CborEncoder(outputStream).encode(authenticatorData.extensions());
                extensionData = outputStream.toByteArray();
            } catch (CborException e) {
                // Failing to re-CBOR-encode a CBOR DataItem?
                throw new IllegalStateException(e);
            }
        }

        int extensionDataLength = extensionData != null ? extensionData.length : 0;

        ByteBuffer result = ByteBuffer.allocate(
                TOTAL_LENGTH_HEADER + attestedCredentialData.length + extensionDataLength);
        result.order(ByteOrder.BIG_ENDIAN);

        result.put(authenticatorData.rpIdHash());
        result.put(authenticatorData.flags());
        result.putInt(authenticatorData.sigCounter());
        result.put(attestedCredentialData);
        if (extensionData != null) {
            result.put(extensionData);
        }

        return result.array();
    }

    private byte[] serializeAttestedCredentialData(AttestedCredentialData attestedCredentialData) {
        if (attestedCredentialData == null) {
            return new byte[0];
        }
        short credentialIdLength = (short) attestedCredentialData.credentialId().length;
        int credentialPublicKeyLength = attestedCredentialData.credentialPublicKey().length;
        ByteBuffer result = ByteBuffer.allocate(LENGTH_AAGUID + 2 + credentialIdLength + credentialPublicKeyLength);

        result.put(attestedCredentialData.aaguid());
        result.putShort(credentialIdLength);
        result.put(attestedCredentialData.credentialId());
        result.put(attestedCredentialData.credentialPublicKey());

        return result.array();
    }

    private static Map parseExtensionData(ByteBuffer buf) throws IOException {
        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(
                    buf.array(), buf.arrayOffset() + buf.position(), buf.remaining());
            DataItem dataItem = new CborDecoder(inputStream).decodeNext();
            if (dataItem.getMajorType() != MajorType.MAP) {
                throw new IOException("Extension data not a CBOR map!");
            }
            return (Map) dataItem;
        } catch (CborException e) {
            throw new IOException("Error reading CBOR-encoded credential data!", e);
        }
    }

    private static AttestedCredentialData parseAttestedCredentialData(ByteBuffer buf) throws IOException {
        byte[] aaguid = new byte[LENGTH_AAGUID];
        buf.get(aaguid);
        int credentialIdLength = buf.getShort() & 0xFFFF;
        byte[] credentialId = new byte[credentialIdLength];
        buf.get(credentialId);

        try {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(
                    buf.array(), buf.arrayOffset() + buf.position(), buf.remaining());
            DataItem dataItem = new CborDecoder(inputStream).decodeNext();
            byte[] credentialPublicKey = CborUtils.writeCborDataToBytes(dataItem);
            buf.position(buf.position() + credentialPublicKey.length);
            return AttestedCredentialData.create(aaguid, credentialId, credentialPublicKey);
        } catch (CborException e) {
            throw new IOException("Error reading CBOR-encoded credential data!", e);
        }
    }
}
