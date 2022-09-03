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

package de.cotech.hw.fido2.internal.ctap2.commands.getAssertion;


import java.io.IOException;
import java.util.List;

import de.cotech.hw.fido2.domain.create.AuthenticatorData;
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.MajorType;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;
import de.cotech.hw.fido2.internal.cbor_java.model.UnsignedInteger;
import de.cotech.hw.fido2.domain.PublicKeyCredentialUserEntity;
import de.cotech.hw.fido2.internal.cbor.CborUtils;
import de.cotech.hw.fido2.internal.ctap2.Ctap2CborConstants;
import de.cotech.hw.fido2.internal.ctap2.Ctap2ResponseFactory;
import de.cotech.hw.fido2.internal.webauthn.AuthenticatorDataParser;


public class AuthenticatorGetAssertionResponseFactory implements
        Ctap2ResponseFactory<AuthenticatorGetAssertionResponse> {
    private final AuthenticatorGetAssertion authenticatorGetAssertion;
    private static final AuthenticatorDataParser authenticatorDataParser = new AuthenticatorDataParser();
    private static final UnicodeString HMAC_SECRET_EXTENSION_ID = new UnicodeString("hmac-secret");

    AuthenticatorGetAssertionResponseFactory(AuthenticatorGetAssertion authenticatorGetAssertion) {
        this.authenticatorGetAssertion = authenticatorGetAssertion;
    }

    @Override
    public AuthenticatorGetAssertionResponse createResponse(byte[] rawResponseData)
            throws IOException {
        try {
            List<DataItem> dataItems = CborDecoder.decode(rawResponseData);
            DataItem dataItem = dataItems.get(0);
            return readAuthenticatorGetAssertionResponse(dataItem);
        } catch (CborException | ClassCastException e) {
            throw new IOException("Received incorrectly formatted AuthenticatorGetAssertionResponse", e);
        }
    }

    private AuthenticatorGetAssertionResponse readAuthenticatorGetAssertionResponse(DataItem dataItem)
            throws CborException, IOException {
        Map responseMap = (Map) dataItem;

        DataItem credential = responseMap.get(Ctap2CborConstants.CBOR_ONE);
        ByteString authData = (ByteString) responseMap.get(Ctap2CborConstants.CBOR_TWO);
        ByteString signature = (ByteString) responseMap.get(Ctap2CborConstants.CBOR_THREE);
        DataItem user = responseMap.get(Ctap2CborConstants.CBOR_FOUR);
        UnsignedInteger numberOfCredentials =
                (UnsignedInteger) responseMap.get(Ctap2CborConstants.CBOR_FIVE);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity =
                readPublicKeyCredentialUserEntity(user);

        byte[] decryptedHmacSecretValue = null;
        AuthenticatorData decodedAuthData = authenticatorDataParser.fromBytes(authData.getBytes());
        if (decodedAuthData.hasExtensionData()) {
            DataItem hmacSecretValue = decodedAuthData.extensions().get(HMAC_SECRET_EXTENSION_ID);
            if (hmacSecretValue != null) {
                if (hmacSecretValue.getMajorType() != MajorType.BYTE_STRING) {
                    throw new IOException("hmac-secret response is not a byte string");
                }
                byte[] hmacSecretBytes = ((ByteString) hmacSecretValue).getBytes();
                decryptedHmacSecretValue = authenticatorGetAssertion.pinToken().decrypt(hmacSecretBytes);
            }
        }

        return AuthenticatorGetAssertionResponse.create(
                credential != null ? CborUtils.writeCborDataToBytes(credential) : null,
                authData.getBytes(),
                signature.getBytes(),
                publicKeyCredentialUserEntity,
                numberOfCredentials != null ? numberOfCredentials.getValue().intValue() : null,
                authenticatorGetAssertion.clientDataJson().getBytes(),
                decryptedHmacSecretValue
        );
    }

    private PublicKeyCredentialUserEntity readPublicKeyCredentialUserEntity(DataItem dataItem)
            throws IOException {
        if (dataItem == null) {
            return null;
        }
        if (dataItem.getMajorType() != MajorType.MAP) {
            throw new IOException("Expected user field to be of type Map, found " +
                    dataItem.getMajorType());
        }

        Map userMap = ((Map) dataItem);
        ByteString id = (ByteString) userMap.get(Ctap2CborConstants.CBOR_ID);
        UnicodeString name = (UnicodeString) userMap.get(Ctap2CborConstants.CBOR_NAME);
        UnicodeString displayName =  (UnicodeString) userMap.get(Ctap2CborConstants.CBOR_DISPLAYNAME);
        UnicodeString icon = (UnicodeString) userMap.get(Ctap2CborConstants.CBOR_ICON);

        return PublicKeyCredentialUserEntity.create(
                id.getBytes(),
                name != null ? name.getString() : null,
                displayName != null ? displayName.getString() : null,
                icon != null ? icon.getString() : null
        );
    }
}
