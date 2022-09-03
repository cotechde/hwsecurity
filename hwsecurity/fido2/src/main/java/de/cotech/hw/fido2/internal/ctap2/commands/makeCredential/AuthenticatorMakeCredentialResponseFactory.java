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

package de.cotech.hw.fido2.internal.ctap2.commands.makeCredential;


import java.io.IOException;
import java.util.List;

import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString;
import de.cotech.hw.fido2.internal.cbor.CborUtils;
import de.cotech.hw.fido2.internal.ctap2.Ctap2CborConstants;
import de.cotech.hw.fido2.internal.ctap2.Ctap2ResponseFactory;


public class AuthenticatorMakeCredentialResponseFactory implements
        Ctap2ResponseFactory<AuthenticatorMakeCredentialResponse> {
    private final AuthenticatorMakeCredential authenticatorMakeCredential;

    AuthenticatorMakeCredentialResponseFactory(AuthenticatorMakeCredential authenticatorMakeCredential) {
        this.authenticatorMakeCredential = authenticatorMakeCredential;
    }

    @Override
    public AuthenticatorMakeCredentialResponse createResponse(byte[] rawResponseData)
            throws IOException {
        try {
            List<DataItem> dataItems = CborDecoder.decode(rawResponseData);
            Map map = (Map) dataItems.get(0);

            UnicodeString fmt = (UnicodeString) map.get(Ctap2CborConstants.CBOR_ONE);
            ByteString authData = (ByteString) map.get(Ctap2CborConstants.CBOR_TWO);
            DataItem attStmt = map.get(Ctap2CborConstants.CBOR_THREE);

            return AuthenticatorMakeCredentialResponse.create(
                    fmt.getString(),
                    authData.getBytes(),
                    CborUtils.writeCborDataToBytes(attStmt),
                    authenticatorMakeCredential.clientDataJson().getBytes()
            );
        } catch (CborException e) {
            throw new IOException(e);
        }
    }

}
