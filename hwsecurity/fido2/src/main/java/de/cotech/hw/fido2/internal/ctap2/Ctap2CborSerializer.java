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

package de.cotech.hw.fido2.internal.ctap2;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map.Entry;

import de.cotech.hw.fido2.domain.BooleanExtensionParameterValue;
import de.cotech.hw.fido2.domain.ByteArrayExtensionParameterValue;
import de.cotech.hw.fido2.domain.ExtensionParameter;
import de.cotech.hw.fido2.domain.HmacSecretExtensionParameterValue;
import de.cotech.hw.fido2.internal.cbor_java.CborBuilder;
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder;
import de.cotech.hw.fido2.internal.cbor_java.CborEncoder;
import de.cotech.hw.fido2.internal.cbor_java.CborException;
import de.cotech.hw.fido2.internal.cbor_java.builder.ArrayBuilder;
import de.cotech.hw.fido2.internal.cbor_java.builder.MapBuilder;
import de.cotech.hw.fido2.internal.cbor_java.model.DataItem;
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers.CoseAlg;
import de.cotech.hw.fido2.internal.ctap2.commands.clientPin.AuthenticatorClientPin;
import de.cotech.hw.fido2.internal.ctap2.commands.getAssertion.AuthenticatorGetAssertion;
import de.cotech.hw.fido2.internal.ctap2.commands.getInfo.AuthenticatorGetInfo;
import de.cotech.hw.fido2.internal.ctap2.commands.makeCredential.AuthenticatorMakeCredential;
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.domain.AuthenticatorTransport;
import de.cotech.hw.fido2.domain.PublicKeyCredentialParameters;
import de.cotech.hw.fido2.domain.PublicKeyCredentialType;
import de.cotech.hw.fido2.domain.PublicKeyCredentialEntity;
import de.cotech.hw.fido2.domain.PublicKeyCredentialRpEntity;
import de.cotech.hw.fido2.domain.PublicKeyCredentialUserEntity;
import de.cotech.hw.fido2.internal.ctap2.commands.makeCredential.AuthenticatorMakeCredential.AuthenticatorMakeCredentialOptions;
import de.cotech.hw.fido2.internal.ctap2.commands.rawCommand.RawCtap2Command;
import de.cotech.hw.fido2.internal.pinauth.PinToken;
import de.cotech.hw.util.Arrays;


class Ctap2CborSerializer {

    byte[] toCborBytes(Ctap2Command command) {
        if (command instanceof RawCtap2Command) {
            return ((RawCtap2Command) command).data();
        }

        CborBuilder cborBuilder = new CborBuilder();
        writeToBuilder(cborBuilder, command);
        List<DataItem> cborData = cborBuilder.build();
        return writeCborDataToBytes(cborData);
    }

    private byte[] writeCborDataToBytes(List<DataItem> cborData) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            new CborEncoder(outputStream).encode(cborData);
            return outputStream.toByteArray();
        } catch (CborException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void writeToBuilder(CborBuilder cborBuilder, Ctap2Command command) {
        if (command instanceof AuthenticatorMakeCredential) {
            writeToBuilder(cborBuilder, (AuthenticatorMakeCredential) command);
        } else if (command instanceof AuthenticatorGetAssertion) {
            writeToBuilder(cborBuilder, (AuthenticatorGetAssertion) command);
        } else if (command instanceof AuthenticatorGetInfo) {
            // nothing to do, this command doesn't contain any parameters
        } else if (command instanceof AuthenticatorClientPin) {
            writeToBuilder(cborBuilder, (AuthenticatorClientPin) command);
        } else {
            throw new UnsupportedOperationException();
        }
    }

    private void writeToBuilder(CborBuilder cborBuilder2, AuthenticatorMakeCredential amc) {
        MapBuilder<?> cborBuilder = cborBuilder2.addMap();

        // clientDataHash 	0x01 	byte string (CBOR major type 2).
        cborBuilder.put(0x01, amc.clientDataHash());

        // rp 	0x02 	CBOR definite length map (CBOR major type 5).
        MapBuilder<?> rpMapBuilder = cborBuilder.putMap(0x02);
        writeToMap(rpMapBuilder, amc.rp());

        // user 	0x03 	CBOR definite length map (CBOR major type 5).
        MapBuilder<?> userMapBuilder = cborBuilder.putMap(0x03);
        writeToMap(userMapBuilder, amc.user());

        // pubKeyCredParams 	0x04 	CBOR definite length array (CBOR major type 4) of CBOR definite length maps (CBOR major type 5).
        ArrayBuilder<?> pubCredBuilder = cborBuilder.putArray(0x04);
        for (PublicKeyCredentialParameters params : amc.pubKeyCredParams()) {
            MapBuilder<?> pubCredMapBuidler = pubCredBuilder.addMap();
            writeToMap(pubCredMapBuidler, params);
        }

        // optional parameters

        // excludeList 	0x05 	CBOR definite length array (CBOR major type 4) of CBOR definite length maps (CBOR major type 5).
        List<PublicKeyCredentialDescriptor> excludeList = amc.excludeList();
        if (excludeList != null) {
            ArrayBuilder<?> arrayBuilder = cborBuilder.putArray(0x05);
            for (PublicKeyCredentialDescriptor descriptor : excludeList) {
                MapBuilder<?> mapBuilder = arrayBuilder.addMap();
                writeToMap(mapBuilder, descriptor);
                mapBuilder.end();
            }
            arrayBuilder.end();
        }
        // extensions 	0x06 	CBOR definite length map (CBOR major type 5).
        List<ExtensionParameter> extensionParameters = amc.extensions();
        if (extensionParameters != null) {
            MapBuilder<?> mapBuilder = cborBuilder.putMap(0x06);
            for (ExtensionParameter param : extensionParameters) {
                writeToMap(mapBuilder, param);
            }
        }

        // options 	0x07 	CBOR definite length map (CBOR major type 5).
        AuthenticatorMakeCredentialOptions options = amc.options();
        if (options != null) {
            MapBuilder<?> mapBuilder = cborBuilder.putMap(0x07);
            Boolean rk = options.rk();
            if (rk != null) {
                mapBuilder.put("rk", rk);
            }
            mapBuilder.end();
            /* not supported yet
            Boolean uv = options.uv();
            if (uv != null) {
                mapBuilder.put("uv", rk);
            }
            */
        }

        // pinAuth 	0x08 	byte string (CBOR major type 2).
        if (amc.pinAuth() != null) {
            cborBuilder.put(0x08, amc.pinAuth());
        }

        // pinProtocol 	0x09 	PIN protocol version chosen by the client. For this version of the spec, this SHALL be the number 1.
        Integer pinProtocol = amc.pinProtocol();
        if (pinProtocol != null) {
            cborBuilder.put(0x09, pinProtocol);
        }
    }

    private void writeToBuilder(CborBuilder cborBuilder2, AuthenticatorGetAssertion aga) {
        MapBuilder<?> cborBuilder = cborBuilder2.addMap();

        // rpId 	0x01 	UTF-8 encoded text string (CBOR major type 3).
        cborBuilder.put(0x01, aga.rpId());
        // clientDataHash 	0x02 	byte string (CBOR major type 2).
        cborBuilder.put(0x02, aga.clientDataHash());

        // optional parameters

        // allowList 	0x03 	CBOR definite length array (CBOR major type 4) of CBOR definite length maps (CBOR major type 5).
        List<PublicKeyCredentialDescriptor> publicKeyCredentialDescriptors = aga.allowList();
        if (publicKeyCredentialDescriptors != null && !publicKeyCredentialDescriptors.isEmpty()) {
            ArrayBuilder<?> pubCredBuilder = cborBuilder.putArray(0x03);
            for (PublicKeyCredentialDescriptor params : publicKeyCredentialDescriptors) {
                MapBuilder<?> pubCredMapBuidler = pubCredBuilder.addMap();
                writeToMap(pubCredMapBuidler, params);
            }
        }
        // extensions 	0x04 	CBOR definite length map (CBOR major type 5).
        List<ExtensionParameter> extensionParameters = aga.extensions();
        if (extensionParameters != null) {
            MapBuilder<?> mapBuilder = cborBuilder.putMap(0x04);
            for (ExtensionParameter param : extensionParameters) {
                writeToMap(mapBuilder, param, aga);
            }
        }
        // options 	0x05 	CBOR definite length map (CBOR major type 5).

        // pinAuth 	0x06 	byte string (CBOR major type 2).
        if (aga.pinAuth() != null) {
            cborBuilder.put(0x06, aga.pinAuth());
        }

        // pinProtocol 	0x07 	PIN protocol version chosen by the client. For this version of the spec, this SHALL be the number 1.
        Integer pinProtocol = aga.pinProtocol();
        if (pinProtocol != null) {
            cborBuilder.put(0x07, pinProtocol);
        }
    }

    private void writeToBuilder(CborBuilder cborBuilder2, AuthenticatorClientPin acp) {
        MapBuilder<?> cborBuilder = cborBuilder2.addMap();

        // pinProtocol (0x01) 	Unsigned Integer 	Required 	PIN protocol version chosen by the client. For this version of the spec, this SHALL be the number 1.
        cborBuilder.put(0x01, acp.pinProtocol());
        // subCommand (0x02) 	Unsigned Integer 	Required 	The authenticator Client PIN sub command currently being requested
        cborBuilder.put(0x02, acp.subCommand());

        // optional parameters

        // keyAgreement (0x03) 	COSE_Key 	Optional 	Public key of platformKeyAgreementKey. The COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
        if (acp.keyAgreement() != null) {
            try {
                cborBuilder.put(Ctap2CborConstants.CBOR_THREE, new CborDecoder(new ByteArrayInputStream(acp.keyAgreement())).decodeNext());
            } catch (CborException e) {
                throw new IllegalArgumentException(e);
            }
        }

        // pinAuth (0x04) 	Byte Array 	Optional 	First 16 bytes of HMAC-SHA-256 of encrypted contents using sharedSecret. See Setting a new PIN, Changing existing PIN and Getting pinToken from the authenticator for more details.
        if (acp.pinAuth() != null) {
            cborBuilder.put(0x04, acp.pinAuth());
        }

        // newPinEnc (0x05) 	Byte Array 	Optional 	Encrypted new PIN using sharedSecret. Encryption is done over UTF-8 representation of new PIN.
        if (acp.newPinEnc() != null) {
            cborBuilder.put(0x05, acp.newPinEnc());
        }

        // pinHashEnc (0x06) 	Byte Array 	Optional 	Encrypted first 16 bytes of SHA-256 of PIN using sharedSecret.
        if (acp.pinHashEnc() != null) {
            cborBuilder.put(0x06, acp.pinHashEnc());
        }
    }

    private void writeToMap(MapBuilder<?> mapBuilder, PublicKeyCredentialRpEntity rpEntity) {
        writeToMap(mapBuilder, (PublicKeyCredentialEntity) rpEntity);
        if (rpEntity.id() != null) {
            mapBuilder.put("id", rpEntity.id());
        }
    }

    private void writeToMap(MapBuilder<?> mapBuilder, PublicKeyCredentialUserEntity userEntity) {
        writeToMap(mapBuilder, (PublicKeyCredentialEntity) userEntity);
        mapBuilder.put("id", userEntity.id());
        if (userEntity.displayName() != null) {
            mapBuilder.put("displayName", userEntity.displayName());
        }
    }

    private void writeToMap(MapBuilder<?> mapBuilder, PublicKeyCredentialParameters publicKeyCredentialParameters) {
        for (Entry<PublicKeyCredentialType, CoseAlg> entry : publicKeyCredentialParameters.parameters().entrySet()) {
            mapBuilder.put("type", entry.getKey().type);
            mapBuilder.put("alg", entry.getValue().label);
        }
    }

    private void writeToMap(MapBuilder<?> mapBuilder, PublicKeyCredentialEntity credentialEntity) {
        mapBuilder.put("name", credentialEntity.name());
        if (credentialEntity.icon() != null) {
            mapBuilder.put("icon", credentialEntity.icon());
        }
    }

    private void writeToMap(MapBuilder<?> mapBuilder, PublicKeyCredentialDescriptor descriptor) {
        mapBuilder.put("type", descriptor.type().type);
        mapBuilder.put("id", descriptor.id());
        List<AuthenticatorTransport> transports = descriptor.transports();
        if (transports != null) {
            ArrayBuilder<?> arrayBuilder = mapBuilder.putArray("transports");
            for (AuthenticatorTransport transport : transports) {
                arrayBuilder.add(transport.transport);
            }
        }
    }

    private void writeToMap(MapBuilder<?> mapBuilder, ExtensionParameter extensionParameters) {
        Object value = extensionParameters.value();
        if (value instanceof BooleanExtensionParameterValue) {
            mapBuilder.put(extensionParameters.key(), ((BooleanExtensionParameterValue) value).value());
        } else if (value instanceof ByteArrayExtensionParameterValue) {
            mapBuilder.put(extensionParameters.key(), ((ByteArrayExtensionParameterValue) value).value());
        } else {
            throw new UnsupportedOperationException();
        }
    }

    private void writeToMap(MapBuilder<?> mapBuilder, ExtensionParameter extensionParameters, AuthenticatorGetAssertion aga) {
        // Handle parameters which require assertion-specific data here
        Object value = extensionParameters.value();
        if (value instanceof HmacSecretExtensionParameterValue) {
            HmacSecretExtensionParameterValue param = (HmacSecretExtensionParameterValue) value;
            MapBuilder<?> hmacParamsMap = mapBuilder.putMap(extensionParameters.key());

            PinToken pinToken = aga.pinToken();
            if (pinToken == null) {
                throw new UnsupportedOperationException("An HMAC secret cannot be requested without PIN auth");
            }

            byte[] salts;
            if (param.salt2() == null) {
                salts = param.salt1();
            } else {
                salts = Arrays.concatenate(param.salt1(), param.salt2());
            }

            byte[] saltEnc = pinToken.encrypt(salts);

            try {
                hmacParamsMap.put(Ctap2CborConstants.CBOR_ONE, new CborDecoder(new ByteArrayInputStream(pinToken.platformKeyAgreementKey())).decodeNext());
            } catch (CborException e) {
                throw new IllegalArgumentException(e);
            } // keyAgreement
            hmacParamsMap.put(0x02, saltEnc); // saltEnc
            hmacParamsMap.put(0x03, pinToken.authenticate(saltEnc)); // saltAuth
            if (pinToken.pinProtocol().version() != 1) { // pinUvAuthProtocol
                hmacParamsMap.put(0x04, pinToken.pinProtocol().version());
            }

            return;
        }

        writeToMap(mapBuilder, extensionParameters);
    }
}
