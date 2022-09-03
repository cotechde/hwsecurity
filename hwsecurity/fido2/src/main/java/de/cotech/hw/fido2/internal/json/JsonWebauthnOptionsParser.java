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

package de.cotech.hw.fido2.internal.json;


import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import de.cotech.hw.fido2.domain.AuthenticatorTransport;
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.domain.PublicKeyCredentialParameters;
import de.cotech.hw.fido2.domain.PublicKeyCredentialRpEntity;
import de.cotech.hw.fido2.domain.PublicKeyCredentialType;
import de.cotech.hw.fido2.domain.PublicKeyCredentialUserEntity;
import de.cotech.hw.fido2.domain.UserVerificationRequirement;
import de.cotech.hw.fido2.domain.create.AttestationConveyancePreference;
import de.cotech.hw.fido2.domain.create.AuthenticatorAttachment;
import de.cotech.hw.fido2.domain.create.AuthenticatorSelectionCriteria;
import de.cotech.hw.fido2.domain.create.PublicKeyCredentialCreationOptions;
import de.cotech.hw.fido2.domain.get.PublicKeyCredentialRequestOptions;
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers.CoseAlg;
import de.cotech.hw.util.HwTimber;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;


public class JsonWebauthnOptionsParser {
    public PublicKeyCredentialCreationOptions fromOptionsJsonMakeCredential(String jsonString) throws JSONException {
        JSONObject jsonObject = new JSONObject(jsonString);
        return fromJsonMakeCredential(jsonObject);
    }

    private PublicKeyCredentialCreationOptions fromJsonMakeCredential(JSONObject jsonObject) throws JSONException {
        JSONObject publicKeyObject = jsonObject.getJSONObject("publicKey");

        PublicKeyCredentialRpEntity rp = jsonToRpEntity(publicKeyObject.getJSONObject("rp"));
        PublicKeyCredentialUserEntity user = jsonToUserEntity(publicKeyObject.getJSONObject("user"));
        byte[] challenge = jsonObjectOrArrayToByteArray(publicKeyObject.getJSONObject("challenge"));
        List<PublicKeyCredentialParameters> pubKeyCredParams = jsonToPubKeyCredParamsList(publicKeyObject.optJSONArray("pubKeyCredParams"));
        Long timeout = !publicKeyObject.isNull("timeout") ? publicKeyObject.getLong("timeout") : null;
        AttestationConveyancePreference attestationConveyancePreference =
                AttestationConveyancePreference.fromString(publicKeyObject.optString("attestation", null));
        AuthenticatorSelectionCriteria authenticatorSelection = jsonToAuthenticatorSelectionCriteria(
                publicKeyObject.optJSONObject("authenticatorSelection"));

        return PublicKeyCredentialCreationOptions.create(rp, user, challenge, pubKeyCredParams, timeout,
                authenticatorSelection, null, attestationConveyancePreference, null);
    }

    private List<PublicKeyCredentialParameters> jsonToPubKeyCredParamsList(
            JSONArray pubKeyCredParams) throws JSONException {
        List<PublicKeyCredentialParameters> result = new ArrayList<>();
        if (pubKeyCredParams == null) {
            return result;
        }

        for (int i = 0; i < pubKeyCredParams.length(); i++) {
            JSONObject pubkeyCredParam = pubKeyCredParams.getJSONObject(i);
            PublicKeyCredentialType type = PublicKeyCredentialType.fromString(pubkeyCredParam.getString("type"));
            CoseAlg alg = CoseAlg.fromIdentifier(pubkeyCredParam.getInt("alg"));
            if (alg == null) {
                HwTimber.d("Skipping unknown COSE identifier: %s", pubkeyCredParam.getInt("alg"));
                continue;
            }
            PublicKeyCredentialParameters parameters =
                    PublicKeyCredentialParameters.createSingle(type, alg);
            result.add(parameters);
        }
        return result;
    }

    private List<PublicKeyCredentialDescriptor> jsonToPubKeyKeyCredDescriptorList(JSONArray allowCredentials)
            throws JSONException {
        List<PublicKeyCredentialDescriptor> result = new ArrayList<>();
        if (allowCredentials == null) {
            return null;
        }

        for (int i = 0; i < allowCredentials.length(); i++) {
            JSONObject pubkeyCredParam = allowCredentials.getJSONObject(i);
            PublicKeyCredentialType type = PublicKeyCredentialType.fromString(pubkeyCredParam.getString("type"));
            byte[] id = jsonObjectOrArrayToByteArray(pubkeyCredParam.get("id"));
            List<AuthenticatorTransport> transports = jsonToAuthenticatorTransports(pubkeyCredParam.optJSONArray("transports"));
            PublicKeyCredentialDescriptor parameters =
                    PublicKeyCredentialDescriptor.create(type, id, transports);
            result.add(parameters);
        }
        return result;
    }

    private List<AuthenticatorTransport> jsonToAuthenticatorTransports(JSONArray transports) {
        if (transports == null) {
            return null;
        }
        try {
            return jsonToAuthenticatorTransportsOrThrow(transports);
        } catch(JSONException e){
            return null;
        }
    }

    private List<AuthenticatorTransport> jsonToAuthenticatorTransportsOrThrow(JSONArray transports)
            throws JSONException {
        List<AuthenticatorTransport> result = new ArrayList<>();
        for (int i = 0; i < transports.length(); i++) {
            String transportName = transports.getString(i);
            AuthenticatorTransport transport = AuthenticatorTransport.fromString(transportName);
            if (transport != null) {
                result.add(transport);
            } else {
                HwTimber.e("Ignoring unknown transport value: %s", transportName);
            }
        }
        return result;
    }

    private AuthenticatorSelectionCriteria jsonToAuthenticatorSelectionCriteria(
            JSONObject authenticatorSelection) {
        if (authenticatorSelection == null) {
            return null;
        }
        AuthenticatorAttachment authenticatorAttachment = AuthenticatorAttachment.fromString(
                authenticatorSelection.optString("authenticatorAttachment", null));
        boolean requireResidentKey = authenticatorSelection.optBoolean("requireResidentKey", false);
        UserVerificationRequirement userVerification = UserVerificationRequirement.fromString(
                authenticatorSelection.optString("userVerification", null));

        return AuthenticatorSelectionCriteria.create(authenticatorAttachment, requireResidentKey, userVerification);
    }

    private PublicKeyCredentialUserEntity jsonToUserEntity(JSONObject jsonObject) throws JSONException {
        byte[] id = jsonObjectOrArrayToByteArray(jsonObject.get("id"));
        String name = jsonObject.optString("name", null);
        String displayName = jsonObject.optString("displayName", null);
        String icon = jsonObject.optString("icon", null);

        return PublicKeyCredentialUserEntity.create(id, name, displayName, icon);
    }

    private PublicKeyCredentialRpEntity jsonToRpEntity(JSONObject jsonObject) {
        String id = jsonObject.optString("id", null);
        String name = jsonObject.optString("name", null);
        String icon = jsonObject.optString("icon", null);

        return PublicKeyCredentialRpEntity.create(id, name, icon);
    }

    private byte[] jsonObjectOrArrayToByteArray(Object object) throws JSONException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (object instanceof JSONObject) {
            JSONObject jsonObject = (JSONObject) object;
            for (int i = 0; i < jsonObject.length(); i++) {
                String key = Integer.toString(i);
                if (!jsonObject.has(key)) {
                    throw new JSONException("Missing key '" + key + "' for byte array in JSON object!");
                }
                baos.write(jsonObject.getInt(key));
            }
        } else if (object instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) object;
            for (int i = 0; i < jsonArray.length(); i++) {
                baos.write(jsonArray.getInt(i));
            }
        }
        return baos.toByteArray();
    }

    public PublicKeyCredentialRequestOptions fromOptionsJsonGetAssertion(String jsonString) throws JSONException {
        JSONObject jsonObject = new JSONObject(jsonString);
        return fromOptionsJsonGetAssertion(jsonObject);
    }

    private PublicKeyCredentialRequestOptions fromOptionsJsonGetAssertion(JSONObject jsonObject)
            throws JSONException {
        JSONObject publicKeyObject = jsonObject.getJSONObject("publicKey");

        byte[] challenge = jsonObjectOrArrayToByteArray(publicKeyObject.getJSONObject("challenge"));
        Long timeout = !publicKeyObject.isNull("timeout") ? publicKeyObject.getLong("timeout") : null;
        String rpId = publicKeyObject.optString("rpId", null);
        List<PublicKeyCredentialDescriptor> allowCredentials = jsonToPubKeyKeyCredDescriptorList(publicKeyObject.optJSONArray("allowCredentials"));
        UserVerificationRequirement userVerification = UserVerificationRequirement.fromString(
                publicKeyObject.optString("userVerification", null));

        return PublicKeyCredentialRequestOptions.create(
                challenge,
                timeout,
                rpId,
                allowCredentials,
                userVerification
        );
    }
}
