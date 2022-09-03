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

package de.cotech.hw.fido2.domain.create;


import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.internal.cbor_java.model.Map;


@AutoValue
public abstract class AuthenticatorData {
    // Bit 0: User Present (UP) result.
    //      1 means the user is present.
    //      0 means the user is not present.
    public static final byte FLAG_USER_PRESENT = 1;
    // Bit 1: Reserved for future use (RFU1).
    private static final byte FLAG_RFU_1 = 1<<1;
    // Bit 2: User Verified (UV) result.
    //      1 means the user is verified.
    //      0 means the user is not verified.
    private static final byte FLAG_USER_VERIFIED = 1<<2;
    // Bits 3-5: Reserved for future use (RFU2).
    private static final byte FLAG_RFU_2 = 1<<3;
    private static final byte FLAG_RFU_3 = 1<<4;
    private static final byte FLAG_RFU_4 = 1<<5;
    // Bit 6: Attested credential data included (AT).
    //      Indicates whether the authenticator added attested credential data.
    public static final byte FLAG_ATTESTED_CREDENTIAL_DATA = 1<<6;
    // Bit 7: Extension data included (ED).
    //      Indicates if the authenticator data has extensions.
    public static final byte FLAG_EXTENSION_DATA = (byte) (1<<7);

    // rpIdHash 	32 	SHA-256 hash of the RP ID the credential is scoped to.
    @SuppressWarnings("mutable")
    public abstract byte[] rpIdHash();

    // flags 	1 	Flags (bit 0 is the least significant bit):
    public abstract byte flags();

    // signCount 	4 	Signature counter, 32-bit unsigned big-endian integer.
    public abstract int sigCounter();

    // attestedCredentialData 	variable (if present) 	attested credential data (if present). See §6.4.1 Attested Credential Data for details. Its length depends on the length of the credential ID and credential public key being attested.
    @Nullable
    public abstract AttestedCredentialData attestedCredentialData();

    // extensions 	variable (if present) 	Extension-defined authenticator data. This is a CBOR [RFC7049] map with extension identifiers as keys, and authenticator extension outputs as values. See §9 WebAuthn Extensions for details.
    @Nullable
    @SuppressWarnings("mutable")
    public abstract Map extensions();

    public boolean hasAttestedCredentialData() {
        return (flags() & FLAG_ATTESTED_CREDENTIAL_DATA) != 0;
    }

    public boolean hasExtensionData() {
        return (flags() & FLAG_EXTENSION_DATA) != 0;
    }

    public static AuthenticatorData create(byte[] rpIdHash, byte flags, int sigCounter,
                                           AttestedCredentialData credentialData, Map extensions) {
        return new AutoValue_AuthenticatorData(rpIdHash, flags, sigCounter, credentialData, extensions);
    }

    public AuthenticatorData withEmptyAaguid() {
        AttestedCredentialData attestedCredentialData = attestedCredentialData();
        if (attestedCredentialData != null) {
            attestedCredentialData = attestedCredentialData.withEmptyAaguid();
        }
        return new AutoValue_AuthenticatorData(rpIdHash(), flags(), sigCounter(), attestedCredentialData, extensions());
    }
}
