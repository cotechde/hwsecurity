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

package de.cotech.hw.openpgp.internal.openpgp;


import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import de.cotech.hw.internal.iso7816.Iso7816TLV;
import de.cotech.hw.util.HwTimber;


@RestrictTo(Scope.LIBRARY_GROUP)
class RsaKeyFormatParser implements KeyFormatParser {

    private static final int DO_RSA_MODULUS_TAG = 0x81;
    private static final int DO_RSA_EXPONENT_TAG = 0x82;

    @Override
    public RSAPublicKey parseKey(byte[] publicKeyBytes) throws IOException {
        Iso7816TLV publicKeyTlv = Iso7816TLV.readSingle(publicKeyBytes, true);
        Iso7816TLV rsaModulusMpiTlv = Iso7816TLV.findRecursive(publicKeyTlv, DO_RSA_MODULUS_TAG);
        Iso7816TLV rsaPublicExponentMpiTlv = Iso7816TLV.findRecursive(publicKeyTlv, DO_RSA_EXPONENT_TAG);

        if (rsaModulusMpiTlv == null || rsaPublicExponentMpiTlv == null) {
            throw new IOException("Missing required data for RSA public key (tags 0x81 and 0x82)");
        }

        try {
            BigInteger rsaModulus = new BigInteger(1, rsaModulusMpiTlv.mV);
            BigInteger rsaPublicExponent = new BigInteger(1, rsaPublicExponentMpiTlv.mV);
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(rsaModulus, rsaPublicExponent);
            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);

            HwTimber.d("key parsed as RSAPublicKey");
            return publicKey;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }
}
