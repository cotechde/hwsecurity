/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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

package de.cotech.hw.fido;

import android.util.Base64;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;


@RestrictTo(Scope.LIBRARY_GROUP)
public class WebsafeBase64 {

    /**
     * websafe-base64 encoding
     * This is the "Base 64 Encoding with URL and Filename Safe Alphabet" from Section 5 in [RFC4648] without padding.
     * See Section 7
     * https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#bib-RFC4648
     */
    public static String encodeToString(byte[] decoded) {
        return Base64.encodeToString(decoded, Base64.NO_PADDING | Base64.NO_WRAP | Base64.URL_SAFE);
    }

    public static byte[] decode(String encoded) {
        return Base64.decode(encoded, Base64.NO_PADDING | Base64.NO_WRAP | Base64.URL_SAFE);
    }
}
