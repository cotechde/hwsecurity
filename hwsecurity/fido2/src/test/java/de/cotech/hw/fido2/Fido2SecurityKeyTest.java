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

package de.cotech.hw.fido2;


import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;

import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.fido2.domain.AuthenticatorTransport;
import de.cotech.hw.fido2.domain.PublicKeyCredentialDescriptor;
import de.cotech.hw.fido2.domain.PublicKeyCredentialParameters;
import de.cotech.hw.fido2.domain.PublicKeyCredentialRpEntity;
import de.cotech.hw.fido2.domain.PublicKeyCredentialType;
import de.cotech.hw.fido2.domain.PublicKeyCredentialUserEntity;
import de.cotech.hw.fido2.domain.UserVerificationRequirement;
import de.cotech.hw.fido2.domain.create.AttestationConveyancePreference;
import de.cotech.hw.fido2.domain.create.AuthenticatorAttestationResponse;
import de.cotech.hw.fido2.domain.create.AuthenticatorSelectionCriteria;
import de.cotech.hw.fido2.domain.create.PublicKeyCredentialCreationOptions;
import de.cotech.hw.fido2.domain.get.AuthenticatorAssertionResponse;
import de.cotech.hw.fido2.domain.get.PublicKeyCredentialRequestOptions;
import de.cotech.hw.fido2.internal.FakeFido2AppletConnection;
import de.cotech.hw.fido2.internal.async.Fido2AsyncOperationManager;
import de.cotech.hw.fido2.internal.operations.WebauthnSecurityKeyOperationFactory;
import de.cotech.hw.fido2.internal.pinauth.PinAuthCryptoUtil;
import de.cotech.hw.fido2.internal.pinauth.PinProtocolV1;
import de.cotech.hw.fido2.internal.utils.WebsafeBase64;
import de.cotech.hw.util.Hex;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@SuppressWarnings("WeakerAccess")
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 24)
public class Fido2SecurityKeyTest {
    static final String ORIGIN = "https://webauthn.hwsecurity.dev";

    static final String MAKE_ATTESTATION_REQUEST = "80100000e201a4015820c11f694f75b520b404ae975766483d52eb6e34e7628e6ee28aba967dba520c0502a262696477776562617574686e2e687773656375726974792e646576646e616d656441636d6503a462696450313039383233373233353430393837326469636f6e782868747470733a2f2f706963732e61636d652e636f6d2f30302f702f61426a6a6a707150622e706e67646e616d6578186a6f686e2e702e736d697468406578616d706c652e636f6d6b646973706c61794e616d656d4a6f686e20502e20536d6974680481a263616c672664747970656a7075626c69632d6b6579";
    static final String MAKE_ATTESTATION_RESPONSE = "00a301667061636b65640258c4964491febf301ee4bcb88cb5dc1fa95df27f1643a0c7cef9f71ceef6689e067a41000000026d44ba9bf6ec2e49b9300c8fe920cb730040eb6e2f838e654e6666e8f6f63cc076b3b73eb80b5ccc461c2258f95335447c82f72d1b0bc171d907877a79b07886ea567a7910edfd346d0f4b2200641e425dbea5010203262001215820dbe952bfc071b1115266146a0a212177d0ba205871e5c4e88f3c70ceeafe0e2e2258201fc5f020e608ca048569682b2afad4b444a4a51bc0e97ec7736f81fb3cf9a00703a363616c67266373696758473045022100d262feb0b6576857fe7b78e7144b0ffb287dbe4dbd797f7250a550f063b2917d02206b11aeef426fc94f2a0eea7d8c3736da65bd6f45a1f7a21d3d1bca49331bc14363783563815902c1308202bd308201a5a00302010202042ae76263300d06092a864886f70d01010b0500302e312c302a0603550403132359756269636f2055324620526f6f742043412053657269616c203435373230303633313020170d3134303830313030303030305a180f32303530303930343030303030305a306e310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3127302506035504030c1e59756269636f205532462045452053657269616c203731393830373037353059301306072a8648ce3d020106082a8648ce3d030107034200042a03865e6043d99e11ff10aa25545784bf09af8e6b1e3b321729216f55121a8cd910d399ddc768bdfe4a7bc7e3dabc62e6d2469ff5675b8ffa890cca74869e3fa36c306a302206092b0601040182c40a020415312e332e362e312e342e312e34313438322e312e313013060b2b0601040182e51c0201010404030204303021060b2b0601040182e51c010104041204106d44ba9bf6ec2e49b9300c8fe920cb73300c0603551d130101ff04023000300d06092a864886f70d01010b050003820101007257d03cdcc3e115698490d6f80ef95b53072373d9e64732632b11dcdc778aec6bd5926d07e17b9c5430788de32f4e47b45876ff8c5522029be9387879572331e7277016828a711b39c74fd6c1258bd1e4d9e566d570790347da5235c03f0ffe40b1428e05c6e91799e47554716901eeb88bb057893588ad88aad30d714f2f2fac36d54dbad7109c5b027ab0cab8cf354ef1008a09086ca08696af0cfcdbc18398fcdf02316c2622c95ee622bdd1c00a4789e4a1ccb749a354ba5f27604230beffae06e6bf02fbc015bcd151df35d70a98a8e42dca4488fcf071042188dfea1d5f74b7ea788b2af9c514a9bab94fe7389cda195190b2b1307dbf9118e1a929f89000";

    static final String GET_ATTESTATION_REQUEST = "80100000ae02a30177776562617574686e2e687773656375726974792e646576025820577e406c1b2b403d4d564151de3eb21acd54e78ac9c11aef53f1a950f90f3b700381a36269645840eb6e2f838e654e6666e8f6f63cc076b3b73eb80b5ccc461c2258f95335447c82f72d1b0bc171d907877a79b07886ea567a7910edfd346d0f4b2200641e425dbe64747970656a7075626c69632d6b65796a7472616e73706f7274738363757362636e666363626c65";
    static final String GET_ATTESTATION_RESPONSE = "00a301a26269645840eb6e2f838e654e6666e8f6f63cc076b3b73eb80b5ccc461c2258f95335447c82f72d1b0bc171d907877a79b07886ea567a7910edfd346d0f4b2200641e425dbe64747970656a7075626c69632d6b6579025825964491febf301ee4bcb88cb5dc1fa95df27f1643a0c7cef9f71ceef6689e067a01000000030358473045022074b37f0ebd2934c74106032f2e15e322cb505b52f624c6e635bc07e5c70528980221009db77c087db7882a9b0343dd0ea3acc9efa08367031ff38a34103f8da870574e9000";

    static final String GET_ATTESTATION_USERNAMELESS_REQUEST = "8010000000003b02a201747777772e70617373776f72646c6573732e6465760258202365959d0ee11f2435d495bb1ae45fa009791231ca7924014a6c6d57f2ace3320000";
    static final String GET_ATTESTATION_USERNAMELESS_RESPONSE = "00a501a262696450569f7b7441d8a21477c89666de4d04de64747970656a7075626c69632d6b6579025825e628e3d57a75e0a221131be840c2dbd5c6d779c12fad3e631fba871494612d6e010000002a03584730450220571dd10ec977ff31ce1ee58e8eb97391187082a4bcf20016df869037d415cde5022100efe23a62efc504feca19cd6440c180952a39395880c4f568857a5f5e9fa7523804a162696458342028557365726e616d656c6573732075736572206372656174656420617420362f392f323032302031323a33363a323620504d2905039000";

    static final String CLIENT_PIN_GET_RETRIES = "801000000606a201010201";
    static final String CLIENT_PIN_GET_RETRIES_RESPONSE_EIGHT = "00a103089000";
    static final String CLIENT_PIN_GET_AGREEMENT = "801000000606a201010202";
    static final String CLIENT_PIN_GET_AGREEMENT_RESPONSE = "00a101a501020338182001215820f370174f29f360cff04035c4b46daf2a93468398521ac7fc7bf8f8f986d9e08f2258202ba85af4992d37ef3977eea283b65a00e7c06dc473aeecc24b70f9b9d22d5e8d9000";
    static final byte[] AUTHENTICATOR_KEY_AGREEMENT = Hex.decodeHexOrFail(
            "a501020338182001215820f370174f29f360cff04035c4b46daf2a93468398521ac7fc7bf8f8f986d9e08f2258202ba85af4992d37ef3977eea283b65a00e7c06dc473aeecc24b70f9b9d22d5e8d");
    static final byte[] PLATFORM_KEY_AGREEMENT = Hex.decodeHexOrFail(
            "a501020326200121582099401f6ffa9446585074d1058578f4c68ab46953ccf8cb7910d8b3c9350e1040225820a3c962cddad166b1fdea8a95a377dbf8efbedd82778a8004b884f0009bd6df9506");
    static final byte[] PIN_HASH_ENC = Hex.decodeHexOrFail("2eb756ae474f7ca032b5111b2eef6959");
    static final byte[] PIN_TOKEN_ENC = Hex.decodeHexOrFail("554df3802226935b2bf49f30aae3096f");
    static final String CLIENT_PIN_GET_TOKEN = "801000006606a40101020503a501020326200121582099401f6ffa9446585074d1058578f4c68ab46953ccf8cb7910d8b3c9350e1040225820a3c962cddad166b1fdea8a95a377dbf8efbedd82778a8004b884f0009bd6df9506502eb756ae474f7ca032b5111b2eef6959";
    static final String CLIENT_PIN_GET_TOKEN_RESPONSE = "00a10250554df3802226935b2bf49f30aae3096f9000";
    public static final String MAKE_ATTESTATION_REQUEST_PIN_AUTH =
            "80100000f601a6015820c11f694f75b520b404ae975766483d52eb6e34e7628e6ee28aba967dba520c0502a262696477776562617574686e2e687773656375726974792e646576646e616d656441636d6503a462696450313039383233373233353430393837326469636f6e782868747470733a2f2f706963732e61636d652e636f6d2f30302f702f61426a6a6a707150622e706e67646e616d6578186a6f686e2e702e736d697468406578616d706c652e636f6d6b646973706c61794e616d656d4a6f686e20502e20536d6974680481a263616c672664747970656a7075626c69632d6b65790850313233343536373839404142434546470901";

    static final byte[] SHARED_SECRET = new byte[1];
    static final byte[] PIN_TOKEN = new byte[2];
    static final byte[] CLIENT_DATA_HASH = Hex.decodeHexOrFail("c11f694f75b520b404ae975766483d52eb6e34e7628e6ee28aba967dba520c05");
    static final byte[] PIN_AUTH = Hex.decodeHexOrFail("31323334353637383940414243454647");

    public static final byte[] USER_ID = Hex.decodeHexOrFail("31303938323337323335343039383732");
    public static final String USER_NAME = "john.p.smith@example.com";
    public static final String USER_ICON = "https://pics.acme.com/00/p/aBjjjpqPb.png";
    public static final String USER_DISPLAYNAME = "John P. Smith";
    public static final byte[] CREDENTIAL_ID = WebsafeBase64
            .decode("624vg45lTmZm6Pb2PMB2s7c-uAtczEYcIlj5UzVEfIL3LRsLwXHZB4d6ebB4hupWenkQ7f00bQ9LIgBkHkJdvg");

    Fido2SecurityKey fido2SecurityKey, fido2SecurityKeyWithPin;
    FakeFido2AppletConnection fakeFidoConnection, fakeFidoConnectionWithPin;
    Fido2AsyncOperationManager fido2AsyncOperationManager;
    PinAuthCryptoUtil pinAuthCryptoUtil;

    @Before
    public void setup() throws Exception {
        fakeFidoConnection = FakeFido2AppletConnection.create(false);
        fakeFidoConnectionWithPin = FakeFido2AppletConnection.create(true);
        fido2AsyncOperationManager = new Fido2AsyncOperationManager();
        pinAuthCryptoUtil = mock(PinAuthCryptoUtil.class);
        WebauthnSecurityKeyOperationFactory operationFactory = new WebauthnSecurityKeyOperationFactory(new PinProtocolV1(pinAuthCryptoUtil));

        fido2SecurityKey = new Fido2SecurityKey(
                new SecurityKeyManagerConfig.Builder().build(),
                fakeFidoConnection.connection, null, fido2AsyncOperationManager,
                operationFactory);
        fido2SecurityKeyWithPin = new Fido2SecurityKey(
                new SecurityKeyManagerConfig.Builder().build(),
                fakeFidoConnectionWithPin.connection, null, fido2AsyncOperationManager,
                operationFactory);
    }

    @Test
    public void makeCredential() throws Exception {
        byte[] challenge = WebsafeBase64.decode("GNxfVQfEVOoi9uU1W_jM-w");
        PublicKeyCredentialCreate createParameters = PublicKeyCredentialCreate.create(ORIGIN,
            PublicKeyCredentialCreationOptions.create(
                    PublicKeyCredentialRpEntity.create("webauthn.hwsecurity.dev", "Acme", null),
                    PublicKeyCredentialUserEntity.create(USER_ID, USER_NAME, USER_DISPLAYNAME, USER_ICON),
                    challenge,
                    Collections.singletonList(PublicKeyCredentialParameters.createDefaultEs256()),
                    null,
                    AuthenticatorSelectionCriteria.create(null, false, UserVerificationRequirement.PREFERRED),
                    null,
                    AttestationConveyancePreference.NONE
            )
        );
        fakeFidoConnection.expect(MAKE_ATTESTATION_REQUEST, MAKE_ATTESTATION_RESPONSE);

        PublicKeyCredential publicKeyCredential = fido2SecurityKey.webauthnCommand(createParameters);

        fakeFidoConnection.verify();
        assertArrayEquals(CREDENTIAL_ID, publicKeyCredential.rawId());
        assertEquals(WebsafeBase64.encodeToString(CREDENTIAL_ID), publicKeyCredential.id());
        assertEquals("public-key", publicKeyCredential.type());
        assertTrue(publicKeyCredential.response() instanceof AuthenticatorAttestationResponse);
        assertEquals("{\"type\":\"webauthn.create\",\"origin\":\"https:\\/\\/webauthn.hwsecurity.dev\",\"challenge\":\"GNxfVQfEVOoi9uU1W_jM-w\",\"hashAlgorithm\":\"SHA-256\"}",
                new String(publicKeyCredential.response().clientDataJson()));
    }

    @Test
    public void getAssertion() throws Exception {
        byte[] challenge = WebsafeBase64.decode("BCNrbzS9WfmkDbISaw6WQg");
        PublicKeyCredentialGet getParameters = PublicKeyCredentialGet.create(ORIGIN,
                PublicKeyCredentialRequestOptions.create(
                        challenge,
                        null,
                        "webauthn.hwsecurity.dev",
                        Collections.singletonList(PublicKeyCredentialDescriptor.create(
                                PublicKeyCredentialType.PUBLIC_KEY, CREDENTIAL_ID, Arrays.asList(
                                        AuthenticatorTransport.USB,
                                        AuthenticatorTransport.NFC,
                                        AuthenticatorTransport.BLE
                                )
                        )), UserVerificationRequirement.PREFERRED)
        );
        fakeFidoConnection.expect(GET_ATTESTATION_REQUEST, GET_ATTESTATION_RESPONSE);

        PublicKeyCredential publicKeyCredential = fido2SecurityKey.webauthnCommand(getParameters);

        fakeFidoConnection.verify();
        assertArrayEquals(CREDENTIAL_ID, publicKeyCredential.rawId());
        assertEquals(WebsafeBase64.encodeToString(CREDENTIAL_ID), publicKeyCredential.id());
        assertEquals("public-key", publicKeyCredential.type());
        assertTrue(publicKeyCredential.response() instanceof AuthenticatorAssertionResponse);
        AuthenticatorAssertionResponse response = (AuthenticatorAssertionResponse) publicKeyCredential.response();
        assertNull(response.userHandle());
        assertEquals("{\"type\":\"webauthn.get\",\"origin\":\"https:\\/\\/webauthn.hwsecurity.dev\",\"challenge\":\"BCNrbzS9WfmkDbISaw6WQg\",\"hashAlgorithm\":\"SHA-256\"}",
                new String(publicKeyCredential.response().clientDataJson()));
    }

    @Test
    public void getAssertion_usernameless() throws Exception {
        byte[] challenge = WebsafeBase64.decode("n46bFSgRdToqeoIeef252g");
        PublicKeyCredentialGet getParameters = PublicKeyCredentialGet.create(
                "https://www.passwordless.dev",
                PublicKeyCredentialRequestOptions.create(
                        challenge,
                        null,
                        "www.passwordless.dev",
                        Collections.emptyList(), UserVerificationRequirement.PREFERRED)
        );
        fakeFidoConnection.expect(GET_ATTESTATION_USERNAMELESS_REQUEST, GET_ATTESTATION_USERNAMELESS_RESPONSE);

        PublicKeyCredential publicKeyCredential = fido2SecurityKey.webauthnCommand(getParameters);

        fakeFidoConnection.verify();
        byte[] rawId = WebsafeBase64.decode("Vp97dEHYohR3yJZm3k0E3g");
        assertArrayEquals(rawId, publicKeyCredential.rawId());
        assertEquals(WebsafeBase64.encodeToString(rawId), publicKeyCredential.id());
        assertEquals("public-key", publicKeyCredential.type());
        assertTrue(publicKeyCredential.response() instanceof AuthenticatorAssertionResponse);
        AuthenticatorAssertionResponse response = (AuthenticatorAssertionResponse) publicKeyCredential.response();
        assertEquals("IChVc2VybmFtZWxlc3MgdXNlciBjcmVhdGVkIGF0IDYvOS8yMDIwIDEyOjM2OjI2IFBNKQ", WebsafeBase64.encodeToString(response.userHandle()));
        assertEquals("{\"type\":\"webauthn.get\",\"origin\":\"https:\\/\\/www.passwordless.dev\",\"challenge\":\"n46bFSgRdToqeoIeef252g\",\"hashAlgorithm\":\"SHA-256\"}",
                new String(publicKeyCredential.response().clientDataJson()));
    }

    @Test
    public void makeCredential_withPin() throws Exception {
        byte[] challenge = WebsafeBase64.decode("GNxfVQfEVOoi9uU1W_jM-w");
        PublicKeyCredentialCreate createParameters = PublicKeyCredentialCreate.create(ORIGIN,
                PublicKeyCredentialCreationOptions.create(
                        PublicKeyCredentialRpEntity.create("webauthn.hwsecurity.dev", "Acme", null),
                        PublicKeyCredentialUserEntity.create(USER_ID, USER_NAME, USER_DISPLAYNAME, USER_ICON),
                        challenge,
                        Collections.singletonList(PublicKeyCredentialParameters.createDefaultEs256()),
                        null,
                        AuthenticatorSelectionCriteria.create(null, false, UserVerificationRequirement.PREFERRED),
                        null,
                        AttestationConveyancePreference.NONE
                )
        ).withClientPin("1234", false);
        fakeFidoConnectionWithPin.expect(CLIENT_PIN_GET_RETRIES, CLIENT_PIN_GET_RETRIES_RESPONSE_EIGHT);
        fakeFidoConnectionWithPin.expect(CLIENT_PIN_GET_AGREEMENT, CLIENT_PIN_GET_AGREEMENT_RESPONSE);
        fakeFidoConnectionWithPin.expect(CLIENT_PIN_GET_TOKEN, CLIENT_PIN_GET_TOKEN_RESPONSE);
        fakeFidoConnectionWithPin.expect(MAKE_ATTESTATION_REQUEST_PIN_AUTH, MAKE_ATTESTATION_RESPONSE);

        PublicKey publicKey = mock(PublicKey.class);
        PrivateKey privateKey = mock(PrivateKey.class);
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        PublicKey authenticatorPublicKey = mock(PublicKey.class);

        when(pinAuthCryptoUtil.generatePlatformKeyPair()).thenReturn(keyPair);
        when(pinAuthCryptoUtil.cosePublicKeyFromPublicKey(publicKey))
                .thenReturn(PLATFORM_KEY_AGREEMENT);
        when(pinAuthCryptoUtil.publicKeyFromCosePublicKey(aryEq(AUTHENTICATOR_KEY_AGREEMENT)))
                .thenReturn(authenticatorPublicKey);
        when(pinAuthCryptoUtil.calculatePinHashEnc(aryEq(SHARED_SECRET), eq("1234")))
                .thenReturn(PIN_HASH_ENC);
        when(pinAuthCryptoUtil.generateSharedSecret(privateKey, authenticatorPublicKey))
                .thenReturn(SHARED_SECRET);
        when(pinAuthCryptoUtil.decryptPinToken(SHARED_SECRET, PIN_TOKEN_ENC)).thenReturn(PIN_TOKEN);
        when(pinAuthCryptoUtil.calculatePinAuth(same(PIN_TOKEN), aryEq(CLIENT_DATA_HASH))).thenReturn(PIN_AUTH);

        PublicKeyCredential publicKeyCredential = fido2SecurityKeyWithPin.webauthnCommand(createParameters);

        fakeFidoConnectionWithPin.verify();
        assertArrayEquals(CREDENTIAL_ID, publicKeyCredential.rawId());
        assertEquals(WebsafeBase64.encodeToString(CREDENTIAL_ID), publicKeyCredential.id());
        assertEquals("public-key", publicKeyCredential.type());
        assertTrue(publicKeyCredential.response() instanceof AuthenticatorAttestationResponse);
        assertEquals("{\"type\":\"webauthn.create\",\"origin\":\"https:\\/\\/webauthn.hwsecurity.dev\",\"challenge\":\"GNxfVQfEVOoi9uU1W_jM-w\",\"hashAlgorithm\":\"SHA-256\"}",
                new String(publicKeyCredential.response().clientDataJson()));
    }
}
