/**
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.wessendorf.salt;

import org.jboss.aerogear.AeroGearCrypto;
import org.jboss.aerogear.crypto.CryptoBox;
import org.jboss.aerogear.crypto.Random;
import org.jboss.aerogear.crypto.password.Pbkdf2;
import org.junit.Before;
import org.junit.Test;

import java.security.spec.InvalidKeySpecException;

import static org.assertj.core.api.Assertions.assertThat;

public class SecretKeyTest {

    private final  String passphraseForCertificateRequiredByAPNs = "Rockers Hi-Fi: Push Push";




    private byte[] privateKeyToBeStoredInDatabase;
    private byte[] IV_ToBeStoredInDatabase;
    private byte[] ciphertextToBeStoredInDatabase;



    @Before
    public void encryptionDance() throws InvalidKeySpecException {

        Pbkdf2 pbkdf2 = AeroGearCrypto.pbkdf2();


        // TODO:
        // I am not sure if it is a good idea to use
        // the actual passphrase (for the certificate) for the generation of the privateKey:
        privateKeyToBeStoredInDatabase = pbkdf2.encrypt(passphraseForCertificateRequiredByAPNs);


        // get me a crypto box
        CryptoBox cryptoBox = new CryptoBox(privateKeyToBeStoredInDatabase);

        // generate the IV and the ciphertext (using the given passphrase)
        // and stash em, to be stored (e.g. in database) as well:
        IV_ToBeStoredInDatabase = new Random().randomBytes();
        ciphertextToBeStoredInDatabase = cryptoBox.encrypt(IV_ToBeStoredInDatabase, passphraseForCertificateRequiredByAPNs.getBytes());
    }

    @Test
    public void decryptTheEncryptedApplePassphrase() throws InvalidKeySpecException {

        // use the stored private key:
        CryptoBox pandora = new CryptoBox(privateKeyToBeStoredInDatabase);

        // apply the actual decryption so that we can connect to Apple's cloud:
        byte[] message = pandora.decrypt(IV_ToBeStoredInDatabase, ciphertextToBeStoredInDatabase);


        // byte[]
        assertThat(message).isEqualTo("Rockers Hi-Fi: Push Push".getBytes());

        // String... :-)
        assertThat(new String(message)).isEqualTo("Rockers Hi-Fi: Push Push");

    }
}
