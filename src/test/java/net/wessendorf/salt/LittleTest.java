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
import org.jboss.aerogear.crypto.password.DefaultPbkdf2;
import org.jboss.aerogear.crypto.password.Pbkdf2;
import org.junit.Before;
import org.junit.Test;

import java.security.spec.InvalidKeySpecException;

import static org.assertj.core.api.Assertions.assertThat;

public class LittleTest {

    private byte[] encryptedPasswordToBeStoredInDatabase;
    private byte[] saltToBeStoredInDatabase;


    @Before
    public void encryptionDance() throws InvalidKeySpecException {

        Pbkdf2 pbkdf2 = AeroGearCrypto.pbkdf2();

        // encrypt the password given by a user
        // store the salt + the encrypted password (e.g. in the database)
        encryptedPasswordToBeStoredInDatabase = pbkdf2.encrypt("Like a boss");
        saltToBeStoredInDatabase = ((DefaultPbkdf2) pbkdf2).getSalt();
    }

    @Test
    public void verifySaltedPasswordOnLogin() throws InvalidKeySpecException {
        String passwordEnteredByUser = "Like a boss";
        boolean validationResult = AeroGearCrypto.pbkdf2().validate(passwordEnteredByUser, encryptedPasswordToBeStoredInDatabase, saltToBeStoredInDatabase);

        // got a true back ?
        assertThat(validationResult).isTrue();

    }

    @Test
    public void verifySaltedPasswordOnLoginButUserMadeTypo() throws InvalidKeySpecException {
        String passwordEnteredByUser = "Like a Boss";
        boolean validationResult = AeroGearCrypto.pbkdf2().validate(passwordEnteredByUser, encryptedPasswordToBeStoredInDatabase, saltToBeStoredInDatabase);

        // got a false back ?
        assertThat(validationResult).isFalse();
    }
}
