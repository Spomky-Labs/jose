<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Object\JWS;
use Jose\Test\TestCase;

/**
 * @group CheckerManager
 */
class CheckerManager extends TestCase
{
    /*
     * @expectedException \Exception
     * @expectedExceptionMessage Issuer not allowed.
     */
    /*public function testCheckJWTWithBadIssuer()
    {
        $jwt = new JWS();
        $jwt = $jwt->withPayload([
            'exp' => time() + 10000,
            'iss' => 'foo',
            'sub' => 'SUB2',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }*/

    /*
     * @expectedException \Exception
     * @expectedExceptionMessage Bad audience.
     */
    /*public function testCheckJWTWithBadAudience()
    {
        $jwt = new JWS();
        $jwt = $jwt->withPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'SUB2',
            'aud' => 'foo',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }*/

    /*
     * @expectedException \Exception
     * @expectedExceptionMessage The JWT has expired.
     */
    /*public function testCheckExpiredJWT()
    {
        $jwt = new JWS();
        $jwt = $jwt->withPayload([
            'exp' => time() - 10000,
            'iss' => 'ISS1',
            'sub' => 'SUB2',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }*/

    /*
     * @expectedException \Exception
     * @expectedExceptionMessage The JWT is issued in the futur.
     */
    /*public function testCheckJWTIssuedInTheFutur()
    {
        $jwt = new JWS();
        $jwt = $jwt->withPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'SUB2',
            'aud' => 'My service',
            'iat' => time() + 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }*/

    /*
     * @expectedException \Exception
     * @expectedExceptionMessage Can not use this JWT yet.
     */
    /*public function testCheckJWTNotYetUsable()
    {
        /*$jwt = new JWS();
        $jwt = $jwt->withPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'SUB2',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() + 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }*/

    /*
     * @expectedException \Exception
     * @expectedExceptionMessage Invalid subject.
     */
    /*public function testCheckJWTWithBadSubject()
    {
        $jwt = new JWS();
        $jwt = $jwt->withPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'foo',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }*/

    /*
     * @expectedException \Exception
     * @expectedExceptionMessage The claim/header 'foo' is marked as critical but value is not set.
     */
    /*public function testCheckJWTWithMissingCriticalParameters()
    {
        $jwt = new JWS();
        $jwt = $jwt->withProtectedHeader('crit', ['exp', 'iss', 'foo']);
        $jwt = $jwt->withPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'foo',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }*/

    /*public function testCheckValidJWT()
    {
        $jwt = new JWS();
        $jwt = $jwt->withProtectedHeader('crit', ['exp', 'iss', 'foo']);
        $jwt = $jwt->withPayload([
                'exp' => time() + 10000,
                'iss' => 'ISS1',
                'sub' => 'SUB2',
                'aud' => 'My service',
                'iat' => time() - 10000,
                'nbf' => time() - 10000,
                'foo' => 'bar',
            ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }*/
}
