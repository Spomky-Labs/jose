<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWEFactory;
use Jose\Test\TestCase;
use Jose\Object\Recipient;

/**
 * @group CheckerManager
 * @group Functional
 */
class CheckerManagerTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT has expired.
     */
    public function testExpiredJWT()
    {
        $jwe = JWEFactory::createJWE(
            [
                'exp' => time()-1,
            ],
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [],
            'foo,bar,baz'
        );
        $jwe = $jwe->addRecipient(new Recipient());

        $this->getCheckerManager()->checkJWE($jwe, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT is issued in the futur.
     */
    public function testJWTIssuedInTheFuture()
    {
        $jwe = JWEFactory::createJWE(
            [
                'exp' => time()+3600,
                'iat' => time()+100,
            ],
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [],
            'foo,bar,baz'
        );
        $jwe = $jwe->addRecipient(new Recipient());

        $this->getCheckerManager()->checkJWE($jwe, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Can not use this JWT yet.
     */
    public function testJWTNotNow()
    {
        $jwe = JWEFactory::createJWE(
            [
                'exp' => time()+3600,
                'iat' => time()-100,
                'nbf' => time()+100,
            ],
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [],
            'foo,bar,baz'
        );
        $jwe = $jwe->addRecipient(new Recipient());

        $this->getCheckerManager()->checkJWE($jwe, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testJWTNotForAudience()
    {
        $jwe = JWEFactory::createJWE(
            [
                'exp' => time()+3600,
                'iat' => time()-100,
                'nbf' => time()-100,
                'aud' => 'Other Service',
            ],
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [],
            'foo,bar,baz'
        );
        $jwe = $jwe->addRecipient(new Recipient());

        $this->getCheckerManager()->checkJWE($jwe, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage One or more claims are marked as critical, but they are missing or have not been checked (["iss"]).
     */
    public function testJWTHasCriticalClaimsNotSatisfied()
    {
        $jwe = JWEFactory::createJWE(
            [
                'exp' => time()+3600,
                'iat' => time()-100,
                'nbf' => time()-100,
            ],
            [
                'enc'  => 'A256CBC-HS512',
                'alg'  => 'RSA-OAEP-256',
                'zip'  => 'DEF',
                'crit' => ['exp', 'iss'],
            ],
            [],
            'foo,bar,baz'
        );
        $jwe = $jwe->addRecipient(new Recipient());

        $this->getCheckerManager()->checkJWE($jwe, 0);
    }
}
