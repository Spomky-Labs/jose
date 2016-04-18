<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Base64Url\Base64Url;
use Jose\Algorithm\Signature\Ed25519;
use Jose\Factory\JWSFactory;
use Jose\Loader;
use Jose\Object\JWK;
use Jose\Object\JWSInterface;
use Jose\Test\TestCase;
use Jose\Verifier;

/**
 * Class Ed25519SignatureTest.
 *
 * @group Ed25519
 * @group Unit
 */
class Ed25519SignatureTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.5
     */
    public function testEd25519VerifyAlgorithm()
    {
        if (!function_exists('ed25519_sign')) {
            $this->markTestSkipped('Ed25519 extension not available');
        }

        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd'   => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x'   => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        $ed25519 = new Ed25519();
        $input = 'eyJhbGciOiJFZDI1NTE5In0.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = Base64Url::decode('UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ');

        $ed25519->verify($key, $input, $signature);
    }

    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.5
     */
    public function testEd25519SignAndVerifyAlgorithm()
    {
        if (!function_exists('ed25519_sign')) {
            $this->markTestSkipped('Ed25519 extension not available');
        }

        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd'   => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x'   => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        $header = ['alg' => 'Ed25519'];
        $input = Base64Url::decode('RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc');

        $jws = JWSFactory::createJWSToCompactJSON($input, $key, $header);

        $this->assertEquals('eyJhbGciOiJFZDI1NTE5In0.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ', $jws);

        $loader = new Loader();
        $loaded = $loader->load($jws);
        $verifier = Verifier::createVerifier(['Ed25519']);

        $this->assertInstanceOf(JWSInterface::class, $loaded);
        $this->assertEquals(1, $loaded->countSignatures());
        $verifier->verifyWithKey($loaded, $key);
    }
}
