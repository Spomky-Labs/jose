<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

include_once __DIR__.'/../../vendor/autoload.php';

use Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Object\JWK;
use Jose\Object\JWKInterface;
use Jose\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Util\StringUtil;

function testKeyAgreementWithKeyWrappingEncryptionPerformance($message, KeyAgreementWrappingInterface $alg, JWKInterface $recipient_key, JWKInterface $sender_key)
{
    $header = [
        'alg' => $alg->getAlgorithmName(),
        'enc' => 'A128GCM',
        'exp' => time()+3600,
        'iat' => time(),
        'nbf' => time(),
    ];
    $ahv = [];
    $cek = StringUtil::generateRandomBytes(512);
    $nb = 100;

    $time_start = microtime(true);
    for($i = 0; $i < $nb; $i++) {
        $alg->wrapAgreementKey($sender_key, $recipient_key, $cek, 128, $header, $ahv);
    }
    $time_end = microtime(true);

    $time = ($time_end - $time_start)/$nb*1000;
    printf('%s: %f milliseconds/wrapping of key agreement (%s)'.PHP_EOL, $alg->getAlgorithmName(), $time, $message);
}

function testKeyAgreementWithKeyWrappingDecryptionPerformance($message, KeyAgreementWrappingInterface $alg, JWKInterface $recipient_key, JWKInterface $sender_key)
{
    $header = [
        'alg' => $alg->getAlgorithmName(),
        'enc' => 'A128GCM',
        'exp' => time()+3600,
        'iat' => time(),
        'nbf' => time(),
    ];
    $cek = StringUtil::generateRandomBytes(512/8);

    $encrypted_cek = $alg->wrapAgreementKey($sender_key, $recipient_key, $cek, 128, $header, $header);
    $nb = 100;

    $time_start = microtime(true);
    for($i = 0; $i < $nb; $i++) {
        $alg->unwrapAgreementKey($recipient_key, $encrypted_cek, 128, $header);
    }
    $time_end = microtime(true);

    $time = ($time_end - $time_start)/$nb*1000;
    printf('%s: %f milliseconds/unwrapping of key agreement (%s)'.PHP_EOL, $alg->getAlgorithmName(), $time, $message);
}

function dataKeyAgreementWithKeyWrappingPerformance()
{
    return [
        [
            'With P-256 curve',
            new ECDHESA128KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
                'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
                'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            ]),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ]),
        ],
        [
            'With P-521 curve',
            new ECDHESA128KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
                'd'   => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
            ]),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x'   => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y'   => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
                'd'   => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            ]),
        ],
        [
            'With P-256 curve',
            new ECDHESA192KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ]),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
                'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
                'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            ]),
        ],
        [
            'With P-521 curve',
            new ECDHESA192KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
                'd'   => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
            ]),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x'   => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y'   => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
                'd'   => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            ]),
        ],
        [
            'With P-256 curve',
            new ECDHESA256KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ]),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
                'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
                'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            ]),
        ],
        [
            'With P-521 curve',
            new ECDHESA256KW(),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
                'd'   => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
            ]),
            new JWK([
                'kty' => 'EC',
                'crv' => 'P-521',
                'x'   => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
                'y'   => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
                'd'   => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            ]),
        ],
    ];
}

$environments = dataKeyAgreementWithKeyWrappingPerformance();

print_r('###################################'.PHP_EOL);
print_r('# KEY AGREEMENT PERFORMANCE TESTS #'.PHP_EOL);
print_r('###################################'.PHP_EOL);

foreach($environments as $environment) {
    testKeyAgreementWithKeyWrappingEncryptionPerformance($environment[0], $environment[1], $environment[2], $environment[3]);
}
foreach($environments as $environment) {
    testKeyAgreementWithKeyWrappingDecryptionPerformance($environment[0], $environment[1], $environment[2], $environment[3]);
}

print_r('###################################'.PHP_EOL);
