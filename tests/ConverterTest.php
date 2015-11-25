<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\JSONSerializationModes;
use Jose\Util\Converter;

/**
 * @group Converter
 */
class ConverterTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Nothing to merge
     */
    public function testEmptyArgument()
    {
        Converter::merge();
    }

    public function testConvertSignatureCompactSerializationIntoSerialization()
    {
        $input = 'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.SmUgc3VpcyBDaGFybGll.j8Ixg1CtPKdjn_nQbzRuFfX2I5i13uOLXDW1bPDMG4glp9ZW7mBi5_8ISnir-JVl93MpveppJo2adN_YkmmQjAgIYBgqO64Z1ltvjT5BwtS54SXCV4_YQDK-Tgy-IM6oG-T7zRz1GL_HowkkcUs9TenmakP3EDHL3MOsK6yo2HKhXgTvQ3ud0zKacdo4RQ_OQBoAle3Dr2rnTBVaF_4YRem2YrdFMzOHN9Luo7RxQJQcQTv99KTUNGih5mZug4k6W4YZPHi9lWfqzSTrlhKnnIc-EkecSsgjgWJzXjH2JQkd5rlKLWB96Al1iGjiGmsanmqcnETjnYZQAK0Hy73Lgw';
        $result = Converter::convert($input, JSONSerializationModes::JSON_SERIALIZATION);

        $expected_result = json_encode([
            'payload'    => 'SmUgc3VpcyBDaGFybGll',
            'signatures' => [
                [
                    'protected' => 'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0',
                    'signature' => 'j8Ixg1CtPKdjn_nQbzRuFfX2I5i13uOLXDW1bPDMG4glp9ZW7mBi5_8ISnir-JVl93MpveppJo2adN_YkmmQjAgIYBgqO64Z1ltvjT5BwtS54SXCV4_YQDK-Tgy-IM6oG-T7zRz1GL_HowkkcUs9TenmakP3EDHL3MOsK6yo2HKhXgTvQ3ud0zKacdo4RQ_OQBoAle3Dr2rnTBVaF_4YRem2YrdFMzOHN9Luo7RxQJQcQTv99KTUNGih5mZug4k6W4YZPHi9lWfqzSTrlhKnnIc-EkecSsgjgWJzXjH2JQkd5rlKLWB96Al1iGjiGmsanmqcnETjnYZQAK0Hy73Lgw',
                ], ], ]);
        $this->assertEquals($expected_result, $result);
    }

    public function testConvertSignatureCompactSerializationIntoCompactSerialization()
    {
        $input = 'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.SmUgc3VpcyBDaGFybGll.j8Ixg1CtPKdjn_nQbzRuFfX2I5i13uOLXDW1bPDMG4glp9ZW7mBi5_8ISnir-JVl93MpveppJo2adN_YkmmQjAgIYBgqO64Z1ltvjT5BwtS54SXCV4_YQDK-Tgy-IM6oG-T7zRz1GL_HowkkcUs9TenmakP3EDHL3MOsK6yo2HKhXgTvQ3ud0zKacdo4RQ_OQBoAle3Dr2rnTBVaF_4YRem2YrdFMzOHN9Luo7RxQJQcQTv99KTUNGih5mZug4k6W4YZPHi9lWfqzSTrlhKnnIc-EkecSsgjgWJzXjH2JQkd5rlKLWB96Al1iGjiGmsanmqcnETjnYZQAK0Hy73Lgw';
        $result = Converter::convert($input, JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
        $this->assertEquals($input, $result);
    }

    public function testConvertSignatureCompactSerializationIntoFlattenedSerialization()
    {
        $input = 'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.SmUgc3VpcyBDaGFybGll.j8Ixg1CtPKdjn_nQbzRuFfX2I5i13uOLXDW1bPDMG4glp9ZW7mBi5_8ISnir-JVl93MpveppJo2adN_YkmmQjAgIYBgqO64Z1ltvjT5BwtS54SXCV4_YQDK-Tgy-IM6oG-T7zRz1GL_HowkkcUs9TenmakP3EDHL3MOsK6yo2HKhXgTvQ3ud0zKacdo4RQ_OQBoAle3Dr2rnTBVaF_4YRem2YrdFMzOHN9Luo7RxQJQcQTv99KTUNGih5mZug4k6W4YZPHi9lWfqzSTrlhKnnIc-EkecSsgjgWJzXjH2JQkd5rlKLWB96Al1iGjiGmsanmqcnETjnYZQAK0Hy73Lgw';
        $result = Converter::convert($input, JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $expected_result = json_encode([
            'payload'   => 'SmUgc3VpcyBDaGFybGll',
            'signature' => 'j8Ixg1CtPKdjn_nQbzRuFfX2I5i13uOLXDW1bPDMG4glp9ZW7mBi5_8ISnir-JVl93MpveppJo2adN_YkmmQjAgIYBgqO64Z1ltvjT5BwtS54SXCV4_YQDK-Tgy-IM6oG-T7zRz1GL_HowkkcUs9TenmakP3EDHL3MOsK6yo2HKhXgTvQ3ud0zKacdo4RQ_OQBoAle3Dr2rnTBVaF_4YRem2YrdFMzOHN9Luo7RxQJQcQTv99KTUNGih5mZug4k6W4YZPHi9lWfqzSTrlhKnnIc-EkecSsgjgWJzXjH2JQkd5rlKLWB96Al1iGjiGmsanmqcnETjnYZQAK0Hy73Lgw',
            'protected' => 'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0',
        ]);

        $this->assertEquals($expected_result, $result);
    }

    public function testConvertEncryptedFlattenedSerializationIntoSerialization()
    {
        $input = '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}';
        $result = Converter::convert($input, JSONSerializationModes::JSON_SERIALIZATION);

        $expected_result = [
            'ciphertext'  => 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
            'protected'   => 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
            'unprotected' => ['jku' => 'https://server.example.com/keys.jwks'],
            'iv'          => 'AxY8DCtDaGlsbGljb3RoZQ',
            'tag'         => 'Mz-VPPyU4RlcuYv1IwIvzw',
            'recipients'  => [[
                'header'        => ['alg' => 'A128KW','kid' => '7'],
                'encrypted_key' => '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
            ]], ];
        $this->assertEquals($expected_result, json_decode($result, true));
    }

    public function testConvertEncryptedFlattenedSerializationIntoCompactSerialization()
    {
        $input = '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}';
        $result = Converter::convert($input, JSONSerializationModes::JSON_COMPACT_SERIALIZATION);

        $expected_result = 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.Mz-VPPyU4RlcuYv1IwIvzw';
        $this->assertEquals($expected_result, $result);
    }

    public function testConvertEncryptedFlattenedSerializationIntoFlattenedSerialization()
    {
        $input = '{"ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https:\/\/server.example.com\/keys.jwks"},"iv":"AxY8DCtDaGlsbGljb3RoZQ","tag":"Mz-VPPyU4RlcuYv1IwIvzw","header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}';
        $result = Converter::convert($input, JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);
        $this->assertEquals($input, $result);
    }

    public function testConvertEncryptedSerializationIntoSerialization()
    {
        $input = '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https:\/\/server.example.com\/keys.jwks"},"recipients":[{"header":{"alg":"RSA1_5","kid":"2011-04-29"},"encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},{"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],"iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}';
        $result = Converter::convert($input, JSONSerializationModes::JSON_SERIALIZATION);
        $this->assertEquals($input, $result);
    }

    public function testConvertEncryptedSerializationIntoCompactSerialization()
    {
        $input = '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","recipients":[{"encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},{"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],"iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}';
        $result = Converter::convert($input, JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
        $expected_result = [
            'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.Mz-VPPyU4RlcuYv1IwIvzw',
            'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.Mz-VPPyU4RlcuYv1IwIvzw',
        ];
        $this->assertEquals($expected_result, $result);
    }

    public function testConvertEncryptedSerializationIntoFlattenedSerialization()
    {
        $input = '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https:\/\/server.example.com\/keys.jwks"},"recipients":[{"header":{"alg":"RSA1_5","kid":"2011-04-29"},"encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},{"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],"iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}';
        $result = Converter::convert($input, JSONSerializationModes::JSON_FLATTENED_SERIALIZATION);

        $expected_result = [json_encode([
            'ciphertext'    => 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
            'protected'     => 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
            'unprotected'   => ['jku' => 'https://server.example.com/keys.jwks'],
            'iv'            => 'AxY8DCtDaGlsbGljb3RoZQ',
            'tag'           => 'Mz-VPPyU4RlcuYv1IwIvzw',
            'header'        => ['alg' => 'RSA1_5', 'kid' => '2011-04-29'],
            'encrypted_key' => 'UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A',
        ]),json_encode([
            'ciphertext'    => 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
            'protected'     => 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
            'unprotected'   => ['jku' => 'https://server.example.com/keys.jwks'],
            'iv'            => 'AxY8DCtDaGlsbGljb3RoZQ',
            'tag'           => 'Mz-VPPyU4RlcuYv1IwIvzw',
            'header'        => ['alg' => 'A128KW', 'kid' => '7'],
            'encrypted_key' => '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
        ])];

        $this->assertEquals($expected_result, $result);
    }

    public function testMergeSignature()
    {
        $result = Converter::merge(
            'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw'
        );

        $expected_result = json_encode([
            'payload'    => 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            'signatures' => [
                [
                    'protected' => 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
                    'signature' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                ],
                [
                    'protected' => 'eyJhbGciOiJSUzI1NiJ9',
                    'signature' => 'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw',
                ],
            ], ]);
        $this->assertEquals($expected_result, $result);
    }

    public function testMergeEncrypted()
    {
        $result = Converter::merge(
            [
                'ciphertext'    => 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
                'protected'     => 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
                'unprotected'   => ['jku' => 'https://server.example.com/keys.jwks'],
                'iv'            => 'AxY8DCtDaGlsbGljb3RoZQ',
                'tag'           => 'Mz-VPPyU4RlcuYv1IwIvzw',
                'header'        => ['alg' => 'RSA1_5', 'kid' => '2011-04-29'],
                'encrypted_key' => 'UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A',
            ],
            [
                'ciphertext'    => 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
                'protected'     => 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
                'unprotected'   => ['jku' => 'https://server.example.com/keys.jwks'],
                'iv'            => 'AxY8DCtDaGlsbGljb3RoZQ',
                'tag'           => 'Mz-VPPyU4RlcuYv1IwIvzw',
                'header'        => ['alg' => 'A128KW', 'kid' => '7'],
                'encrypted_key' => '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
            ]
        );

        $expected_result = json_encode([
            'ciphertext'  => 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
            'protected'   => 'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
            'unprotected' => ['jku' => 'https://server.example.com/keys.jwks'],
            'iv'          => 'AxY8DCtDaGlsbGljb3RoZQ',
            'tag'         => 'Mz-VPPyU4RlcuYv1IwIvzw',
            'recipients'  => [
                [
                    'header'        => ['alg' => 'RSA1_5', 'kid' => '2011-04-29'],
                    'encrypted_key' => 'UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A',
                ],
                [
                    'header'        => ['alg' => 'A128KW', 'kid' => '7'],
                    'encrypted_key' => '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
                ],
            ], ]);

        $this->assertEquals($expected_result, $result);
    }
}
