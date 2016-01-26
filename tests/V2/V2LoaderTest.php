<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\V2;

use Jose\Loader;

/**
 * @group V2
 */
class V2LoaderTest extends \PHPUnit_Framework_TestCase
{
    public function testLoadCompactJWS()
    {
        $input = 'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoidHBTMVptZlZLVlA1S29mSWhNQlAwdFNXYzRxbGg2Zm0ybHJaU2t1S3hVakVhV2p6WlN6czcyZ0VJR3hyYVd1c01kb1J1VjU0eHNXUnlmNUtlWlQwUy1JNVBybGUzSWRpM2dJQ2lPNE53dk1rNkp3U0JjSld3bVNMRkVLeVVTbkIyQ3RmaUdjMF81clFDcGNFdF9EbjVpTS1CTm43ZnFwb0xJYmtzOHJYS1VJajgtcU1WcWtUWHNFS2VLaW5FMjN0MXlrTWxkc05hYU9ILWh2R3RpNUp0MkRNbkgxSmpvWGREWGZ4dlNQXzBnalVZYjBla3R1ZFlGWG9BNndla21ReUplSW12Z3g0TXl6MUk0aUh0a1lfQ3A3SjRNbjFlalo2SE5teXZvVEVfNE91WTF1Q2VZdjRVeVhGYzFzMXVVeVl0ajR6NTdxc0hHc1M0ZFEzQTJNSnN3IiwiZSI6IkFRQUIifX0.SmUgc3VpcyBDaGFybGll.j8Ixg1CtPKdjn_nQbzRuFfX2I5i13uOLXDW1bPDMG4glp9ZW7mBi5_8ISnir-JVl93MpveppJo2adN_YkmmQjAgIYBgqO64Z1ltvjT5BwtS54SXCV4_YQDK-Tgy-IM6oG-T7zRz1GL_HowkkcUs9TenmakP3EDHL3MOsK6yo2HKhXgTvQ3ud0zKacdo4RQ_OQBoAle3Dr2rnTBVaF_4YRem2YrdFMzOHN9Luo7RxQJQcQTv99KTUNGih5mZug4k6W4YZPHi9lWfqzSTrlhKnnIc-EkecSsgjgWJzXjH2JQkd5rlKLWB96Al1iGjiGmsanmqcnETjnYZQAK0Hy73Lgw';
        $result = Loader::load($input);
    }

    public function testLoadFlattenedJWS()
    {
        $input = '{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}';
        $result = Loader::load($input);
    }
}
