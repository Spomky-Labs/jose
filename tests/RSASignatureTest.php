<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\JWK;
use SpomkyLabs\JOSE\Util\Base64Url;
use SpomkyLabs\JOSE\Util\RSAConverter;
use SpomkyLabs\JOSE\Algorithm\Signature\RS256;
use SpomkyLabs\JOSE\Algorithm\Signature\RS384;
use SpomkyLabs\JOSE\Algorithm\Signature\RS512;
use SpomkyLabs\JOSE\Algorithm\Signature\PS256;
use SpomkyLabs\JOSE\Algorithm\Signature\PS384;
use SpomkyLabs\JOSE\Algorithm\Signature\PS512;

class RSASignatureTest extends \PHPUnit_Framework_TestCase
{
    public function testRS256Sign()
    {
        $rsa = new RS256();
        $key = new JWK();
        $key->setValues(array(
                'kty' => 'RSA',
                'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e'   => 'AQAB',
                'p'   => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                'd'   => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                'q'   => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                'dp'  => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                'dq'  => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                'qi'  => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
        ));
        $data = 'aaa';

        $signature = $rsa->sign($key, $data);

        $this->assertEquals('MA_L5qZwpYINqPvCQs3FD3aLx2h4pr1sD85Ds0uSXPqoDttHUUoGkEGaItA8I7mX0_YzXKte4jNjcox7uC3yehjtex4DtCmFd0fmZnG0UeQtue_f9tZrmXZ2eSLi2WVOErHDPWIg0GmyFXVDAVTD4E6pQWeGdUsxUNgoQx59-UWcgNEJMNT0He1-HN1SZQQbxqr5TB6dWzP8SecBRoUFr4d4i7Aq_aTIZsUBb8lgrx3Tm6YUctu8A_MZ-qHrqVihNWNI87oG3MvBRnYi_nvBhjc8KtHiOQ9uf1sFmWeQPLj4zoEJgiy3mOJEFiRQVzt5tX8axhO7cD0XdAFovkEEiw', Base64Url::encode($signature));
        $this->assertTrue($rsa->verify($key, $data, $signature));
    }

    public function testRS384Sign()
    {
        $rsa = new RS384();
        $key = new JWK();
        $key->setValues(array(
                'kty' => 'RSA',
                'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e'   => 'AQAB',
                'p'   => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                'd'   => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                'q'   => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                'dp'  => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                'dq'  => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                'qi'  => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
        ));
        $data = 'aaa';

        $signature = $rsa->sign($key, $data);

        $this->assertEquals('H5fNc33al40J_OHlE9aZ7lAnyo0fcDRvf-ZttOefaw1MQTIQVReu-c0Cl96Hur4DanCq9HlRGNbAI7YcRq3f1Lj7DfnYurxEqEAG-7DhGx9Cxqpm4XBCVT54OXHZt6f7SCszYbsIJFeSCKTd1l97aiVnAOOWcIvdOrvwloti6nWqB8_vgf6_sPkTvZKOY79G09qwPHBkuk8vvIJIjZmEc7olZUe54EHI0ptfe_nvuIicV-_QWl8W6ADbhoUOvm6l6cvRsqgCuYfO6KYJ_mnc3Oza4BwNivnyX2FDeWQK0VeGw1nWOt46aFIYDMPw5s6iZAXvJiFKB5yD4BY8SAYeQQ', Base64Url::encode($signature));
        $this->assertTrue($rsa->verify($key, $data, $signature));
    }

    public function testRS512Sign()
    {
        $rsa = new RS512();
        $key = new JWK();
        $key->setValues(array(
                'kty' => 'RSA',
                'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e'   => 'AQAB',
                'p'   => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                'd'   => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                'q'   => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                'dp'  => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                'dq'  => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                'qi'  => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
        ));
        $data = 'aaa';

        $signature = $rsa->sign($key, $data);

        $this->assertEquals('eKVxA-jSyoCqG7usFnOuGy-MS96_JUrUj5uFC1aPWOiVDUrnzDdq2XTuBIQUBRy-sBlY7LWiNkpI67soMayWDvKR6VH5NFRwsc9JBNF9QP8dVuq4gU5xyRshLPne2bSdoWUyPbIsYPwAB6uxtOQEhQHwcI322RGfSBmH3_MGnYmdw2WUgN_1WImnKlL3pcFAqV7_DqQGZVKEMffXE71XmtCDbu34IhYtFQaLlZEBcya_PzEvH8eNC8Wm93knnfVRc0ZAToKO3DREJoe8mALCAb1M_7KlfbDBa2dSN5FD_Kmj2PvFGcp_fLIn-VzpKkP7J6VOeMRzRFWo5bTNroCXog', Base64Url::encode($signature));
        $this->assertTrue($rsa->verify($key, $data, $signature));
    }

    public function testPS256Sign()
    {
        $rsa = new PS256();
        $key = new JWK();
        $key->setValues(array(
                'kty' => 'RSA',
                'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e'   => 'AQAB',
                'p'   => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                'd'   => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                'q'   => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                'dp'  => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                'dq'  => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                'qi'  => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
        ));
        $data = 'aaa';

        $signature = $rsa->sign($key, $data);

        $this->assertTrue($rsa->verify($key, $data, $signature));
    }

    public function testPS384Sign()
    {
        $rsa = new PS384();
        $key = new JWK();
        $key->setValues(array(
                'kty' => 'RSA',
                'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e'   => 'AQAB',
                'p'   => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                'd'   => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                'q'   => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                'dp'  => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                'dq'  => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                'qi'  => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
        ));
        $data = 'aaa';

        $signature = $rsa->sign($key, $data);

        $this->assertTrue($rsa->verify($key, $data, $signature));
    }

    public function testPS512Sign()
    {
        $rsa = new PS512();
        $key = new JWK();
        $key->setValues(array(
                'kty' => 'RSA',
                'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e'   => 'AQAB',
                'p'   => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                'd'   => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                'q'   => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                'dp'  => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                'dq'  => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                'qi'  => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
        ));
        $data = 'aaa';

        $signature = $rsa->sign($key, $data);

        $this->assertTrue($rsa->verify($key, $data, $signature));
    }

    public function testCertificateConversion()
    {
        $details = RSAConverter::fromCertificateToArray("file://".__DIR__.DIRECTORY_SEPARATOR."private.key", "tests");
        $this->assertEquals($details, array(
                'kty' => 'RSA',
                'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e'   => 'AQAB',
                'p'   => '5BGU1c7af_5sFyfsa-onIJgo5BZu8uHvz3Uyb8OA0a-G9UPO1ShLYjX0wUfhZcFB7fwPtgmmYAN6wKGVce9eMAbX4PliPk3r-BcpZuPKkuLk_wFvgWAQ5Hqw2iEuwXLV0_e8c2gaUt_hyMC5-nFc4v0Bmv6NT6Pfry-UrK3BKWc',
                'd'   => 'Kp0KuZwCZGL1BLgsVM-N0edMNitl9wN5Hf2WOYDoIqOZNAEKzdJuenIMhITJjRFUX05GVL138uyp2js_pqDdY9ipA7rAKThwGuDdNphZHech9ih3DGEPXs-YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1_BpJthrFxjDRhw9DxJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEmtGoJnd9RE4oywKhgN7_TK7wXRlqA4UoRPiH2ACrdU-_cLQL9Jc0u0GqZJK31LDbOeN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn-CAQ',
                'q'   => 'zPD-B-nrngwF-O99BHvb47XGKR7ON8JCI6JxavzIkusMXCB8rMyYW8zLs68L8JLAzWZ34oMq0FPUnysBxc5nTF8Nb4BZxTZ5-9cHfoKrYTI3YWsmVW2FpCJFEjMs4NXZ28PBkS9b4zjfS2KhNdkmCeOYU0tJpNfwmOTI90qeUdU',
                'dp'  => 'aJrzw_kjWK9uDlTeaES2e4muv6bWbopYfrPHVWG7NPGoGdhnBnd70-jhgMEiTZSNU8VXw2u7prAR3kZ-kAp1DdwlqedYOzFsOJcPA0UZhbORyrBy30kbll_7u6CanFm6X4VyJxCpejd7jKNw6cCTFP1sfhWg5NVJ5EUTkPwE66M',
                'dq'  => 'Swz1-m_vmTFN_pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2dKZZfV2tbse5N9-JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFXEZQGUm_BVhoIb2_WPkjav6YSkguCUHt4HRd2YwE',
                'qi'  => 'BocuCOEOq-oyLDALwzMXU8gOf3IL1Q1_BWwsdoANoh6i179psxgE4JXToWcpXZQQqub8ngwE6uR9fpd3m6N_PL4T55vbDDyjPKmrL2ttC2gOtx9KrpPh-Z7LQRo4BE48nHJJrystKHfFlaH2G7JxHNgMBYVADyttN09qEoav8Os',
        ));

        $details = RSAConverter::fromCertificateToArray("file://".__DIR__.DIRECTORY_SEPARATOR."public.key", "tests");
        $this->assertEquals($details, array(
                'kty' => 'RSA',
                'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
                'e'   => 'AQAB',
        ));
    }
}
