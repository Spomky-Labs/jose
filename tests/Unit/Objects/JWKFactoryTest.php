<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWKFactory;
/**
 * Class JWKFactoryTest.
 *
 * @group JWKFactory
 * @group Unit
 */
class JWKFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function testCreateFromECCertificateFileInDERFormat()
    {
        $result = JWKFactory::createFromCertificateFile(__DIR__.'/../Certificates/EC/DER/prime256v1-cert.der');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"xEsr_55aqgFXdrbRNz1_WSNI8UaSUxCka2kGEN1bXsI","y":"SM45Hsr9dnUR6Ox-TpmNv2fbDX4CoVo-3patMUpXANA","x5t":"ZnnaQDssCKJQZLp6zyHssIZOa7o","x5t#256":"v7VlokKTGL3anRk8Nl0VcqVC9u5j2Fb5tdlQntUgDT4"}', json_encode($result));
    }
    public function testCreateFromECCertificateFileInPEMFormat()
    {
        $result = JWKFactory::createFromCertificateFile(__DIR__.'/../Certificates/EC/PEM/prime256v1-cert.pem');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"xEsr_55aqgFXdrbRNz1_WSNI8UaSUxCka2kGEN1bXsI","y":"SM45Hsr9dnUR6Ox-TpmNv2fbDX4CoVo-3patMUpXANA","x5t":"ZnnaQDssCKJQZLp6zyHssIZOa7o","x5t#256":"v7VlokKTGL3anRk8Nl0VcqVC9u5j2Fb5tdlQntUgDT4"}', json_encode($result));
    }

    public function testCreateFrom32kRSACertificateFileInDERFormat()
    {
        $result = JWKFactory::createFromCertificateFile(__DIR__.'/../Certificates/RSA/DER/32k-rsa-example-cert.der');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"RSA","n":"qzPFsFIf3cSes25DloV3y3d8gKMcZVE_EQ_6e_MZnyqDbuOEP39yQs3aunzbZRoO8Xw8lLoJNduiKKsco7odI753kBvz1eLyke-sWBVZttbnYyz9AE3ZXfAb9rHW2AxgIqHNsQOsLJS_douGZwxawNdE90WM4QG80bDpkxxHfObtmZIbZoOFSeokDHA5jokQGzJ65t6ARtQOIht84pIlAr8RO0vCUiJ0R4TdAffbdIukMcVfSoZBlZJ_q-yBtPoqB1Nmr1x1FqCtR81NrEtdp7CUHy4yLIskMzHTwJL24dx8zPS9RBIAuR6HO6soQwQgKY5NYmyaZGuWDrzw0Lor9_jjcx3x7NlXEUffGyUdT_bZ6owsgd-SpvnbqXPXIf-u5JH7afSUuajytHnGVilQOpEg06B0F-AumUEx8vdLPczCx0CED11mhRhT1eRQPJlzxgqA22SN1Yz0P55R8QbfFYcflpEtZbHmdvwMSipEoEUyI8aA9z268oNVnnAGhG3cOqk8-4HOvtqZ9LIc8jUcQLtWX-PJav9EePnWuV6pFwzvKcwl09m08xIfIh9DvFVJz3Fks-X6c1tVo2Valftlj8fnlzu9WgownkwhM4KN2UpcHcff4G-v9zckhcpROSzZ1ax5mPOUMF6B2OVawMhf3li9A9JEpBDxVu2-gZU6NbhvfH1f4PdNPUnlasPylHn4qz4S6_V1fuxho-2O_V72w3V5FDBi-m2D9vDVQvJtuoiJxUEyOWaxsenuzoFlq3jNHwm0SiabwVjaMyre4qktmHopLuLX2ixME3rbTtaXLAaly-t2X6oS4nFyhwP9f_WbJb4Yh_RDxksPj1hR_4nH43NTYjZBlLDM0YRb4xRzFmATQOUhPou6LSUbl8Tl2z7WYFzlcKgHwkWRaTGUV8Sz_h-_IfgZDvCtyyLhzvWOmfJBhsV1nTbDrr8DivZGH5huBNH88v_gbCVw36aAjH8BnmcHQ0ImUUwXoiB1iWSWB3x1xdYnAyQf5RV2PK86wVc4EBRxW6MeJHWZr-kFgHtcwk2ys8MewL8xlKs1S64APAWtD-WsLGEnUVMfM5EuWjoS9kB4BI4DC6M0uyDjaCuFu80wMmWfx9C3-Y2x7l5Lw0G4gRcUk-F3ONtKfsxMqAmV6aUVkXmdkX5LLa105CpIVqflM40CPl5mlVGEFlTf9u0zclyQ0_-qWt78ZzkpolPj9XKHikdYA_DKbvtfgtgNC07GIwBctoQsOrKGOxigeWzrAwfS9S5Wt7hvcs2R0Y04rXoeSTPbHWLumsJYLxC2HPtam3IxQJzCljIOFB5Sqi9WLO5l_yjmUGS2Fzy5DkuyFuC3o79rB-Vu0zpHQ5sHdbyYkfvi3QZx4jLuj2ki-3_1Qj7RfVdd1yWeudnFUy5QGfWh3-VoaK9UIZ1EeX62owXTGNOJovn9yMdwbXmy75qrkPXadFQG3lnuqq_Ucd8ZAYJvwfQb6uhTSv1kSFCpxyyaSBYjLU44QDF6FRh_QHLMBM2DVasOT0hsF2UWsIXUneoJHk_qVZSRmj5EDaIrWAUEZfL_geiwcW3_L3Y9iaHMkB93fHNsVEpLmTO-vLHZHYN0c-kKNVBw_40xGZ5ZgPJlT4JZVvBKuB2ka2OsSLcRXZvzZZZTnrRHb_9dngGkFpI0gc6gFu2d1mPIIFp6JS7AJ4_sYKE4yxuGG7IsA4ErnNBEK9Sr1XSu0_KfcIv63dm_AybDg1vmqMLCl5EiP9OIFsWdIM42970PH9h8Ri7KUn0D53RSRVkV38NW312A2JYCHfEfbIxyibEIrsusib98x6Bedh-3BpsWyih2XlDT6AFwJdD0cc_Uf56Vqv9waUtsSx-1xBwliZ35MKq-IfV6hcLnFgLhxsqakV8aFLAEzI8Ulned6zjRAC28aaDOZcFdKEMD0wHPUW8-9UTQxAgug8otEITWSkKubyXbdofpVa9Xwjq1-jLb4eylqey0RokKrHO6B7F3KtUF8Zsm0mGEg7nvUhjEBFL3AqkLke5Nb_78uqb3tzZF3iO6ghENar9s1DUIYqNkbMSeh7smgER_PBUB0MGMqRnx8qcr5t5yBEurZ7qq7-LYoJOoc6UwaPrQN_AFRou4ugiRrxIrvOwrDPr4y2zoi9XKnBBuYMnt2AkGVCNIA0WOKgmex4x_2Nri2JlRieAPwNPfW5PLkyPVRfw0dNzhg7csMl1Wctdw1JpHJhgMswuhYhRWGyzYWE4ZU8lvQWqA42MOKfUixAV4LmEzGz2eRQSPGWjLC85-mcxf_vssmD-mbuJAjzlLDzzwllrTDCQrt18DftpAAHhD5hG2HmQH9RDzcS3sniIx4p2zyqBHVQsWM74BlQjbODjgHRHerTgxYaNmh4KRA38lmb9omrUhI2Q0Lj5CF2of_Apd7fo8u6LpBpdEtirkn_7-9vPPiGerClV6lSjoNi_I_hHCneAq-3KZq7hM5XliJPvUrws_m0X5n6_fazdk-gOohEuF0Aq_1I5633sS-DGrFyan2K7oeoBGQN994-kweTR0lLko14nC5wnvizbsv7sDUNJTjM7LMYIrhKEILTjjGQ6WuCkYhQuM4RAnx74jFIchW8pS1tEnUcIOyBWgFB9M2zdbNmJg7vH43mmX408jMYVKs9CQz2Y7Vu33S0dSp9sWxM1KUREFVy1xTbVgKNxLxOzXiLOjm_b4EifAHZh_KTf0POm5RESU-TSrO29y5puTHL-PLuOE30jrxXaKhW5UzmQLUMhBGI7geYP6fE6QxyUi0gD_tLdMmzxTlZiOXkE6HnBQ-3Ar54uA-RFUhnzU-XT3wm--eINsvqyrHCyLQlmM71aBXnMlH5g0NJjdm42XSecTopWfFCfcNe1-ufpUuMGGg0C3LxVN5fkTmB2_6gai0AHh4dNhefGkKCZ5OcSNtA_UUI1nKr_wgPTI4X1catN9RE9mMYhOt-I5gOVRCihxDcUcBl2apUaFK-jHPs5rABqhykbi_dOS-zy42I86Vcu4B-_0GNlRIPRLZWFIhNRy_kfCOq4kb4SK9DjTvHsaq6YWMoL9Jk3JiqvH4yrMZ6T-XEFdJ8DGSc41lo1YJwhFUu0eGbGFKxyUBrHv1l9ByPrqWaiepnBBsda4y8G3SoiCfndwkbvLeE5ykYgurPpkYX_bau2PqsoAkiJ_GmbitKpXD71C5PmzvzLvpxkgC6hQq-v4L4WLelADvBpeikX9k23qhR5H3mkzNeMZgHyoFisy161cDgOlcg64g6C2UzJKlb5C1tOlQwM3fdm7cjBJXOjuxgi8Ewx6ov90eeaqIEfFvnUu1_IC_tFve9P_Us21Ak53vwStlHueYHtedJsHg84C5Ppt_z1LFR3Hh8m1pOnlb3kJw5eGpvsXweZrIIN0cvwz-NZ_orIxjPxLf23wy-y-lhObK17BfX1g-p759XtRSaG4Rj_QedauXHAA-SKgvwAOY3kBuWo9Oxx73JbC1kov55TkecHj2lXO_o49O5LCOa_h0nHIVb3JIGWot11sF_6zwNzFM2WtHFNu7Iu9hllumC8rvz3HEbylvSPQYzBQKy8NSyC6T9wbH6cAYY-vl59q1J4DwBH3DHKoMAec8InlnBO_ekJa8SMdQMZxov0BaxJc0W__29w2Sza0cBsMslfpRIWRWMb4jNpyvCyEVxrGf7AakOl0_9P3JCQ2o8cuf-BGg_z_iQ3aTMYVWi_pWuxnhh5NchjQU8C3dxvnEd0Te9mmDlvZh-N9GULo0tlzHz3WZniUp7mxVQ3nkeS31M0LIIF3SetSMjXrGJ_4bzAnb3EjH44eFuvgOiJ8ChXLCmHLtIpFa0WSC6YVpBxqfPrxke-DyB2Lvz_46MSQ4iKvCFhdYWxBtwXCZDN5Dt4XFpMknL_VnuVU8a5_rRqpEebv_VF1pBZsvfTK6UXFWAApFvL4ebApuLsFInG3uk89N2SbenTTiBGWZWZjsEFsvf3iSFZdQ2bgKSLmJIsuXV1mUPkzGEr8SsPLDKhGNZBevtka-CfnukEPn7a3K_O5sYcccEtYwx0VNiC6dWu7B_-pflffa1m4pbhdg6KfykDO9_jU_LE692dhWUzbv977zGUlOnmsEMeqmSTo9V5Hv0UsEDGEjoe9piKidoZ8JdAq1WIpSBfW9M2wtkZHbi2nlaBnKJuTaaNs_nWjbG4y73hEqEqRlQMKrLsJU7rsmy3h6x6-J_tXfkKpWu_Z_PhR-ca2RV4ldwUNejBhBomg-6bcSq1lHXGTpwc0wSDmIUfE2W6ZZysaFpmGpTDFjTDqfeeAwwbzShK7Uc-OnJVNiQ5w1KALJNjXURSfI61vyWRBMtFHaC7t6ixwDfv6pqEa0xeDe4xf4Z1qdX1Zfs4xpdAyzZWmslUsXIYDtiTXq6NYGjnCEPYqneVGOWhP6re0UfzeqqB6p6_L42UoqFrrjU7jnEWRlz6gxdU9qOJgLX3u6CIYtN6b44tpsqA23fNBiuf4SqoYimbd2YVjXFRFFNZ2XqJ-wBqYcD5xIfudMN6W5cAD4p5cTQ11_-EqIp8rDxiWOs-PN8SQTIE7ZYQ6na-lSITpchNybreE9SqhzluoY71DN8oQuUJHonrAW5Hh_VroGBxpbO9XdNhw0XrC-S9iH9DDEUedanM2DznPUZsHHutG8H0K9AEyWRS01sAwrF73ZG57qy5IciYMHZuFbkY0lzwbF-vd15jgNfP4JTmZD2sVWwVgI7Qp9T2hd0uuZL_huHl2baRCyC_DSI9c6p3q9Ud_tBN_yCcNcUVx0rS6EGfzM8VYOGwyiBVBAgVDjBXiKBsUVWA3ljfOtYhLKBDHkqhvoQaczSI2fKX7L7cwgXeBdckoaNhno6mCpZBamuyBZ1Iy6TnguQi59MCCKdiczIpfeumbSDEovy2IbQmPqld_JI6WOufgldiITu3hXR5KNazan2mc3NrKu1SEXZpdzb4wJZZ26U_1xE2GLMJru05yZoVNEkN72DhagM1R5oqHwPzRcn3ahdYvUzDoP6UHEpa76A23lqafY7F98l66hmAnXXlEKzEVwthYoxWANYtVsxs9NktNJdNMB3OCMnCo9BWkefmjlrzMJSkBP_1mfxN2o3W1tMNXpk5OQPO20_eWPF3iYhobSo8fcxzXtw9bg1BXr0TADj0hl_z4jw93wVGGLlsA3qYstay0I9yJgHBZmhxc7V1JzNWdwxIDmRgA5eCm1ELVBxpIup9WGZlUs1rzwqXzI-37i7l3dwFfCf_i2g8m-gNQjuM6YqkSz-XKcn-sJEg1XSMhoB15sgYE9U-2Oe-_EGLK0dOU2zyHO40F8ghvhKWpuAcITX_QnEMremwsiCl0PEnGZ98BXzlRvd1MFNc0ZUwzN-wTVxs4jNkteNbp0MjIKA5Y6FiCEX6koNWY9cLXSNg4XG4IsWRQrfIn2WWFz_nhzlaZNm_NUM1kmKRREPmsvQ","e":"AQAB","x5t":"KGApLybHWJmBwZGgBk07AlRD9nU","x5t#256":"YD12k6kc4xuh_5vEHMyyOFpGs6VqTyaKMlxg0Nt2crA"}', json_encode($result));
    }
    public function testCreateFrom32kRSACertificateFileInPEMFormat()
    {
        $result = JWKFactory::createFromCertificateFile(__DIR__.'/../Certificates/RSA/PEM/32k-rsa-example-cert.pem');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"RSA","n":"qzPFsFIf3cSes25DloV3y3d8gKMcZVE_EQ_6e_MZnyqDbuOEP39yQs3aunzbZRoO8Xw8lLoJNduiKKsco7odI753kBvz1eLyke-sWBVZttbnYyz9AE3ZXfAb9rHW2AxgIqHNsQOsLJS_douGZwxawNdE90WM4QG80bDpkxxHfObtmZIbZoOFSeokDHA5jokQGzJ65t6ARtQOIht84pIlAr8RO0vCUiJ0R4TdAffbdIukMcVfSoZBlZJ_q-yBtPoqB1Nmr1x1FqCtR81NrEtdp7CUHy4yLIskMzHTwJL24dx8zPS9RBIAuR6HO6soQwQgKY5NYmyaZGuWDrzw0Lor9_jjcx3x7NlXEUffGyUdT_bZ6owsgd-SpvnbqXPXIf-u5JH7afSUuajytHnGVilQOpEg06B0F-AumUEx8vdLPczCx0CED11mhRhT1eRQPJlzxgqA22SN1Yz0P55R8QbfFYcflpEtZbHmdvwMSipEoEUyI8aA9z268oNVnnAGhG3cOqk8-4HOvtqZ9LIc8jUcQLtWX-PJav9EePnWuV6pFwzvKcwl09m08xIfIh9DvFVJz3Fks-X6c1tVo2Valftlj8fnlzu9WgownkwhM4KN2UpcHcff4G-v9zckhcpROSzZ1ax5mPOUMF6B2OVawMhf3li9A9JEpBDxVu2-gZU6NbhvfH1f4PdNPUnlasPylHn4qz4S6_V1fuxho-2O_V72w3V5FDBi-m2D9vDVQvJtuoiJxUEyOWaxsenuzoFlq3jNHwm0SiabwVjaMyre4qktmHopLuLX2ixME3rbTtaXLAaly-t2X6oS4nFyhwP9f_WbJb4Yh_RDxksPj1hR_4nH43NTYjZBlLDM0YRb4xRzFmATQOUhPou6LSUbl8Tl2z7WYFzlcKgHwkWRaTGUV8Sz_h-_IfgZDvCtyyLhzvWOmfJBhsV1nTbDrr8DivZGH5huBNH88v_gbCVw36aAjH8BnmcHQ0ImUUwXoiB1iWSWB3x1xdYnAyQf5RV2PK86wVc4EBRxW6MeJHWZr-kFgHtcwk2ys8MewL8xlKs1S64APAWtD-WsLGEnUVMfM5EuWjoS9kB4BI4DC6M0uyDjaCuFu80wMmWfx9C3-Y2x7l5Lw0G4gRcUk-F3ONtKfsxMqAmV6aUVkXmdkX5LLa105CpIVqflM40CPl5mlVGEFlTf9u0zclyQ0_-qWt78ZzkpolPj9XKHikdYA_DKbvtfgtgNC07GIwBctoQsOrKGOxigeWzrAwfS9S5Wt7hvcs2R0Y04rXoeSTPbHWLumsJYLxC2HPtam3IxQJzCljIOFB5Sqi9WLO5l_yjmUGS2Fzy5DkuyFuC3o79rB-Vu0zpHQ5sHdbyYkfvi3QZx4jLuj2ki-3_1Qj7RfVdd1yWeudnFUy5QGfWh3-VoaK9UIZ1EeX62owXTGNOJovn9yMdwbXmy75qrkPXadFQG3lnuqq_Ucd8ZAYJvwfQb6uhTSv1kSFCpxyyaSBYjLU44QDF6FRh_QHLMBM2DVasOT0hsF2UWsIXUneoJHk_qVZSRmj5EDaIrWAUEZfL_geiwcW3_L3Y9iaHMkB93fHNsVEpLmTO-vLHZHYN0c-kKNVBw_40xGZ5ZgPJlT4JZVvBKuB2ka2OsSLcRXZvzZZZTnrRHb_9dngGkFpI0gc6gFu2d1mPIIFp6JS7AJ4_sYKE4yxuGG7IsA4ErnNBEK9Sr1XSu0_KfcIv63dm_AybDg1vmqMLCl5EiP9OIFsWdIM42970PH9h8Ri7KUn0D53RSRVkV38NW312A2JYCHfEfbIxyibEIrsusib98x6Bedh-3BpsWyih2XlDT6AFwJdD0cc_Uf56Vqv9waUtsSx-1xBwliZ35MKq-IfV6hcLnFgLhxsqakV8aFLAEzI8Ulned6zjRAC28aaDOZcFdKEMD0wHPUW8-9UTQxAgug8otEITWSkKubyXbdofpVa9Xwjq1-jLb4eylqey0RokKrHO6B7F3KtUF8Zsm0mGEg7nvUhjEBFL3AqkLke5Nb_78uqb3tzZF3iO6ghENar9s1DUIYqNkbMSeh7smgER_PBUB0MGMqRnx8qcr5t5yBEurZ7qq7-LYoJOoc6UwaPrQN_AFRou4ugiRrxIrvOwrDPr4y2zoi9XKnBBuYMnt2AkGVCNIA0WOKgmex4x_2Nri2JlRieAPwNPfW5PLkyPVRfw0dNzhg7csMl1Wctdw1JpHJhgMswuhYhRWGyzYWE4ZU8lvQWqA42MOKfUixAV4LmEzGz2eRQSPGWjLC85-mcxf_vssmD-mbuJAjzlLDzzwllrTDCQrt18DftpAAHhD5hG2HmQH9RDzcS3sniIx4p2zyqBHVQsWM74BlQjbODjgHRHerTgxYaNmh4KRA38lmb9omrUhI2Q0Lj5CF2of_Apd7fo8u6LpBpdEtirkn_7-9vPPiGerClV6lSjoNi_I_hHCneAq-3KZq7hM5XliJPvUrws_m0X5n6_fazdk-gOohEuF0Aq_1I5633sS-DGrFyan2K7oeoBGQN994-kweTR0lLko14nC5wnvizbsv7sDUNJTjM7LMYIrhKEILTjjGQ6WuCkYhQuM4RAnx74jFIchW8pS1tEnUcIOyBWgFB9M2zdbNmJg7vH43mmX408jMYVKs9CQz2Y7Vu33S0dSp9sWxM1KUREFVy1xTbVgKNxLxOzXiLOjm_b4EifAHZh_KTf0POm5RESU-TSrO29y5puTHL-PLuOE30jrxXaKhW5UzmQLUMhBGI7geYP6fE6QxyUi0gD_tLdMmzxTlZiOXkE6HnBQ-3Ar54uA-RFUhnzU-XT3wm--eINsvqyrHCyLQlmM71aBXnMlH5g0NJjdm42XSecTopWfFCfcNe1-ufpUuMGGg0C3LxVN5fkTmB2_6gai0AHh4dNhefGkKCZ5OcSNtA_UUI1nKr_wgPTI4X1catN9RE9mMYhOt-I5gOVRCihxDcUcBl2apUaFK-jHPs5rABqhykbi_dOS-zy42I86Vcu4B-_0GNlRIPRLZWFIhNRy_kfCOq4kb4SK9DjTvHsaq6YWMoL9Jk3JiqvH4yrMZ6T-XEFdJ8DGSc41lo1YJwhFUu0eGbGFKxyUBrHv1l9ByPrqWaiepnBBsda4y8G3SoiCfndwkbvLeE5ykYgurPpkYX_bau2PqsoAkiJ_GmbitKpXD71C5PmzvzLvpxkgC6hQq-v4L4WLelADvBpeikX9k23qhR5H3mkzNeMZgHyoFisy161cDgOlcg64g6C2UzJKlb5C1tOlQwM3fdm7cjBJXOjuxgi8Ewx6ov90eeaqIEfFvnUu1_IC_tFve9P_Us21Ak53vwStlHueYHtedJsHg84C5Ppt_z1LFR3Hh8m1pOnlb3kJw5eGpvsXweZrIIN0cvwz-NZ_orIxjPxLf23wy-y-lhObK17BfX1g-p759XtRSaG4Rj_QedauXHAA-SKgvwAOY3kBuWo9Oxx73JbC1kov55TkecHj2lXO_o49O5LCOa_h0nHIVb3JIGWot11sF_6zwNzFM2WtHFNu7Iu9hllumC8rvz3HEbylvSPQYzBQKy8NSyC6T9wbH6cAYY-vl59q1J4DwBH3DHKoMAec8InlnBO_ekJa8SMdQMZxov0BaxJc0W__29w2Sza0cBsMslfpRIWRWMb4jNpyvCyEVxrGf7AakOl0_9P3JCQ2o8cuf-BGg_z_iQ3aTMYVWi_pWuxnhh5NchjQU8C3dxvnEd0Te9mmDlvZh-N9GULo0tlzHz3WZniUp7mxVQ3nkeS31M0LIIF3SetSMjXrGJ_4bzAnb3EjH44eFuvgOiJ8ChXLCmHLtIpFa0WSC6YVpBxqfPrxke-DyB2Lvz_46MSQ4iKvCFhdYWxBtwXCZDN5Dt4XFpMknL_VnuVU8a5_rRqpEebv_VF1pBZsvfTK6UXFWAApFvL4ebApuLsFInG3uk89N2SbenTTiBGWZWZjsEFsvf3iSFZdQ2bgKSLmJIsuXV1mUPkzGEr8SsPLDKhGNZBevtka-CfnukEPn7a3K_O5sYcccEtYwx0VNiC6dWu7B_-pflffa1m4pbhdg6KfykDO9_jU_LE692dhWUzbv977zGUlOnmsEMeqmSTo9V5Hv0UsEDGEjoe9piKidoZ8JdAq1WIpSBfW9M2wtkZHbi2nlaBnKJuTaaNs_nWjbG4y73hEqEqRlQMKrLsJU7rsmy3h6x6-J_tXfkKpWu_Z_PhR-ca2RV4ldwUNejBhBomg-6bcSq1lHXGTpwc0wSDmIUfE2W6ZZysaFpmGpTDFjTDqfeeAwwbzShK7Uc-OnJVNiQ5w1KALJNjXURSfI61vyWRBMtFHaC7t6ixwDfv6pqEa0xeDe4xf4Z1qdX1Zfs4xpdAyzZWmslUsXIYDtiTXq6NYGjnCEPYqneVGOWhP6re0UfzeqqB6p6_L42UoqFrrjU7jnEWRlz6gxdU9qOJgLX3u6CIYtN6b44tpsqA23fNBiuf4SqoYimbd2YVjXFRFFNZ2XqJ-wBqYcD5xIfudMN6W5cAD4p5cTQ11_-EqIp8rDxiWOs-PN8SQTIE7ZYQ6na-lSITpchNybreE9SqhzluoY71DN8oQuUJHonrAW5Hh_VroGBxpbO9XdNhw0XrC-S9iH9DDEUedanM2DznPUZsHHutG8H0K9AEyWRS01sAwrF73ZG57qy5IciYMHZuFbkY0lzwbF-vd15jgNfP4JTmZD2sVWwVgI7Qp9T2hd0uuZL_huHl2baRCyC_DSI9c6p3q9Ud_tBN_yCcNcUVx0rS6EGfzM8VYOGwyiBVBAgVDjBXiKBsUVWA3ljfOtYhLKBDHkqhvoQaczSI2fKX7L7cwgXeBdckoaNhno6mCpZBamuyBZ1Iy6TnguQi59MCCKdiczIpfeumbSDEovy2IbQmPqld_JI6WOufgldiITu3hXR5KNazan2mc3NrKu1SEXZpdzb4wJZZ26U_1xE2GLMJru05yZoVNEkN72DhagM1R5oqHwPzRcn3ahdYvUzDoP6UHEpa76A23lqafY7F98l66hmAnXXlEKzEVwthYoxWANYtVsxs9NktNJdNMB3OCMnCo9BWkefmjlrzMJSkBP_1mfxN2o3W1tMNXpk5OQPO20_eWPF3iYhobSo8fcxzXtw9bg1BXr0TADj0hl_z4jw93wVGGLlsA3qYstay0I9yJgHBZmhxc7V1JzNWdwxIDmRgA5eCm1ELVBxpIup9WGZlUs1rzwqXzI-37i7l3dwFfCf_i2g8m-gNQjuM6YqkSz-XKcn-sJEg1XSMhoB15sgYE9U-2Oe-_EGLK0dOU2zyHO40F8ghvhKWpuAcITX_QnEMremwsiCl0PEnGZ98BXzlRvd1MFNc0ZUwzN-wTVxs4jNkteNbp0MjIKA5Y6FiCEX6koNWY9cLXSNg4XG4IsWRQrfIn2WWFz_nhzlaZNm_NUM1kmKRREPmsvQ","e":"AQAB","x5t":"KGApLybHWJmBwZGgBk07AlRD9nU","x5t#256":"YD12k6kc4xuh_5vEHMyyOFpGs6VqTyaKMlxg0Nt2crA"}', json_encode($result));
    }

    public function testCreateFromPrivateEC256KeyFileEncrypted()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/private.es256.encrypted.key', 'test');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-256","d":"q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ","x":"vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U","y":"oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE"}', json_encode($result));
    }

    public function testCreateFromPrivateEC384KeyFileEncrypted()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/private.es384.encrypted.key', 'test');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-384","d":"pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr","x":"6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ","y":"b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU"}', json_encode($result));
    }

    public function testCreateFromPrivateEC512KeyFileEncrypted()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/private.es512.encrypted.key', 'test');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-521","d":"Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE","x":"AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS","y":"AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC"}', json_encode($result));
    }

    public function testCreateFromPublicEC256KeyFile()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/public.es256.key');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U","y":"oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE"}', json_encode($result));
    }

    public function testCreateFromPublicEC384KeyFile()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/public.es384.key');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-384","x":"6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ","y":"b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU"}', json_encode($result));
    }

    public function testCreateFromPublicEC512KeyFile()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/public.es512.key');

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-521","x":"AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS","y":"AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC"}', json_encode($result));
    }

    public function testCreateFromJKU()
    {
        $result = JWKFactory::createFromJKU('https://www.googleapis.com/oauth2/v3/certs');

        $this->assertInstanceOf('\Jose\Object\JWKSetInterface', $result);
        $this->assertEquals(2, $result->count());
    }

    public function testCreateFromX5U()
    {
        $result = JWKFactory::createFromX5U('https://www.googleapis.com/oauth2/v1/certs');

        $this->assertInstanceOf('\Jose\Object\JWKSetInterface', $result);
        $this->assertEquals(2, $result->count());
    }

    public function testCreateFromJKU2()
    {
        $result = JWKFactory::createFromValues([
            'kty' => 'EC',
            'crv' => 'P-521',
            'd'   => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x'   => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y'   => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',

        ]);

        $this->assertInstanceOf('\Jose\Object\JWKInterface', $result);
        $this->assertEquals('{"kty":"EC","crv":"P-521","d":"Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE","x":"AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS","y":"AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC"}', json_encode($result));
    }
}
