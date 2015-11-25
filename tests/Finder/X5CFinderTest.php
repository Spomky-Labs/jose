<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Finder\X5CFinder;

/**
 * @group Finder
 */
class X5CFinderTest extends \PHPUnit_Framework_TestCase
{
    public function testWithValidParameter1()
    {
        $finder = new X5CFinder();
        $result = $finder->findJWK([
            "x5c" =>
                [
                    "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB
                     gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD
                     VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1
                     wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg
                     NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV
                     QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w
                     YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH
                     YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66
                     s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6
                     SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn
                     fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq
                     PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk
                     aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA
                     QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL
                     +9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1
                     zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL
                     2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo
                     4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq
                     gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="
                ],
            ]
        );

        $this->assertEquals([
            'kty'     => 'RSA',
            "n"       => "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
            "e"       => "AQAB",
            "x5t"     => "4pNenEBLv0JpLIdugWxQkOsZcK0",
            "x5t#256" => "pJm2BBpkB8y7tCqrWM0X37WOmQTO8zQw-VpxVgBb21I",
        ], $result);
    }

    public function testWithValidParameter2()
    {
        $finder = new X5CFinder();
        $result = $finder->findJWK([
            "x5c" =>
                [
                    'MIIEqzCCA5OgAwIBAgIDAOTBMA0GCSqGSIb3DQEBCwUAMEcxCzAJBgNVBAYTAlVT
                     MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMSAwHgYDVQQDExdSYXBpZFNTTCBTSEEy
                     NTYgQ0EgLSBHMzAeFw0xNDEyMDMwMjEyMDlaFw0xNjExMTYxOTI5MjNaMIGQMRMw
                     EQYDVQQLEwpHVDExMjEwNDA1MTEwLwYDVQQLEyhTZWUgd3d3LnJhcGlkc3NsLmNv
                     bS9yZXNvdXJjZXMvY3BzIChjKTE0MS8wLQYDVQQLEyZEb21haW4gQ29udHJvbCBW
                     YWxpZGF0ZWQgLSBSYXBpZFNTTChSKTEVMBMGA1UEAwwMKi5waHBuZXQub3JnMIIB
                     IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAQtpDsGC/pVXUUaJdyVo3Py
                     3ocozUzZqpXHmZ2RoWYuSOU9COtI1nx4euD5eSEPCVosSSZUPS+zMJUAZpAwnI47
                     Tnx6XIQ1j2PibP6HEVvyNCa7V2Pm+Mek31DcOCweyqndV1XGzFuy5U3bosCu5Rgz
                     PIkEfa70b2Dss1yCKtBswXkfwVwZ4y109mjQqopvSxTRW+gyFCgILK1vit3MblUY
                     8d2hyurcY0Y9Ltb90VrR9RmE2SkU2x5Na24PGn+ZwFg5RYV68JaWRH9eYWyyMhv1
                     GRpZ1kedmARnzKM3C81GtXw82A5CK8eeLsRFLX/+Igue+Es0dn4Kk7lJta51XwID
                     AQABo4IBVDCCAVAwHwYDVR0jBBgwFoAUw5zz/NNGCDS7zkZ/oHxb8+IIy1kwVwYI
                     KwYBBQUHAQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vZ3Yuc3ltY2QuY29tMCYG
                     CCsGAQUFBzAChhpodHRwOi8vZ3Yuc3ltY2IuY29tL2d2LmNydDAOBgNVHQ8BAf8E
                     BAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMCMGA1UdEQQcMBqC
                     DCoucGhwbmV0Lm9yZ4IKcGhwbmV0Lm9yZzArBgNVHR8EJDAiMCCgHqAchhpodHRw
                     Oi8vZ3Yuc3ltY2IuY29tL2d2LmNybDAMBgNVHRMBAf8EAjAAMEUGA1UdIAQ+MDww
                     OgYKYIZIAYb4RQEHNjAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5yYXBpZHNz
                     bC5jb20vbGVnYWwwDQYJKoZIhvcNAQELBQADggEBAJWvtD50H86gflawq05fEUUM
                     sr7LD1kEP2lbnJ7FRb0fmC4wtsUnq5hxrAjxyu7vpHXSJ3rp8bI2MUm1aFZBQKcx
                     HpgsIfaKrFwU5YD93Wx95K3ldwYKx2aayy1A9jDXedwGNlRdR+oJNCO6WOxvVcej
                     4RhAPgIKSrqVtdY+Vvz7zWtkQr7vHFvMgJDohxz+BNbqVNKOOyAyYtRsgMtBEBVe
                     LLLZG0yqS0DuinEEZTQSyRwa+sFERVjRa1BEP43+D8ZMgvQaI5V/xX+SztSXSPLw
                     n9ZQw8YJcxPiePguPy0BiqY1hUfv6S7Wlgeo7DcKKM6+7thJi+26IRYVUqK5XXM=',
                    'MIIEJTCCAw2gAwIBAgIDAjp3MA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT
                     MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
                     YWwgQ0EwHhcNMTQwODI5MjEzOTMyWhcNMjIwNTIwMjEzOTMyWjBHMQswCQYDVQQG
                     EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEgMB4GA1UEAxMXUmFwaWRTU0wg
                     U0hBMjU2IENBIC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCv
                     VJvZWF0eLFbG1eh/9H0WA//Qi1rkjqfdVC7UBMBdmJyNkA+8EGVf2prWRHzAn7Xp
                     SowLBkMEu/SW4ib2YQGRZjEiwzQ0Xz8/kS9EX9zHFLYDn4ZLDqP/oIACg8PTH2lS
                     1p1kD8mD5xvEcKyU58Okaiy9uJ5p2L4KjxZjWmhxgHsw3hUEv8zTvz5IBVV6s9cQ
                     DAP8m/0Ip4yM26eO8R5j3LMBL3+vV8M8SKeDaCGnL+enP/C1DPz1hNFTvA5yT2AM
                     QriYrRmIV9cE7Ie/fodOoyH5U/02mEiN1vi7SPIpyGTRzFRIU4uvt2UevykzKdkp
                     YEj4/5G8V1jlNS67abZZAgMBAAGjggEdMIIBGTAfBgNVHSMEGDAWgBTAephojYn7
                     qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUw5zz/NNGCDS7zkZ/oHxb8+IIy1kwEgYD
                     VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwNQYDVR0fBC4wLDAqoCig
                     JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMC4GCCsGAQUF
                     BwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL2cuc3ltY2QuY29tMEwGA1UdIARF
                     MEMwQQYKYIZIAYb4RQEHNjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vd3d3Lmdlb3Ry
                     dXN0LmNvbS9yZXNvdXJjZXMvY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCjWB7GQzKs
                     rC+TeLfqrlRARy1+eI1Q9vhmrNZPc9ZE768LzFvB9E+aj0l+YK/CJ8cW8fuTgZCp
                     fO9vfm5FlBaEvexJ8cQO9K8EWYOHDyw7l8NaEpt7BDV7o5UzCHuTcSJCs6nZb0+B
                     kvwHtnm8hEqddwnxxYny8LScVKoSew26T++TGezvfU5ho452nFnPjJSxhJf3GrkH
                     uLLGTxN5279PURt/aQ1RKsHWFf83UTRlUfQevjhq7A6rvz17OQV79PP7GqHQyH5O
                     ZI3NjGFVkP46yl0lD/gdo0p0Vk8aVUBwdSWmMy66S6VdU5oNMOGNX2Esr8zvsJmh
                     gP8L8mJMcCaY',
                    'MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
                     MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
                     YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG
                     EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg
                     R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9
                     9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq
                     fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv
                     iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU
                     1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+
                     bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW
                     MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA
                     ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l
                     uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn
                     Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS
                     tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF
                     PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un
                     hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV
                     5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==',
                ],
            ]
        );

        $this->assertEquals([
            'kty'     => 'RSA',
            "n"       => "vAQtpDsGC_pVXUUaJdyVo3Py3ocozUzZqpXHmZ2RoWYuSOU9COtI1nx4euD5eSEPCVosSSZUPS-zMJUAZpAwnI47Tnx6XIQ1j2PibP6HEVvyNCa7V2Pm-Mek31DcOCweyqndV1XGzFuy5U3bosCu5RgzPIkEfa70b2Dss1yCKtBswXkfwVwZ4y109mjQqopvSxTRW-gyFCgILK1vit3MblUY8d2hyurcY0Y9Ltb90VrR9RmE2SkU2x5Na24PGn-ZwFg5RYV68JaWRH9eYWyyMhv1GRpZ1kedmARnzKM3C81GtXw82A5CK8eeLsRFLX_-Igue-Es0dn4Kk7lJta51Xw",
            "e"       => "AQAB",
            "x5t"     => "W5um-UKlTZcSB84X3INJcDnY4ME",
            "x5t#256" => "UJMIANU7ytKwE1JCKh5IXlzIt3QIF6LDBe5RMXMZDfs",
        ], $result);
    }
}
