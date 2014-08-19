<?php

namespace SpomkyLabs\JOSE;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class JWTManager implements JWTManagerInterface
{
    abstract protected function getKeyManager();

    public function load($data)
    {
        //We try to identity if the data is a JSON object. In this case, we consider that data is a JWE or JWS Seralization object
        if (json_decode($data,true) !== null) {
            return $this->loadSerializedJson($data);
        }

        //Else, we consider that data is a JWE or JWS Compact Seralized object
        return $this->loadCompactSerializedJson($data);
    }

    public function convertToCompactSerializedJson(JWTInterface $jwt, JWKInterface $jwk)
    {
        if (!$jwk->isPrivate()) {
            throw new \Exception("The key is not a private key");
        }

        $header = Base64Url::encode(json_encode($jwt->getHeader()));

        //We try to encrypt first
        if ($this->canEncrypt($jwk)) {
            $data = array(
                'header'=>$jwt->getHeader(),
            );
            $key = $this->getKeyManager()->createJWK(array(
                "enc" =>$data['header']['enc'],
            ));
            if (!$key instanceof JWKContentEncryptionInterface) {
                throw new \Exception("The content encryption algorithm is not valid");
            }
            $key->createIV()
                ->createCEK();
            $data['iv'] = $key->getValue('iv');
            $data['encrypted_cek'] = $jwk->encrypt($key->getValue('cek'));
            $data['encrypted_data'] = $key->encrypt(is_array($jwt->getPayload()) ? json_encode($jwt->getPayload()) : $jwt->getPayload());
            $data['authentication_tag'] = $key->calculateAuthenticationTag($data);

            return implode(".", array(
                Base64Url::encode(json_encode($data['header'])),
                Base64Url::encode($data['encrypted_cek']),
                Base64Url::encode($data['iv']),
                Base64Url::encode($data['encrypted_data']),
                Base64Url::encode($data['authentication_tag']),
            ));
        }
        //Then we try to sign
        if ($this->canSign($jwk)) {
            $payload = Base64Url::encode(json_encode($jwt->getPayload()));
            $signature = $jwk->sign($header.".".$payload);

            return $header.".".$payload.".".$signature;
        }
        throw new \Exception("The key can not sign or encrypt data");
    }

    public function convertToSerializedJson(JWTInterface $jwt, JWKSetInterface $jwk_set)
    {
        throw new \Exception('Not implemented');
    }

    private function loadSerializedJson($data)
    {
        throw new \Exception('Not implemented');
    }

    private function loadCompactSerializedJson($data)
    {
        $parts = explode('.', $data);

        switch (count($parts)) {
            case 3:
                return $this->loadCompactSerializedJWS($parts);
            case 5:
                return $this->loadCompactSerializedJWE($parts);
            default:
                throw new \InvalidArgumentException('Unable to load data');
        }
    }

    private function loadCompactSerializedJWE($parts)
    {
        $data = array(
            "header" => json_decode(Base64Url::decode($parts[0]), true),
            "encrypted_cek" => Base64Url::decode($parts[1]),
            "iv" => Base64Url::decode($parts[2]),
            "encrypted_data" => Base64Url::decode($parts[3]),
            "authentication_tag" => Base64Url::decode($parts[4]),
        );

        $key_set = $this->getKeyManager()->findJWKSetByHeader($data['header']);

        foreach ($key_set->getKeys() as $key) {
            if ($this->canDecrypt($key)) {
                $cek = null;
                //try {
                    $cek = $key->decrypt($data['encrypted_cek']);
                //} catch (\Exception $e) {}
                if ($cek !== null) {
                    return $this->decryptContent($data, $cek);
                }
            }
        }
        throw new \InvalidArgumentException('Unable to find the key used to encrypt this token');
    }

    private function decryptContent(array $data, $cek)
    {
        $key = $this->getKeyManager()->createJWK(array(
            "enc" =>$data['header']['enc'],
            "cek" =>$cek,
            "iv"  =>$data["iv"],
        ));

        if ($key instanceof JWKAuthenticationTagInterface) {
            if (!$key->checkAuthenticationTag($data)) {
                throw new \Exception("Authentication Tag verification failed");
            }
        }
        //We must check the authentication tag here

        $dec = $key->decrypt($data['encrypted_data']);

        if (isset($data['header']['cty'])) {
            switch ($data['header']['cty']) {
                case 'jwk+json':
                    return $this->getKeyManager()->createJWK(json_decode($dec,true));
                case 'jwkset+json':
                    return $this->getKeyManager()->createJWKSet(json_decode($dec,true));
                default:
                    return $dec;
                    break;
            }
        }

        return $dec;
    }

    private function loadCompactSerializedJWS($parts)
    {
        $header     = json_decode(Base64Url::decode($parts[0]), true);
        $payload    = json_decode(Base64Url::decode($parts[1]), true);

        $key_set = $this->getKeyManager()->findJWKSetByHeader($header);

        if ($key_set->isEmpty()) {
            throw new \Exception('Unable to find the key used for this token');
        }

        foreach ($key_set->getKeys() as $key) {
            if ($this->canVerify($key) && $key->verify($parts[0].".".$parts[1], $parts[2]) === true) {
                $jwt = $this->createJWT();
                $jwt->setHeader($header);
                $jwt->setPayload($payload);

                return $jwt;
            }
        }
        throw new \InvalidArgumentException('Unable to find the key used to sign this token');
    }

    private function canEncrypt(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "encrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "encrypt") === -1) {
            return false;
        }

        //If the JWK does not implement JWKEncryptInterface, we can not use it
        return $jwk instanceof JWKEncryptInterface;
    }

    private function canDecrypt(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "enc", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "enc") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "decrypt", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "decrypt") === -1) {
            return false;
        }

        //If the JWK does not implement JWKDecryptInterface, we can not use it
        return $jwk instanceof JWKDecryptInterface;
    }

    private function canSign(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "sig", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "sign", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "sign") === -1) {
            return false;
        }

        //If the JWK does not implement JWKSignInterface, we can not use it
        return $jwk instanceof JWKSignInterface;
    }

    private function canVerify(JWKInterface $jwk)
    {
        //If "use" parameter is not null or not "sig", we can not use it
        $use = $jwk->getValue('use');
        if ($use !== null && $use !== "sig") {
            return false;
        }

        //If "key_ops" parameter is not null or does not contain "verify", we can not use it
        $key_ops = $jwk->getValue('key_ops');
        if ($key_ops !== null && strpos($key_ops, "verify") === -1) {
            return false;
        }

        //If the JWK does not implement JWKVerifyInterface, we can not use it
        return $jwk instanceof JWKVerifyInterface;
    }
}
