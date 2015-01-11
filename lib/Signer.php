<?php

namespace SpomkyLabs\Jose;

use SpomkyLabs\Jose\Util\Base64Url;
use Jose\JWKInterface;
use Jose\JWTInterface;
use Jose\JWKSetInterface;
use Jose\SignerInterface;
use Jose\JSONSerializationModes;
use Jose\Operation\SignatureInterface;

/**
 * Class representing a JSON Web Token Manager.
 */
abstract class Signer implements SignerInterface
{
    /**
     * @return \Jose\JWKManagerInterface
     */
    abstract protected function getJWKManager();

    /**
     * @return \Jose\JWAManagerInterface
     */
    abstract protected function getJWAManager();

    /**
     * @return \Jose\JWAManagerInterface
     */
    abstract protected function getJWTManager();

    public function sign($jwt, JWKSetInterface $keys, $serialization = JSONSerializationModes::JSON_COMPACT_SERIALIZATION)
    {
        if ($jwt instanceof JWKInterface) {
            $input = $this->getJWTManager()->createJWT();
            $input->setPayload(json_encode($jwt))
                  ->setProtectedHeaderValue("cty", "jwk+json");
            $jwt = $input;
        } elseif ($jwt instanceof JWKSetInterface) {
            $input = $this->getJWTManager()->createJWT();
            $input->setPayload(json_encode($jwt))
                  ->setProtectedHeaderValue("cty", "jwkset+json");
            $jwt = $input;
        } elseif (is_array($jwt)) {
            $jwt->setPayload(json_encode($jwt->getPayload()));
        } elseif (is_array($jwt->getPayload())) {
            $jwt->setPayload(json_encode($jwt->getPayload()));
        }
        if (!$jwt instanceof JWTInterface) {
            throw new \InvalidArgumentException("Unsupported input type");
        }
        $jwt_payload = Base64Url::encode($jwt->getPayload());

        $signatures = array();
        foreach ($keys as $key) {
            $jwt_protected = $jwt->getProtectedHeader();
            $jwt_header = $jwt->getUnprotectedHeader();
            $alg = $jwt->getAlgorithm();

            if ($alg === null) {
                $alg = $key->getAlgorithm();
            }

            if (null === $alg) {
                throw new \RuntimeException("No 'alg' parameter set in the header or the key.");
            }
            $jwt_protected += array("alg" => $alg);

            $algorithm = $this->getJWAManager()->getAlgorithm($alg);
            if (null === $algorithm || !$algorithm instanceof SignatureInterface) {
                throw new \RuntimeException("The algorithm '$alg' is not supported.");
            }

            $protected = Base64Url::encode(json_encode($jwt_protected));
            $signature = Base64Url::encode($algorithm->sign($key, $protected.".".$jwt_payload, $jwt_protected));
            switch ($serialization) {
                case JSONSerializationModes::JSON_COMPACT_SERIALIZATION:
                    $signatures[] = $protected.".".$jwt_payload.".".$signature;
                    break;
                case JSONSerializationModes::JSON_FLATTENED_SERIALIZATION:
                    $result = array(
                        "payload" => $jwt_payload,
                        "protected" => $protected,
                        "signature" => $signature,
                    );
                    if (!empty($jwt_header)) {
                        $result["header"] = $jwt_header;
                    }
                    $signatures[] = json_encode($result);
                    break;
                case JSONSerializationModes::JSON_SERIALIZATION:
                    $result = array(
                        "protected" => $protected,
                        "signature" => $signature,
                    );
                    if (!empty($jwt_header)) {
                        $result["header"] = $jwt_header;
                    }
                    $signatures['signatures'][] = $result;
                    break;
                default:
                    throw new \RuntimeException("The serialization methode '$serialization' is not supported");
            }
        }

        if (count($signatures) === 0) {
            throw new \RuntimeException("No signature created");
        } elseif (count($signatures) === 1) {
            if (array_key_exists("signatures", $signatures)) {
                $signatures["payload"] = $jwt_payload;

                return json_encode($signatures);
            }

            return current($signatures);
        } else {
            return $signatures;
        }
    }
}
