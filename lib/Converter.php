<?php

namespace SpomkyLabs\Jose;

use Jose\JSONSerializationModes;

class Converter
{
    /**
     * This function will try to convert JWS/JWE from a serialization mode into an other.
     * It always returns an array:.
     *
     * @param array|string $input    The JWS/JWE to convert
     * @param string       $mode     Output mode
     * @param bool         $toString If true, the output is serialized, else, an array is returned
     *
     * @return array|string
     */
    public static function convert($input, $mode, $toString = true)
    {
        $prepared = self::getPreparedInput($input);
        switch ($mode) {
            case JSONSerializationModes::JSON_SERIALIZATION:
                return $toString ? json_encode($prepared) : $prepared;
            case JSONSerializationModes::JSON_FLATTENED_SERIALIZATION:
                return self::fromSerializationToFlattenedSerialization($prepared, $toString);
            case JSONSerializationModes::JSON_COMPACT_SERIALIZATION:
                return self::fromSerializationToCompactSerialization($prepared);
            default:
                throw new \InvalidArgumentException(sprintf("The serialization method '%s' is not supported.", $mode));
        }
    }

    /**
     * This function will merge JWS or JWE. The result is always represents a JWS or JWE Json Serialization.
     * It accepts multiple arguments.
     *
     * @return array
     */
    public static function merge()
    {
        $inputs = array();

        //We convert all parameters into Json Serialization
        foreach (func_get_args() as $arg) {
            $inputs[] = json_decode(self::convert($arg, JSONSerializationModes::JSON_SERIALIZATION), true);
        }

        if (empty($inputs)) {
            throw new \InvalidArgumentException('Nothing to merge');
        }
        //We verify there is only JWS or JWE
        $type = null;
        foreach ($inputs as $input) {
            if (is_null($type)) {
                $type = self::getType($input);
            } else {
                $current = self::getType($input);
                if ($current !== $type) {
                    throw new \InvalidArgumentException('You cannot merge JWS and JWE');
                }
            }
        }
        switch ($type) {
            case 'JWS':
                return json_encode(self::mergeJWS($inputs));
            case 'JWE':
                return json_encode(self::mergeJWE($inputs));
            default:
                throw new \InvalidArgumentException('Unsupported input type');
        }
    }

    /**
     * @param array $inputs
     *
     * @return array
     */
    private static function mergeJWS($inputs)
    {
        //We determine if all common information are identical
        foreach (array('payload') as $key) {
            $$key = null;
        }
        foreach ($inputs as $input) {
            foreach (array('payload') as $key) {
                if (is_null($$key) && array_key_exists($key, $input)) {
                    $$key = $input[$key];
                } elseif (!is_null($$key) && array_key_exists($key, $input)) {
                    if ($$key !== $input[$key]) {
                        throw new \InvalidArgumentException('Unable to merge: parameter "%s" is not identical with other inputs');
                    }
                }
            }
        }
        //All good!
        $result = array();
        foreach (array('payload') as $key) {
            if (!is_null($$key)) {
                $result[$key] = $$key;
            }
        }
        $result['signatures'] = array();
        foreach ($inputs as $input) {
            foreach ($input['signatures'] as $recipient) {
                $temp = array();
                foreach (array('header', 'protected', 'signature') as $key) {
                    if (array_key_exists($key, $recipient)) {
                        $temp[$key] = $recipient[$key];
                    }
                }
                $result['signatures'][] = $temp;
            }
        }

        return $result;
    }

    /**
     * @param array $inputs
     *
     * @return array
     */
    private static function mergeJWE($inputs)
    {
        //We determine if all common information are identical
        foreach (array('ciphertext', 'protected', 'unprotected', 'iv', 'aad', 'tag') as $key) {
            $$key = null;
        }
        foreach ($inputs as $input) {
            foreach (array('ciphertext', 'protected', 'unprotected', 'iv', 'aad', 'tag') as $key) {
                if (is_null($$key) && array_key_exists($key, $input)) {
                    $$key = $input[$key];
                } elseif (!is_null($$key) && array_key_exists($key, $input)) {
                    if ($$key !== $input[$key]) {
                        throw new \InvalidArgumentException('Unable to merge: parameter "%s" is not identical with other inputs');
                    }
                }
            }
        }
        //All good!
        $result = array();
        foreach (array('ciphertext', 'protected', 'unprotected', 'iv', 'aad', 'tag') as $key) {
            if (!is_null($$key)) {
                $result[$key] = $$key;
            }
        }
        $result['recipients'] = array();
        foreach ($inputs as $input) {
            foreach ($input['recipients'] as $recipient) {
                $temp = array();
                foreach (array('header', 'encrypted_key') as $key) {
                    if (array_key_exists($key, $recipient)) {
                        $temp[$key] = $recipient[$key];
                    }
                }
                $result['recipients'][] = $temp;
            }
        }

        return $result;
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromSerializationToFlattenedSerialization($input, $toString)
    {
        if (array_key_exists('signatures', $input)) {
            return self::fromSerializationSignatureToFlattenedSerialization($input, $toString);
        }

        return self::fromSerializationRecipientToFlattenedSerialization($input, $toString);
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromSerializationSignatureToFlattenedSerialization($input, $toString)
    {
        $signatures = array();
        foreach ($input['signatures'] as $signature) {
            $temp = array(
                'payload' => $input['payload'],
                'signature' => $signature['signature'],
            );
            foreach (array('protected', 'header') as $key) {
                if (array_key_exists($key, $signature)) {
                    $temp[$key] = $signature[$key];
                }
            }
            $signatures[] = $toString ? json_encode($temp) : $temp;
        }

        return $signatures;
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromSerializationRecipientToFlattenedSerialization($input, $toString)
    {
        $recipients = array();
        foreach ($input['recipients'] as $recipient) {
            $temp = array();
            foreach (array('ciphertext', 'protected', 'unprotected', 'iv', 'aad', 'tag') as $key) {
                if (array_key_exists($key, $input)) {
                    $temp[$key] = $input[$key];
                }
            }
            foreach (array('header', 'encrypted_key') as $key) {
                if (array_key_exists($key, $recipient)) {
                    $temp[$key] = $recipient[$key];
                }
            }
            $recipients[] = $toString ? json_encode($temp) : $temp;
        }

        return $recipients;
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromSerializationToCompactSerialization($input)
    {
        if (array_key_exists('signatures', $input)) {
            return self::fromSerializationSignatureToCompactSerialization($input);
        }

        return self::fromSerializationRecipientToCompactSerialization($input);
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromSerializationSignatureToCompactSerialization($input)
    {
        $signatures = array();
        foreach ($input['signatures'] as $signature) {
            if (!array_key_exists('protected', $signature)) {
                throw new \InvalidArgumentException("Cannot convert into Compact Json Serialisation: 'protected' parameter is missing");
            }
            if (array_key_exists('header', $signature)) {
                throw new \InvalidArgumentException("Cannot convert into Compact Json Serialisation: 'header' parameter cannot be kept");
            }
            $temp = array(
                $signature['protected'],
                $input['payload'],
                $signature['signature'],
            );
            $signatures[] = implode('.', $temp);
        }

        return $signatures;
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromSerializationRecipientToCompactSerialization($input)
    {
        $recipients = array();
        foreach ($input['recipients'] as $recipient) {
            if (array_key_exists('header', $recipient)) {
                throw new \InvalidArgumentException("Cannot convert into Compact Json Serialisation: 'header' parameter cannot be kept");
            }
            if (!array_key_exists('protected', $input)) {
                throw new \InvalidArgumentException("Cannot convert into Compact Json Serialisation: 'protected' parameter is missing");
            }
            foreach (array('unprotected', 'aad') as $key) {
                if (array_key_exists($key, $input)) {
                    throw new \InvalidArgumentException(sprintf("Cannot convert into Compact Json Serialisation: '%s' parameter cannot be kept", $key));
                }
            }
            $temp = array(
                $input['protected'],
                array_key_exists('encrypted_key', $recipient) ? $recipient['encrypted_key'] : '',
                array_key_exists('iv', $input) ? $input['iv'] : '',
                $input['ciphertext'],
                array_key_exists('tag', $input) ? $input['tag'] : '',
            );
            $recipients[] = implode('.', $temp);
        }

        return $recipients;
    }

    /**
     * @param array $input
     *
     * @return string
     */
    public static function getType(array $input)
    {
        if (array_key_exists('signatures', $input)) {
            return 'JWS';
        } elseif (array_key_exists('ciphertext', $input)) {
            return 'JWE';
        }
    }

    /**
     * @param $input
     *
     * @return array
     */
    private static function fromFlattenedSerializationRecipientToSerialization($input)
    {
        $recipient = array();
        foreach (array('header', 'encrypted_key') as $key) {
            if (array_key_exists($key, $input)) {
                $recipient[$key] = $input[$key];
            }
        }
        $recipients = array(
            'ciphertext' => $input['ciphertext'],
            'recipients' => array($recipient),
        );
        foreach (array('ciphertext', 'protected', 'unprotected', 'iv', 'aad', 'tag') as $key) {
            if (array_key_exists($key, $input)) {
                $recipients[$key] = $input[$key];
            }
        }

        return $recipients;
    }

    /**
     * @param $input
     *
     * @return array
     */
    private static function fromFlattenedSerializationSignatureToSerialization($input)
    {
        $signature = array(
            'signature' => $input['signature'],
        );
        foreach (array('protected', 'header') as $key) {
            if (array_key_exists($key, $input)) {
                $signature[$key] = $input[$key];
            }
        }

        return array(
            'payload' => $input['payload'],
            'signatures' => array($signature),
        );
    }

    /**
     * @param $input
     *
     * @return array
     */
    private static function fromCompactSerializationToSerialization($input)
    {
        $parts = explode('.', $input);
        switch (count($parts)) {
            case 3:
                return self::fromCompactSerializationSignatureToSerialization($parts);
            case 5:
                return self::fromCompactSerializationRecipientToSerialization($parts);
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private static function fromCompactSerializationRecipientToSerialization(array $parts)
    {
        $recipient = array();
        if (!empty($parts[1])) {
            $recipient['encrypted_key'] = $parts[1];
        }

        $recipients = array(
            'recipients' => array($recipient),
        );
        foreach (array(3 => 'ciphertext', 0 => 'protected', 2 => 'iv', 4 => 'tag') as $part => $key) {
            if (!empty($parts[$part])) {
                $recipients[$key] = $parts[$part];
            }
        }

        return $recipients;
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private static function fromCompactSerializationSignatureToSerialization(array $parts)
    {
        return array(
            'payload' => $parts[1],
            'signatures' => array(
                array(
                    'protected' => $parts[0],
                    'signature' => $parts[2],
                ),
            ),
        );
    }

    /**
     * @param string|array $input
     *
     * @return array
     */
    private static function getPreparedInput($input)
    {
        if (is_array($input)) {
            if (array_key_exists('signatures', $input) || array_key_exists('recipients', $input)) {
                return $input;
            }
            if (array_key_exists('signature', $input)) {
                return self::fromFlattenedSerializationSignatureToSerialization($input);
            }
            if (array_key_exists('ciphertext', $input)) {
                return self::fromFlattenedSerializationRecipientToSerialization($input);
            }
        } elseif (is_string($input)) {
            $json = json_decode($input, true);
            if (is_array($json)) {
                return self::getPreparedInput($json);
            }

            return self::fromCompactSerializationToSerialization($input);
        }
        throw new \InvalidArgumentException('Unsupported input');
    }
}
