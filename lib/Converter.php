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
        $prepared = array();
        self::getMode($input, $prepared);
        switch ($mode) {
            case JSONSerializationModes::JSON_SERIALIZATION:
                return $toString ? json_encode($prepared) : $prepared;
            case JSONSerializationModes::JSON_FLATTENED_SERIALIZATION:
                return self::convertToFlattened($prepared, $toString);
            case JSONSerializationModes::JSON_COMPACT_SERIALIZATION:
                return self::convertToCompact($prepared);
            default:
                throw new \InvalidArgumentException('Unsupported mode');
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
    private static function convertToFlattened($input, $toString)
    {
        if (array_key_exists('signatures', $input)) {
            return self::convertSignatureToFlattened($input, $toString);
        }

        return self::convertRecipientToFlattened($input, $toString);
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function convertSignatureToFlattened($input, $toString)
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
    private static function convertRecipientToFlattened($input, $toString)
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
    private static function convertToCompact($input)
    {
        if (array_key_exists('signatures', $input)) {
            return self::convertSignatureToCompact($input);
        }

        return self::convertRecipientToCompact($input);
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function convertSignatureToCompact($input)
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
    private static function convertRecipientToCompact($input)
    {
        $recipients = array();
        foreach ($input['recipients'] as $recipient) {
            if (array_key_exists('header', $recipient)) {
                throw new \InvalidArgumentException("Cannot convert into Compact Json Serialisation: 'header' parameter cannot be kept");
            }
            if (!array_key_exists('protected', $input)) {
                throw new \InvalidArgumentException("Cannot convert into Compact Json Serialisation: 'protected' parameter is missing");
            }
            if (array_key_exists('unprotected', $input)) {
                throw new \InvalidArgumentException("Cannot convert into Compact Json Serialisation: 'unprotected' parameter cannot be kept");
            }
            if (array_key_exists('aad', $input)) {
                throw new \InvalidArgumentException("Cannot convert into Compact Json Serialisation: 'aad' parameter cannot be kept");
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
     * @param string|array $input
     * @param array        $prepared
     *
     * @return string
     */
    private static function getMode($input, array &$prepared)
    {
        if (is_array($input)) {
            if (array_key_exists('signatures', $input) || array_key_exists('recipients', $input)) {
                $prepared = $input;

                return JSONSerializationModes::JSON_SERIALIZATION;
            }
            if (array_key_exists('signature', $input)) {
                $signature = array(
                    'signature' => $input['signature'],
                );
                foreach (array('protected', 'header') as $key) {
                    if (array_key_exists($key, $input)) {
                        $signature[$key] = $input[$key];
                    }
                }
                $prepared = array(
                    'payload' => $input['payload'],
                    'signatures' => array($signature),
                );

                return JSONSerializationModes::JSON_FLATTENED_SERIALIZATION;
            }
            if (array_key_exists('ciphertext', $input)) {
                $recipient = array();
                foreach (array('header', 'encrypted_key') as $key) {
                    if (array_key_exists($key, $input)) {
                        $recipient[$key] = $input[$key];
                    }
                }
                $prepared = array(
                    'ciphertext' => $input['ciphertext'],
                    'recipients' => array($recipient),
                );
                foreach (array('ciphertext', 'protected', 'unprotected', 'iv', 'aad', 'tag') as $key) {
                    if (array_key_exists($key, $input)) {
                        $prepared[$key] = $input[$key];
                    }
                }

                return JSONSerializationModes::JSON_FLATTENED_SERIALIZATION;
            }
        } elseif (is_string($input)) {
            $json = json_decode($input, true);
            if (is_array($json)) {
                return self::getMode($json, $prepared);
            }
            $parts = explode('.', $input);
            switch (count($parts)) {
                case 3:
                    $prepared = array(
                        'payload' => $parts[1],
                        'signatures' => array(
                            array(
                                'protected' => $parts[0],
                                'signature' => $parts[2],
                            ),
                        ),
                    );

                    return JSONSerializationModes::JSON_COMPACT_SERIALIZATION;
                case 5:
                    $recipient = array();
                    if (!empty($parts[1])) {
                        $recipient['encrypted_key'] = $parts[1];
                    }

                    $prepared = array(
                        'recipients' => array($recipient),
                    );
                    foreach (array(3 => 'ciphertext', 0 => 'protected', 2 => 'iv', 4 => 'tag') as $part => $key) {
                        if (!empty($parts[$part])) {
                            $prepared[$key] = $parts[$part];
                        }
                    }

                    return JSONSerializationModes::JSON_COMPACT_SERIALIZATION;
                default:
                    throw new \InvalidArgumentException('Unsupported input');
            }
        } else {
            throw new \InvalidArgumentException('Unsupported input');
        }
        throw new \InvalidArgumentException('Unsupported input');
    }
}
