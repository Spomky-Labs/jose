<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Base64Url\Base64Url;
use Jose\Algorithm\Signature\SignatureInterface;
use Jose\Behaviour\HasJWAManager;
use Jose\Behaviour\HasJWTManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Behaviour\HasPayloadConverter;
use Jose\Object\JWKInterface;
use Jose\Object\JWTInterface;
use Jose\Object\SignatureInstructionInterface;
use Jose\Payload\PayloadConverterManagerInterface;
use Jose\Util\Converter;

/**
 */
final class Verifier implements VerifierInterface
{
}
