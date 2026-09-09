<?php

namespace Firebase\JWT;

use DomainException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use stdClass;
use UnexpectedValueException;

/**
 * Tests for the ML-DSA algorithms defined by RFC 9964.
 *
 * The test vectors in tests/data/ml-dsa-rfc9964-vectors.json are taken verbatim from
 * RFC 9964, Appendix A.1, and tests/data/ml-dsa-jwkset.json contains the AKP public
 * keys from those same vectors.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9964#appendix-A.1
 *
 * @group ml-dsa
 */
class MLDSATest extends TestCase
{
    /**
     * Public key and signature sizes in bytes, from RFC 9964, Section 5.
     */
    private const SIZES = [
        'ML-DSA-44' => ['pub' => 1312, 'sig' => 2420, 'expanded' => 2560],
        'ML-DSA-65' => ['pub' => 1952, 'sig' => 3309, 'expanded' => 4032],
        'ML-DSA-87' => ['pub' => 2592, 'sig' => 4627, 'expanded' => 4896],
    ];

    /** @var array<string, array<string, string>> The RFC 9964 vectors, keyed by "alg" */
    private static $vectors = [];

    public static function setUpBeforeClass(): void
    {
        $data = json_decode(
            file_get_contents(__DIR__ . '/data/ml-dsa-rfc9964-vectors.json'),
            true
        );

        foreach ($data['vectors'] as $vector) {
            self::$vectors[$vector['alg']] = $vector;
        }
    }

    public function setUp(): void
    {
        if (!class_exists('\ParagonIE\PQCrypto\Compat')) {
            $this->markTestSkipped('paragonie/pqcrypto_compat is not available');
        }
    }

    public function provideParameterSets()
    {
        return [
            ['ML-DSA-44'],
            ['ML-DSA-65'],
            ['ML-DSA-87'],
        ];
    }

    /**
     * Verifies the signatures published in RFC 9964, which were produced by an
     * independent implementation.
     *
     * @dataProvider provideParameterSets
     */
    public function testRfcVectorSignatureVerifies($alg)
    {
        $vector = self::$vectors[$alg];
        list($signingInput, $signature) = self::splitJws($vector['jws']);

        // Guard against a mangled fixture making this test vacuous
        $header = JWT::jsonDecode(JWT::urlsafeB64Decode(explode('.', $vector['jws'])[0]));
        $this->assertSame($alg, $header->alg);
        $this->assertSame($vector['kid'], $header->kid);
        $this->assertSame(self::SIZES[$alg]['sig'], \strlen($signature));
        $this->assertSame(self::SIZES[$alg]['pub'], \strlen(JWT::urlsafeB64Decode($vector['pub'])));

        $key = JWK::parseKey(self::publicJwk($alg));

        $this->assertTrue(
            self::verify($signingInput, $signature, $key->getKeyMaterial(), $alg)
        );
    }

    /**
     * @dataProvider provideParameterSets
     */
    public function testRfcVectorWithTamperedSignatureFails($alg)
    {
        $vector = self::$vectors[$alg];
        list($signingInput, $signature) = self::splitJws($vector['jws']);

        $offset = \intdiv(\strlen($signature), 2);
        $signature[$offset] = $signature[$offset] === 'a' ? 'b' : 'a';

        $this->assertFalse(
            self::verify($signingInput, $signature, $vector['pub'], $alg)
        );
    }

    /**
     * @dataProvider provideParameterSets
     */
    public function testRfcVectorWithTruncatedSignatureFails($alg)
    {
        $vector = self::$vectors[$alg];
        list($signingInput, $signature) = self::splitJws($vector['jws']);

        $this->assertFalse(
            self::verify($signingInput, substr($signature, 0, -1), $vector['pub'], $alg)
        );
    }

    /**
     * @dataProvider provideParameterSets
     */
    public function testRfcVectorWithDifferentPublicKeyFails($alg)
    {
        $vector = self::$vectors[$alg];
        list($signingInput, $signature) = self::splitJws($vector['jws']);

        // Any byte string of the right length decodes to a valid ML-DSA public key
        $publicKey = JWT::urlsafeB64Decode($vector['pub']);
        $offset = \intdiv(\strlen($publicKey), 2);
        $publicKey[$offset] = $publicKey[$offset] === "\x01" ? "\x02" : "\x01";

        $this->assertFalse(
            self::verify($signingInput, $signature, base64_encode($publicKey), $alg)
        );
    }

    /**
     * Signing with the seed from an RFC 9964 vector and verifying with the public key
     * published alongside it also proves that the public key this library derives from
     * the seed is the one the RFC expects.
     *
     * @dataProvider provideParameterSets
     */
    public function testEncodeDecodeWithRfcKeys($alg)
    {
        $vector = self::$vectors[$alg];

        $jwt = JWT::encode(['foo' => 'bar'], $vector['priv'], $alg, $vector['kid']);

        $headers = new stdClass();
        $decoded = JWT::decode($jwt, new Key($vector['pub'], $alg), $headers);

        $this->assertSame('bar', $decoded->foo);
        $this->assertSame($alg, $headers->alg);
        $this->assertSame($vector['kid'], $headers->kid);
        $this->assertSame(
            self::SIZES[$alg]['sig'],
            \strlen(JWT::urlsafeB64Decode(explode('.', $jwt)[2]))
        );
    }

    /**
     * @dataProvider provideParameterSets
     */
    public function testEncodeDecodeWithGeneratedKeys($alg)
    {
        $seed = random_bytes(32);
        $publicKey = self::derivePublicKey($seed, $alg);

        $jwt = JWT::encode(['foo' => 'bar'], base64_encode($seed), $alg);
        $decoded = JWT::decode($jwt, new Key(base64_encode($publicKey), $alg));

        $this->assertSame('bar', $decoded->foo);
    }

    public function testKeysMayBeBase64UrlEncoded()
    {
        // A seed and public key whose standard base64 encoding contains characters that
        // differ from base64url
        $seed = str_repeat("\xfb\xff", 16);
        $publicKey = self::derivePublicKey($seed, 'ML-DSA-44');

        $encodedSeed = JWT::urlsafeB64Encode($seed);
        $this->assertMatchesRegularExpression('/[-_]/', $encodedSeed);

        $jwt = JWT::encode(['foo' => 'bar'], $encodedSeed, 'ML-DSA-44');
        $decoded = JWT::decode($jwt, new Key(JWT::urlsafeB64Encode($publicKey), 'ML-DSA-44'));

        $this->assertSame('bar', $decoded->foo);
    }

    public function testKeysMayBeRawBytes()
    {
        $seed = random_bytes(32);
        $publicKey = self::derivePublicKey($seed, 'ML-DSA-44');

        $jwt = JWT::encode(['foo' => 'bar'], $seed, 'ML-DSA-44');
        $decoded = JWT::decode($jwt, new Key($publicKey, 'ML-DSA-44'));

        $this->assertSame('bar', $decoded->foo);
    }

    public function testKeysUseTheLastNonEmptyLine()
    {
        $vector = self::$vectors['ML-DSA-44'];
        list($signingInput, $signature) = self::splitJws($vector['jws']);

        // As for EdDSA keys, the last non-empty line is used, so a key file may carry
        // leading comments or blank lines
        $keyMaterial = "# ML-DSA-44 public key\n\n"
            . JWT::convertBase64UrlToBase64($vector['pub']) . "\n";

        $this->assertTrue(
            self::verify($signingInput, $signature, $keyMaterial, 'ML-DSA-44')
        );
    }

    public function testDecodeByAkpJwkKeySet()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/ml-dsa-jwkset.json'),
            true
        );
        $keys = JWK::parseKeySet($jwkSet);

        foreach (self::$vectors as $alg => $vector) {
            $jwt = JWT::encode(
                ['sub' => 'foo', 'exp' => strtotime('+10 seconds')],
                $vector['priv'],
                $alg,
                $vector['kid']
            );

            $this->assertSame('foo', JWT::decode($jwt, $keys)->sub);
        }
    }

    public function testDecodeWithWrongPublicKeyFails()
    {
        $jwt = JWT::encode(['foo' => 'bar'], random_bytes(32), 'ML-DSA-44');

        $this->expectException(SignatureInvalidException::class);
        $this->expectExceptionMessage('Signature verification failed');

        JWT::decode($jwt, new Key(self::$vectors['ML-DSA-44']['pub'], 'ML-DSA-44'));
    }

    public function testDecodeWithTamperedPayloadFails()
    {
        $vector = self::$vectors['ML-DSA-44'];
        $jwt = JWT::encode(['foo' => 'bar'], $vector['priv'], 'ML-DSA-44');

        list($header, $payload, $signature) = explode('.', $jwt);
        $tampered = $header . '.' . JWT::urlsafeB64Encode('{"foo":"baz"}') . '.' . $signature;

        $this->expectException(SignatureInvalidException::class);

        JWT::decode($tampered, new Key($vector['pub'], 'ML-DSA-44'));
    }

    public function testDecodeWithMismatchedParameterSetFails()
    {
        $jwt = JWT::encode(['foo' => 'bar'], self::$vectors['ML-DSA-44']['priv'], 'ML-DSA-44');

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Incorrect key for this algorithm');

        JWT::decode($jwt, new Key(self::$vectors['ML-DSA-65']['pub'], 'ML-DSA-65'));
    }

    /**
     * @dataProvider provideParameterSets
     */
    public function testPublicKeyIsRejectedForSigning($alg)
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage($alg . ' public key provided where a private key is required');

        JWT::sign('message', self::$vectors[$alg]['pub'], $alg);
    }

    /**
     * @dataProvider provideParameterSets
     */
    public function testPrivateKeyIsRejectedForVerifying($alg)
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage($alg . ' private key provided where a public key is required');

        self::verify('message', 'signature', self::$vectors[$alg]['priv'], $alg);
    }

    /**
     * @dataProvider provideParameterSets
     */
    public function testExpandedPrivateKeyIsRejected($alg)
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage(
            $alg . ' expanded private keys are not supported, provide the 32 byte seed instead'
        );

        // RFC 9964, Section 4 supports the seed format exclusively
        $expanded = str_repeat("\0", self::SIZES[$alg]['expanded']);

        JWT::sign('message', base64_encode($expanded), $alg);
    }

    public function testWrongLengthPrivateKeyIsRejected()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('ML-DSA-44 private key must be a 32 byte seed, 31 bytes given');

        JWT::sign('message', base64_encode(random_bytes(31)), 'ML-DSA-44');
    }

    /**
     * @dataProvider provideParameterSets
     */
    public function testWrongLengthPublicKeyIsRejected($alg)
    {
        $expected = self::SIZES[$alg]['pub'];

        $this->expectException(DomainException::class);
        $this->expectExceptionMessage(\sprintf(
            '%s public key must be %d bytes, %d bytes given',
            $alg,
            $expected,
            $expected - 1
        ));

        self::verify('message', 'signature', base64_encode(random_bytes($expected - 1)), $alg);
    }

    public function testEmptyKeyIsRejected()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Key cannot be empty string');

        JWT::sign('message', '!!!', 'ML-DSA-44');
    }

    public function testNonStringKeyIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('key must be a string when using ML-DSA-44');

        $key = openssl_pkey_get_private(file_get_contents(__DIR__ . '/data/rsa1-private.pem'));

        JWT::sign('message', $key, 'ML-DSA-44');
    }

    public function testUnsupportedParameterSetIsRejected()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Algorithm not supported');

        JWT::sign('message', self::$vectors['ML-DSA-44']['priv'], 'ML-DSA-45');
    }

    /**
     * @return array<string, string> The AKP public JWK for the given algorithm
     */
    private static function publicJwk(string $alg): array
    {
        return [
            'kid' => self::$vectors[$alg]['kid'],
            'kty' => 'AKP',
            'alg' => $alg,
            'pub' => self::$vectors[$alg]['pub'],
        ];
    }

    /**
     * @return array{string, string} The signing input and the decoded signature
     */
    private static function splitJws(string $jws): array
    {
        list($header, $payload, $signature) = explode('.', $jws);

        return ["{$header}.{$payload}", JWT::urlsafeB64Decode($signature)];
    }

    private static function derivePublicKey(string $seed, string $alg): string
    {
        $level = substr($alg, -2);
        $keyPair = \ParagonIE\PQCrypto\Compat::{"mldsa{$level}_seed_keypair"}($seed);

        return $keyPair['verificationKey']->bytes();
    }

    /**
     * JWT::verify() is private, and JWT::decode() cannot be used to check the RFC 9964
     * vectors because their payloads are strings rather than JSON objects, so decode()
     * rejects them before it verifies anything.
     *
     * @param string|\OpenSSLAsymmetricKey|\OpenSSLCertificate $keyMaterial
     */
    private static function verify(
        string $signingInput,
        string $signature,
        $keyMaterial,
        string $alg
    ): bool {
        $verify = new ReflectionMethod(JWT::class, 'verify');
        $verify->setAccessible(true);

        return $verify->invoke(null, $signingInput, $signature, $keyMaterial, $alg);
    }
}
