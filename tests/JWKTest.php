<?php

namespace Firebase\JWT;

use DomainException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

class JWKTest extends TestCase
{
    private static $keys;

    public static function setUpBeforeClass(): void
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        self::$keys = JWK::parseKeySet($jwkSet);
    }

    public function testMissingKty()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('JWK must contain a "kty" parameter');

        $badJwk = ['kid' => 'foo'];
        $keys = JWK::parseKeySet(['keys' => [$badJwk]]);
    }

    public function testInvalidAlgorithm()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('No supported algorithms found in JWK Set');

        $badJwk = ['kty' => 'BADTYPE', 'alg' => 'RSA256'];
        $keys = JWK::parseKeySet(['keys' => [$badJwk]]);
    }

    public function testParsePrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('RSA private keys are not supported');

        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        $jwkSet['keys'][0]['d'] = 'privatekeyvalue';

        JWK::parseKeySet($jwkSet);
    }

    public function testParsePrivateKeyWithoutAlg()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('JWK must contain an "alg" parameter');

        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        unset($jwkSet['keys'][0]['alg']);

        JWK::parseKeySet($jwkSet);
    }

    public function testParsePrivateKeyWithoutAlgWithDefaultAlgParameter()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        unset($jwkSet['keys'][0]['alg']);

        $jwks = JWK::parseKeySet($jwkSet, 'foo');
        $this->assertSame('foo', $jwks['jwk1']->getAlgorithm());
    }

    public function testParseKeyWithEmptyDValue()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );

        // empty or null values are ok
        $jwkSet['keys'][0]['d'] = null;

        $keys = JWK::parseKeySet($jwkSet);
        $this->assertTrue(\is_array($keys));
    }

    /** @dataProvider provideParseJwkKeySet */
    public function testParseJwkKeySet($jwkFile, $keyId, $pubkeyFile)
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/' . $jwkFile),
            true
        );
        $keys = JWK::parseKeySet($jwkSet);
        $this->assertTrue(\is_array($keys));
        $this->assertArrayHasKey($keyId, $keys);

        // verify public key
        $keyMaterial = $keys[$keyId]->getKeyMaterial();
        $publicKey = openssl_pkey_get_details($keyMaterial)['key'];

        $this->assertEquals(
            file_get_contents(__DIR__ . '/data/' . $pubkeyFile),
            $publicKey
        );
    }

    public function provideParseJwkKeySet()
    {
        return [
            ['rsa-jwkset.json', 'jwk1', 'rsa1-public.pub'],
            ['rsa-jwkset-2.json', 'jwk2', 'rsa-jwk2-public.pub'],
        ];
    }

    public function testParseJwkKey_empty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JWK must not be empty');

        JWK::parseKeySet(['keys' => [[]]]);
    }

    public function testParseJwkKeySet_empty()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JWK Set did not contain any keys');

        JWK::parseKeySet(['keys' => []]);
    }

    public function testParseJwkKeySetWithValidButUnsupportedCurveDoesNotThrowException()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/unsupported-alg-keyset.json'),
            true
        );

        $this->assertCount(3, $jwkSet['keys']);

        $keys = JWK::parseKeySet($jwkSet);

        $this->assertCount(2, $keys);
        $this->assertArrayHasKey('jwk1', $keys);
        $this->assertArrayHasKey('jwk2', $keys);
        $this->assertArrayNotHasKey('unsupported-ec-curve', $keys);
    }

    public function testParseJwkKeySetWithInvalidCurveThrowsException()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Unrecognised EC curve');

        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/unsupported-alg-keyset.json'),
            true
        );

        $jwkSet['keys'][2]['crv'] = 'invalid-curve';

        $keys = JWK::parseKeySet($jwkSet);
    }

    /**
     * @depends testParseJwkKeySet
     */
    public function testDecodeByJwkKeySetTokenExpired()
    {
        $privKey1 = file_get_contents(__DIR__ . '/data/rsa1-private.pem');
        $payload = ['exp' => strtotime('-1 hour')];
        $msg = JWT::encode($payload, $privKey1, 'RS256', 'jwk1');

        $this->expectException(ExpiredException::class);

        JWT::decode($msg, self::$keys);
    }

    /**
     * @dataProvider provideDecodeByJwkKeySet
     */
    public function testDecodeByJwkKeySet($pemFile, $jwkFile, $alg, $keyId)
    {
        $privKey1 = file_get_contents(__DIR__ . '/data/' . $pemFile);
        $payload = ['sub' => 'foo', 'exp' => strtotime('+10 seconds')];
        $msg = JWT::encode($payload, $privKey1, $alg, $keyId);

        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/' . $jwkFile),
            true
        );

        $keys = JWK::parseKeySet($jwkSet);
        $result = JWT::decode($msg, $keys);

        $this->assertSame('foo', $result->sub);
    }

    public function provideDecodeByJwkKeySet()
    {
        return [
            ['rsa1-private.pem', 'rsa-jwkset.json', 'RS256', 'jwk1'],
            ['ecdsa256-private.pem', 'ec-jwkset.json', 'ES256', 'jwk1'],
            ['ecdsa384-private.pem', 'ec-jwkset.json', 'ES384', 'jwk4'],
            ['ed25519-1.sec', 'ed25519-jwkset.json', 'EdDSA', 'jwk1'],
        ];
    }

    /**
     * @depends testParseJwkKeySet
     */
    public function testDecodeByMultiJwkKeySet()
    {
        $privKey2 = file_get_contents(__DIR__ . '/data/rsa2-private.pem');
        $payload = ['sub' => 'bar', 'exp' => strtotime('+10 seconds')];
        $msg = JWT::encode($payload, $privKey2, 'RS256', 'jwk2');

        $result = JWT::decode($msg, self::$keys);

        $this->assertSame('bar', $result->sub);
    }

    public function testDecodeByOctetJwkKeySet()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/octet-jwkset.json'),
            true
        );
        $keys = JWK::parseKeySet($jwkSet);
        $payload = ['sub' => 'foo', 'exp' => strtotime('+10 seconds')];
        foreach ($keys as $keyId => $key) {
            $msg = JWT::encode($payload, $key->getKeyMaterial(), $key->getAlgorithm(), $keyId);
            $result = JWT::decode($msg, $keys);

            $this->assertSame('foo', $result->sub);
        }
    }

    public function testOctetJwkMissingK()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('k not set');

        $badJwk = ['kty' => 'oct', 'alg' => 'HS256'];
        $keys = JWK::parseKeySet(['keys' => [$badJwk]]);
    }

    public function testParseAkpJwk()
    {
        $jwk = self::getAkpJwk('ML-DSA-44');

        $key = JWK::parseKey($jwk);

        $this->assertNotNull($key);
        $this->assertSame('ML-DSA-44', $key->getAlgorithm());
        // The key material is the public key in standard base64, as for OKP keys
        $this->assertSame(
            JWT::urlsafeB64Decode($jwk['pub']),
            base64_decode($key->getKeyMaterial())
        );
        $this->assertSame(1312, \strlen(base64_decode($key->getKeyMaterial())));
    }

    public function testParseAkpJwkKeySet()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/ml-dsa-jwkset.json'),
            true
        );

        $keys = JWK::parseKeySet($jwkSet);

        $this->assertCount(3, $keys);
        foreach ($jwkSet['keys'] as $jwk) {
            $this->assertArrayHasKey($jwk['kid'], $keys);
            $this->assertSame($jwk['alg'], $keys[$jwk['kid']]->getAlgorithm());
        }
    }

    public function testParseAkpJwkWithPrivateKey()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Key data must be for a public key');

        $jwk = self::getAkpJwk('ML-DSA-44');
        // RFC 9964 defines "priv" as the private key seed, which must not be present
        // in a public key
        $jwk['priv'] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

        JWK::parseKey($jwk);
    }

    public function testParseAkpJwkMissingPub()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('pub not set');

        $jwk = self::getAkpJwk('ML-DSA-44');
        unset($jwk['pub']);

        JWK::parseKey($jwk);
    }

    public function testParseAkpJwkMissingAlgIsNotDefaulted()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('AKP keys must contain an "alg" parameter');

        $jwk = self::getAkpJwk('ML-DSA-44');
        unset($jwk['alg']);

        // An AKP key's "alg" determines its parameter set, so unlike other key types
        // it is not defaulted
        JWK::parseKey($jwk, 'ML-DSA-44');
    }

    public function testParseAkpJwkWithUnsupportedMlDsaParameterSet()
    {
        $this->expectException(DomainException::class);
        $this->expectExceptionMessage('Unrecognised or unsupported ML-DSA parameter set');

        $jwk = self::getAkpJwk('ML-DSA-44');
        $jwk['alg'] = 'ML-DSA-99';

        JWK::parseKey($jwk);
    }

    public function testParseAkpJwkWithUnsupportedAlgorithmIsSkipped()
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/rsa-jwkset.json'),
            true
        );
        // The AKP key type is not limited to the algorithms registered by RFC 9964, so
        // an unknown one must not invalidate the rest of the key set
        $jwkSet['keys'][] = [
            'kid' => 'unsupported-akp-alg',
            'kty' => 'AKP',
            'alg' => 'SLH-DSA-SHA2-128s',
            'pub' => 'ZmFrZQ',
        ];

        $keys = JWK::parseKeySet($jwkSet);

        $this->assertArrayHasKey('jwk1', $keys);
        $this->assertArrayNotHasKey('unsupported-akp-alg', $keys);
    }

    public function testParseAkpJwkWithWrongLengthPub()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('AKP public key for ML-DSA-44 must be 1312 bytes, 1311 bytes given');

        $jwk = self::getAkpJwk('ML-DSA-44');
        $jwk['pub'] = JWT::urlsafeB64Encode(
            substr(JWT::urlsafeB64Decode($jwk['pub']), 0, -1)
        );

        JWK::parseKey($jwk);
    }

    public function testParseAkpJwkWithMismatchedParameterSet()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('AKP public key for ML-DSA-65 must be 1952 bytes, 1312 bytes given');

        // An ML-DSA-44 public key labelled as ML-DSA-65
        $jwk = self::getAkpJwk('ML-DSA-44');
        $jwk['alg'] = 'ML-DSA-65';

        JWK::parseKey($jwk);
    }

    /**
     * @return array<string, string> The RFC 9964 AKP JWK for the given algorithm
     */
    private static function getAkpJwk(string $alg): array
    {
        $jwkSet = json_decode(
            file_get_contents(__DIR__ . '/data/ml-dsa-jwkset.json'),
            true
        );

        foreach ($jwkSet['keys'] as $jwk) {
            if ($jwk['alg'] === $alg) {
                return $jwk;
            }
        }

        throw new \RuntimeException('No AKP JWK for ' . $alg);
    }

    public function testParseKey()
    {
        // Use a known module and exponent, and ensure it parses as expected
        $jwk = [
            'alg' => 'RS256',
            'kty' => 'RSA',
            'n' => 'hsYvCPtkUV7SIxwkOkJsJfhwV_CMdXU5i0UmY2QEs-Pa7v0-0y-s4EjEDtsQ8Yow6hc670JhkGBcMzhU4DtrqNGROXebyOse5FX0m0UvWo1qXqNTf28uBKB990mY42Icr8sGjtOw8ajyT9kufbmXi3eZKagKpG0TDGK90oBEfoGzCxoFT87F95liNth_GoyU5S8-G3OqIqLlQCwxkI5s-g2qvg_aooALfh1rhvx2wt4EJVMSrdnxtPQSPAtZBiw5SwCnVglc6OnalVNvAB2JArbqC9GAzzz9pApAk28SYg5a4hPiPyqwRv-4X1CXEK8bO5VesIeRX0oDf7UoM-pVAw',
            'use' => 'sig',
            'e' => 'AQAB',
            'kid' => '838c06c62046c2d948affe137dd5310129f4d5d1'
        ];

        $key = JWK::parseKey($jwk);
        $this->assertNotNull($key);

        $openSslKey = $key->getKeyMaterial();
        $pubKey = openssl_pkey_get_public($openSslKey);
        $keyData = openssl_pkey_get_details($pubKey);

        $expectedPublicKey = <<<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhsYvCPtkUV7SIxwkOkJs
JfhwV/CMdXU5i0UmY2QEs+Pa7v0+0y+s4EjEDtsQ8Yow6hc670JhkGBcMzhU4Dtr
qNGROXebyOse5FX0m0UvWo1qXqNTf28uBKB990mY42Icr8sGjtOw8ajyT9kufbmX
i3eZKagKpG0TDGK90oBEfoGzCxoFT87F95liNth/GoyU5S8+G3OqIqLlQCwxkI5s
+g2qvg/aooALfh1rhvx2wt4EJVMSrdnxtPQSPAtZBiw5SwCnVglc6OnalVNvAB2J
ArbqC9GAzzz9pApAk28SYg5a4hPiPyqwRv+4X1CXEK8bO5VesIeRX0oDf7UoM+pV
AwIDAQAB
-----END PUBLIC KEY-----

EOF;

        $this->assertEquals($expectedPublicKey, $keyData['key']);
    }
}
