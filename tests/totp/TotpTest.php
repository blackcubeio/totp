<?php

use Blackcube\Totp\Totp;

class TotpTest extends \Codeception\Test\Unit
{
    /**
     * @var \tests\TotpTester
     */
    protected $tester;

    private Totp $totp;

    protected function _before()
    {
        $this->totp = new Totp();
    }

    protected function _after()
    {
    }

    public function testConstructorDefaults()
    {
        $totp = new Totp();
        $this->assertEquals(6, $totp->getLength());
    }

    public function testConstructorWithCustomValues()
    {
        $totp = new Totp(window: 5, step: 60, length: 8, algorithm: 'sha256');
        $this->assertEquals(8, $totp->getLength());
    }

    public function testSetAndGetLength()
    {
        $this->totp->setLength(8);
        $this->assertEquals(8, $this->totp->getLength());
    }

    public function testSetKey()
    {
        $key = 'JBSWY3DPEHPK3PXP';
        $this->totp->setKey('test', $key);

        // Should not throw exception
        $this->assertTrue(true);
    }

    public function testSetKeyThrowsExceptionForEmptyKey()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Key for identifier 'test' cannot be empty");

        $this->totp->setKey('test', '');
    }

    public function testGenerateKey()
    {
        $key = $this->totp->generateKey();

        $this->assertIsString($key);
        $this->assertGreaterThan(0, strlen($key));
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+$/', $key); // Base32 pattern
    }

    public function testGenerate()
    {
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');
        $token = $this->totp->generate('test');

        $this->assertIsString($token);
        $this->assertEquals(6, strlen($token)); // Default length
        $this->assertMatchesRegularExpression('/^\d{6}$/', $token);
    }

    public function testGenerateThrowsExceptionForUnknownKey()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Key not found for identifier 'unknown'");

        $this->totp->generate('unknown');
    }

    public function testValidate()
    {
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');
        $token = $this->totp->generate('test');

        // Should validate the token we just generated
        $this->assertTrue($this->totp->validate('test', $token));
    }

    public function testValidateReturnsFalseForInvalidToken()
    {
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');

        $this->assertFalse($this->totp->validate('test', '000000'));
    }

    public function testValidateThrowsExceptionForUnknownKey()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Key not found for identifier 'unknown'");

        $this->totp->validate('unknown', '123456');
    }

    public function testGenerateWithDerivationParam()
    {
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');

        $token1 = $this->totp->generate('test', 'param1');
        $token2 = $this->totp->generate('test', 'param2');

        // Different derivation params should produce different tokens
        $this->assertNotEquals($token1, $token2);
    }

    public function testValidateWithDerivationParam()
    {
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');

        $token = $this->totp->generate('test', 'param1');

        // Should validate with same derivation param
        $this->assertTrue($this->totp->validate('test', $token, 'param1'));

        // Should not validate with different derivation param
        $this->assertFalse($this->totp->validate('test', $token, 'param2'));
    }

    public function testSetWindow()
    {
        $this->totp->setWindow(2);
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');

        $token = $this->totp->generate('test');
        $this->assertTrue($this->totp->validate('test', $token));
    }

    public function testSetStep()
    {
        $this->totp->setStep(60);
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');

        $token = $this->totp->generate('test');
        $this->assertTrue($this->totp->validate('test', $token));
    }

    public function testSetAlgorithm()
    {
        $this->totp->setAlgorithm('sha256');
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');

        $token = $this->totp->generate('test');
        $this->assertTrue($this->totp->validate('test', $token));
    }

    public function testDifferentLengths()
    {
        $this->totp->setKey('test', 'JBSWY3DPEHPK3PXP');

        // Six is the floor of RFC 4226 section 5.3, ten the ceiling where the
        // modulus still fits a 64-bit integer.
        $lengths = [
            6,
            8,
            10,
        ];

        foreach ($lengths as $length) {
            $this->totp->setLength($length);
            $token = $this->totp->generate('test');

            $this->assertEquals($length, strlen($token));
            $this->assertTrue($this->totp->validate('test', $token));
        }
    }

    public function testEncodeBase32WithRemainingBits()
    {
        // Test the remaining bits handling in encodeBase32 method
        // Use reflection to access the private method
        $reflection = new \ReflectionClass($this->totp);
        $method = $reflection->getMethod('encodeBase32');
        $method->setAccessible(true);

        // Create a buffer that will result in remaining bits
        // 1 byte = 8 bits, which leaves 3 bits after first 5-bit extraction
        $buffer = pack('C', 0xFF); // Single byte: 11111111

        $result = $method->invoke($this->totp, $buffer);

        // Should encode the byte and handle the remaining 3 bits
        $this->assertIsString($result);
        $this->assertGreaterThan(0, strlen($result));

        // Test with different buffer sizes to ensure remaining bits are handled
        $buffer2 = pack('CC', 0xFF, 0xFF); // 2 bytes: 16 bits, leaves 1 bit
        $result2 = $method->invoke($this->totp, $buffer2);

        $this->assertIsString($result2);
        $this->assertGreaterThan(strlen($result), strlen($result2));
    }

    /**
     * The reference vectors of RFC 6238, Appendix B.
     *
     * Checking that validate() accepts what generate() produced proves only
     * that the class agrees with itself. These vectors are what proves it
     * agrees with everyone else — an authenticator app included.
     *
     * @return array<string, array{string, string, int, string}>
     */
    public static function rfc6238Provider(): array
    {
        // The RFC states its keys in ASCII, and a longer one per algorithm.
        // They are encoded here rather than read from the class under test:
        // a fixture built by the code it checks proves nothing.
        $keys = [
            'sha1' => self::toBase32('12345678901234567890'),
            'sha256' => self::toBase32('12345678901234567890123456789012'),
            'sha512' => self::toBase32('1234567890123456789012345678901234567890123456789012345678901234'),
        ];

        $vectors = [
            'sha1' => [
                59 => '94287082',
                1111111109 => '07081804',
                1111111111 => '14050471',
                1234567890 => '89005924',
                2000000000 => '69279037',
                20000000000 => '65353130',
            ],
            'sha256' => [
                59 => '46119246',
                1111111109 => '68084774',
                1111111111 => '67062674',
                1234567890 => '91819424',
                2000000000 => '90698825',
                20000000000 => '77737706',
            ],
            'sha512' => [
                59 => '90693936',
                1111111109 => '25091201',
                1111111111 => '99943326',
                1234567890 => '93441116',
                2000000000 => '38618901',
                20000000000 => '47863826',
            ],
        ];

        $cases = [];
        foreach ($vectors as $algorithm => $expectations) {
            foreach ($expectations as $timestamp => $expected) {
                $cases[$algorithm . ' t=' . $timestamp] = [
                    $algorithm,
                    $keys[$algorithm],
                    $timestamp,
                    $expected,
                ];
            }
        }

        return $cases;
    }

    /**
     * @dataProvider rfc6238Provider
     */
    public function testMatchesTheReferenceVectorsOfRfc6238(
        string $algorithm,
        string $key,
        int $timestamp,
        string $expected
    ) {
        $totp = new Totp(window: 0, step: 30, length: 8, algorithm: $algorithm);
        $totp->setKey('rfc', $key);

        $this->assertEquals($expected, $totp->generate('rfc', null, $timestamp));
        $this->assertTrue($totp->validate('rfc', $expected, null, $timestamp));
    }

    public function testWindowDefaultsToOneStep()
    {
        $window = (new \ReflectionClass(Totp::class))
            ->getConstructor()
            ->getParameters()[0]
            ->getDefaultValue();

        // RFC 6238 section 5.2: one step of tolerance, not ten.
        $this->assertEquals(1, $window);
    }

    public function testSetKeyRejectsAKeyWithoutAnyBase32Character()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Key for identifier 'test' is not a valid Base32 string");

        // Such a key used to decode to zero byte, and every account holding
        // one produced the very same code.
        $this->totp->setKey('test', '!!!!');
    }

    public function testSetKeyRejectsAKeyWithStrayCharacters()
    {
        $this->expectException(\InvalidArgumentException::class);

        // This one used to decode exactly like 'JBSWY3DPEHPK3PXP'.
        $this->totp->setKey('test', 'JBSWY3DP!!!EHPK3PXP');
    }

    public function testSetKeyAcceptsSpacesAndPadding()
    {
        // What an authenticator app displays, and the padding of RFC 4648.
        $this->totp->setKey('spaced', 'jbsw y3dp ehpk 3pxp=');
        $this->totp->setKey('plain', 'JBSWY3DPEHPK3PXP');

        $this->assertEquals(
            $this->totp->generate('plain'),
            $this->totp->generate('spaced')
        );
    }

    public function testSetWindowRejectsANegativeWindow()
    {
        $this->expectException(\InvalidArgumentException::class);

        // A negative window empties the validation loop: validate() would
        // answer false to every token, its own included.
        $this->totp->setWindow(-1);
    }

    public function testSetLengthRejectsALengthOutOfRange()
    {
        $this->expectException(\InvalidArgumentException::class);

        // Ten digits is the ceiling: eleven overflows into float arithmetic.
        $this->totp->setLength(20);
    }

    public function testSetStepRejectsAStepBelowOneSecond()
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->totp->setStep(0);
    }

    public function testSetAlgorithmRejectsAnUnknownAlgorithm()
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->totp->setAlgorithm('nawak');
    }

    public function testAFiveMinuteCodeIsAMatterOfStepNotOfWindow()
    {
        // Five minutes of validity, three live codes — where a window of ten
        // over a thirty-second step would keep twenty-one.
        $totp = new Totp(window: 1, step: 300);
        $totp->setKey('reset', 'JBSWY3DPEHPK3PXP');

        $now = 1800000000;
        $code = $totp->generate('reset', null, $now);

        $this->assertTrue($totp->validate('reset', $code, null, $now - 300));
        $this->assertTrue($totp->validate('reset', $code, null, $now + 300));
        $this->assertFalse($totp->validate('reset', $code, null, $now + 900));
    }

    /**
     * Encode an ASCII string to Base32, for the RFC fixtures only.
     */
    private static function toBase32(string $ascii): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $encoded = '';
        $bits = 0;
        $value = 0;

        for ($i = 0; $i < strlen($ascii); $i++) {
            $value = ($value << 8) | ord($ascii[$i]);
            $bits += 8;

            while ($bits >= 5) {
                $encoded .= $alphabet[($value >> ($bits - 5)) & 31];
                $bits -= 5;
            }
        }

        if ($bits > 0) {
            $encoded .= $alphabet[($value << (5 - $bits)) & 31];
        }

        return $encoded;
    }
}
