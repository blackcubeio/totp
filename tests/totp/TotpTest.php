<?php

use blackcube\totp\Totp;

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
        $this->expectExceptionMessage("Key for type 'test' cannot be empty");

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
        $this->expectExceptionMessage("Key not found for type 'unknown'");

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
        $this->expectExceptionMessage("Key not found for type 'unknown'");

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

        foreach ([4, 6, 8] as $length) {
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
}
