<?php
/**
 * Totp.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@gmail.com>
 * @copyright 2010-2025 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

declare(strict_types=1);

namespace blackcube\totp;

use InvalidArgumentException;

/**
 * Class Totp
 *
 * TOTP (Time-based One-Time Password) implementation
 *
 * This class provides methods to generate and validate TOTP codes
 * according to RFC 6238 specification.
 *
 * @author Philippe Gaultier <pgaultier@gmail.com>
 * @copyright 2010-2025 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class Totp
{
    /**
     * Storage for keys indexed by type
     *
     * @var array<string, string>
     */
    private array $keys = [];

    /**
     * Constructor
     *
     * @param int $window Time window for validation in steps (±5 minutes by default)
     * @param int $step Time interval in seconds (30s by default)
     * @param int $length TOTP code length (6 digits by default)
     * @param string $algorithm Hash algorithm ('sha1' by default)
     */
    public function __construct(
        private int $window = 10,
        private int $step = 30,
        private int $length = 6,
        private string $algorithm = 'sha1'
    ) {
    }

    /**
     * Set the time window for validation
     *
     * @param int $window Number of time steps to check before and after current time
     * @return void
     */
    public function setWindow(int $window): void
    {
        $this->window = $window;
    }

    /**
     * Set the time step interval
     *
     * @param int $step Time interval in seconds
     * @return void
     */
    public function setStep(int $step): void
    {
        $this->step = $step;
    }

    /**
     * Set the length of generated TOTP codes
     *
     * @param int $length Number of digits in the TOTP code
     * @return void
     */
    public function setLength(int $length): void
    {
        $this->length = $length;
    }

    /**
     * Get the length of generated TOTP codes
     *
     * @return int Number of digits in the TOTP code
     */
    public function getLength(): int
    {
        return $this->length;
    }

    /**
     * Set the hash algorithm
     *
     * @param string $algorithm Hash algorithm (e.g., 'sha1', 'sha256', 'sha512')
     * @return void
     */
    public function setAlgorithm(string $algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    /**
     * Set a key for a specific type
     *
     * @param string $type Key type identifier
     * @param string $key Base32 encoded key
     * @return void
     * @throws InvalidArgumentException When key is empty
     */
    public function setKey(string $type, string $key): void
    {
        if (empty($key)) {
            throw new InvalidArgumentException("Key for type '{$type}' cannot be empty");
        }
        $this->keys[$type] = $key;
    }

    /**
     * Generate a TOTP code
     *
     * @param string $type Key type to use for generation
     * @param string|null $derivationParam Optional parameter for key derivation
     * @return string Generated TOTP code
     * @throws InvalidArgumentException When key type is not found
     */
    public function generate(string $type, ?string $derivationParam = null): string
    {
        $key = $this->getCompositeKey($type, $derivationParam);
        $counter = $this->getCounter();
        return $this->generateTOTP($key, $counter, $this->length);
    }

    /**
     * Validate a TOTP token
     *
     * @param string $type Key type to use for validation
     * @param string $token TOTP token to validate
     * @param string|null $derivationParam Optional parameter for key derivation
     * @return bool True if token is valid, false otherwise
     * @throws InvalidArgumentException When key type is not found
     */
    public function validate(string $type, string $token, ?string $derivationParam = null): bool
    {
        $key = $this->getCompositeKey($type, $derivationParam);
        $currentCounter = $this->getCounter();

        // Check within the defined time window
        for ($i = -$this->window; $i <= $this->window; $i++) {
            $counter = $currentCounter + $i;
            if ($this->generateTOTP($key, $counter, $this->length) === $token) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate a random Base32 encoded key
     *
     * @return string Base32 encoded random key (160 bits)
     */
    public function generateKey(): string
    {
        $buffer = random_bytes(20); // 160 bits
        return $this->encodeBase32($buffer);
    }

    /**
     * Get the composite key for TOTP generation
     *
     * @param string $type Key type
     * @param string|null $derivationParam Optional derivation parameter
     * @return string Binary key data
     * @throws InvalidArgumentException When key type is not found
     */
    private function getCompositeKey(string $type, ?string $derivationParam = null): string
    {
        if (!isset($this->keys[$type])) {
            throw new InvalidArgumentException("Key not found for type '{$type}'");
        }

        $baseKey = $this->keys[$type];

        // Decode base32 key to buffer
        $keyBuffer = $this->decodeBase32($baseKey);

        // If no derivation parameter is provided, return the base key
        if ($derivationParam === null) {
            return $keyBuffer;
        }

        // Derive a new key using HMAC
        return hash_hmac($this->algorithm, $derivationParam, $keyBuffer, true);
    }

    /**
     * Get the current time counter
     *
     * @param int|null $timestamp Optional timestamp in milliseconds
     * @return int Time counter based on step interval
     */
    private function getCounter(?int $timestamp = null): int
    {
        if ($timestamp === null) {
            $timestamp = time() * 1000; // Convert to milliseconds like Date.now()
        }
        return intval(floor($timestamp / 1000 / $this->step));
    }

    /**
     * Generate TOTP using HMAC-based algorithm
     *
     * @param string $key Binary key data
     * @param int $counter Time counter
     * @param int $digits Number of digits in output
     * @return string TOTP code padded with leading zeros
     */
    private function generateTOTP(string $key, int $counter, int $digits): string
    {
        // Convert counter to bytes (big endian 8 bytes)
        $counterBuffer = pack('J', $counter);

        // Calculate HMAC hash
        $hmacResult = hash_hmac($this->algorithm, $counterBuffer, $key, true);

        // Extract value based on the last nibble
        $offset = ord($hmacResult[strlen($hmacResult) - 1]) & 0xf;

        // Extract 4 bytes from offset and mask MSB
        $code = ((ord($hmacResult[$offset]) & 0x7f) << 24) |
                ((ord($hmacResult[$offset + 1]) & 0xff) << 16) |
                ((ord($hmacResult[$offset + 2]) & 0xff) << 8) |
                (ord($hmacResult[$offset + 3]) & 0xff);

        // Convert to code of specified length
        $code = $code % (10 ** $digits);

        // Add leading zeros if necessary
        return str_pad((string)$code, $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Decode Base32 encoded string to binary data
     *
     * @param string $encoded Base32 encoded string
     * @return string Binary data
     */
    private function decodeBase32(string $encoded): string
    {
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = 0;
        $value = 0;

        // Remove spaces and convert to uppercase
        $encoded = strtoupper(preg_replace('/\s+/', '', $encoded));

        // Result as array
        $result = [];

        for ($i = 0; $i < strlen($encoded); $i++) {
            $char = $encoded[$i];
            $charValue = strpos($base32Chars, $char);

            if ($charValue === false) {
                continue; // Ignore invalid characters
            }

            $value = ($value << 5) | $charValue;
            $bits += 5;

            if ($bits >= 8) {
                $result[] = ($value >> ($bits - 8)) & 0xff;
                $bits -= 8;
            }
        }

        return pack('C*', ...$result);
    }

    /**
     * Encode binary data to Base32 string
     *
     * @param string $buffer Binary data
     * @return string Base32 encoded string
     */
    private function encodeBase32(string $buffer): string
    {
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $result = '';
        $bits = 0;
        $value = 0;

        for ($i = 0; $i < strlen($buffer); $i++) {
            $value = ($value << 8) | ord($buffer[$i]);
            $bits += 8;

            while ($bits >= 5) {
                $result .= $base32Chars[($value >> ($bits - 5)) & 31];
                $bits -= 5;
            }
        }

        // Handle remaining bits if needed
        if ($bits > 0) {
            $result .= $base32Chars[($value << (5 - $bits)) & 31];
        }

        return $result;
    }
}
