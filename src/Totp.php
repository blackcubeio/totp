<?php

declare(strict_types=1);

/**
 * Totp.php
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */

namespace Blackcube\Totp;

use InvalidArgumentException;

/**
 * Class Totp
 *
 * TOTP (Time-based One-Time Password) implementation
 *
 * This class provides methods to generate and validate TOTP codes
 * according to RFC 6238 specification.
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 */
class Totp
{
    /**
     * The Base32 alphabet of RFC 4648, without its padding.
     */
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * RFC 4226 section 5.3 defines the truncation for six to eight digits. Ten
     * is where the modulus still fits a 64-bit integer; past it the code is
     * computed on a float and loses its last digits.
     */
    private const MIN_LENGTH = 6;
    private const MAX_LENGTH = 10;

    /**
     * Storage for keys indexed by type
     *
     * @var array<string, string>
     */
    private array $keys = [];

    /**
     * Constructor
     *
     * The window follows RFC 6238 section 5.2: one step of tolerance on each
     * side, no more. A code that has to stay valid longer is a matter of STEP,
     * not of window - five minutes is step 300 and window 1, which keeps three
     * codes alive where a window of ten would keep twenty-one.
     *
     * @param int $window Steps accepted before and after the current one
     * @param int $step Time interval in seconds (30s by default)
     * @param int $length TOTP code length (6 digits by default)
     * @param string $algorithm Hash algorithm ('sha1' by default)
     * @throws InvalidArgumentException When a setting is out of range
     */
    public function __construct(
        private int $window = 1,
        private int $step = 30,
        private int $length = 6,
        private string $algorithm = 'sha1'
    ) {
        $this->setWindow($window);
        $this->setStep($step);
        $this->setLength($length);
        $this->setAlgorithm($algorithm);
    }

    /**
     * Set the time window for validation
     *
     * @param int $window Number of time steps to check before and after current time
     * @return void
     * @throws InvalidArgumentException When the window is negative
     */
    public function setWindow(int $window): void
    {
        if ($window < 0) {
            // A negative window makes the validation loop empty: validate()
            // would answer false to every token, including the ones it has
            // just produced, and lock the account without saying a word.
            throw new InvalidArgumentException(
                sprintf('Window cannot be negative, got %d.', $window)
            );
        }

        $this->window = $window;
    }

    /**
     * Set the time step interval
     *
     * @param int $step Time interval in seconds
     * @return void
     * @throws InvalidArgumentException When the step is below one second
     */
    public function setStep(int $step): void
    {
        if ($step < 1) {
            throw new InvalidArgumentException(
                sprintf('Step must be at least one second, got %d.', $step)
            );
        }

        $this->step = $step;
    }

    /**
     * Set the length of generated TOTP codes
     *
     * @param int $length Number of digits in the TOTP code
     * @return void
     * @throws InvalidArgumentException When the length is out of the usable range
     */
    public function setLength(int $length): void
    {
        if ($length < self::MIN_LENGTH || $length > self::MAX_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'Length must be between %d and %d digits, got %d.',
                self::MIN_LENGTH,
                self::MAX_LENGTH,
                $length
            ));
        }

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
        if (in_array($algorithm, hash_hmac_algos(), true) === false) {
            throw new InvalidArgumentException(
                sprintf('Unknown hash algorithm "%s".', $algorithm)
            );
        }

        $this->algorithm = $algorithm;
    }

    /**
     * Set a key for a specific identifier
     *
     * The key is checked HERE rather than when it is used. A key that holds no
     * Base32 character at all used to decode to zero byte, and two accounts
     * carrying such a key produced the SAME code - the empty key. The mistake
     * has to surface where it is made.
     *
     * @param string $keyIdentifier Key identifier
     * @param string $key Base32 encoded key
     * @return void
     * @throws InvalidArgumentException When the key is empty or not Base32
     */
    public function setKey(string $keyIdentifier, string $key): void
    {
        $normalized = $this->normalizeBase32($key);

        if ($normalized === '') {
            throw new InvalidArgumentException(
                sprintf("Key for identifier '%s' cannot be empty", $keyIdentifier)
            );
        }

        if (preg_match('/^[A-Z2-7]+$/', $normalized) !== 1) {
            throw new InvalidArgumentException(
                sprintf("Key for identifier '%s' is not a valid Base32 string", $keyIdentifier)
            );
        }

        $this->keys[$keyIdentifier] = $normalized;
    }

    /**
     * Generate a TOTP code
     *
     * @param string $keyIdentifier Key identifier to use for generation
     * @param string|null $derivationParam Optional parameter for key derivation
     * @return string Generated TOTP code
     * @throws InvalidArgumentException When key type is not found
     */
    public function generate(
        string $keyIdentifier,
        ?string $derivationParam = null,
        ?int $timestamp = null
    ): string {
        $key = $this->getCompositeKey($keyIdentifier, $derivationParam);
        $counter = $this->getCounter($timestamp);
        return $this->generateTOTP($key, $counter, $this->length);
    }

    /**
     * Validate a TOTP token
     *
     * @param string $keyIdentifier Key identifier to use for validation
     * @param string $token TOTP token to validate
     * @param string|null $derivationParam Optional parameter for key derivation
     * @return bool True if token is valid, false otherwise
     * @throws InvalidArgumentException When key identifier is not found
     */
    public function validate(
        string $keyIdentifier,
        string $token,
        ?string $derivationParam = null,
        ?int $timestamp = null
    ): bool {
        $key = $this->getCompositeKey($keyIdentifier, $derivationParam);
        $currentCounter = $this->getCounter($timestamp);
        $valid = false;

        // The whole window is walked even once a match is found, and each
        // candidate is compared with hash_equals: neither the answer nor the
        // time taken to reach it tells where in the window the token sat.
        for ($i = -$this->window; $i <= $this->window; $i++) {
            $candidate = $this->generateTOTP($key, $currentCounter + $i, $this->length);
            if (hash_equals($candidate, $token) === true) {
                $valid = true;
            }
        }

        return $valid;
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
     * @param string $keyIdentifier Key identifier
     * @param string|null $derivationParam Optional derivation parameter
     * @return string Binary key data
     * @throws InvalidArgumentException When key identifier is not found
     */
    private function getCompositeKey(string $keyIdentifier, ?string $derivationParam = null): string
    {
        if (isset($this->keys[$keyIdentifier]) === false) {
            throw new InvalidArgumentException(
                sprintf("Key not found for identifier '%s'", $keyIdentifier)
            );
        }

        $key = $this->decodeBase32($this->keys[$keyIdentifier]);

        if ($derivationParam !== null) {
            $key = hash_hmac($this->algorithm, $derivationParam, $key, true);
        }

        return $key;
    }

    /**
     * Get the current time counter
     *
     * The timestamp is in SECONDS, like time(). It used to be carried in
     * milliseconds - a leftover of a port from JavaScript, where Date.now()
     * answers in milliseconds - which made the parameter a trap for any PHP
     * caller. Nothing outside this class ever passed it.
     *
     * @param int|null $timestamp Optional Unix timestamp in seconds
     * @return int Time counter based on step interval
     */
    private function getCounter(?int $timestamp = null): int
    {
        if ($timestamp === null) {
            $timestamp = time();
        }

        return (int) floor($timestamp / $this->step);
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
        $normalized = $this->normalizeBase32($encoded);
        $bits = 0;
        $value = 0;
        $result = [];

        for ($i = 0; $i < strlen($normalized); $i++) {
            $charValue = strpos(self::BASE32_ALPHABET, $normalized[$i]);

            if ($charValue === false) {
                // Skipping the character would silently change the key:
                // 'JBSWY3DP!!!EHPK3PXP' decoded to the same bytes as
                // 'JBSWY3DPEHPK3PXP', and a key of nothing but invalid
                // characters decoded to nothing at all.
                throw new InvalidArgumentException(sprintf(
                    'Invalid Base32 character "%s" at offset %d.',
                    $normalized[$i],
                    $i
                ));
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
     * Bring a Base32 string to its canonical form
     *
     * Spaces are what an authenticator app shows to make a key readable, and
     * '=' is the padding of RFC 4648: both are dropped rather than refused.
     * What remains has to belong to the alphabet.
     *
     * @param string $encoded Base32 string, as typed or as displayed
     * @return string Uppercase, unspaced, unpadded
     */
    private function normalizeBase32(string $encoded): string
    {
        $normalized = (string) preg_replace('/\s+/', '', $encoded);

        return rtrim(strtoupper($normalized), '=');
    }

    /**
     * Encode binary data to Base32 string
     *
     * @param string $buffer Binary data
     * @return string Base32 encoded string
     */
    private function encodeBase32(string $buffer): string
    {
        $base32Chars = self::BASE32_ALPHABET;
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
