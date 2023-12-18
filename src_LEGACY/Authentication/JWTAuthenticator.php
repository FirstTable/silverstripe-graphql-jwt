<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Authentication;

use BadMethodCallException;
use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Exception;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\MemberTokenGenerator;
use Firesphere\GraphQLJWT\Model\JWTRecord;
use Firesphere\GraphQLJWT\Resolvers\Resolver;
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
use Firesphere\GraphQLJWT\Types\TokenStatusEnum;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
=======
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token;
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Token\RegisteredClaims;
=======
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
use LogicException;
use OutOfBoundsException;
use Psr\Clock\ClockInterface as Clock;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

class JWTAuthenticator extends MemberAuthenticator
{
    use Injectable;
    use Configurable;
    use MemberTokenGenerator;

    const JWT_SIGNER_KEY = 'JWT_SIGNER_KEY';

    const JWT_KEY_PASSWORD = 'JWT_KEY_PASSWORD';

    const JWT_PUBLIC_KEY = 'JWT_PUBLIC_KEY';

    /**
     * Key is RSA public/private pair
     */
    const RSA = 'RSA';

    /**
     * Key is RSA public/private pair, with password enabled
     */
    const RSA_PASSWORD = 'RSA_PASSWORD';

    /**
     * Key is HMAC string
     */
    const HMAC = 'HMAC';

    /**
     * Set to true to allow anonymous JWT tokens (no member record / email / password)
     *
     * @config
     * @var bool
     */
    private static $anonymous_allowed = false;

    /**
     * @config
     * @var int
     */
    private static $nbf_time = 0;

    /**
     * Expires after 1 hour
     *
     * @config
     * @var int
     */
    private static $nbf_expiration = 30; //TODO: change back to 3600

    /**
     * Token can be refreshed within 7 days
     *
     * @config
     * @var int
     */
    private static $nbf_refresh_expiration = 604800;

    /**
     * @config
     * @var Config
     */
    private $config;

    public function __construct(Configuration $config = null)
    {

        $this->config = $config ?? Configuration::forSymmetricSigner($this->getSigner(), $this->getPrivateKey());
    }

    /**

    /**
     * Keys are one of:
     *   - public / private RSA pair files
     *   - public / private RSA pair files, password protected private key
     *   - private HMAC string
     *
     * @return string
     */
    protected function getKeyType(): string
    {
        $signerKey = $this->getEnv(self::JWT_SIGNER_KEY);
        $path = $this->resolvePath($signerKey);
        if (!$path) {
            return self::HMAC;
        }
        if ($this->getEnv(self::JWT_KEY_PASSWORD, null)) {
            return self::RSA_PASSWORD;
        }
        return self::RSA;
    }

    /**
     * @return Signer
     */
    protected function getSigner(): Signer
    {
        switch ($this->getKeyType()) {
            case self::HMAC:
                return new Hmac\Sha256();
            case self::RSA:
            case self::RSA_PASSWORD:
            default:
                return new Rsa\Sha256();
        }
    }

    /**
     * Get private key used to generate JWT tokens
     *
     * @return Key
     */
    protected function getPrivateKey(): Key
    {
        // Note: Only private key has password enabled
        $password = $this->getEnv(self::JWT_KEY_PASSWORD, null);
        return $this->makeKey(self::JWT_SIGNER_KEY, $password);
    }

    /**
     * Get public key used to validate JWT tokens
     *
     * @return Key
     * @throws LogicException
     */
    protected function getPublicKey(): Key
    {
        switch ($this->getKeyType()) {
            case self::HMAC:
                // If signer key is a HMAC string instead of a path, public key == private key
                return $this->getPrivateKey();
            default:
                // If signer key is a path to RSA token, then we require a separate public key path
                return $this->makeKey(self::JWT_PUBLIC_KEY);
        }
    }

    /**
     * Construct a new key from the named config variable
     *
     * @param string $name Key name
     * @param string|null $password Optional password
     * @return Key
     */
    private function makeKey(string $name, string $password = null): Key
    {
        $key = $this->getEnv($name);
        $path = $this->resolvePath($key);

        // String key
        if (empty($path)) {
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
            return InMemory::plainText($key);
        }

        // Build key from path
        return InMemory::file('file://' . $path, $password);
=======
            if ($this->isBase64String($key)) {
                return InMemory::base64Encoded($key);
            } else {
                return InMemory::plainText($key);
            }
        }

        // Build key from path
        return InMemory::file($path, $password);
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
    }

    /**
     * JWT is stateless, therefore, we don't support anything but login
     *
     * @return int
     */
    public function supportedServices(): int
    {
        return Authenticator::LOGIN;
    }

    /**
     * @param array $data
     * @param HTTPRequest $request
     * @param ValidationResult|null $result
     * @return Member|null
     * @throws OutOfBoundsException
     * @throws BadMethodCallException
     * @throws Exception
     */
    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null): ?Member
    {
        if (!$result) {
            $result = new ValidationResult();
        }
        $token = $data['token'];

        /** @var JWTRecord $record */
        list($record, $status) = $this->validateToken($token, $request);

        // Report success!
        if ($status === Resolver::STATUS_OK) {
            return $record->Member();
        }

        // Add errors to result
        $result->addError(
            $this->getErrorMessage($status),
            ValidationResult::TYPE_ERROR,
            $status
        );
        return null;
    }

    /**
     * Generate a new JWT token for a given request, and optional (if anonymous_allowed) user
     *
     * @param HTTPRequest $request
     * @param Member|MemberExtension $member
     * @return Token
     * @throws ValidationException
     * @throws Exception
     */
    public function generateToken(HTTPRequest $request, Member $member): Token
    {
        $config = static::config();
        $uniqueID = uniqid($this->getEnv('JWT_PREFIX', ''), true);

        // Create new record
        $record = new JWTRecord();
        $record->UID = $uniqueID;
        $record->UserAgent = $request->getHeader('User-Agent');
        $member->AuthTokens()->add($record);
        if (!$record->isInDB()) {
            $record->write();
        }

        // Create builder for this record
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
        $builder = $this->config->builder(ChainedFormatter::withUnixTimestampDates());
=======
        $builder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));

>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
        $token = $builder
            // Configures the issuer (iss claim)
            ->issuedBy($request->getHeader('Origin'))
            // Configures the audience (aud claim)
            ->permittedFor(Director::absoluteBaseURL())
            // Configures the id (jti claim), replicating as a header item
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
            ->identifiedBy($uniqueID)->withHeader(RegisteredClaims::ID, $uniqueID)
=======
            ->identifiedBy($uniqueID)->withHeader('jti', $uniqueID)
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($this->getNow())
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($this->getNowPlus($config->get('nbf_time')))
            // Configures the expiration time of the token (nbf claim)
            ->expiresAt($this->getNowPlus($config->get('nbf_expiration')))
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
            // Set renew expiration
=======
            // Set renew expiration (unix timestamp)
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
            ->withClaim('rexp', $this->getNowPlus($config->get('nbf_refresh_expiration')))
            // Configures a new claim, called "rid"
            ->withClaim('rid', $record->ID)
            // Set the subject, which is the member
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
            ->relatedTo($member->getJWTData());
            // Sign the key with the Signer's key
//            ->sign($this->getSigner(), $this->getPrivateKey());

        // Return the token
        return $token->getToken($this->config->signer(), $this->config->signingKey());
=======
            ->relatedTo($member->getJWTData())
            // Sign the key with the Signer's key
            ->getToken($this->getSigner(), $this->getPrivateKey());

        // Return the token
        return $token;
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
    }

    /**
     * @param string $token
     * @param HTTPRequest $request
     * @return array|null Array with JWTRecord and int status (STATUS_*)
     * @throws BadMethodCallException|Exception
     */
    public function validateToken(?string $token, HTTPrequest $request): array
    {
        // Parse token
        $parsedToken = $this->parseToken($token);
        if (!$parsedToken) {
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
            echo 'failed 1';exit;
            return [null, TokenStatusEnum::STATUS_INVALID];
=======
            return [null, Resolver::STATUS_INVALID];
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
        }

        // Find local record for this token
        /** @var JWTRecord $record */
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
//        $record = DataObject::get_one(JWTRecord::class, ['UID' => $parsedToken->isIdentifiedBy()]);
        $record = JWTRecord::get()->byID($parsedToken->claims()->get('rid'));
        if (!$record) {
            echo 'failed 2';exit;
            return [null, TokenStatusEnum::STATUS_INVALID];
=======
        $record = JWTRecord::get()->byID($parsedToken->claims()->get('rid'));
        if (!$record) {
            return [null, Resolver::STATUS_INVALID];
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
        }

        // Verified and valid = ok!
        $valid = $this->validateParsedToken($parsedToken, $request, $record);
        if ($valid) {
            return [$record, Resolver::STATUS_OK];
        }

        // If the token is invalid, but not because it has expired, fail
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
        $now = $this->getNow();
        if (!$parsedToken->isExpired($now)) {
            echo 'failed 3 - ' . $parsedToken->claims()->get(RegisteredClaims::EXPIRATION_TIME)->format('Y-m-d H:i:s');exit;
            return [$record, TokenStatusEnum::STATUS_INVALID];
=======
        if ((new Validator())->validate($parsedToken, new LooseValidAt($this->getClock()))) {
            return [$record, Resolver::STATUS_INVALID];
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
        }

        // If expired, check if it can be renewed
        $canReniew = $this->canTokenBeRenewed($parsedToken);
        if ($canReniew) {
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
            echo 'failed 4';exit;
            return [$record, TokenStatusEnum::STATUS_EXPIRED];
=======
            return [$record, Resolver::STATUS_EXPIRED];
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
        }

//        echo 'failed 5';exit;
        // If expired and cannot be renewed, it's dead
        return [$record, Resolver::STATUS_DEAD];
    }

    /**
     * Parse a string into a token
     *
     * @param string|null $token
     * @return UnencryptedToken|null
     */
    protected function parseToken(?string $token): ?UnencryptedToken
    {
        // Ensure token given at all
        if (!$token) {
            return null;
        }

        try {
            $parser = $this->config->parser();
            // Verify parsed token matches signer
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
=======
            $parser = new Parser(new JoseEncoder());
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
            $parsedToken = $parser->parse($token);
            return $parsedToken;
        } catch (Exception $ex) {
            // Un-parsable tokens are invalid
            return null;
        }

        // Verify this token with configured keys
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
//        $verified = $parsedToken->verify($this->getSigner(), $this->getPublicKey());
//        return $verified ? $parsedToken : null;
=======
        $validator = new Validator();
        $verified = $validator->validate($parsedToken, new SignedWith($this->getSigner(), $this->getPublicKey()));

        return $verified ? $parsedToken : null;
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
    }

    /**
     * Determine if the given token is current, given the context of the current request
     *
     * @param UnencryptedToken $parsedToken
     * @param HTTPRequest      $request
     * @param JWTRecord        $record
     * @return bool
     * @throws Exception
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
     **/
     protected function validateParsedToken(UnencryptedToken $parsedToken, HTTPrequest $request, JWTRecord $record): bool
     {
     // @todo - upgrade
     // @see https://lcobucci-jwt.readthedocs.io/en/latest/upgrading/#replace-tokenverify-and-tokenvalidate-with-validation-api

         $this->config->setValidationConstraints(
//            new IssuedBy($request->getHeader('Origin')),
            new PermittedFor(Director::absoluteBaseURL()),
            new IdentifiedBy($record->UID),
            new StrictValidAt(new SystemClock(new DateTimeZone(date_default_timezone_get())))
        );

        $validator = $this->config->validator();
        return $validator->validate($parsedToken, ...$this->config->validationConstraints());
     }
=======
     */
    protected function validateParsedToken(Token $parsedToken, HTTPrequest $request, JWTRecord $record): bool
    {
        $validator = new Validator();

        if (!$validator->validate($parsedToken, new IssuedBy($request->getHeader('Origin')))) {
            // The token was not issued by the given issuer
            return false;
        }

        if (!$validator->validate($parsedToken, new PermittedFor(Director::absoluteBaseURL()))) {
            // The token is not allowed to be used by this audience
            return false;
        }

        if (!$validator->validate($parsedToken, new IdentifiedBy($record->UID))) {
            // The token is not related to the expected subject
            return false;
        }

        if (!$validator->validate($parsedToken, new LooseValidAt($this->getClock()))) {
            // The token is expired
            return false;
        }

        return true;
    }
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php

    /**
     * Check if the given token can be renewed
     *
     * @param UnencryptedToken $parsedToken
     * @return bool
     * @throws Exception
     */
    protected function canTokenBeRenewed(UnencryptedToken $parsedToken): bool
    {
<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
//        $renewBefore = $parsedToken->claims()->get(RegisteredClaims::ISSUED_AT) + $this->config->get('nbf_refresh_expiration');
        $renewBefore = $parsedToken->claims()->get('rexp');
        $now = $this->getNow()->getTimestamp();
        return $renewBefore > $now;
=======
        $renewBefore = $parsedToken->claims()->get('rexp');
        return $renewBefore > $this->getNow()->getTimestamp();
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
    }

    /**
     * Return an absolute path from a relative one
     * If the path doesn't exist, returns null
     *
     * @param string $path
     * @param string $base
     * @return string|null
     */
    protected function resolvePath(string $path, string $base = BASE_PATH): ?string
    {
        if (strstr($path, '/') !== 0) {
            $path = $base . '/' . $path;
        }
        return realpath($path) ?: null;
    }


    /**
     * Get an environment value. If $default is not set and the environment isn't set either this will error.
     *
     * @param string $key
     * @param string|null $default
     * @return string|null
     * @throws LogicException Error if environment variable is required, but not configured
     */
    protected function getEnv(string $key, $default = null): ?string
    {
        $value = Environment::getEnv($key);
        if ($value) {
            return $value;
        }
        if (func_num_args() === 1) {
            throw new LogicException("Required environment variable {$key} not set");
        }
        return $default;
    }

<<<<<<< HEAD:src_LEGACY/Authentication/JWTAuthenticator.php
    protected function getNow(): DateTimeImmutable
    {
        $clock = new SystemClock(new DateTimeZone(date_default_timezone_get()));
        return $clock->now();
    }

    protected function getNowPlus($seconds)
    {
        return $this->getNow()->add(new DateInterval(sprintf("PT%dS", $seconds)));
=======
    /**
     * @return DateTimeImmutable
     * @throws Exception
     */
    protected function getNow(): DateTimeImmutable
    {
        return new DateTimeImmutable(DBDatetime::now()->getValue());
    }

    /**
     * @param int $seconds
     * @return DateTimeImmutable
     * @throws Exception
     */
    protected function getNowPlus($seconds)
    {
        $sec = $seconds;
        $sec = ($sec < 0) ? abs($sec) : $sec;

        $di = new DateInterval(sprintf("PT%dS", $sec));

        if ($seconds < 0) {
            $di->invert = 1;
        }

        return $this->getNow()->add($di);
    }

    /**
     * @return Clock
     */
    protected function getClock(): Clock
    {
        return new class implements Clock {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable(DBDatetime::now()->getValue());
            }
        };
    }

    /**
     * @param string $string
     * @return bool
     */
    protected function isBase64String(string $string): bool
    {
        // Check if there are valid base64 characters
        if (!preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $string)) return false;
    
        // Decode the string in strict mode and check the results
        $decoded = base64_decode($string, true);
        if(false === $decoded) return false;
    
        // Encode the string again
        if(base64_encode($decoded) != $string) return false;
    
        return true;
>>>>>>> c00f882754eef77e94c59ff909be585d9d2cba44:src/Authentication/JWTAuthenticator.php
    }
}
