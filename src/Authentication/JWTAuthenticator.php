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
use Firesphere\GraphQLJWT\Types\TokenStatusEnum;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Token\RegisteredClaims;
use LogicException;
use OutOfBoundsException;
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
    private static $nbf_expiration = 3600;

    /**
     * Token can be refreshed within 7 days
     *
     * @config
     * @var int
     */
    private static $nbf_refresh_expiration = 604800;

    /**
     * @config
     * @var Configuration
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
            return InMemory::plainText($key);
        }

        // Build key from path
        return InMemory::file('file://' . $path, $password);
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

        $builder = $this->config->builder(ChainedFormatter::withUnixTimestampDates());

        $token = $builder
            // Configures the issuer (iss claim)
            ->issuedBy($request->getHeader('Origin'))
            // Configures the audience (aud claim)
            ->permittedFor(Director::absoluteBaseURL())
            // Configures the id (jti claim), replicating as a header item
            ->identifiedBy($uniqueID)->withHeader(RegisteredClaims::ID, $uniqueID)
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($this->getNow())
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($this->getNowPlus($config->get('nbf_time')))
            // Configures the expiration time of the token (nbf claim)
            ->expiresAt($this->getNowPlus($config->get('nbf_expiration')))
            // Set renew expiration

            ->withClaim('rexp', $this->getNowPlus($config->get('nbf_refresh_expiration'))->getTimestamp())
            // Configures a new claim, called "rid"
            ->withClaim('rid', $record->ID)
            // Set the subject, which is the member
            ->relatedTo($member->getJWTData());

        // Return the signed token
        return $token->getToken($this->config->signer(), $this->config->signingKey());
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
            return [null, Resolver::STATUS_INVALID];
        }

        // Find local record for this token
        /** @var JWTRecord $record */
//        $record = DataObject::get_one(JWTRecord::class, ['UID' => $parsedToken->isIdentifiedBy()]);
        $record = JWTRecord::get()->byID($parsedToken->claims()->get('rid'));
        if (!$record) {
            return [null, Resolver::STATUS_INVALID];
        }

        // Verified and valid = ok!
        $valid = $this->validateParsedToken($parsedToken, $request, $record);
        if ($valid) {
            return [$record, Resolver::STATUS_OK];
        }

        // If the token is invalid, but not because it has expired, fail
        $now = $this->getNow();
        if (!$parsedToken->isExpired($now)) {
            return [$record, Resolver::STATUS_INVALID];
        }

        // If expired, check if it can be renewed
        $canReniew = $this->canTokenBeRenewed($parsedToken);
        if ($canReniew) {
            return [$record, Resolver::STATUS_EXPIRED];
        }

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
            $parsedToken = $parser->parse($token);
            return $parsedToken;
        } catch (Exception $ex) {
            // Un-parsable tokens are invalid
            return null;
        }
    }

    /**
     * Determine if the given token is current, given the context of the current request
     *
     * @param UnencryptedToken $parsedToken
     * @param HTTPRequest      $request
     * @param JWTRecord        $record
     * @return bool
     * @throws Exception
     **/
     protected function validateParsedToken(UnencryptedToken $parsedToken, HTTPrequest $request, JWTRecord $record): bool
     {
     // @see https://lcobucci-jwt.readthedocs.io/en/latest/upgrading/#replace-tokenverify-and-tokenvalidate-with-validation-api

         // todo: is this relevant from the old code? $validator->setIssuer($request->getHeader('Origin'));
         $this->config->setValidationConstraints(
//            new IssuedBy($request->getHeader('Origin')),
            new PermittedFor(Director::absoluteBaseURL()),
            new IdentifiedBy($record->UID),
            new StrictValidAt(new SystemClock(new DateTimeZone(date_default_timezone_get())))
        );

        $validator = $this->config->validator();
        return $validator->validate($parsedToken, ...$this->config->validationConstraints());
     }

    /**
     * Check if the given token can be renewed
     *
     * @param UnencryptedToken $parsedToken
     * @return bool
     * @throws Exception
     */
    protected function canTokenBeRenewed(UnencryptedToken $parsedToken): bool
    {
//        $renewBefore = $parsedToken->claims()->get(RegisteredClaims::ISSUED_AT) + $this->config->get('nbf_refresh_expiration');
        $renewBefore = $parsedToken->claims()->get('rexp');
        $now = $this->getNow()->getTimestamp();
        return $renewBefore > $now;
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

    protected function getNow(): DateTimeImmutable
    {
        $clock = new SystemClock(new DateTimeZone(date_default_timezone_get()));
        return $clock->now();
    }

    protected function getNowPlus($seconds): DateTimeImmutable
    {
        return $this->getNow()->add(new DateInterval(sprintf("PT%dS", $seconds)));
    }

    /**
     * @param Token $token
     * @return DateTimeImmutable
     * @throws Exception
     */
    protected function getTokenREXP(Token $token): DateTimeImmutable
    {
        $renewBefore = $token->getClaim('rexp');

        return new DateTimeImmutable($renewBefore->date);
    }

}
