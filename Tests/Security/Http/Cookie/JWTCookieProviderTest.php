<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Tests\Security\Http\Cookie;

use Lexik\Bundle\JWTAuthenticationBundle\Security\Http\Cookie\JWTCookieProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * JWTCookieProviderTest.
 */
class JWTCookieProviderTest extends TestCase
{
    public function testCreateCookieWithExpiration()
    {
        $expiresAt = time() + 3600;
        $cookieProvider = new JWTCookieProvider("default_name");
        $cookie = $cookieProvider->createCookie("header.payload.signature", "name", $expiresAt);

        $this->assertSame($expiresAt, $cookie->getExpiresTime());
    }

    public function testCreateCookieWithLifetime()
    {
        $lifetime = 3600;
        $cookieProvider = new JWTCookieProvider("default_name", $lifetime);
        $cookie = $cookieProvider->createCookie("header.payload.signature");

        $this->assertSame(time() + $lifetime, $cookie->getExpiresTime());
    }

    public function testCreateSessionCookie()
    {
        $cookieProvider = new JWTCookieProvider("default_name", 0);
        $cookie = $cookieProvider->createCookie("header.payload.signature");

        $this->assertSame(0, $cookie->getExpiresTime());
    }

    /**
     * @dataProvider createCookieFlagDataProvider
     */
    public function testCreateCookieHttpOnlyFlag(bool $defaultHttpOnlyFlag, bool $httpOnlyParam, bool $expectedFlag): void
    {
        $cookieProvider = new JWTCookieProvider(
            "default_name",
            0,
            Cookie::SAMESITE_LAX,
            '/',
            null,
            true,
            $defaultHttpOnlyFlag
        );
        $cookie = $cookieProvider->createCookie(
            "header.payload.signature",
            null,
            null,
            null,
            null,
            null,
            null,
            $httpOnlyParam
        );

        $this->assertSame($expectedFlag, $cookie->isHttpOnly());
    }

    /**
     * @dataProvider createCookieFlagDataProvider
     */
    public function testCreateCookieSecureFlag(bool $defaultSecureFlag, bool $secureParam, bool $expectedFlag): void
    {
        $cookieProvider = new JWTCookieProvider(
            "default_name",
            0,
            Cookie::SAMESITE_LAX,
            '/',
            null,
            $defaultSecureFlag
        );
        $cookie = $cookieProvider->createCookie(
            "header.payload.signature",
            null,
            null,
            null,
            null,
            null,
            $secureParam
        );

        $this->assertSame($expectedFlag, $cookie->isSecure());
    }

    /**
     * @dataProvider createCookieFlagDataProvider
     */
    public function testCreateCookiePartitionedFlag(bool $defaultPartitionedFlag, bool $parititionedParam, bool $expectedFlag): void
    {
        $cookieProvider = new JWTCookieProvider(
            "default_name",
            0,
            Cookie::SAMESITE_LAX,
            '/',
            null,
            true,
            true,
            [],
            $defaultPartitionedFlag
        );
        $cookie = $cookieProvider->createCookie(
            "header.payload.signature",
            null,
            null,
            null,
            null,
            null,
            true,
            true,
            [],
            $parititionedParam
        );

        $this->assertSame($expectedFlag, $cookie->isPartitioned());
    }

    public static function createCookieFlagDataProvider(): array
    {
        return [
            [true, true, true],
            [false, false, false],
            [true, false, false],
            [false, true, true],
        ];
    }
}
