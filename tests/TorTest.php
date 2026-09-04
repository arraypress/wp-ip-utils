<?php
/**
 * The Tor check, and who it believes.
 *
 * @package ArrayPress\IPUtils
 */

declare( strict_types=1 );

namespace ArrayPress\IPUtils\Tests;

use ArrayPress\IPUtils\IP;
use PHPUnit\Framework\TestCase;

/**
 * Class TorTest
 */
final class TorTest extends TestCase {

	/**
	 * The server variables as they were.
	 *
	 * @var array
	 */
	private array $server;

	protected function setUp(): void {
		$this->server = $_SERVER;
	}

	protected function tearDown(): void {
		$_SERVER = $this->server;
	}

	/**
	 * Cloudflare's Tor marker is believed only when Cloudflare sent it.
	 *
	 * The header is the client's to write unless a trusted proxy wrote it:
	 * a visitor reaching the origin directly could send T1 and trip, or
	 * dodge, a Tor rule.
	 */
	public function test_the_tor_marker_is_believed_only_through_a_trusted_proxy(): void {
		$_SERVER['HTTP_CF_IPCOUNTRY'] = 'T1';

		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
		$this->assertFalse( IP::is_tor(), 'A header from a direct visitor was believed.' );

		// 104.16.0.0/13 is one of Cloudflare's own ranges, trusted by default.
		$_SERVER['REMOTE_ADDR'] = '104.16.1.1';
		$this->assertTrue( IP::is_tor() );

		$_SERVER['HTTP_CF_IPCOUNTRY'] = 'GB';
		$this->assertFalse( IP::is_tor() );

		unset( $_SERVER['HTTP_CF_IPCOUNTRY'], $_SERVER['REMOTE_ADDR'] );
		$this->assertFalse( IP::is_tor() );
	}
}
