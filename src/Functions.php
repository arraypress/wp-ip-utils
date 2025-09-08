<?php
/**
 * Global IP Helper Functions
 *
 * Provides convenient global functions for common IP operations.
 * These functions are wrappers around the ArrayPress\IPUtils\IP class.
 *
 * Functions included:
 * - get_user_ip() - Get the current user's IP address
 * - anonymize_ip() - Anonymize an IP address
 * - is_valid_ip() - Check if IP address is valid
 * - is_ip_in_range() - Check if IP is in CIDR range
 *
 * @package ArrayPress\IPUtils
 * @since   1.0.0
 */

// Exit if accessed directly
use ArrayPress\IPUtils\IP;

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'get_user_ip' ) ) {
	/**
	 * Get the current user's IP address.
	 *
	 * @since 1.0.0
	 * @return string|null The user's IP address, or null if not found.
	 */
	function get_user_ip(): ?string {
		return IP::get();
	}
}

if ( ! function_exists( 'is_valid_ip' ) ) {
	/**
	 * Validate an IP address (IPv4 or IPv6).
	 *
	 * @since 1.0.0
	 * @param string $ip The IP address to validate.
	 * @return bool True if the IP address is valid.
	 */
	function is_valid_ip( string $ip ): bool {
		return IP::is_valid( $ip );
	}
}

if ( ! function_exists( 'is_ip_in_range' ) ) {
	/**
	 * Check if an IP address is within a specified CIDR range.
	 *
	 * @since 1.0.0
	 * @param string $ip    The IP address to check.
	 * @param string $range The IP range in CIDR format.
	 * @return bool True if IP is in range.
	 */
	function is_ip_in_range( string $ip, string $range ): bool {
		return IP::is_in_range( $ip, $range );
	}
}