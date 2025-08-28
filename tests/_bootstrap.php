<?php
/**
 * _boostrap.php
 *
 * PHP Version 8.3+
 *
 * @author Philippe Gaultier <pgaultier@gmail.com>
 * @copyright 2010-2025 Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
 * @package tests\unit
 */

use Codeception\Configuration;

date_default_timezone_set('Europe/Paris');

// fcgi doesn't have STDIN and STDOUT defined by default
defined('STDIN') or define('STDIN', fopen('php://stdin', 'r'));
defined('STDOUT') or define('STDOUT', fopen('php://stdout', 'w'));

// init autoloaders
require dirname(__DIR__).'/vendor/autoload.php';

ini_set('display_errors', '1');
error_reporting(E_ALL);
