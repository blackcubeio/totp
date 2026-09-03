<?php

declare(strict_types=1);

/**
 * _bootstrap.php
 *
 * @copyright 2010-2026 Blackcube - Philippe Gaultier
 * @license https://www.blackcube.io/license
 * @link https://www.blackcube.io
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
