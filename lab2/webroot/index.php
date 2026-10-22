<?php
// Default endpoint: any app that keeps state starts a session.
session_start();
header('Content-Type: text/plain');
echo "index\n";
echo "php=" . PHP_VERSION . "\n";
echo "sapi=" . PHP_SAPI . "\n";
echo "handler=" . ini_get('session.serialize_handler') . "\n";
