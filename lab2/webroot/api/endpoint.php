<?php
/**
 * ============================================================================
 *  LAB ONLY — DO NOT DEPLOY THIS FILE ON A REAL HOST
 * ============================================================================
 *
 * This endpoint exists for one reason: to prove that a corrupted session can
 * reach a destructor and run a command. The `Evil` class below is a stand-in
 * for the POP chain a real application already carries (Laravel
 * PendingBroadcast, Symfony TagAwareAdapter, a WordPress plugin object, ...).
 *
 * On a real engagement you do NOT add a class. You find one the target already
 * has, and pass its name and property with --gadget-class / --gadget-prop.
 *
 * The exploit itself (exploit.py) needs nothing added to the target. If you are
 * reading this because you found it on someone else's server, you are looking
 * at the lab, not at the bug.
 * ============================================================================
 */

class Evil
{
    public $cmd = '';

    public function __destruct()
    {
        if ($this->cmd !== '') {
            $out = @shell_exec($this->cmd . ' 2>&1');
            @file_put_contents('/tmp/p2s_proof.txt', (string)$out);
            echo "P2SOUT:" . $out . ":P2SEND\n";
        }
    }
}

session_start();

header('Content-Type: text/plain');
echo "api/endpoint handler=" . ini_get('session.serialize_handler') . "\n";
echo "objects=" . count(array_filter($_SESSION, 'is_object')) . "\n";
