<?php
// Lab LFI sink: includes a path from the query string, like a template loader
// that trusts its input. This is the application bug chain B needs.
$page = $_GET['page'] ?? '';
if ($page !== '') { include($page); }
