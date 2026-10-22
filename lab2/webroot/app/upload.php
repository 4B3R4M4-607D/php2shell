<?php
header('Content-Type: text/plain');
echo "app/upload handler=".ini_get('session.serialize_handler')."\n";
