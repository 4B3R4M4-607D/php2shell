<?php
// No session handling at all. Still parses the multipart body during request
// startup, which is all the upload-progress handler needs to write into the
// session of the SID we send as a form field.
header('Content-Type: text/plain');
echo "nosession\nhandler=" . ini_get('session.serialize_handler') . "\n";
