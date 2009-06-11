<?php

header("X-Sendfile: " . getcwd() . "/index.txt");

if ($_GET["range"]) header("X-Sendfile-Range: " . $_GET["range"]);

?>