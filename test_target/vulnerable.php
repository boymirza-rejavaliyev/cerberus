<?php
// Vulnerable Test Script for Cerberus SAST
$api_key = "secret_key = 'abcdef1234567890abcdef'";
$aws_key = "AKIA1234567890ABCDEF";

$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
mysqli_query($conn, $query);

$cmd = $_POST['command'];
system("ping -c 4 " . $cmd);

$file = $_GET['page'];
include($file);
?>
