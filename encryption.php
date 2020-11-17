<?php

$a="www.baidu.com:80";

function getBytes($string) {
    $bytes = array();
    for($i = 0; $i < strlen($string); $i++){
         $bytes[] = ord($string[$i]);
    }
    return $bytes;
}

function toStr($bytes) {
    $str = '';
    foreach($bytes as $ch) {
        $str .= chr($ch);
    }

    return $str;
}

function array_xor($arr) {
    $s=[];
    foreach ($arr as $key => $value) {
        $s[]=$value^1;
    }
    return $s;
}

$encode = toStr(array_xor(getBytes($a)));
$decode = toStr(array_xor(getBytes($encode)));

var_dump($encode);

var_dump($decode);


