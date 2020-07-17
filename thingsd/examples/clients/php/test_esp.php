<?php

$subscribe = "~~~subscribe{{name,\"metar_slp\"},{things{thing{\"data_esp\",\"Password\"}}}}\n";
$host = "10.0.100.5";
$port = "50000";

$url = "ftp://tgftp.nws.noaa.gov/data/observations/metar/stations/KPTV.TXT";
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

if ((preg_match("/SLP[0-9]+/", curl_exec($ch), $content)) === false) {
        die("");
} else {

        if (count($content) == 0) {
                die("");
        }
        $slp = str_replace("SLP", "", $content[0]);
        if ($slp > 500) {
                $slp += 9000;
        } else {
                $slp += 10000;
        }

        $slp /= 10;

        if (($sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false) {
                die("");
        }

        if (socket_connect($sock, $host, $port) === false) {
                die("");
        }
        $msg_array = array('stationid' => 'weather_station', 'key' => '3b5912b9015c', 'slp' => $slp * 1.0);
        $msg_json = json_encode($msg_array);
        $msg_json .= "}";

        $slength = strlen($subscribe);
        $jlength = strlen($msg_json);

        socket_write($sock, $subscribe, $slength);
        sleep(1);
        socket_write($sock, $msg_json, $jlength);

        sleep(1);
        socket_close($sock);

}
