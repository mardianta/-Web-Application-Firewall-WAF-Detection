# -Web-Application-Firewall-WAF-Detection
Url: 
```
  https://raw.githubusercontent.com/mardianta/-Web-Application-Firewall-WAF-Detection/main/script.js
```

Code:
```
  <?php
$output = '';
$waf_detected_overall = false;
$all_detected = true;
$conclusion = '';

if (isset($_POST['check_waf_payload']) && $_POST['check_waf_payload'] === 'true') {
    $domain = isset($_POST['domain']) ? $_POST['domain'] : '';
    $url_base = 'http://' . $domain . '/?q=';

    $waf_signatures = [
        "<script>alert('XSS')</script>",
        "</script><script>alert('XSS')</script>",
        "<iframe></iframe>",
        "<object data='data:text/html,<script>alert(\"XSS\")</script>'></object>",
        "<embed src='data:text/html,<script>alert(\"XSS\")</script>' type='text/html'></embed>",
        "union select 1,2,3",
        "SELECT * FROM information_schema.tables",
        "../etc/passwd",
        "..\\windows\\win.ini",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "%2E%2E%2F",
        "%2E%2E%5C"
    ];

    foreach ($waf_signatures as $payload) {
        $test_url = $url_base . urlencode($payload);

        $options = [
            'http' => [
                'method' => 'GET',
                'timeout' => 5,
                'ignore_errors' => true
            ]
        ];
        $context = stream_context_create($options);

        libxml_use_internal_errors(true);
        $response = @file_get_contents($test_url, false, $context);
        $response_code = isset($http_response_header[0]) ? $http_response_header[0] : '';
        libxml_clear_errors();

        $detected = false;
        if (strpos($response_code, '403') !== false || strpos($response_code, '406') !== false || (stripos($response, 'blocked') !== false) || (stripos($response, 'forbidden') !== false)) {
            $detected = true;
            $waf_detected_overall = true;
        } else {
            $all_detected = false;
        }

        $payload_results[] = [
            'payload' => htmlspecialchars($payload),
            'url' => htmlspecialchars($test_url),
            'response_code' => htmlspecialchars(substr($response_code, 9, 3)),
            'detected' => $detected
        ];
        unset($http_response_header);
    }

    if ($waf_detected_overall) {
        $conclusion = '<div id="overall-result" class="detected"><strong>Kesimpulan:</strong> Kemungkinan WAF aktif terdeteksi karena beberapa payload diblokir.</div>';
    } else {
        $conclusion = '<div id="overall-result" class="not-detected"><strong>Kesimpulan:</strong> Tidak ada pemblokiran payload yang jelas terdeteksi. WAF mungkin tidak aktif atau menggunakan metode deteksi lain.</div>';
    }

    $output .= $conclusion;
    $output .= '<div class="payload-results-container"><h2>Hasil Uji Payload:</h2>';

    foreach ($payload_results as $result) {
        $output .= '<div class="payload-result">';
        $output .= '<strong>Payload:</strong> ' . $result['payload'] . '<br>';
        $output .= '<strong>URL:</strong> ' . $result['url'] . '<br>';
        $output .= '<strong>Response Code:</strong> ' . $result['response_code'] . '<br>';
        $output .= '<strong>Status:</strong> <span class="' . ($result['detected'] ? 'payload-detected' : 'payload-not-detected') . '">' . ($result['detected'] ? 'Kemungkinan Diblokir' : 'Tidak Terdeteksi Diblokir') . '</span>';
        $output .= '</div>';
    }

    $output .= '</div>';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deteksi WAF Sederhana (Domain dengan Payload)</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; }
        h1, h2 { color: #333; }
        #wafForm { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: bold; color: #555; }
        input[type="text"] { width: calc(100% - 22px); padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 16px; }
        button { background-color: #5cb85c; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; transition: background-color 0.3s ease; }
        button:hover { background-color: #4cae4c; }
        #result { margin-top: 20px; }
        .detected { color: red; }
        .not-detected { color: green; }
        .warning { color: orange; }
        .payload-results-container { margin-top: 20px; }
        .payload-result { background-color: #fff; border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 4px; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05); }
        .payload-result strong { font-weight: bold; color: #333; }
        .payload-detected { color: red; font-weight: bold; }
        .payload-not-detected { color: green; font-weight: bold; }
        #overall-result { padding: 15px; border-radius: 4px; font-size: 1.1em; margin-bottom: 15px; }
        #overall-result.detected { background-color: #fdecea; border: 1px solid #e74c3c; color: #e74c3c; }
        #overall-result.not-detected { background-color: #e8f5e9; border: 1px solid #2ecc71; color: #2ecc71; }
    </style>
</head>
<body>

    <h1>Deteksi WAF Sederhana (Domain dengan Uji Payload)</h1>

    <form id="wafForm" method="POST">
        <label for="domain">Masukkan Domain:</label><br>
        <input type="text" id="domain" name="domain" size="50" placeholder="contoh: example.com"><br><br>
        <input type="hidden" name="check_waf_payload" value="true">
        <button type="submit">Deteksi</button>
    </form>

    <div id="result"><?php echo $output; ?></div>

    <script>
        document.getElementById('wafForm').addEventListener('submit', function(event) {
            const domain = document.getElementById('domain').value;
            const resultDiv = document.getElementById('result');

            if (!domain) {
                event.preventDefault();
                resultDiv.innerHTML = '<span class="warning">Harap masukkan domain.</span>';
            }
        });
    </script>

</body>
</html>
```
