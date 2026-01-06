<?php
session_start();

// --- 1. LOGIKA AJAX FETCHER ---
if (isset($_GET['ajax_target'])) {
    header('Content-Type: text/plain');
    $target_url = base64_decode($_GET['ajax_target']);
    $options = [
        'http' => [
            'method' => 'GET',
            'timeout' => 12,
            'follow_location' => 1, 
            'max_redirects' => 5,
            'ignore_errors' => true,
            'header' => "User-Agent: WAF-Auditor-Mardianta\r\n"
        ]
    ];
    $context = stream_context_create($options);
    $response = @file_get_contents($target_url, false, $context);
    echo $response ?: "Error: Gagal menjangkau target setelah mengikuti redirect.";
    exit;
}

// --- 2. SISTEM BAHASA ---
if (isset($_GET['lang'])) $_SESSION['lang'] = ($_GET['lang'] == 'en') ? 'en' : 'id';
$lang = isset($_SESSION['lang']) ? $_SESSION['lang'] : 'id';

$text = [
    'id' => [
        'title' => 'WAF PAYLOAD CHECKER',
        'subtitle' => 'Sistem Deteksi Keamanan Firewall & Audit Payload Injection',
        'single' => 'Cek Single Domain',
        'bulk' => 'Cek Bulking Domain',
        'placeholder' => 'example.com',
        'btn' => 'Mulai Deteksi',
        'about_title' => 'Mekanisme & Cara Kerja Audit',
        'about_desc' => 'Alat ini bekerja dengan mensimulasikan serangan berbasis teks (Payload Injection) melalui parameter URL. Setiap permintaan dikirimkan menggunakan protokol HTTP/S dengan kemampuan mengikuti pengalihan (Follow Redirect). Analisis dilakukan berdasarkan kode status HTTP dan pola konten pada body response untuk menentukan apakah sebuah Web Application Firewall (WAF) memberikan proteksi aktif terhadap pola serangan tertentu.',
        'sig_title' => 'Rincian Payload Signature',
        'sig_desc' => 'Signature berikut dipilih berdasarkan pola serangan paling umum yang sering digunakan untuk mengeksploitasi celah keamanan aplikasi web:',
        'dev_title' => 'Profil Pengembang'
    ],
    'en' => [
        'title' => 'WAF PAYLOAD CHECKER',
        'subtitle' => 'Firewall Security Detection & Payload Injection Audit System',
        'single' => 'Single Domain Check',
        'bulk' => 'Bulk Domain Check',
        'placeholder' => 'example.com',
        'btn' => 'Start Detection',
        'about_title' => 'Mechanism & Audit Workflow',
        'about_desc' => 'This tool works by simulating text-based attacks (Payload Injection) via URL parameters. Each request is sent using the HTTP/S protocol with the ability to follow redirects. Analysis is performed based on HTTP status codes and patterns within the response body to determine if a Web Application Firewall (WAF) provides active protection against specific attack patterns.',
        'sig_title' => 'Payload Signature Details',
        'sig_desc' => 'The following signatures are selected based on the most common attack patterns used to exploit web application vulnerabilities:',
        'dev_title' => 'Developer Profile'
    ]
];
$t = $text[$lang];

$waf_signatures = [
    ['type' => 'Cross-Site Scripting (XSS)', 'payload' => "<script>alert('XSS')</script>", 'desc' => 'Menguji filter terhadap skrip klien berbahaya.'],
    ['type' => 'HTML Injection', 'payload' => "<iframe></iframe>", 'desc' => 'Mengecek proteksi terhadap penyisipan elemen HTML eksternal.'],
    ['type' => 'SQL Injection', 'payload' => "union select 1,2,3", 'desc' => 'Simulasi penggabungan query database untuk pencurian data.'],
    ['type' => 'Database Schema Leak', 'payload' => "SELECT * FROM information_schema.tables", 'desc' => 'Mencoba mengakses struktur metadata database.'],
    ['type' => 'Path Traversal (LFI)', 'payload' => "../etc/passwd", 'desc' => 'Menguji akses ilegal ke file sensitif sistem operasi.'],
    ['type' => 'XSS (URL Encoded)', 'payload' => "%3Cscript%3Ealert('XSS')%3C/script%3E", 'desc' => 'Variasi encoding untuk melewati filter berbasis teks mentah.'],
    ['type' => 'Directory Traversal (Encoded)', 'payload' => "%2E%2E%2F", 'desc' => 'Menguji ketahanan filter terhadap karakter dot-dot-slash terenkripsi.']
];

$results = [];
$has_searched = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $has_searched = true;
    $domains = !empty($_POST['bulk_domains']) ? explode("\n", $_POST['bulk_domains']) : [$_POST['domain']];
    foreach (array_filter($domains) as $dom) {
        $dom = trim($dom);
        if (!preg_match("~^(?:f|ht)tps?://~i", $dom)) $dom = "http://" . $dom;
        $payload_details = [];
        foreach ($waf_signatures as $sig) {
            $p = $sig['payload'];
            $test_url = rtrim($dom, '/') . '/?q=' . urlencode($p);
            $opts = ['http' => ['method' => 'GET', 'timeout' => 8, 'follow_location' => 1, 'max_redirects' => 5, 'ignore_errors' => true]];
            $ctx = stream_context_create($opts);
            $response = @file_get_contents($test_url, false, $ctx);
            $code = 'ERR';
            if (isset($http_response_header)) {
                foreach (array_reverse($http_response_header) as $h) {
                    if (strpos($h, 'HTTP/') === 0) { $code = substr($h, 9, 3); break; }
                }
            }
            $is_blocked = in_array($code, ['403', '406']) || (stripos($response, 'blocked') !== false);
            $payload_details[] = ['type' => $sig['type'], 'payload' => htmlspecialchars($p), 'code' => $code, 'url_raw' => $test_url, 'url_encoded' => base64_encode($test_url), 'detected' => $is_blocked];
        }
        $results[] = ['domain' => $dom, 'data' => $payload_details];
    }
}
?>

<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $t['title'] ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <style>
        :root { --maroon: #800000; --maroon-light: #a52a2a; }
        body { background-color: #f8f9fa; font-family: 'Inter', sans-serif; }
        .bg-maroon { background-color: var(--maroon) !important; color: white; }
        .text-maroon { color: var(--maroon); }
        .btn-maroon { background-color: var(--maroon); color: white; border: none; }
        .btn-maroon:hover { background-color: var(--maroon-light); color: white; }
        .card { border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 12px; }
        .nav-tabs .nav-link.active { color: var(--maroon) !important; font-weight: bold; border-bottom: 3px solid var(--maroon); border-top:0; border-left:0; border-right:0; }
        pre { background: #1a1a1a; color: #56db56; padding: 15px; border-radius: 8px; max-height: 450px; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
        .info-section { background: #fff; padding: 40px; border-radius: 12px; margin-top: 50px; border-left: 5px solid var(--maroon); }
        .payload-card { border: 1px solid #eee; padding: 15px; border-radius: 8px; height: 100%; transition: 0.3s; }
        .payload-card:hover { border-color: var(--maroon); background: #fffafb; }
    </style>
</head>
<body>

<nav class="navbar navbar-dark bg-maroon mb-4 shadow">
    <div class="container d-flex justify-content-between">
        <span class="navbar-brand fw-bold">🛡️ <?= $t['title'] ?></span>
        <div>
            <a href="?lang=id" class="btn btn-sm <?= $lang=='id'?'btn-light text-maroon':'btn-outline-light' ?>">ID</a>
            <a href="?lang=en" class="btn btn-sm <?= $lang=='en'?'btn-light text-maroon':'btn-outline-light' ?>">EN</a>
        </div>
    </div>
</nav>

<div class="container py-3">
    <div class="text-center mb-5">
        <h2 class="fw-bold text-maroon"><?= $t['title'] ?></h2>
        <p class="text-muted"><?= $t['subtitle'] ?></p>
    </div>

    <ul class="nav nav-tabs mb-4 justify-content-center border-0">
        <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#single"><?= $t['single'] ?></button></li>
        <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#bulk"><?= $t['bulk'] ?></button></li>
    </ul>

    <div class="tab-content mb-5">
        <div class="tab-pane fade show active" id="single">
            <div class="card p-4 mx-auto shadow-sm" style="max-width: 650px;">
                <form method="POST">
                    <div class="input-group">
                        <span class="input-group-text bg-white border-end-0 text-muted">http://</span>
                        <input type="text" name="domain" class="form-control form-control-lg border-start-0" placeholder="<?= $t['placeholder'] ?>" required>
                        <button type="submit" class="btn btn-maroon px-4 fw-bold"><?= $t['btn'] ?></button>
                    </div>
                </form>
            </div>
        </div>
        <div class="tab-pane fade" id="bulk">
            <div class="card p-4 mx-auto shadow-sm" style="max-width: 650px;">
                <form method="POST">
                    <textarea name="bulk_domains" class="form-control mb-3" rows="5" placeholder="domain1.com&#10;domain2.com"></textarea>
                    <button type="submit" class="btn btn-maroon w-100 fw-bold py-2"><?= $t['btn'] ?></button>
                </form>
            </div>
        </div>
    </div>

    <?php if ($has_searched): ?>
        <?php foreach ($results as $res): ?>
            <div class="card mb-4 overflow-hidden border">
                <div class="card-header bg-white py-3 fw-bold border-bottom">Target: <span class="text-maroon"><?= htmlspecialchars($res['domain']) ?></span></div>
                <div class="table-responsive text-center">
                    <table class="table table-hover align-middle mb-0">
                        <thead class="table-light small text-uppercase fw-bold text-muted">
                            <tr>
                                <th class="text-start ps-4">Payload Signature</th>
                                <th>HTTP Code</th>
                                <th>Result</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($res['data'] as $det): ?>
                            <tr>
                                <td class="text-start ps-4"><code><?= $det['payload'] ?></code></td>
                                <td class="fw-bold"><?= $det['code'] ?></td>
                                <td>
                                    <span class="badge bg-<?= $det['detected'] ? 'danger' : 'success' ?> shadow-sm">
                                        <?= $det['detected'] ? '🛡️ BLOCKED' : '✅ ALLOWED' ?>
                                    </span>
                                </td>
                                <td>
                                    <div class="btn-group shadow-sm">
                                        <button class="btn btn-outline-dark btn-sm btn-view-body" data-url="<?= $det['url_encoded'] ?>"><i class="bi bi-code-square"></i></button>
                                        <a href="<?= $det['url_raw'] ?>" target="_blank" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-up-right"></i></a>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <div class="info-section shadow-sm mb-5">
        <h4 class="fw-bold text-maroon mb-3"><i class="bi bi-info-circle-fill me-2"></i><?= $t['about_title'] ?></h4>
        <p class="text-muted mb-5" style="text-align: justify; line-height: 1.8;"><?= $t['about_desc'] ?></p>

        <h5 class="fw-bold text-maroon mb-4"><?= $t['sig_title'] ?></h5>
        <p class="text-muted small mb-4"><?= $t['sig_desc'] ?></p>
        <div class="row g-3">
            <?php foreach ($waf_signatures as $sig): ?>
                <div class="col-md-6 col-lg-4">
                    <div class="payload-card shadow-sm">
                        <div class="fw-bold text-dark mb-1 small text-uppercase"><?= $sig['type'] ?></div>
                        <code class="text-maroon d-block mb-2"><?= htmlspecialchars($sig['payload']) ?></code>
                        <small class="text-muted"><?= $sig['desc'] ?></small>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="card bg-white p-4 shadow-sm border-0 mb-5">
        <div class="row align-items-center">
            <div class="col-md-8">
                <h5 class="fw-bold text-maroon mb-1"><?= $t['dev_title'] ?></h5>
                <p class="h4 fw-bold text-dark mb-1">Mardianta Putra Anggara, S.Kom</p>
                <p class="text-muted mb-0 small text-uppercase fw-bold">Cyber Security Enthusiast & Web Developer</p>
            </div>
            <div class="col-md-4 text-md-end mt-3 mt-md-0">
                <a href="https://www.linkedin.com/in/mardianta/" target="_blank" class="btn btn-maroon px-4 rounded-pill fw-bold shadow-sm">
                    <i class="bi bi-linkedin me-2"></i>Hubungi via LinkedIn
                </a>
            </div>
        </div>
    </div>
</div>

<footer class="text-center py-4 bg-white border-top text-muted">
    <small>WAF Checker Tools &bull; Security Audit Tool &bull; &copy; <?= date('Y') ?></small>
</footer>

<div class="modal fade" id="bodyModal" tabindex="-1">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content border-0">
            <div class="modal-header bg-maroon text-white">
                <h5 class="modal-title fw-bold"><i class="bi bi-terminal me-2"></i> Raw HTTP Response Body</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body bg-dark">
                <div id="modalLoading" class="text-center py-5 d-none text-light">
                    <div class="spinner-border mb-3"></div>
                    <p>Fetching content...</p>
                </div>
                <pre id="modalContent" class="mb-0"></pre>
            </div>
        </div>
    </div>
</div>

<script>
document.querySelectorAll('.btn-view-body').forEach(button => {
    button.addEventListener('click', function() {
        const encodedUrl = this.getAttribute('data-url');
        const contentBox = document.getElementById('modalContent');
        const loader = document.getElementById('modalLoading');
        const modal = new bootstrap.Modal(document.getElementById('bodyModal'));
        contentBox.textContent = '';
        loader.classList.remove('d-none');
        modal.show();
        fetch('?ajax_target=' + encodedUrl).then(res => res.text()).then(data => {
            loader.classList.add('d-none');
            contentBox.textContent = data || '--- No Content Found ---';
        }).catch(() => {
            loader.classList.add('d-none');
            contentBox.textContent = 'Error: Gagal memuat data.';
        });
    });
});
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
