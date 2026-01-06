<?php
session_start();

// --- 1. LOGIKA AJAX FETCHER (Mendukung Follow Redirects) ---
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
            'header' => "User-Agent: Mozilla/5.0 (WAF-Auditor-Mardianta-v2)\r\n"
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
        'title' => 'WAF AUDITOR PRO',
        'subtitle' => 'Security Audit & Payload Injection Detection System',
        'single' => 'Single Target',
        'bulk' => 'Bulk Scan',
        'placeholder' => 'masukkan domain (contoh.com)',
        'btn' => 'Mulai Audit',
        'about' => 'Mekanisme Audit',
        'dev' => 'Profil Pengembang',
        'sig_title' => 'Daftar Payload Signature',
        'sig_desc' => 'Berikut adalah signature yang digunakan untuk menguji respon firewall:'
    ],
    'en' => [
        'title' => 'WAF AUDITOR PRO',
        'subtitle' => 'Security Audit & Payload Injection Detection System',
        'single' => 'Single Target',
        'bulk' => 'Bulk Scan',
        'placeholder' => 'enter domain (example.com)',
        'btn' => 'Start Audit',
        'about' => 'Audit Mechanism',
        'dev' => 'Developer Profile',
        'sig_title' => 'Payload Signature List',
        'sig_desc' => 'The following signatures are used to test firewall responses:'
    ]
];
$t = $text[$lang];

// --- 3. DATA PAYLOAD & LOGIKA ---
$waf_signatures = [
    ['type' => 'Cross-Site Scripting (XSS)', 'payload' => "<script>alert('XSS')</script>"],
    ['type' => 'Iframe Injection', 'payload' => "<iframe></iframe>"],
    ['type' => 'SQL Injection (Union)', 'payload' => "union select 1,2,3"],
    ['type' => 'Information Schema Leak', 'payload' => "SELECT * FROM information_schema.tables"],
    ['type' => 'Local File Inclusion (LFI)', 'payload' => "../etc/passwd"],
    ['type' => 'URL Encoded XSS', 'payload' => "%3Cscript%3Ealert('XSS')%3C/script%3E"],
    ['type' => 'Directory Traversal Encoded', 'payload' => "%2E%2E%2F"]
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
            
            $is_blocked = in_array($code, ['403', '406', '501']) || (stripos($response, 'blocked') !== false);

            $payload_details[] = [
                'type' => $sig['type'],
                'payload' => htmlspecialchars($p),
                'code' => $code,
                'url_raw' => $test_url,
                'url_encoded' => base64_encode($test_url),
                'detected' => $is_blocked
            ];
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
        :root { --maroon: #660000; --maroon-soft: #800000; --gold: #c5a059; }
        body { background-color: #fdfdfd; font-family: 'Inter', sans-serif; color: #333; }
        
        /* Layout */
        .navbar { background: linear-gradient(90deg, var(--maroon) 0%, var(--maroon-soft) 100%); border-bottom: 3px solid var(--gold); }
        .hero-section { background: white; padding: 60px 0; border-bottom: 1px solid #eee; margin-bottom: 40px; }
        
        /* Cards & UI */
        .card { border: none; border-radius: 16px; transition: all 0.3s ease; box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
        .card-header { background: white; border-bottom: 1px solid #f0f0f0; padding: 20px; border-radius: 16px 16px 0 0 !important; }
        .nav-tabs .nav-link { border: none; color: #888; font-weight: 500; padding: 12px 25px; }
        .nav-tabs .nav-link.active { color: var(--maroon) !important; background: transparent; border-bottom: 3px solid var(--maroon); }
        
        /* Buttons */
        .btn-maroon { background-color: var(--maroon); color: white; border-radius: 8px; padding: 10px 24px; font-weight: 600; }
        .btn-maroon:hover { background-color: #4a0000; color: white; transform: translateY(-1px); }
        
        /* Results */
        .table thead { background-color: #fafafa; }
        .badge-blocked { background-color: #ffe5e5; color: #d00000; border: 1px solid #ffcccc; }
        .badge-allowed { background-color: #e5f9e5; color: #008000; border: 1px solid #ccf2cc; }
        
        /* Modal & Pre */
        pre { background: #1a1a1a; color: #a6e22e; padding: 20px; border-radius: 12px; border-left: 5px solid var(--gold); font-size: 13px; }
        .payload-box { background: #f8f9fa; border-radius: 8px; padding: 15px; margin-bottom: 10px; border-left: 4px solid var(--maroon); }
    </style>
</head>
<body>

<nav class="navbar navbar-dark shadow-sm py-3">
    <div class="container d-flex justify-content-between align-items-center">
        <span class="navbar-brand fw-bold fs-4"><i class="bi bi-shield-lock-fill me-2" style="color: var(--gold);"></i><?= $t['title'] ?></span>
        <div class="language-switcher">
            <a href="?lang=id" class="btn btn-sm <?= $lang=='id'?'btn-light text-maroon shadow-sm':'text-white' ?> fw-bold me-1">ID</a>
            <a href="?lang=en" class="btn btn-sm <?= $lang=='en'?'btn-light text-maroon shadow-sm':'text-white' ?> fw-bold">EN</a>
        </div>
    </div>
</nav>

<div class="hero-section text-center">
    <div class="container">
        <h1 class="display-5 fw-bold text-maroon mb-2"><?= $t['title'] ?></h1>
        <p class="lead text-muted mx-auto" style="max-width: 700px;"><?= $t['subtitle'] ?></p>
    </div>
</div>

<div class="container pb-5">
    <div class="row justify-content-center mb-5">
        <div class="col-lg-8">
            <ul class="nav nav-tabs mb-4 justify-content-center border-0" id="scanTab">
                <li class="nav-item">
                    <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#single"><i class="bi bi-hdd-network me-2"></i><?= $t['single'] ?></button>
                </li>
                <li class="nav-item">
                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#bulk"><i class="bi bi-layers-half me-2"></i><?= $t['bulk'] ?></button>
                </li>
            </ul>

            <div class="tab-content">
                <div class="tab-pane fade show active" id="single">
                    <div class="card p-4 shadow-lg border-0">
                        <form method="POST">
                            <div class="input-group input-group-lg">
                                <span class="input-group-text bg-light border-end-0 text-muted"><i class="bi bi-globe"></i></span>
                                <input type="text" name="domain" class="form-control border-start-0 ps-0" placeholder="<?= $t['placeholder'] ?>" required>
                                <button type="submit" class="btn btn-maroon"><?= $t['btn'] ?></button>
                            </div>
                        </form>
                    </div>
                </div>
                <div class="tab-pane fade" id="bulk">
                    <div class="card p-4 shadow-lg border-0">
                        <form method="POST">
                            <textarea name="bulk_domains" class="form-control mb-3" rows="5" placeholder="domain1.com&#10;domain2.com"></textarea>
                            <button type="submit" class="btn btn-maroon w-100"><?= $t['btn'] ?></button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <?php if ($has_searched): ?>
        <div class="row mb-5">
            <div class="col-12">
                <h3 class="fw-bold text-maroon mb-4"><i class="bi bi- clipboard-data me-2"></i>Audit Results</h3>
                <?php foreach ($results as $res): ?>
                    <div class="card mb-5 overflow-hidden border-0">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <span class="fw-bold fs-5">Target: <span class="text-maroon"><?= htmlspecialchars($res['domain']) ?></span></span>
                            <span class="badge rounded-pill bg-light text-dark border p-2 px-3 fw-medium">Audit Completed</span>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-hover align-middle mb-0">
                                <thead class="small text-uppercase fw-bold text-muted">
                                    <tr>
                                        <th class="ps-4 py-3">Vulnerability Type</th>
                                        <th>Signature</th>
                                        <th class="text-center">Response</th>
                                        <th class="text-center">Status</th>
                                        <th class="text-center">Inspection</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($res['data'] as $det): ?>
                                    <tr>
                                        <td class="ps-4">
                                            <div class="fw-bold"><?= $det['type'] ?></div>
                                        </td>
                                        <td><code><?= $det['payload'] ?></code></td>
                                        <td class="text-center"><span class="fw-bold"><?= $det['code'] ?></span></td>
                                        <td class="text-center">
                                            <?php if ($det['detected']): ?>
                                                <span class="badge badge-blocked px-3 py-2"><i class="bi bi-shield-fill-check me-1"></i>BLOCKED</span>
                                            <?php else: ?>
                                                <span class="badge badge-allowed px-3 py-2"><i class="bi bi-unlock-fill me-1"></i>ALLOWED</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="text-center">
                                            <div class="btn-group">
                                                <button class="btn btn-sm btn-outline-dark btn-view-body" data-url="<?= $det['url_encoded'] ?>" title="Inspect Body"><i class="bi bi-search"></i></button>
                                                <a href="<?= $det['url_raw'] ?>" target="_blank" class="btn btn-sm btn-outline-danger" title="Open External"><i class="bi bi-box-arrow-up-right"></i></a>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>

    <div class="row g-4 border-top pt-5">
        <div class="col-lg-7">
            <h4 class="fw-bold text-maroon mb-3"><?= $t['sig_title'] ?></h4>
            <p class="text-muted mb-4"><?= $t['sig_desc'] ?></p>
            <div class="row g-3">
                <?php foreach ($waf_signatures as $sig): ?>
                    <div class="col-md-6">
                        <div class="payload-box h-100 shadow-sm">
                            <div class="small fw-bold text-maroon text-uppercase mb-1"><?= $sig['type'] ?></div>
                            <code class="text-dark"><?= htmlspecialchars($sig['payload']) ?></code>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        <div class="col-lg-5">
            <div class="card bg-maroon text-white p-4 h-100 shadow-lg">
                <h4 class="fw-bold mb-3" style="color: var(--gold);"><?= $t['dev'] ?></h4>
                <div class="d-flex align-items-center mb-4">
                    <div class="bg-white rounded-circle d-flex align-items-center justify-content-center shadow-sm" style="width: 60px; height: 60px;">
                        <i class="bi bi-person-fill text-maroon fs-2"></i>
                    </div>
                    <div class="ms-3">
                        <div class="h5 mb-0 fw-bold">Mardianta Putra Anggara, S.Kom</div>
                        <div class="small opacity-75">Cyber Security Professional</div>
                    </div>
                </div>
                <p class="small opacity-75 mb-4">Specializing in Web Application Security, Penetration Testing, and Digital Forensics.</p>
                <a href="https://www.linkedin.com/in/mardianta/" target="_blank" class="btn btn-light text-maroon fw-bold w-100 py-2 rounded-pill">
                    <i class="bi bi-linkedin me-2"></i>Connect on LinkedIn
                </a>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="bodyModal" tabindex="-1">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content border-0">
            <div class="modal-header bg-maroon text-white">
                <h5 class="modal-title fw-bold"><i class="bi bi-terminal-fill me-2"></i>Response Header & Body Analysis</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body bg-dark">
                <div id="modalLoading" class="text-center py-5 d-none text-light">
                    <div class="spinner-border text-light mb-3" style="width: 3rem; height: 3rem;"></div>
                    <p class="fw-bold">Following Redirects & Fetching Raw Content...</p>
                </div>
                <pre id="modalContent" class="mb-0"></pre>
            </div>
        </div>
    </div>
</div>

<footer class="text-center py-4 bg-white border-top mt-5 text-muted">
    <div class="container">
        <small class="fw-medium">WAF Auditor Tool &bull; Secured with Redirect Following Technology &bull; <?= date('Y') ?></small>
    </div>
</footer>



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

        fetch('?ajax_target=' + encodedUrl)
            .then(res => res.text())
            .then(data => {
                loader.classList.add('d-none');
                contentBox.textContent = data || '--- No Content Found (Empty Body) ---';
            })
            .catch(() => {
                loader.classList.add('d-none');
                contentBox.textContent = 'Error: Gagal memuat data dari server proxy.';
            });
    });
});
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
