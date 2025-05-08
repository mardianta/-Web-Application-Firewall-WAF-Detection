async function deteksiWAF(url) {
  try {
    const response = await fetch(url, {
      method: 'HEAD', // Hanya meminta header
      mode: 'cors', // Atur mode CORS jika diperlukan
      redirect: 'follow' // Ikuti pengalihan jika ada
    });

    if (response.headers) {
      const headers = Array.from(response.headers.entries());

      for (const [name, value] of headers) {
        const lowerName = name.toLowerCase();
        const lowerValue = value.toLowerCase();

        if (lowerName.includes('server') && lowerValue.includes('cloudflare')) {
          return 'Cloudflare';
        } else if (lowerName.includes('server') && lowerValue.includes('nginx') && lowerValue.includes('modsecurity')) {
          return 'ModSecurity (kemungkinan)';
        } else if (lowerName.includes('x-powered-by') && lowerValue.includes('plesk')) {
          return 'Plesk (mungkin dengan WAF)';
        } else if (lowerName.includes('server') && lowerValue.includes('apache') && lowerValue.includes('mod_security')) {
          return 'ModSecurity (kemungkinan)';
        } else if (lowerName.includes('x-akamai-request-id')) {
          return 'Akamai';
        } else if (lowerName.includes('x-cdn') && lowerValue.includes('imperva')) {
          return 'Imperva';
        } else if (lowerName.includes('x-cdn') && lowerValue.includes('incapsula')) {
          return 'Imperva (sebelumnya Incapsula)';
        } else if (lowerName.includes('x-frame-options') && lowerValue.includes('sameorigin') && response.status === 403) {
          return 'Kemungkinan WAF memblokir akses';
        }
        // Tambahkan deteksi header lain sesuai kebutuhan
      }
    }

    return 'WAF tidak terdeteksi melalui header umum.';

  } catch (error) {
    console.error("Terjadi kesalahan saat mengambil header:", error);
    return 'Gagal mengambil header respons.';
  }
}

async function deteksiWAFMelaluiBlokir(url) {
  const payloads = [
    "?q=<script>alert(1)</script>",
    "?q=../etc/passwd",
    "?q=union select 1,2,3",
    "' or 1=1 --",
    "<svg onload=alert(1)>",
    // Tambahkan payload lain yang berpotensi diblokir
  ];

  for (const payload of payloads) {
    const testUrl = url + payload;
    try {
      const response = await fetch(testUrl, {
        mode: 'cors', // Atur mode CORS jika diperlukan
        redirect: 'follow' // Ikuti pengalihan jika ada
      });

      if (response.status === 403) {
        return 'WAF terdeteksi memblokir permintaan mencurigakan.';
      } else if (response.status === 200) {
        const text = await response.text();
        if (text.toLowerCase().includes('modsecurity')) {
          return 'Kemungkinan ModSecurity (terdeteksi melalui respons)';
        }
      }
    } catch (error) {
      // Kesalahan jaringan mungkin terjadi, lanjutkan pengujian payload lain
      console.warn(`Gagal melakukan permintaan dengan payload ${payload}:`, error);
    }
  }

  return 'WAF tidak terdeteksi melalui respons blokir.';
}

// Anda bisa menambahkan logika lain atau fungsi pembantu di sini jika diperlukan
