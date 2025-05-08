async function deteksiWAF() {
  const url = window.location.href; // Atau URL target spesifik

  try {
    const response = await fetch(url);

    if (response.headers) {
      const headers = Array.from(response.headers.entries());

      for (const [name, value] of headers) {
        const lowerName = name.toLowerCase();

        if (lowerName.includes('server') && value.toLowerCase().includes('cloudflare')) {
          return 'Cloudflare';
        } else if (lowerName.includes('server') && value.toLowerCase().includes('nginx') && value.toLowerCase().includes('modsecurity')) {
          return 'ModSecurity (kemungkinan)';
        } else if (lowerName.includes('x-powered-by') && value.toLowerCase().includes('plesk')) {
          return 'Plesk (mungkin dengan WAF)';
        } else if (lowerName.includes('server') && value.toLowerCase().includes('apache') && value.toLowerCase().includes('mod_security')) {
          return 'ModSecurity (kemungkinan)';
        } else if (lowerName.includes('x-akamai-request-id')) {
          return 'Akamai';
        } else if (lowerName.includes('x-cdn')) {
          if (value.toLowerCase().includes('imperva')) {
            return 'Imperva';
          } else if (value.toLowerCase().includes('incapsula')) {
            return 'Imperva (sebelumnya Incapsula)';
          }
        } else if (lowerName.includes('x-frame-options') && value.toLowerCase().includes('sameorigin') && response.status === 403) {
          return 'Kemungkinan WAF memblokir akses';
        }
        // Tambahkan deteksi header lain sesuai kebutuhan
      }
    }

    return 'WAF tidak terdeteksi melalui header umum.';

  } catch (error) {
    console.error("Terjadi kesalahan:", error);
    return 'Gagal mengambil respons.';
  }
}

deteksiWAF().then(waf => {
  console.log("Jenis WAF (kemungkinan):", waf);
});
