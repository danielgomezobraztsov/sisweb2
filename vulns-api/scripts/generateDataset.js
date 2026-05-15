#!/usr/bin/env node
/**
 * generateDataset.js
 * Genera data/vulns.json con 1200 vulnerabilidades ficticias pero realistas.
 * Ejecutar: npm run generate-dataset
 */

const fs   = require('fs');
const path = require('path');

// ── Datos de ejemplo para construir entradas realistas ────────────────────────

const WINDOWS_VERSIONS = ['windows-10', 'windows-11', 'windows-server-2019', 'windows-server-2022', 'windows-server-2025'];
const LINUX_VERSIONS   = ['ubuntu', 'debian', 'alpine', 'arch', 'fedora', 'centos', 'rhel', 'opensuse'];
const SEVERITIES       = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const TIPOS            = ['RCE', 'EoP', 'DoS', 'InfoDisclosure', 'AuthBypass', 'SQLi', 'XSS', 'Other'];
const FUENTES          = ['NVD', 'MSRC', 'CVE.org', 'CISA-KEV', 'OSV', 'Exploit-DB'];

// Distribución de severidad aproximada a la real (mayoría HIGH/MEDIUM)
const SEVERITY_WEIGHTS = { LOW: 0.10, MEDIUM: 0.35, HIGH: 0.38, CRITICAL: 0.17 };

const WINDOWS_COMPONENTS = [
  'Kernel', 'Win32k', 'CLFS Driver', 'Hyper-V', 'MSHTML', 'Print Spooler',
  'Remote Desktop Services', 'SMBv3', 'NTLM', 'Active Directory',
  'Defender', 'Installer', 'Task Scheduler', 'COM Object', 'RPC Runtime',
  'LDAP Client', 'Network Policy Server', 'DNS Server', 'IIS', 'Exchange Server',
  'SharePoint', 'Scripting Engine', 'Edge (Chromium)', 'Secure Boot', 'BitLocker',
  'TCP/IP Stack', 'Bluetooth Driver', 'Wi-Fi Driver', 'Azure Connected Machine Agent',
  'PowerShell', 'WinHTTP', 'WebDAV', 'Kerberos', 'Certificate Services',
];

const LINUX_COMPONENTS = [
  'Linux Kernel', 'sudo', 'glibc', 'OpenSSL', 'OpenSSH', 'polkit',
  'systemd', 'bash', 'curl/libcurl', 'nftables', 'eBPF subsystem',
  'ext4 filesystem', 'USB subsystem', 'Bluetooth subsystem', 'ALSA',
  'Netfilter', 'perf subsystem', 'KVM hypervisor', 'FUSE filesystem',
  'NFS client', 'Snap daemon', 'apt/dpkg', 'rpm', 'D-Bus',
  'X.Org Server', 'Wayland', 'PAM', 'NSS', 'cryptsetup',
  'GRUB2', 'containerd', 'runc', 'cgroups v2',
];

const APP_TITLES_WINDOWS = [
  'Adobe Acrobat Reader Remote Code Execution',
  'Microsoft Office Excel Formula Injection',
  'Google Chrome V8 Engine Out-of-Bounds Write',
  'Mozilla Firefox Use-After-Free in WebAudio',
  '7-Zip Integer Overflow during Archive Extraction',
  'VLC Media Player Heap Buffer Overflow',
  'WinSCP Path Traversal in SFTP Component',
  'Zoom Client Privilege Escalation',
  'Slack Desktop App XSS via Deep Link',
  'TeamViewer Improper Authentication Bypass',
  'Notepad++ Buffer Overflow in XML Plugin',
  'PuTTY RSA Key Exchange Integer Overflow',
  'WireShark PCAP Dissector Stack Overflow',
];

const APP_TITLES_LINUX = [
  'Firefox ESR Out-of-Bounds Memory Access',
  'LibreOffice Calc Formula Injection via .ods',
  'Thunderbird S/MIME Certificate Validation Bypass',
  'VLC Heap Use-After-Free in MKV Demuxer',
  'Vim Null Pointer Dereference in netrw Plugin',
  'ImageMagick Command Injection via SVG',
  'FFmpeg Out-of-Bounds Write in HEVC Decoder',
  'GIMP Script-Fu Remote Code Execution',
  'Apache HTTP Server mod_proxy SSRF',
  'Nginx off-by-one Heap Write in HTTP/2',
  'PHP Integer Overflow in json_decode',
  'Python tarfile Module Path Traversal',
  'Node.js HTTP Request Smuggling',
  'Redis Arbitrary Code Execution via Lua',
];

const CVSS_VECTORS = {
  RCE:           'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  EoP:           'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
  DoS:           'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  InfoDisclosure:'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
  AuthBypass:    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
  SQLi:          'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
  XSS:           'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  Other:         'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L',
};

const SEVERITY_SCORE_RANGES = {
  LOW:      [0.1, 3.9],
  MEDIUM:   [4.0, 6.9],
  HIGH:     [7.0, 8.9],
  CRITICAL: [9.0, 10.0],
};

// ── Funciones helpers ─────────────────────────────────────────────────────────

function rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function randInt(min, max) { return min + Math.floor(Math.random() * (max - min + 1)); }

function weightedSeverity() {
  const r = Math.random();
  let acc = 0;
  for (const [sev, w] of Object.entries(SEVERITY_WEIGHTS)) {
    acc += w;
    if (r < acc) return sev;
  }
  return 'HIGH';
}

function randScore(severity) {
  const [min, max] = SEVERITY_SCORE_RANGES[severity];
  return parseFloat((min + Math.random() * (max - min)).toFixed(1));
}

function randDate(startYear = 2018, endYear = 2025) {
  const start = new Date(`${startYear}-01-01`).getTime();
  const end   = new Date(`${endYear}-12-31`).getTime();
  return new Date(start + Math.random() * (end - start)).toISOString().split('T')[0];
}

function generateCVEId(year, seq) {
  return `CVE-${year}-${String(seq).padStart(5, '0')}`;
}

function buildDescription(os, component, tipo) {
  const templates = {
    RCE: `A remote code execution vulnerability exists in ${component} when it fails to properly handle objects in memory. An attacker who successfully exploited this vulnerability could run arbitrary code in the security context of the current user.`,
    EoP: `An elevation of privilege vulnerability exists in ${component} due to improper handling of objects in memory. An authenticated attacker could exploit this vulnerability to execute code with elevated privileges.`,
    DoS: `A denial of service vulnerability exists in ${component} when it fails to properly handle specific requests. An attacker could exploit this vulnerability to cause a system or application stop responding.`,
    InfoDisclosure: `An information disclosure vulnerability exists in ${component} when it improperly handles objects in memory. An attacker who successfully exploited this vulnerability could obtain information to further compromise the user's system.`,
    AuthBypass: `An authentication bypass vulnerability exists in ${component} that could allow an unauthenticated attacker to bypass security mechanisms and gain unauthorized access.`,
    SQLi: `A SQL injection vulnerability exists in ${component} when it fails to properly sanitize user-supplied input. An attacker could exploit this to execute arbitrary SQL commands.`,
    XSS: `A cross-site scripting vulnerability exists in ${component} when it fails to properly sanitize user-supplied input in web output. An attacker could exploit this to run script in the context of another user.`,
    Other: `A security vulnerability exists in the ${component} component of ${os === 'windows' ? 'Windows' : 'Linux'} that could allow an attacker to compromise the system.`,
  };
  return templates[tipo] ?? templates['Other'];
}

// ── Generador principal ───────────────────────────────────────────────────────

function generateVulns(count = 1200) {
  const vulns  = [];
  const usedIds = new Set();

  let appCount = 0;
  const APP_RATIO = 0.15; // 15% serán vulnerabilidades de aplicaciones

  for (let i = 0; i < count; i++) {
    const year    = randInt(2018, 2025);
    let   seq     = randInt(10000, 49999);
    let   cveId   = generateCVEId(year, seq);

    // Garantizar unicidad
    while (usedIds.has(cveId)) {
      seq++;
      cveId = generateCVEId(year, seq);
    }
    usedIds.add(cveId);

    const os         = Math.random() < 0.55 ? 'windows' : 'linux';
    const isAppVuln  = appCount / count < APP_RATIO && Math.random() < 0.2;
    if (isAppVuln) appCount++;

    const severity   = weightedSeverity();
    const tipo       = rand(TIPOS);
    const score      = randScore(severity);
    const pubDate    = randDate(year, year);
    const updDate    = Math.random() < 0.6 ? randDate(year, 2025) : null;

    let component, titulo;
    if (isAppVuln) {
      titulo    = os === 'windows' ? rand(APP_TITLES_WINDOWS) : rand(APP_TITLES_LINUX);
      component = titulo.split(' ').slice(0, 2).join(' ');
    } else {
      component = os === 'windows' ? rand(WINDOWS_COMPONENTS) : rand(LINUX_COMPONENTS);
      const action = {
        RCE: 'Remote Code Execution Vulnerability',
        EoP: 'Elevation of Privilege Vulnerability',
        DoS: 'Denial of Service Vulnerability',
        InfoDisclosure: 'Information Disclosure Vulnerability',
        AuthBypass: 'Security Feature Bypass Vulnerability',
        SQLi: 'SQL Injection Vulnerability',
        XSS: 'Cross-Site Scripting Vulnerability',
        Other: 'Security Vulnerability',
      }[tipo];
      titulo = `${os === 'windows' ? 'Windows' : 'Linux'} ${component} ${action}`;
    }

    const versionPool = os === 'windows' ? WINDOWS_VERSIONS : LINUX_VERSIONS;
    const version     = Math.random() < 0.75 ? rand(versionPool) : undefined;

    const fuente      = os === 'windows' ? rand(['NVD', 'MSRC', 'CISA-KEV']) : rand(['NVD', 'CVE.org', 'OSV', 'Exploit-DB']);
    const exploited   = severity === 'CRITICAL' ? Math.random() < 0.35
                      : severity === 'HIGH'     ? Math.random() < 0.10
                      : false;

    const urlParche = os === 'windows'
      ? `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`
      : `https://nvd.nist.gov/vuln/detail/${cveId}`;

    const vuln = {
      id:          cveId,
      titulo,
      descripcion: buildDescription(os, component, tipo),
      os,
      severity,
      tipoVuln:    tipo,
      cvss: {
        version:  '3.1',
        score,
        severity,
        vector:   CVSS_VECTORS[tipo],
      },
      fechaPublicacion:    pubDate,
      explotadaActivamente: exploited,
      fuente,
      urlParche,
      referencias: [`https://nvd.nist.gov/vuln/detail/${cveId}`],
      isAppVuln,
    };

    if (version)  vuln.version  = version;
    if (updDate)  vuln.fechaActualizacion = updDate;

    vulns.push(vuln);
  }

  return vulns;
}

// ── Main ──────────────────────────────────────────────────────────────────────
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const vulns = generateVulns(1200);
fs.writeFileSync(path.join(dataDir, 'vulns.json'), JSON.stringify(vulns, null, 2));
console.log(`✅ Dataset generado: ${vulns.length} vulnerabilidades → data/vulns.json`);
console.log(`   - Windows: ${vulns.filter(v => v.os === 'windows').length}`);
console.log(`   - Linux:   ${vulns.filter(v => v.os === 'linux').length}`);
console.log(`   - App vulns: ${vulns.filter(v => v.isAppVuln).length}`);
console.log(`   - Exploited: ${vulns.filter(v => v.explotadaActivamente).length}`);
