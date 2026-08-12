# Docstring alignment audit (ok cases)

Total cases scanned: 392

## Label distribution
- **vulnerable_echo**: 81 (20.7%)
- **vulnerable_echo_leaning**: 10 (2.6%)
- **fix_leak**: 51 (13.0%)
- **fix_leak_leaning**: 6 (1.5%)
- **ambiguous_both**: 8 (2.0%)
- **neutral_no_distinctive_overlap**: 236 (60.2%)

**Any vulnerable-echo lean**: 91 (23.2%)
**Any fix-leak lean**: 57 (14.5%)

## Cross-check vs existing `heuristic_leakage_flag` (19 flagged)
- flagged-by-regex AND `neutral_no_distinctive_overlap`: 11
- flagged-by-regex AND `fix_leak`: 5
- flagged-by-regex AND `vulnerable_echo`: 2
- flagged-by-regex AND `ambiguous_both`: 1

(If the regex-based flag and `fix_leak*` labels barely overlap, the two mechanisms are catching different things and both are worth keeping; if they overlap heavily, the new check is mostly redundant.)

## Sample cases per label (first 5 each)

### vulnerable_echo
- `C_104__1` (krb5/krb5, CVE-2013-1417) - vuln_hits=['empty', 'fqdn', 'hostname', 'kdc_active_realm', 'krb5_principal', 'krbtgt_princ', 'referral', 'request', 'server', 'service'], fix_hits=[]
- `C_1061__0` (chromium/chromium, CVE-2011-2787) - vuln_hits=['content', 'gpuinfo'], fix_hits=[]
- `C_106__0` (krb5/krb5, CVE-2013-1415) - vuln_hits=['cleanup'], fix_hits=[]
- `C_1103__0` (chromium/chromium, CVE-2012-2872) - vuln_hits=['ssl'], fix_hits=[]
- `C_1138__0` (chromium/chromium, CVE-2013-6634) - vuln_hits=['accept', 'all', 'auto', 'based', 'child_id', 'default', 'email', 'gaia', 'headers', 'http', 'io_data', 'later', 'net', 'profile', 'profileiodata', 'request', 'route_id', 'sign', 'source', 'task', 'thread', 'url', 'urlrequest'], fix_hits=[]

### fix_leak
- `C_102__0` (torvalds/linux, CVE-2013-1767) - vuln_hits=[], fix_hits=['remount', 'specified']
- `C_102__1` (torvalds/linux, CVE-2013-1767) - vuln_hits=[], fix_hits=['remount', 'specified']
- `C_1086__0` (chromium/chromium, CVE-2012-2889) - vuln_hits=[], fix_hits=['frameless']
- `C_114__0` (libarchive/libarchive, CVE-2013-0211) - vuln_hits=[], fix_hits=['negative']
- `C_1162__0` (chromium/chromium, CVE-2013-0880) - vuln_hits=[], fix_hits=['permissions']

### fix_leak_leaning
- `C_1088__0` (chromium/chromium, CVE-2012-2881) - vuln_hits=['disabled_testsettingsframepasswords', 'flaky'], fix_hits=['chrome', 'kchromeuisettingsframeurl', 'passwords']
- `C_1126__0` (chromium/chromium, CVE-2011-3108) - vuln_hits=['truncated'], fix_hits=['another', 'requests']
- `C_339__1` (torvalds/linux, CVE-2015-2686) - vuln_hits=['receive'], fix_hits=['size_t', 'unsigned']
- `C_588__7` (ImageMagick/ImageMagick, CVE-2014-9907) - vuln_hits=['dds', 'files', 'images', 'map', 'mipmap'], fix_hits=['exception', 'exceptioninfo', 'height', 'magickbooleantype', 'magickfalse', 'magicktrue']
- `C_96__0` (torvalds/linux, CVE-2013-1819) - vuln_hits=['target'], fix_hits=['bounds', 'filesystem', 'within']

### vulnerable_echo_leaning
- `C_1053__1` (chromium/chromium, CVE-2011-2853) - vuln_hits=['browser_frame', 'browser_view', 'browserframe', 'browserframegtk', 'browserframeviews', 'browserview', 'new', 'views'], fix_hits=['view']
- `C_1086__2` (chromium/chromium, CVE-2012-2889) - vuln_hits=['client_bounds', 'getwindowboundsforclientbounds', 'height', 'rect', 'width'], fix_hits=['frame', 'fullscreen', 'window']
- `C_1231__0` (chromium/chromium, CVE-2015-1210, CVE-2015-1211) - vuln_hits=['dom', 'range', 'reference', 'set', 'syntax', 'throwexception', 'type'], fix_hits=['context']
- `C_19__0` (torvalds/linux, CVE-2012-0957) - vuln_hits=['cannot', 'handle', 'linux', 'programs'], fix_hits=['size_t']
- `C_384__0` (uclouvain/openjpeg, CVE-2017-14164) - vuln_hits=['checks', 'codec', 'contained', 'decoder', 'event', 'manager', 'opj_j2k_get_sot_values', 'opj_j2k_write_sot', 'p_current_part', 'p_data', 'p_data_written', 'p_header_data', 'p_header_size', 'p_num_parts', 'p_tile_no', 'p_tot_len', 'part', 'reads', 'sot', 'state', 'stream', 'tile', 'user', 'values', 'write', 'writes'], fix_hits=['header']