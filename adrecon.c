/*
 * adrecon.c — Active Directory Reconnaissance BOF
 *
 * Enumerates AD over LDAP using wldap32 (ldap_init / ldap_bind_s /
 * ldap_search_ext_s). No powershell.exe, no cmd.exe, no COM/ADSI.
 *
 * ADSI (ADsOpenObject + IDirectorySearch vtables + CoUninitialize)
 * was killing the Beacon process on the lab host. wldap32 is a C API
 * with explicit timeouts, so a failed DC does not hang or crash Beacon.
 *
 * Stack-safe: BOF stack is small. recon_ctx and search buffers live on the heap.
 * For authorized red team training only.
 */

#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "adsi_interfaces.h"

#define DPRINT(...) BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)
#define EPRINT(...) BeaconPrintf(CALLBACK_ERROR, __VA_ARGS__)

#define ACTION_ALL        0
#define ACTION_ASREP      1
#define ACTION_KERBEROAST 2
#define ACTION_USERS      3
#define ACTION_USERDESC   4
#define ACTION_COMPUTERS  5
#define ACTION_ESC1       6
#define ACTION_PWDNEVER   7
#define ACTION_WEAKPWD    8
#define ACTION_ADMINS     9
#define ACTION_GPO        10
#define ACTION_DCS        11
#define ACTION_TRUSTS     12
#define ACTION_SITES      13

#define LDAP_NET_TIMEOUT_SEC  15
#define LDAP_SEARCH_TIMEOUT_SEC 20

typedef struct {
    LDAP *ld;
    char ip[64];
    char domain[128];
    char domainDN[256];
    char configDN[256];
    char forestDN[256];
    char s1[512];
    char s2[512];
    char s3[1024];
} recon_ctx;

/* Force a non-empty .data section. Unmapped .bss is a classic BOF crash. */
static char g_bof_data_anchor __attribute__((used)) = 1;

/* ── String helpers ──────────────────────────────────────── */

static void ascii_lower(char *s)
{
    if (!s) return;
    while (*s) {
        if (*s >= 'A' && *s <= 'Z') *s = (char)(*s + 32);
        s++;
    }
}

/* north.sevenkingdoms.local -> DC=north,DC=sevenkingdoms,DC=local */
static void domain_to_dn(const char *domain, char *out, int outlen)
{
    char *tmp;
    char *p;
    int first = 1;

    if (!domain || !out || outlen <= 0) return;
    out[0] = 0;

    if (MSVCRT$_strnicmp(domain, "DC=", 3) == 0) {
        MSVCRT$_snprintf(out, outlen, "%s", domain);
        return;
    }

    tmp = (char *)intAlloc(256);
    if (!tmp) return;
    MSVCRT$_snprintf(tmp, 256, "%s", domain);
    p = tmp;
    while (*p) {
        char *dot = p;
        char saved;
        while (*dot && *dot != '.') dot++;
        saved = *dot;
        *dot = 0;
        if (*p) {
            if (first) {
                MSVCRT$_snprintf(out, outlen, "DC=%s", p);
                first = 0;
            } else {
                char *chunk = (char *)intAlloc(320);
                if (!chunk) break;
                MSVCRT$_snprintf(chunk, 320, "%s,DC=%s", out, p);
                MSVCRT$_snprintf(out, outlen, "%s", chunk);
                intFree(chunk);
            }
        }
        if (!saved) break;
        p = dot + 1;
    }
    intFree(tmp);
}

static void cn_from_dn(const char *dn, char *out, int outlen)
{
    const char *p;
    int i = 0;
    if (!out || outlen <= 0) return;
    out[0] = 0;
    if (!dn || !dn[0]) return;
    p = dn;
    if (MSVCRT$_strnicmp(p, "CN=", 3) == 0) p += 3;
    while (*p && *p != ',' && i < outlen - 1) {
        out[i++] = *p++;
    }
    out[i] = 0;
}

static void forest_dn_from_config(const char *configDN, char *out, int outlen)
{
    const char *p;
    if (!out || outlen <= 0) return;
    out[0] = 0;
    if (!configDN) return;
    p = MSVCRT$strstr(configDN, "DC=");
    if (!p) p = MSVCRT$strstr(configDN, "dc=");
    if (p) MSVCRT$_snprintf(out, outlen, "%s", p);
}

static void banner(const char *title, const recon_ctx *ctx, const char *filter)
{
    DPRINT("[*] --------------------------------------------");
    DPRINT("[*] ADReconKit - %s", title);
    DPRINT("[*] --------------------------------------------");
    DPRINT("[*] Target : %s", ctx->ip);
    DPRINT("[*] Domain : %s", ctx->domain);
    DPRINT("[*] DN     : %s", ctx->domainDN);
    if (filter && filter[0])
        DPRINT("[*] Filter : %s", filter);
    DPRINT("[*] --------------------------------------------");
}

static const char *eku_friendly(const char *oid)
{
    if (!oid) return "";
    if (MSVCRT$strcmp(oid, "1.3.6.1.5.5.7.3.1") == 0) return "Server Authentication";
    if (MSVCRT$strcmp(oid, "1.3.6.1.5.5.7.3.2") == 0) return "Client Authentication";
    if (MSVCRT$strcmp(oid, "1.3.6.1.5.5.7.3.3") == 0) return "Code Signing";
    if (MSVCRT$strcmp(oid, "1.3.6.1.5.5.7.3.4") == 0) return "Secure Email";
    if (MSVCRT$strcmp(oid, "1.3.6.1.5.5.7.3.8") == 0) return "Time Stamping";
    if (MSVCRT$strcmp(oid, "1.3.6.1.4.1.311.20.2.2") == 0) return "Smart Card Logon";
    if (MSVCRT$strcmp(oid, "1.3.6.1.4.1.311.10.3.4") == 0) return "Encrypting File System";
    if (MSVCRT$strcmp(oid, "1.3.6.1.4.1.311.21.5") == 0) return "Private Key Archival";
    if (MSVCRT$strcmp(oid, "1.3.6.1.4.1.311.10.3.12") == 0) return "Document Signing";
    if (MSVCRT$strcmp(oid, "2.5.29.37.0") == 0) return "Any Purpose";
    return "";
}

static BOOL eku_is_client_auth(const char *oid)
{
    if (!oid || !oid[0]) return TRUE;
    if (MSVCRT$strcmp(oid, "1.3.6.1.5.5.7.3.2") == 0) return TRUE;
    if (MSVCRT$strcmp(oid, "1.3.6.1.4.1.311.20.2.2") == 0) return TRUE;
    if (MSVCRT$strcmp(oid, "2.5.29.37.0") == 0) return TRUE;
    return FALSE;
}

static const char *trust_direction_str(DWORD v)
{
    if (v == 1) return "Inbound";
    if (v == 2) return "Outbound";
    if (v == 3) return "Bidirectional";
    return "Unknown";
}

static const char *trust_type_str(DWORD v)
{
    if (v == 1) return "Downlevel (NT)";
    if (v == 2) return "Uplevel (AD)";
    if (v == 3) return "MIT";
    if (v == 4) return "DCE";
    return "Unknown";
}

static BOOL is_outdated_os(const char *os)
{
    char tmp[160];
    if (!os || !os[0]) return FALSE;
    MSVCRT$_snprintf(tmp, sizeof(tmp), "%s", os);
    ascii_lower(tmp);
    if (MSVCRT$strstr(tmp, "windows xp")) return TRUE;
    if (MSVCRT$strstr(tmp, "windows vista")) return TRUE;
    if (MSVCRT$strstr(tmp, "windows 7")) return TRUE;
    if (MSVCRT$strstr(tmp, "windows 8")) return TRUE;
    if (MSVCRT$strstr(tmp, "windows 2000")) return TRUE;
    if (MSVCRT$strstr(tmp, "windows nt")) return TRUE;
    if (MSVCRT$strstr(tmp, "server 2003")) return TRUE;
    if (MSVCRT$strstr(tmp, "server 2008")) return TRUE;
    if (MSVCRT$strstr(tmp, "server 2012")) return TRUE;
    return FALSE;
}

static void ldap_fail(const char *what, ULONG rc)
{
    PCHAR msg = WLDAP32$ldap_err2stringA(rc);
    if (msg && msg[0])
        EPRINT("[-] %s failed: %lu (%s)", what, (unsigned long)rc, msg);
    else
        EPRINT("[-] %s failed: %lu", what, (unsigned long)rc);
}

static BOOL ldap_is_net_fail(ULONG rc)
{
    return (rc == LDAP_SERVER_DOWN || rc == LDAP_TIMEOUT || rc == LDAP_CONNECT_ERROR);
}

/* ── LDAP session ────────────────────────────────────────── */

static LDAP *ldap_try_bind(const char *ip, int want_sign, int want_encrypt, ULONG *out_rc)
{
    LDAP *ld;
    ULONG ver = LDAP_VERSION3;
    ULONG on = 1;
    ULONG tlim = LDAP_SEARCH_TIMEOUT_SEC;
    LDAP_TIMEVAL tv;
    ULONG rc;

    *out_rc = LDAP_LOCAL_ERROR;
    ld = WLDAP32$ldap_initA((PCHAR)ip, LDAP_PORT);
    if (!ld) {
        *out_rc = LDAP_CONNECT_ERROR;
        return NULL;
    }

    WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);
    tv.tv_sec = LDAP_NET_TIMEOUT_SEC;
    tv.tv_usec = 0;
    WLDAP32$ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    WLDAP32$ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &tlim);
    WLDAP32$ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    WLDAP32$ldap_set_option(ld, LDAP_OPT_AREC_EXCLUSIVE, &on);
    if (want_sign)
        WLDAP32$ldap_set_option(ld, LDAP_OPT_SIGN, &on);
    if (want_encrypt)
        WLDAP32$ldap_set_option(ld, LDAP_OPT_ENCRYPT, &on);

    rc = WLDAP32$ldap_connect(ld, &tv);
    if (rc != LDAP_SUCCESS) {
        *out_rc = rc;
        WLDAP32$ldap_unbind_s(ld);
        return NULL;
    }

    rc = WLDAP32$ldap_bind_sA(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        *out_rc = rc;
        WLDAP32$ldap_unbind_s(ld);
        return NULL;
    }
    *out_rc = LDAP_SUCCESS;
    return ld;
}

static LDAP *ldap_open_dc(const char *ip)
{
    LDAP *ld;
    ULONG rc = 0;

    ld = ldap_try_bind(ip, 1, 1, &rc);
    if (ld) {
        DPRINT("[+] LDAP bind OK (sign+seal) to %s:389", ip);
        return ld;
    }
    if (ldap_is_net_fail(rc) || rc == LDAP_INVALID_CREDENTIALS) {
        ldap_fail("LDAP connect/bind", rc);
        return NULL;
    }
    DPRINT("[*] sign+seal bind failed (%lu), retrying with signing only", (unsigned long)rc);

    ld = ldap_try_bind(ip, 1, 0, &rc);
    if (ld) {
        DPRINT("[+] LDAP bind OK (sign) to %s:389", ip);
        return ld;
    }
    if (ldap_is_net_fail(rc) || rc == LDAP_INVALID_CREDENTIALS) {
        ldap_fail("LDAP connect/bind", rc);
        return NULL;
    }
    DPRINT("[*] signed bind failed (%lu), retrying without signing", (unsigned long)rc);

    ld = ldap_try_bind(ip, 0, 0, &rc);
    if (ld) {
        DPRINT("[+] LDAP bind OK (plain negotiate) to %s:389", ip);
        return ld;
    }
    ldap_fail("LDAP connect/bind", rc);
    return NULL;
}

static BOOL attr_str(LDAP *ld, LDAPMessage *e, const char *name, char *out, int outlen)
{
    PCHAR *vals;
    int i;
    int off = 0;

    if (!out || outlen <= 0) return FALSE;
    out[0] = 0;
    if (!ld || !e || !name) return FALSE;

    vals = WLDAP32$ldap_get_valuesA(ld, e, (PCHAR)name);
    if (!vals || !vals[0]) {
        if (vals) WLDAP32$ldap_value_freeA(vals);
        return FALSE;
    }

    for (i = 0; vals[i] && off < outlen - 1; i++) {
        int n = (int)MSVCRT$strlen(vals[i]);
        if (n <= 0) continue;
        if (i > 0 && off < outlen - 3) {
            out[off++] = ',';
            out[off++] = ' ';
            out[off] = 0;
        }
        if (off + n >= outlen) n = outlen - off - 1;
        if (n > 0) {
            MSVCRT$memcpy(out + off, vals[i], (size_t)n);
            off += n;
            out[off] = 0;
        }
    }
    WLDAP32$ldap_value_freeA(vals);
    return (out[0] != 0);
}

static BOOL attr_int(LDAP *ld, LDAPMessage *e, const char *name, DWORD *val)
{
    PCHAR *vals;
    *val = 0;
    if (!ld || !e || !name) return FALSE;
    vals = WLDAP32$ldap_get_valuesA(ld, e, (PCHAR)name);
    if (!vals || !vals[0]) {
        if (vals) WLDAP32$ldap_value_freeA(vals);
        return FALSE;
    }
    *val = (DWORD)MSVCRT$atoi(vals[0]);
    WLDAP32$ldap_value_freeA(vals);
    return TRUE;
}

static int ldap_foreach(
    recon_ctx *ctx,
    const char *base,
    const char *filter,
    PCHAR *attrs,
    int (*on_row)(recon_ctx *ctx, LDAPMessage *e))
{
    LDAPMessage *res = NULL;
    LDAPMessage *entry;
    LDAP_TIMEVAL tv;
    ULONG st;
    int count = 0;

    if (!ctx || !ctx->ld || !base || !filter) return -1;

    tv.tv_sec = LDAP_SEARCH_TIMEOUT_SEC;
    tv.tv_usec = 0;
    st = WLDAP32$ldap_search_ext_sA(
        ctx->ld,
        (PCHAR)base,
        LDAP_SCOPE_SUBTREE,
        (PCHAR)filter,
        attrs,
        0,
        NULL,
        NULL,
        &tv,
        0,
        &res);

    if (st != LDAP_SUCCESS && st != LDAP_SIZELIMIT_EXCEEDED) {
        ldap_fail("ldap_search", st);
        if (res) WLDAP32$ldap_msgfree(res);
        return -1;
    }
    if (!res) return 0;

    for (entry = WLDAP32$ldap_first_entry(ctx->ld, res);
         entry != NULL;
         entry = WLDAP32$ldap_next_entry(ctx->ld, entry))
    {
        if (on_row) on_row(ctx, entry);
        count++;
    }
    WLDAP32$ldap_msgfree(res);
    return count;
}

static BOOL ldap_rootdse(recon_ctx *ctx)
{
    PCHAR attrs[2];
    LDAPMessage *res = NULL;
    LDAPMessage *entry;
    LDAP_TIMEVAL tv;
    ULONG st;

    attrs[0] = "configurationNamingContext";
    attrs[1] = NULL;
    tv.tv_sec = LDAP_NET_TIMEOUT_SEC;
    tv.tv_usec = 0;

    st = WLDAP32$ldap_search_ext_sA(
        ctx->ld, "", LDAP_SCOPE_BASE, "(objectClass=*)",
        attrs, 0, NULL, NULL, &tv, 0, &res);
    if (st != LDAP_SUCCESS || !res) {
        if (res) WLDAP32$ldap_msgfree(res);
        return FALSE;
    }
    entry = WLDAP32$ldap_first_entry(ctx->ld, res);
    if (entry)
        attr_str(ctx->ld, entry, "configurationNamingContext", ctx->configDN, sizeof(ctx->configDN));
    WLDAP32$ldap_msgfree(res);
    return (ctx->configDN[0] != 0);
}

/* ── Row callbacks ───────────────────────────────────────── */

static int cb_asrep(recon_ctx *ctx, LDAPMessage *e)
{
    if (attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1)))
        DPRINT("[+] %s (vuln AS-REP Roasting)", ctx->s1);
    return 0;
}

static int cb_kerberoast(recon_ctx *ctx, LDAPMessage *e)
{
    if (!attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1))) return 0;
    DPRINT("[+] %s (vuln KerbeRoasting)", ctx->s1);
    if (attr_str(ctx->ld, e, "servicePrincipalName", ctx->s3, sizeof(ctx->s3)))
        DPRINT("[+]    SPN: %s", ctx->s3);
    return 0;
}

static int cb_users(recon_ctx *ctx, LDAPMessage *e)
{
    if (attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1)))
        DPRINT("[+] %s", ctx->s1);
    return 0;
}

static int cb_userdesc(recon_ctx *ctx, LDAPMessage *e)
{
    if (!attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1))) return 0;
    ctx->s2[0] = 0; ctx->s3[0] = 0;
    attr_str(ctx->ld, e, "displayName", ctx->s2, sizeof(ctx->s2));
    attr_str(ctx->ld, e, "description", ctx->s3, sizeof(ctx->s3));
    DPRINT("[+] User        : %s", ctx->s1);
    DPRINT("[+]   Name      : %s", ctx->s2);
    DPRINT("[+]   Description: %s", ctx->s3);
    return 0;
}

static int cb_computers(recon_ctx *ctx, LDAPMessage *e)
{
    if (!attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1))) return 0;
    ctx->s2[0] = 0; ctx->s3[0] = 0;
    attr_str(ctx->ld, e, "operatingSystem", ctx->s2, sizeof(ctx->s2));
    attr_str(ctx->ld, e, "operatingSystemVersion", ctx->s3, 128);
    if (is_outdated_os(ctx->s2))
        DPRINT("[+] %s  OS=%s  Ver=%s  [OUTDATED / HIGH RISK]", ctx->s1, ctx->s2, ctx->s3);
    else
        DPRINT("[+] %s  OS=%s  Ver=%s", ctx->s1, ctx->s2, ctx->s3);
    return 0;
}

static int cb_esc1(recon_ctx *ctx, LDAPMessage *e)
{
    DWORD nameFlag = 0;
    DWORD enrollFlag = 0;
    BOOL san = FALSE;
    BOOL clientAuth = FALSE;
    PCHAR *vals;
    DWORD i;

    if (!attr_str(ctx->ld, e, "cn", ctx->s1, sizeof(ctx->s1))) return 0;
    attr_int(ctx->ld, e, "msPKI-Certificate-Name-Flag", &nameFlag);
    attr_int(ctx->ld, e, "msPKI-Enrollment-Flag", &enrollFlag);
    san = ((nameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0);

    ctx->s3[0] = 0;
    vals = WLDAP32$ldap_get_valuesA(ctx->ld, e, "pKIExtendedKeyUsage");
    if (vals && vals[0]) {
        for (i = 0; vals[i]; i++) {
            const char *fn = eku_friendly(vals[i]);
            if (eku_is_client_auth(vals[i])) clientAuth = TRUE;
            if (!ctx->s3[0]) {
                if (fn && fn[0])
                    MSVCRT$_snprintf(ctx->s3, sizeof(ctx->s3), "%s (%s)", vals[i], fn);
                else
                    MSVCRT$_snprintf(ctx->s3, sizeof(ctx->s3), "%s", vals[i]);
            } else {
                char *acc = (char *)intAlloc(1024);
                if (!acc) break;
                if (fn && fn[0])
                    MSVCRT$_snprintf(acc, 1024, "%s, %s (%s)", ctx->s3, vals[i], fn);
                else
                    MSVCRT$_snprintf(acc, 1024, "%s, %s", ctx->s3, vals[i]);
                MSVCRT$_snprintf(ctx->s3, sizeof(ctx->s3), "%s", acc);
                intFree(acc);
            }
        }
        WLDAP32$ldap_value_freeA(vals);
    } else {
        if (vals) WLDAP32$ldap_value_freeA(vals);
        MSVCRT$_snprintf(ctx->s3, sizeof(ctx->s3), "(none / Any Purpose)");
        clientAuth = TRUE;
    }

    DPRINT("[+] Template : %s", ctx->s1);
    if (san)
        DPRINT("[+]   SAN    : YES (Vulnerable SAN)");
    else
        DPRINT("[+]   SAN    : NO");
    DPRINT("[+]   EKU    : %s", ctx->s3);
    if (enrollFlag & 0x2)
        DPRINT("[+]   Enroll : Manager approval required (less likely ESC1)");
    if (san && clientAuth)
        DPRINT("[+]   ESC1   : LIKELY VULNERABLE");
    else
        DPRINT("[+]   ESC1   : No");
    return 0;
}

static int cb_sam_name(recon_ctx *ctx, LDAPMessage *e)
{
    if (!attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1))) return 0;
    ctx->s2[0] = 0;
    attr_str(ctx->ld, e, "displayName", ctx->s2, sizeof(ctx->s2));
    if (ctx->s2[0])
        DPRINT("[+] %s    Name: %s", ctx->s1, ctx->s2);
    else
        DPRINT("[+] %s", ctx->s1);
    return 0;
}

static int cb_disabled(recon_ctx *ctx, LDAPMessage *e)
{
    if (!attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1))) return 0;
    ctx->s3[0] = 0;
    attr_str(ctx->ld, e, "description", ctx->s3, sizeof(ctx->s3));
    DPRINT("[+] DisabledUser: %s    Description: %s", ctx->s1, ctx->s3);
    return 0;
}

static int cb_admin(recon_ctx *ctx, LDAPMessage *e)
{
    if (!attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1))) return 0;
    ctx->s2[0] = 0;
    attr_str(ctx->ld, e, "displayName", ctx->s2, sizeof(ctx->s2));
    DPRINT("[+] DomainAdmin: %s    Name: %s", ctx->s1, ctx->s2);
    return 0;
}

static int cb_priv_member(recon_ctx *ctx, LDAPMessage *e)
{
    if (!attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1))) return 0;
    ctx->s2[0] = 0;
    attr_str(ctx->ld, e, "displayName", ctx->s2, sizeof(ctx->s2));
    DPRINT("[+]   Member: %s    Name: %s", ctx->s1, ctx->s2);
    return 0;
}

static int cb_gpo(recon_ctx *ctx, LDAPMessage *e)
{
    ctx->s1[0] = 0; ctx->s2[0] = 0; ctx->s3[0] = 0;
    attr_str(ctx->ld, e, "displayName", ctx->s1, sizeof(ctx->s1));
    attr_str(ctx->ld, e, "cn", ctx->s2, sizeof(ctx->s2));
    attr_str(ctx->ld, e, "gPCFileSysPath", ctx->s3, sizeof(ctx->s3));
    DPRINT("[+] GPOName    : %s", ctx->s1);
    DPRINT("[+]   GUID     : %s", ctx->s2);
    DPRINT("[+]   SYSVOL   : %s", ctx->s3);
    return 0;
}

static int cb_dc(recon_ctx *ctx, LDAPMessage *e)
{
    DWORD uac = 0;
    if (!attr_str(ctx->ld, e, "sAMAccountName", ctx->s1, sizeof(ctx->s1))) return 0;
    ctx->s2[0] = 0;
    attr_str(ctx->ld, e, "operatingSystem", ctx->s2, sizeof(ctx->s2));
    attr_int(ctx->ld, e, "userAccountControl", &uac);
    if (uac & UAC_PARTIAL_SECRETS_ACCOUNT)
        DPRINT("[+] DCName: %s    OS: %s    [RODC]", ctx->s1, ctx->s2);
    else
        DPRINT("[+] DCName: %s    OS: %s", ctx->s1, ctx->s2);
    return 0;
}

static int cb_trust(recon_ctx *ctx, LDAPMessage *e)
{
    DWORD dir = 0, typ = 0, attr = 0;
    if (!attr_str(ctx->ld, e, "cn", ctx->s1, sizeof(ctx->s1)))
        attr_str(ctx->ld, e, "trustPartner", ctx->s1, sizeof(ctx->s1));
    attr_int(ctx->ld, e, "trustDirection", &dir);
    attr_int(ctx->ld, e, "trustType", &typ);
    attr_int(ctx->ld, e, "trustAttributes", &attr);
    DPRINT("[+] TargetDomain  : %s", ctx->s1);
    DPRINT("[+]   Direction   : %s (%lu)", trust_direction_str(dir), (unsigned long)dir);
    DPRINT("[+]   Type        : %s (%lu)", trust_type_str(typ), (unsigned long)typ);
    DPRINT("[+]   Attributes  : 0x%08lX", (unsigned long)attr);
    if (dir == 1)
        DPRINT("[+]   Note        : Inbound - target trusts us");
    else if (dir == 2)
        DPRINT("[+]   Note        : Outbound - we trust target (pivot candidate)");
    else if (dir == 3)
        DPRINT("[+]   Note        : Bidirectional - parent-child ExtraSID / SID History possible");
    return 0;
}

static int cb_subnet(recon_ctx *ctx, LDAPMessage *e)
{
    char site[80];
    if (!attr_str(ctx->ld, e, "cn", ctx->s1, sizeof(ctx->s1))) return 0;
    ctx->s3[0] = 0; ctx->s2[0] = 0;
    attr_str(ctx->ld, e, "siteObject", ctx->s3, sizeof(ctx->s3));
    attr_str(ctx->ld, e, "description", ctx->s2, sizeof(ctx->s2));
    if (ctx->s3[0]) {
        cn_from_dn(ctx->s3, site, sizeof(site));
        DPRINT("[+] Subnet      : %s", ctx->s1);
        DPRINT("[+]   Site      : %s", site);
        DPRINT("[+]   Description: %s", ctx->s2);
    } else {
        DPRINT("[+] Subnet      : %s", ctx->s1);
        DPRINT("[+]   Site      : Unassigned");
        DPRINT("[+]   Description: %s", ctx->s2);
    }
    return 0;
}

/* ── Module runners ──────────────────────────────────────── */

static void run_search(
    recon_ctx *ctx,
    const char *title,
    const char *bindDN,
    const char *filterA,
    PCHAR *attrs,
    int (*cb)(recon_ctx *, LDAPMessage *))
{
    int n;
    banner(title, ctx, filterA);
    if (!ctx->ld) {
        DPRINT("[-] No LDAP session, skipping this check");
        return;
    }
    n = ldap_foreach(ctx, bindDN, filterA, attrs, cb);
    if (n < 0)
        DPRINT("[-] Search failed");
    else if (n == 0)
        DPRINT("[-] No results found");
    else
        DPRINT("[*] Total: %d object(s)", n);
}

static void do_asrep(recon_ctx *ctx)
{
    PCHAR attrs[2];
    attrs[0] = "sAMAccountName";
    attrs[1] = NULL;
    run_search(ctx, "AS-REP Roasting",
        ctx->domainDN,
        "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        attrs, cb_asrep);
}

static void do_kerberoast(recon_ctx *ctx)
{
    PCHAR attrs[3];
    attrs[0] = "sAMAccountName";
    attrs[1] = "servicePrincipalName";
    attrs[2] = NULL;
    run_search(ctx, "Kerberoasting",
        ctx->domainDN,
        "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))",
        attrs, cb_kerberoast);
}

static void do_users(recon_ctx *ctx)
{
    PCHAR attrs[2];
    attrs[0] = "sAMAccountName";
    attrs[1] = NULL;
    run_search(ctx, "Enumerate Users",
        ctx->domainDN,
        "(&(objectCategory=person)(objectClass=user))",
        attrs, cb_users);
}

static void do_userdesc(recon_ctx *ctx)
{
    PCHAR attrs[4];
    attrs[0] = "sAMAccountName";
    attrs[1] = "displayName";
    attrs[2] = "description";
    attrs[3] = NULL;
    run_search(ctx, "Users with Description",
        ctx->domainDN,
        "(&(objectCategory=person)(objectClass=user))",
        attrs, cb_userdesc);
}

static void do_computers(recon_ctx *ctx)
{
    PCHAR attrs[4];
    attrs[0] = "sAMAccountName";
    attrs[1] = "operatingSystem";
    attrs[2] = "operatingSystemVersion";
    attrs[3] = NULL;
    run_search(ctx, "Computers / Outdated OS",
        ctx->domainDN,
        "(objectClass=computer)",
        attrs, cb_computers);
}

static void do_esc1(recon_ctx *ctx)
{
    char *tmplDN;
    PCHAR attrs[5];
    attrs[0] = "cn";
    attrs[1] = "msPKI-Certificate-Name-Flag";
    attrs[2] = "pKIExtendedKeyUsage";
    attrs[3] = "msPKI-Enrollment-Flag";
    attrs[4] = NULL;
    tmplDN = (char *)intAlloc(768);
    if (!tmplDN) return;
    MSVCRT$_snprintf(tmplDN, 768,
        "CN=Certificate Templates,CN=Public Key Services,CN=Services,%s",
        ctx->configDN);
    run_search(ctx, "ADCS ESC1 (SAN / EKU)",
        tmplDN,
        "(objectClass=pKICertificateTemplate)",
        attrs, cb_esc1);
    intFree(tmplDN);
}

static void do_pwdnever(recon_ctx *ctx)
{
    PCHAR attrs[3];
    attrs[0] = "sAMAccountName";
    attrs[1] = "displayName";
    attrs[2] = NULL;
    run_search(ctx, "Password Never Expires",
        ctx->domainDN,
        "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        attrs, cb_sam_name);
}

static void do_weakpwd(recon_ctx *ctx)
{
    PCHAR attrs[3];
    attrs[0] = "sAMAccountName";
    attrs[1] = "displayName";
    attrs[2] = NULL;
    run_search(ctx, "PASSWD_NOTREQD (blank / weak / default possible)",
        ctx->domainDN,
        "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))",
        attrs, cb_sam_name);

    attrs[1] = "description";
    run_search(ctx, "Disabled Accounts",
        ctx->domainDN,
        "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        attrs, cb_disabled);
}

static void search_priv_group(recon_ctx *ctx, const char *label, const char *groupDN)
{
    char *filter;
    PCHAR attrs[3];
    attrs[0] = "sAMAccountName";
    attrs[1] = "displayName";
    attrs[2] = NULL;
    filter = (char *)intAlloc(768);
    if (!filter) return;
    MSVCRT$_snprintf(filter, 768,
        "(&(objectCategory=person)(objectClass=user)(memberOf=%s))",
        groupDN);
    DPRINT("[*] Group: %s", label);
    run_search(ctx, label, ctx->domainDN, filter, attrs, cb_priv_member);
    intFree(filter);
}

static void do_admins(recon_ctx *ctx)
{
    char *dn;
    char *filter;
    PCHAR attrs[3];
    attrs[0] = "sAMAccountName";
    attrs[1] = "displayName";
    attrs[2] = NULL;

    dn = (char *)intAlloc(768);
    filter = (char *)intAlloc(768);
    if (!dn || !filter) {
        if (dn) intFree(dn);
        if (filter) intFree(filter);
        return;
    }

    MSVCRT$_snprintf(dn, 768, "CN=Domain Admins,CN=Users,%s", ctx->domainDN);
    MSVCRT$_snprintf(filter, 768,
        "(&(objectCategory=person)(objectClass=user)(memberOf=%s))", dn);
    run_search(ctx, "Domain Admins", ctx->domainDN, filter, attrs, cb_admin);

    MSVCRT$_snprintf(dn, 768, "CN=Administrators,CN=Builtin,%s", ctx->domainDN);
    search_priv_group(ctx, "Administrators (Builtin)", dn);

    MSVCRT$_snprintf(dn, 768, "CN=Account Operators,CN=Builtin,%s", ctx->domainDN);
    search_priv_group(ctx, "Account Operators", dn);

    MSVCRT$_snprintf(dn, 768, "CN=Backup Operators,CN=Builtin,%s", ctx->domainDN);
    search_priv_group(ctx, "Backup Operators", dn);

    MSVCRT$_snprintf(dn, 768, "CN=Server Operators,CN=Builtin,%s", ctx->domainDN);
    search_priv_group(ctx, "Server Operators", dn);

    MSVCRT$_snprintf(dn, 768, "CN=Print Operators,CN=Builtin,%s", ctx->domainDN);
    search_priv_group(ctx, "Print Operators", dn);

    MSVCRT$_snprintf(dn, 768, "CN=DnsAdmins,CN=Users,%s", ctx->domainDN);
    search_priv_group(ctx, "DnsAdmins", dn);

    if (ctx->forestDN[0]) {
        MSVCRT$_snprintf(dn, 768, "CN=Enterprise Admins,CN=Users,%s", ctx->forestDN);
        search_priv_group(ctx, "Enterprise Admins", dn);
        MSVCRT$_snprintf(dn, 768, "CN=Schema Admins,CN=Users,%s", ctx->forestDN);
        search_priv_group(ctx, "Schema Admins", dn);
    }
    intFree(dn);
    intFree(filter);
}

static void do_gpo(recon_ctx *ctx)
{
    char *gpoDN;
    PCHAR attrs[4];
    attrs[0] = "displayName";
    attrs[1] = "cn";
    attrs[2] = "gPCFileSysPath";
    attrs[3] = NULL;
    gpoDN = (char *)intAlloc(768);
    if (!gpoDN) return;
    MSVCRT$_snprintf(gpoDN, 768, "CN=Policies,CN=System,%s", ctx->domainDN);
    run_search(ctx, "GPO Locations",
        gpoDN,
        "(objectClass=groupPolicyContainer)",
        attrs, cb_gpo);
    intFree(gpoDN);
}

static void do_dcs(recon_ctx *ctx)
{
    PCHAR attrs[4];
    attrs[0] = "sAMAccountName";
    attrs[1] = "operatingSystem";
    attrs[2] = "userAccountControl";
    attrs[3] = NULL;

    run_search(ctx, "Domain Controllers (UAC SERVER_TRUST_ACCOUNT=8192)",
        ctx->domainDN,
        "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        attrs, cb_dc);

    run_search(ctx, "Writable Domain Controllers (primaryGroupID=516)",
        ctx->domainDN,
        "(&(objectCategory=computer)(primaryGroupID=516))",
        attrs, cb_dc);

    run_search(ctx, "Read-Only Domain Controllers (primaryGroupID=521)",
        ctx->domainDN,
        "(&(objectCategory=computer)(primaryGroupID=521))",
        attrs, cb_dc);
}

static void do_trusts(recon_ctx *ctx)
{
    char *sysDN;
    PCHAR attrs[6];
    attrs[0] = "cn";
    attrs[1] = "trustPartner";
    attrs[2] = "trustDirection";
    attrs[3] = "trustType";
    attrs[4] = "trustAttributes";
    attrs[5] = NULL;
    sysDN = (char *)intAlloc(768);
    if (!sysDN) return;
    MSVCRT$_snprintf(sysDN, 768, "CN=System,%s", ctx->domainDN);
    run_search(ctx, "Domain Trust Mapping",
        sysDN,
        "(objectClass=trustedDomain)",
        attrs, cb_trust);
    intFree(sysDN);
}

static void do_sites(recon_ctx *ctx)
{
    char *subDN;
    PCHAR attrs[4];
    attrs[0] = "cn";
    attrs[1] = "siteObject";
    attrs[2] = "description";
    attrs[3] = NULL;
    subDN = (char *)intAlloc(768);
    if (!subDN) return;
    MSVCRT$_snprintf(subDN, 768, "CN=Subnets,CN=Sites,%s", ctx->configDN);
    run_search(ctx, "Subnet & Site Topology",
        subDN,
        "(objectClass=subnet)",
        attrs, cb_subnet);
    intFree(subDN);
}

static void do_all(recon_ctx *ctx)
{
    do_asrep(ctx);
    do_kerberoast(ctx);
    do_users(ctx);
    do_userdesc(ctx);
    do_computers(ctx);
    do_esc1(ctx);
    do_pwdnever(ctx);
    do_weakpwd(ctx);
    do_admins(ctx);
    do_gpo(ctx);
    do_dcs(ctx);
    do_trusts(ctx);
    do_sites(ctx);
}

/* ── BOF entry ───────────────────────────────────────────── */

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    int action;
    char *ip;
    char *domain;
    recon_ctx *ctx;

    DPRINT("[*] === ADReconKit BOF Entry ===");

    if (!Buffer || Length == 0) {
        EPRINT("[-] No arguments provided");
        return;
    }

    BeaconDataParse(&parser, Buffer, Length);
    action = BeaconDataInt(&parser);
    ip = BeaconDataExtract(&parser, NULL);
    domain = BeaconDataExtract(&parser, NULL);

    if (!ip || !ip[0]) {
        EPRINT("[-] IP / DC target is required");
        return;
    }
    if (!domain || !domain[0]) {
        EPRINT("[-] Domain FQDN is required (e.g. north.sevenkingdoms.local)");
        return;
    }

    ctx = (recon_ctx *)intAlloc(sizeof(recon_ctx));
    if (!ctx) {
        EPRINT("[-] Failed to allocate recon context");
        return;
    }

    MSVCRT$_snprintf(ctx->ip, sizeof(ctx->ip), "%s", ip);
    MSVCRT$_snprintf(ctx->domain, sizeof(ctx->domain), "%s", domain);
    domain_to_dn(domain, ctx->domainDN, sizeof(ctx->domainDN));

    DPRINT("[*] ============================================");
    DPRINT("[*] ADReconKit - LDAP Active Directory Recon");
    DPRINT("[*] ============================================");
    DPRINT("[*] Target DC : %s", ctx->ip);
    DPRINT("[*] Domain    : %s", ctx->domain);
    DPRINT("[*] Domain DN : %s", ctx->domainDN);
    DPRINT("[*] Action    : %d", action);

    ctx->ld = ldap_open_dc(ctx->ip);
    if (!ctx->ld) {
        EPRINT("[-] LDAP bind failed — beacon is still alive. Check token / DC reachability.");
        intFree(ctx);
        return;
    }

    if (ldap_rootdse(ctx) && ctx->configDN[0]) {
        DPRINT("[*] Config DN : %s", ctx->configDN);
        forest_dn_from_config(ctx->configDN, ctx->forestDN, sizeof(ctx->forestDN));
        if (ctx->forestDN[0])
            DPRINT("[*] Forest DN : %s", ctx->forestDN);
    } else {
        MSVCRT$_snprintf(ctx->configDN, sizeof(ctx->configDN), "CN=Configuration,%s", ctx->domainDN);
        DPRINT("[!] rootDSE configurationNamingContext unavailable, fallback %s", ctx->configDN);
        forest_dn_from_config(ctx->configDN, ctx->forestDN, sizeof(ctx->forestDN));
    }
    DPRINT("[*] ============================================");

    if (action == ACTION_ALL) do_all(ctx);
    else if (action == ACTION_ASREP) do_asrep(ctx);
    else if (action == ACTION_KERBEROAST) do_kerberoast(ctx);
    else if (action == ACTION_USERS) do_users(ctx);
    else if (action == ACTION_USERDESC) do_userdesc(ctx);
    else if (action == ACTION_COMPUTERS) do_computers(ctx);
    else if (action == ACTION_ESC1) do_esc1(ctx);
    else if (action == ACTION_PWDNEVER) do_pwdnever(ctx);
    else if (action == ACTION_WEAKPWD) do_weakpwd(ctx);
    else if (action == ACTION_ADMINS) do_admins(ctx);
    else if (action == ACTION_GPO) do_gpo(ctx);
    else if (action == ACTION_DCS) do_dcs(ctx);
    else if (action == ACTION_TRUSTS) do_trusts(ctx);
    else if (action == ACTION_SITES) do_sites(ctx);
    else EPRINT("[-] Invalid action: %d", action);

    if (ctx->ld) {
        WLDAP32$ldap_unbind_s(ctx->ld);
        ctx->ld = NULL;
    }
    intFree(ctx);
    DPRINT("[*] ============================================");
    DPRINT("[*] ADReconKit complete");
    DPRINT("[*] ============================================");
}
