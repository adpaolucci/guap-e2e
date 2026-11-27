use regex::{Regex, RegexSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Standard,
    ApiCredPek,
    InjSetWindowsHookEx,
    InjWriteProcessMemory,
    LegacyAcm,
}

#[derive(Debug, Clone)]
pub struct RuleDef {
    pub rule_id: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub kind: RuleKind,
    /// Inner pattern (without outer token boundary) for standard source/CLI/MCP matching.
    pub inner_pattern: &'static str,
    /// Binary-safe inner pattern (stricter for 3-letter tokens in raw binary blobs).
    pub binary_inner_pattern: Option<&'static str>,
    pub case_sensitive: bool,
    pub allow_negation_in_comments: bool,
    pub allow_negation_in_strings: bool,
}

pub struct CompiledRule {
    pub def: RuleDef,
    pub source_regex: Regex,
    pub binary_regex: Option<Regex>,
}

pub struct RuleRegistry {
    pub rules: Vec<CompiledRule>,
    pub source_set: RegexSet,
    pub binary_set: RegexSet,
    pub binary_rule_indices: Vec<usize>,
    pub binary_unbounded_set: RegexSet,
    pub binary_unbounded_regexes: Vec<Regex>,
    pub negation_regex: Regex,
    pub negated_assertion_regex: Regex,
    pub cargo_hook_dep_regex: Regex,
    pub pek_context_regex: Regex,
    pub acm_audio_context_regex: Regex,
    pub acm_standalone_id_regex: Regex,
    pub hook_dangerous_const_regex: Regex,
    pub hook_ll_const_regex: Regex,
    pub hook_null_hinstance_regex: Regex,
    pub wpm_struct_regex: Regex,
    pub wpm_exec_or_inj_regex: Regex,
    pub binary_keymaterial_camel_regex: Regex,
}

fn wrap_boundary(inner: &str, case_sensitive: bool) -> String {
    let flag = if case_sensitive { "" } else { "(?i)" };
    format!(r"{flag}(?:^|[^a-zA-Z0-9])({inner})(?:$|[^a-zA-Z0-9])")
}

pub fn all_rule_defs() -> Vec<RuleDef> {
    vec![
        // 1. cred2rust workspace/crate/tool prohibition
        RuleDef {
            rule_id: "R4-CRED-01",
            category: "cred2rust",
            description: "Prohibited cred2rust workspace, crate, binary, or tool",
            kind: RuleKind::Standard,
            inner_pattern: r"cred2rust(?:[-_][a-z0-9_-]+)?",
            binary_inner_pattern: Some(r"cred2rust(?:[-_][a-z0-9_-]+)?"),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        // 2. All 27 prohibited credential/password recovery tools
        RuleDef {
            rule_id: "R4-CRED-02",
            category: "credential_tool",
            description: "Prohibited credential or password recovery tool",
            kind: RuleKind::Standard,
            inner_pattern: concat!(
                r"web[-_ ]?browser[-_ ]?pass[-_ ]?view|",
                r"chrome[-_ ]?pass|",
                r"password[-_ ]?fox|",
                r"ie[-_ ]?pass[-_ ]?view|",
                r"opera[-_ ]?pass[-_ ]?view|",
                r"mail[-_ ]?pass[-_ ]?view|mailpv|",
                r"outlook[-_ ]?pass[-_ ]?view|",
                r"wireless[-_ ]?key[-_ ]?view|",
                r"wifi[-_ ]?key[-_ ]?view|",
                r"network[-_ ]?password[-_ ]?recovery|net[-_ ]?pass|",
                r"credentials[-_ ]?file[-_ ]?view|",
                r"vault[-_ ]?password[-_ ]?view|",
                r"lsa[-_ ]?secrets[-_ ]?view|",
                r"lsa[-_ ]?secrets[-_ ]?dump|",
                r"security[-_ ]?questions[-_ ]?view|",
                r"dialupass|dial[-_ ]?u[-_ ]?pass|",
                r"asterisk[-_ ]?logger|",
                r"bullets[-_ ]?pass[-_ ]?view|",
                r"protected[-_ ]?storage[-_ ]?pass[-_ ]?view|pspv|",
                r"remote[-_ ]?desktop[-_ ]?pass[-_ ]?view|rdpv|",
                r"vnc[-_ ]?pass[-_ ]?view|",
                r"router[-_ ]?pass[-_ ]?view|",
                r"produ[-_ ]?key|product[-_ ]?key|",
                r"sniff[-_ ]?pass|",
                r"chrome[-_ ]?cookies[-_ ]?view|",
                r"edge[-_ ]?cookies[-_ ]?view|",
                r"(?:[a-z0-9_-]*[-_ ])?pass[-_ ]?view|(?-i:[a-z0-9_-]*Pass[-_ ]?View)"
            ),
            binary_inner_pattern: Some(concat!(
                r"web[-_ ]?browser[-_ ]?pass[-_ ]?view|",
                r"chrome[-_ ]?pass|",
                r"password[-_ ]?fox|",
                r"ie[-_ ]?pass[-_ ]?view|",
                r"opera[-_ ]?pass[-_ ]?view|",
                r"mail[-_ ]?pass[-_ ]?view|mailpv|",
                r"outlook[-_ ]?pass[-_ ]?view|",
                r"wireless[-_ ]?key[-_ ]?view|",
                r"wifi[-_ ]?key[-_ ]?view|",
                r"network[-_ ]?password[-_ ]?recovery|net[-_ ]?pass|",
                r"credentials[-_ ]?file[-_ ]?view|",
                r"vault[-_ ]?password[-_ ]?view|",
                r"lsa[-_ ]?secrets[-_ ]?view|",
                r"lsa[-_ ]?secrets[-_ ]?dump|",
                r"security[-_ ]?questions[-_ ]?view|",
                r"dialupass|dial[-_ ]?u[-_ ]?pass|",
                r"asterisk[-_ ]?logger|",
                r"bullets[-_ ]?pass[-_ ]?view|",
                r"protected[-_ ]?storage[-_ ]?pass[-_ ]?view|pspv\.exe|",
                r"remote[-_ ]?desktop[-_ ]?pass[-_ ]?view|rdpv\.exe|",
                r"vnc[-_ ]?pass[-_ ]?view|",
                r"router[-_ ]?pass[-_ ]?view|",
                r"produ[-_ ]?key|product[-_ ]?key|",
                r"sniff[-_ ]?pass|",
                r"chrome[-_ ]?cookies[-_ ]?view|",
                r"edge[-_ ]?cookies[-_ ]?view|",
                r"(?:[a-z0-9_-]*[-_ ])?pass[-_ ]?view|(?-i:[a-z0-9_-]*Pass[-_ ]?View)"
            )),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        // 3..8. Credential / Secret Dumping APIs (R4-API-CRED-01..06)
        RuleDef {
            rule_id: "R4-API-CRED-01",
            category: "credential_api",
            description: "Windows Credential Manager enumeration API (CredEnumerateW/A)",
            kind: RuleKind::Standard,
            inner_pattern: r"cred[-_ ]?enumerate(?:[-_ ]?[wa]|[wa])?",
            binary_inner_pattern: Some(r"cred[-_ ]?enumerate(?:[-_ ]?[wa]|[wa])?"),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        RuleDef {
            rule_id: "R4-API-CRED-02",
            category: "credential_api",
            description: "Windows Credential Vault enumeration/retrieval APIs",
            kind: RuleKind::Standard,
            inner_pattern: r"vault[-_ ]?(?:enumerate[-_ ]?items|get[-_ ]?item|enumerate[-_ ]?vaults|open[-_ ]?vault)",
            binary_inner_pattern: Some(
                r"vault[-_ ]?(?:enumerate[-_ ]?items|get[-_ ]?item|enumerate[-_ ]?vaults|open[-_ ]?vault)",
            ),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        RuleDef {
            rule_id: "R4-API-CRED-03",
            category: "credential_api",
            description: "LSA private secret retrieval API (LsaRetrievePrivateData)",
            kind: RuleKind::Standard,
            inner_pattern: r"lsa[-_ ]?retrieve[-_ ]?private[-_ ]?data",
            binary_inner_pattern: Some(r"lsa[-_ ]?retrieve[-_ ]?private[-_ ]?data"),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        RuleDef {
            rule_id: "R4-API-CRED-04",
            category: "credential_api",
            description: "Windows DPAPI unprotection API (CryptUnprotectData/Memory)",
            kind: RuleKind::Standard,
            inner_pattern: r"crypt[-_ ]?unprotect[-_ ]?(?:data|memory)",
            binary_inner_pattern: Some(r"crypt[-_ ]?unprotect[-_ ]?(?:data|memory)"),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        RuleDef {
            rule_id: "R4-API-CRED-05",
            category: "credential_api",
            description: "Wi-Fi plaintext key recovery (WLAN_PROFILE_GET_PLAINTEXT_KEY / keyMaterial)",
            kind: RuleKind::Standard,
            inner_pattern: r"wlan[-_ ]?profile[-_ ]?get[-_ ]?plaintext[-_ ]?key|WlanGetProfile\s*\([^;]*0x[0_]*4(?:_?(?:u|i)(?:8|16|32|64|128|size))?|key_?material",
            binary_inner_pattern: Some(
                r"wlan[-_ ]?profile[-_ ]?get[-_ ]?plaintext[-_ ]?key|key_?material",
            ),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        RuleDef {
            rule_id: "R4-API-CRED-06",
            category: "credential_api",
            description: "SAM/SECURITY SysKey/BootKey/PEK secret dumping",
            kind: RuleKind::ApiCredPek,
            inner_pattern: r"sys[-_ ]?key|boot[-_ ]?key|lsa[-_ ]?secret[-_ ]?decrypt|sam[-_ ]?(?:hash[-_ ]?dump|secret[-_ ]?decrypt)|nl\$km|pek[-_ ]?decrypt|(?-i:\bPEK\b)",
            binary_inner_pattern: Some(
                r"sys[-_ ]?key|boot[-_ ]?key|lsa[-_ ]?secret[-_ ]?decrypt|sam[-_ ]?(?:hash[-_ ]?dump|secret[-_ ]?decrypt)|nl\$km|pek[-_ ]?decrypt",
            ),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        // 9..12. DLL Injection & API Hooking Rules (R4-INJ-01..04)
        RuleDef {
            rule_id: "R4-INJ-01",
            category: "injection_tool",
            description: "Prohibited DLL injection / hooking utility (RunAsDate, SocketSniff, InjectedDLL)",
            kind: RuleKind::Standard,
            inner_pattern: r"run[-_ ]?as[-_ ]?date|socket[-_ ]?sniff|injected[-_ ]?dll",
            binary_inner_pattern: Some(
                r"run[-_ ]?as[-_ ]?date|socket[-_ ]?sniff|injected[-_ ]?dll",
            ),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        RuleDef {
            rule_id: "R4-INJ-02",
            category: "injection_api",
            description: "Remote thread, APC, detour, MinHook, or IAT patching API",
            kind: RuleKind::Standard,
            inner_pattern: r"create[-_ ]?remote[-_ ]?thread(?:[-_ ]?ex)?|nt[-_ ]?create[-_ ]?thread[-_ ]?ex|rtl[-_ ]?create[-_ ]?user[-_ ]?thread|queue[-_ ]?user[-_ ]?apc|detour[-_ ]?attach|detour[-_ ]?transaction[-_ ]?begin|mh[-_ ]?create[-_ ]?hook|(?:iat[-_ ]?(?:patch|hook)|(?:patch|hook)[-_ ]?iat)[a-z0-9_]*",
            binary_inner_pattern: Some(
                r"create[-_ ]?remote[-_ ]?thread(?:[-_ ]?ex)?|nt[-_ ]?create[-_ ]?thread[-_ ]?ex|rtl[-_ ]?create[-_ ]?user[-_ ]?thread|queue[-_ ]?user[-_ ]?apc|detour[-_ ]?attach|detour[-_ ]?transaction[-_ ]?begin|mh[-_ ]?create[-_ ]?hook|(?:iat[-_ ]?(?:patch|hook)|(?:patch|hook)[-_ ]?iat)[a-z0-9_]*",
            ),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        RuleDef {
            rule_id: "R4-INJ-03",
            category: "injection_api",
            description: "External-DLL SetWindowsHookEx (WH_CBT/WH_GETMESSAGE/WH_CALLWNDPROC)",
            kind: RuleKind::InjSetWindowsHookEx,
            inner_pattern: r"set[-_ ]?windows[-_ ]?hook[-_ ]?ex(?:[-_ ]?[wa]|[wa])?|wh_cbt|wh_getmessage|wh_callwndproc(?:ret)?",
            binary_inner_pattern: Some(
                r"set[-_ ]?windows[-_ ]?hook[-_ ]?ex(?:[-_ ]?[wa]|[wa])?|wh_cbt|wh_getmessage|wh_callwndproc(?:ret)?",
            ),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        RuleDef {
            rule_id: "R4-INJ-04",
            category: "injection_api",
            description: "Cross-process WriteProcessMemory (exempting control-export LVITEMW/TVITEMW marshaling)",
            kind: RuleKind::InjWriteProcessMemory,
            inner_pattern: r"write[-_ ]?process[-_ ]?memory",
            binary_inner_pattern: Some(r"write[-_ ]?process[-_ ]?memory"),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        // 13..51. All 39 Retired Legacy Tools (R4-LEGACY-01..39)
        legacy_rule(
            "R4-LEGACY-01",
            "IECacheView",
            r"ie[-_ ]?cache[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-02",
            "IEHistoryView",
            r"ie[-_ ]?history[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-03",
            "IECookiesView",
            r"ie[-_ ]?cookies[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-04",
            "IEHV / IESessionView",
            r"iehv|ie[-_ ]?session[-_ ]?view",
            Some(r"iehv\.exe|--iehv|ie[-_ ]?session[-_ ]?view"),
        ),
        legacy_rule(
            "R4-LEGACY-05",
            "IEDownloadView",
            r"ie[-_ ]?download[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-06",
            "IEPassView",
            r"ie[-_ ]?pass[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-07",
            "URLStringGrabber",
            r"url[-_ ]?string[-_ ]?grabber",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-08",
            "FavoritesView",
            r"favorites[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-09",
            "WebVideoCap",
            r"web[-_ ]?video[-_ ]?cap",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-10",
            "FlashCookiesView",
            r"flash[-_ ]?cookies[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-11",
            "RTMPDumpHelper",
            r"rtmp[-_ ]?dump[-_ ]?helper",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-12",
            "ActiveXHelper",
            r"active[-_ ]?x[-_ ]?helper",
            None,
        ),
        RuleDef {
            rule_id: "R4-LEGACY-13",
            category: "legacy_tool",
            description: "Retired legacy tool: ActiveX Compatibility Manager (acm)",
            kind: RuleKind::LegacyAcm,
            inner_pattern: r"active[-_ ]?x[-_ ]?compatibility[-_ ]?manager|acm",
            binary_inner_pattern: Some(
                r"active[-_ ]?x[-_ ]?compatibility[-_ ]?manager|acm\.exe|--acm",
            ),
            case_sensitive: false,
            allow_negation_in_comments: true,
            allow_negation_in_strings: true,
        },
        legacy_rule(
            "R4-LEGACY-14",
            "Win9x PassView (win9xpv)",
            r"win[-_ ]?9x[-_ ]?pass[-_ ]?view|win9xpv",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-15",
            "9xProtect / Win9x tools",
            r"9x[-_ ]?protect|win9x[-_]?(?:protect|pass|pwl|tool|utility|hook|view)",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-16",
            "MSNPass / MessenPass",
            r"msn[-_ ]?pass|messen[-_ ]?pass",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-17",
            "SkypeLogView",
            r"skype[-_ ]?log[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-18",
            "SkypeContactsView",
            r"skype[-_ ]?contacts[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-19",
            "pcANYWHERECIF / PassView",
            r"pcanywhere[-_ ]?cif|pcanywhere[-_ ]?pass[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-20",
            "AccessPassView (accesspv)",
            r"access[-_ ]?pass[-_ ]?view|accesspv",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-21",
            "OEView / DBXtract",
            r"oe[-_ ]?view|db[-_ ]?xtract",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-22",
            "Windows Live Mail PassView (wlmpv)",
            r"windows[-_ ]?live[-_ ]?mail[-_ ]?pass[-_ ]?view|wlmpv",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-23",
            "NetscapeCacheView / NSHistoryView",
            r"netscape[-_ ]?cache[-_ ]?view|ns[-_ ]?history[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-24",
            "PaltalkPass / MirandaPass",
            r"paltalk[-_ ]?pass|miranda[-_ ]?pass",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-25",
            "TrillianPass / PidginPass",
            r"trillian[-_ ]?pass|pidgin[-_ ]?pass",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-26",
            "GoogleTalkPass / GizmoPass",
            r"google[-_ ]?talk[-_ ]?pass|gizmo[-_ ]?pass",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-27",
            "ICQPass / AIMPass",
            r"icq[-_ ]?pass|aim[-_ ]?pass",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-28",
            "WinUpdatesList (wul)",
            r"win[-_ ]?updates[-_ ]?list|wul",
            Some(r"win[-_ ]?updates[-_ ]?list|wul\.exe|--wul"),
        ),
        legacy_rule(
            "R4-LEGACY-29",
            "DrWatsonLogView / WinXP UserDump",
            r"dr[-_ ]?watson[-_ ]?log[-_ ]?view|winxp[-_ ]?user[-_ ]?dump|user[-_ ]?dump",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-30",
            "NetPass",
            r"net[-_ ]?pass|network[-_ ]?password[-_ ]?recovery",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-31",
            "LiveContactsView",
            r"live[-_ ]?contacts[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-32",
            "WindowsMail / WinMailPass",
            r"windows[-_ ]?mail|win[-_ ]?mail[-_ ]?pass",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-33",
            "SilverlightCache / JavaCacheView",
            r"silverlight[-_ ]?cache|java[-_ ]?cache[-_ ]?view",
            None,
        ),
        legacy_rule("R4-LEGACY-34", "SiteShoter", r"site[-_ ]?shoter", None),
        legacy_rule(
            "R4-LEGACY-35",
            "HtmlDocEdit",
            r"html[-_ ]?doc[-_ ]?edit",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-36",
            "WebBrowserPassView",
            r"web[-_ ]?browser[-_ ]?pass[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-37",
            "SysTrayRefresh / TaskbarHide",
            r"sys[-_ ]?tray[-_ ]?refresh|taskbar[-_ ]?hide",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-38",
            "FastCache / IndexDatView",
            r"fast[-_ ]?cache|index[-_ ]?dat[-_ ]?view",
            None,
        ),
        legacy_rule(
            "R4-LEGACY-39",
            "SmartFTP/CuteFTP/FileZilla/WS_FTP/FlashFXP PassView",
            r"(?:smart[-_ ]?ftp|cute[-_ ]?ftp|filezilla|ws[-_ ]?ftp|flashfxp|ftp)[-_ ]?pass[-_ ]?view",
            None,
        ),
    ]
}

fn legacy_rule(
    rule_id: &'static str,
    tool_name: &'static str,
    inner_pattern: &'static str,
    binary_override: Option<&'static str>,
) -> RuleDef {
    RuleDef {
        rule_id,
        category: "legacy_tool",
        description: tool_name,
        kind: RuleKind::Standard,
        inner_pattern,
        binary_inner_pattern: Some(binary_override.unwrap_or(inner_pattern)),
        case_sensitive: false,
        allow_negation_in_comments: true,
        allow_negation_in_strings: true,
    }
}

impl RuleRegistry {
    pub fn compile() -> anyhow::Result<Self> {
        let defs = all_rule_defs();
        let mut rules = Vec::with_capacity(defs.len());
        let mut source_patterns = Vec::with_capacity(defs.len());
        let mut binary_patterns = Vec::new();
        let mut binary_unbounded_patterns = Vec::new();
        let mut binary_unbounded_regexes = Vec::new();
        let mut binary_rule_indices = Vec::new();

        for (idx, def) in defs.into_iter().enumerate() {
            let src_pat = wrap_boundary(def.inner_pattern, def.case_sensitive);
            let source_regex = Regex::new(&src_pat)?;
            source_patterns.push(src_pat);

            let binary_regex = if let Some(bin_inner) = def.binary_inner_pattern {
                let bin_pat = wrap_boundary(bin_inner, def.case_sensitive);
                let re = Regex::new(&bin_pat)?;
                binary_patterns.push(bin_pat);
                let flag = if def.case_sensitive { "" } else { "(?i)" };
                let ub_pat = format!("{flag}{bin_inner}");
                binary_unbounded_regexes.push(Regex::new(&ub_pat)?);
                binary_unbounded_patterns.push(ub_pat);
                binary_rule_indices.push(idx);
                Some(re)
            } else {
                None
            };

            rules.push(CompiledRule {
                def,
                source_regex,
                binary_regex,
            });
        }

        let km_ub_pat = r"(?i)key[-_ ]?material";
        binary_unbounded_regexes.push(Regex::new(km_ub_pat)?);
        binary_unbounded_patterns.push(km_ub_pat.to_string());

        let source_set = RegexSet::new(&source_patterns)?;
        let binary_set = RegexSet::new(&binary_patterns)?;
        let binary_unbounded_set = RegexSet::new(&binary_unbounded_patterns)?;

        let negation_regex = Regex::new(
            r"(?i)(?:\b(?:no|not|never|none|zero|without|exclude[ds]?|excluding|prohibit(?:ed|s)?|forbid(?:den)?|disallow(?:ed)?|ban(?:ned)?|omit(?:ted)?|skip(?:ped)?|instead\s+of|rather\s+than|replaces?|replaced|retired|obsolete|deprecated|r4)\b|\bnon-)",
        )?;
        let negated_assertion_regex = Regex::new(
            r"(?i)(?:assert!\s*\(\s*!|assert_eq!\s*\([^,]+,\s*false|!\s*[A-Za-z0-9_.:()]+\s*\.\s*contains\s*\(|assert\s+not\b|self\.assertFalse|self\.assertNotIn)",
        )?;
        let cargo_hook_dep_regex =
            Regex::new(r"(?i)^(?:detour|retour|minhook(?:-rs)?|ilhook|hudhook)$")?;
        let pek_context_regex = Regex::new(
            r"(?i)\b(?:SAM|LSA|SECURITY|BootKey|Boot_?Key|SysKey|Sys_?Key|RC4|pek_decrypt)\b",
        )?;
        let acm_audio_context_regex = Regex::new(
            r"(?i)(?:msacm|audio|codec|wave|installed_?codec|compression\s+manager|acmDriver|acmStream|acmFormat|acmMetrics)",
        )?;
        let acm_standalone_id_regex = Regex::new(
            r#"(?i)(?:#\[command\([^)]*(?:name|alias)\s*=\s*"acm"|Subcommand::Acm\b|"name"\s*:\s*"acm"|tool_id\s*[:=]\s*"acm"|command_id\s*[:=]\s*"acm"|\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+acm\b)"#,
        )?;
        let hook_dangerous_const_regex =
            Regex::new(r"(?i)\b(?:WH_CBT|WH_GETMESSAGE|WH_CALLWNDPROC|WH_CALLWNDPROCRET)\b")?;
        let hook_ll_const_regex = Regex::new(r"(?i)\b(?:WH_MOUSE_LL|WH_KEYBOARD_LL)\b")?;
        let hook_null_hinstance_regex = Regex::new(
            r"(?i)(?:^\s*(?:None(?:\s*::<\s*[^>]+\s*>)?|0(?:\s*as\s*_)?|(?:std::ptr::|core::ptr::)?null(?:_mut)?\s*\(\s*\)|H(?:INSTANCE|MODULE)\s*\(\s*(?:0|(?:std::ptr::|core::ptr::)?null(?:_mut)?\s*\(\s*\))\s*\)|GetModuleHandle[WA]?\s*\(\s*None\s*\))\s*$)",
        )?;
        let wpm_struct_regex = Regex::new(r"\b(?:LVITEMW|LVITEMA|TVITEMW|TVITEMA)\b")?;
        let wpm_exec_or_inj_regex = Regex::new(
            r"(?i)\b(?:PAGE_EXECUTE\w*|LoadLibrary[WA]?|CreateRemoteThread(?:Ex)?|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC|shellcode)\b",
        )?;
        let binary_keymaterial_camel_regex =
            Regex::new(&wrap_boundary(r"key[-_ ]?material", false))?;

        Ok(Self {
            rules,
            source_set,
            binary_set,
            binary_rule_indices,
            binary_unbounded_set,
            binary_unbounded_regexes,
            negation_regex,
            negated_assertion_regex,
            cargo_hook_dep_regex,
            pek_context_regex,
            acm_audio_context_regex,
            acm_standalone_id_regex,
            hook_dangerous_const_regex,
            hook_ll_const_regex,
            hook_null_hinstance_regex,
            wpm_struct_regex,
            wpm_exec_or_inj_regex,
            binary_keymaterial_camel_regex,
        })
    }

    pub fn is_negated_text(&self, text: &str) -> bool {
        self.negation_regex.is_match(text)
    }

    fn collect_raw_matches(re: &Regex, text: &str) -> Vec<(usize, usize, String)> {
        let mut results = Vec::new();
        let mut offset = 0usize;
        while offset <= text.len() {
            let Some(caps) = re.captures_at(text, offset) else {
                break;
            };
            if let Some(m) = caps.get(1) {
                results.push((m.start(), m.end(), m.as_str().to_string()));
                offset = m.end().max(offset + 1);
            } else {
                break;
            }
        }
        results
    }

    pub fn find_all_matches(&self, rule_idx: usize, text: &str) -> Vec<(usize, usize, String)> {
        let rule = &self.rules[rule_idx];
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for (s, e, matched) in Self::collect_raw_matches(&rule.source_regex, text) {
            if !should_skip_benign_match(rule.def.rule_id, text, s, e, &matched)
                && seen.insert((s, e))
            {
                results.push((s, e, matched));
            }
        }

        if has_camel_boundary(text) || has_trailing_digit_boundary(text) {
            let (split_text, orig_map) = split_camel_and_trailing_digits_with_map(text);
            if rule.source_regex.is_match(&split_text) {
                for (s, e, _) in Self::collect_raw_matches(&rule.source_regex, &split_text) {
                    let orig_s = orig_map[s];
                    let orig_e = orig_map[e];
                    if orig_s < orig_e
                        && text.is_char_boundary(orig_s)
                        && text.is_char_boundary(orig_e)
                    {
                        let orig_matched = text[orig_s..orig_e].to_string();
                        if !should_skip_benign_match(
                            rule.def.rule_id,
                            text,
                            orig_s,
                            orig_e,
                            &orig_matched,
                        ) && seen.insert((orig_s, orig_e))
                        {
                            results.push((orig_s, orig_e, orig_matched));
                        }
                    }
                }
            }
        }

        if text.contains("_R") || text.contains("_Z") {
            let (mangled_buf, seg_map) = build_mangled_segments_buf(text);
            if !mangled_buf.is_empty() && rule.source_regex.is_match(&mangled_buf) {
                for (s, e, _) in Self::collect_raw_matches(&rule.source_regex, &mangled_buf) {
                    if let Some((orig_s, orig_e)) = map_mangled_match(&seg_map, s, e) {
                        let orig_matched = text[orig_s..orig_e].to_string();
                        if !should_skip_benign_match(
                            rule.def.rule_id,
                            text,
                            orig_s,
                            orig_e,
                            &orig_matched,
                        ) && seen.insert((orig_s, orig_e))
                        {
                            results.push((orig_s, orig_e, orig_matched));
                        }
                    }
                }
            }
            if !mangled_buf.is_empty()
                && (has_camel_boundary(&mangled_buf) || has_trailing_digit_boundary(&mangled_buf))
            {
                let (it_split, it_map) = split_camel_and_trailing_digits_with_map(&mangled_buf);
                if rule.source_regex.is_match(&it_split) {
                    for (s, e, _) in Self::collect_raw_matches(&rule.source_regex, &it_split) {
                        let bs = it_map[s];
                        let be = it_map[e];
                        if bs < be
                            && let Some((orig_s, orig_e)) = map_mangled_match(&seg_map, bs, be)
                        {
                            let orig_matched = text[orig_s..orig_e].to_string();
                            if !should_skip_benign_match(
                                rule.def.rule_id,
                                text,
                                orig_s,
                                orig_e,
                                &orig_matched,
                            ) && seen.insert((orig_s, orig_e))
                            {
                                results.push((orig_s, orig_e, orig_matched));
                            }
                        }
                    }
                }
            }
        }

        results.sort_by_key(|(s, e, _)| (*s, *e));
        results
    }

    pub fn scan_all_source_matches(&self, text: &str) -> Vec<(usize, usize, usize, String)> {
        let mut rule_indices: Vec<usize> = self.source_set.matches(text).into_iter().collect();
        let camel_split = if has_camel_boundary(text) || has_trailing_digit_boundary(text) {
            let (split_text, orig_map) = split_camel_and_trailing_digits_with_map(text);
            for idx in self.source_set.matches(&split_text) {
                if !rule_indices.contains(&idx) {
                    rule_indices.push(idx);
                }
            }
            Some((split_text, orig_map))
        } else {
            None
        };
        let mangled_data = if text.contains("_R") || text.contains("_Z") {
            let (mangled_buf, seg_map) = build_mangled_segments_buf(text);
            if !mangled_buf.is_empty() {
                for idx in self.source_set.matches(&mangled_buf) {
                    if !rule_indices.contains(&idx) {
                        rule_indices.push(idx);
                    }
                }
                let it_split = if has_camel_boundary(&mangled_buf)
                    || has_trailing_digit_boundary(&mangled_buf)
                {
                    let (s, m) = split_camel_and_trailing_digits_with_map(&mangled_buf);
                    for idx in self.source_set.matches(&s) {
                        if !rule_indices.contains(&idx) {
                            rule_indices.push(idx);
                        }
                    }
                    Some((s, m))
                } else {
                    None
                };
                Some((mangled_buf, seg_map, it_split))
            } else {
                None
            }
        } else {
            None
        };
        rule_indices.sort_unstable();

        let mut out = Vec::new();
        for rule_idx in rule_indices {
            let rule = &self.rules[rule_idx];
            let mut seen = std::collections::HashSet::new();
            for (s, e, matched) in Self::collect_raw_matches(&rule.source_regex, text) {
                if !should_skip_benign_match(rule.def.rule_id, text, s, e, &matched)
                    && seen.insert((s, e))
                {
                    out.push((rule_idx, s, e, matched));
                }
            }
            if let Some((ref split_text, ref orig_map)) = camel_split
                && rule.source_regex.is_match(split_text)
            {
                for (s, e, _) in Self::collect_raw_matches(&rule.source_regex, split_text) {
                    let orig_s = orig_map[s];
                    let orig_e = orig_map[e];
                    if orig_s < orig_e
                        && text.is_char_boundary(orig_s)
                        && text.is_char_boundary(orig_e)
                    {
                        let orig_matched = text[orig_s..orig_e].to_string();
                        if !should_skip_benign_match(
                            rule.def.rule_id,
                            text,
                            orig_s,
                            orig_e,
                            &orig_matched,
                        ) && seen.insert((orig_s, orig_e))
                        {
                            out.push((rule_idx, orig_s, orig_e, orig_matched));
                        }
                    }
                }
            }
            if let Some((ref mangled_buf, ref seg_map, ref it_split)) = mangled_data {
                if rule.source_regex.is_match(mangled_buf) {
                    for (s, e, _) in Self::collect_raw_matches(&rule.source_regex, mangled_buf) {
                        if let Some((orig_s, orig_e)) = map_mangled_match(seg_map, s, e) {
                            let orig_matched = text[orig_s..orig_e].to_string();
                            if !should_skip_benign_match(
                                rule.def.rule_id,
                                text,
                                orig_s,
                                orig_e,
                                &orig_matched,
                            ) && seen.insert((orig_s, orig_e))
                            {
                                out.push((rule_idx, orig_s, orig_e, orig_matched));
                            }
                        }
                    }
                }
                if let Some((ref it_split_text, ref it_map)) = *it_split
                    && rule.source_regex.is_match(it_split_text)
                {
                    for (s, e, _) in Self::collect_raw_matches(&rule.source_regex, it_split_text) {
                        let bs = it_map[s];
                        let be = it_map[e];
                        if bs < be
                            && let Some((orig_s, orig_e)) = map_mangled_match(seg_map, bs, be)
                        {
                            let orig_matched = text[orig_s..orig_e].to_string();
                            if !should_skip_benign_match(
                                rule.def.rule_id,
                                text,
                                orig_s,
                                orig_e,
                                &orig_matched,
                            ) && seen.insert((orig_s, orig_e))
                            {
                                out.push((rule_idx, orig_s, orig_e, orig_matched));
                            }
                        }
                    }
                }
            }
        }
        out
    }

    pub fn find_all_binary_matches(&self, rule_idx: usize, text: &str) -> Vec<String> {
        let rule = &self.rules[rule_idx];
        let Some(re) = &rule.binary_regex else {
            return Vec::new();
        };
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (s, e, matched) in Self::collect_raw_matches(re, text) {
            if !should_skip_benign_match(rule.def.rule_id, text, s, e, &matched)
                && seen.insert((s, e))
            {
                results.push(matched);
            }
        }
        if has_camel_or_mangled_boundary(text) {
            let mut process_split = |split_text: &str, orig_map: &[usize]| {
                if re.is_match(split_text) {
                    for (s, e, _) in Self::collect_raw_matches(re, split_text) {
                        let orig_s = orig_map[s];
                        let orig_e = orig_map[e];
                        if orig_s < orig_e
                            && text.is_char_boundary(orig_s)
                            && text.is_char_boundary(orig_e)
                        {
                            let orig_matched = text[orig_s..orig_e].to_string();
                            if !should_skip_benign_match(
                                rule.def.rule_id,
                                text,
                                orig_s,
                                orig_e,
                                &orig_matched,
                            ) && seen.insert((orig_s, orig_e))
                            {
                                results.push(orig_matched);
                            }
                        }
                    }
                }
                if rule.def.rule_id == "R4-API-CRED-05"
                    && self.binary_keymaterial_camel_regex.is_match(split_text)
                {
                    for (s, e, _) in
                        Self::collect_raw_matches(&self.binary_keymaterial_camel_regex, split_text)
                    {
                        let orig_s = orig_map[s];
                        let orig_e = orig_map[e];
                        if orig_s < orig_e
                            && text.is_char_boundary(orig_s)
                            && text.is_char_boundary(orig_e)
                        {
                            let orig_matched = &text[orig_s..orig_e];
                            if !orig_matched.chars().any(char::is_whitespace)
                                && !should_skip_benign_match(
                                    rule.def.rule_id,
                                    text,
                                    orig_s,
                                    orig_e,
                                    orig_matched,
                                )
                                && seen.insert((orig_s, orig_e))
                            {
                                results.push(orig_matched.to_string());
                            }
                        }
                    }
                }
            };

            let (split_text, orig_map) = split_camel_and_hash_with_map(text);
            process_split(&split_text, &orig_map);

            if has_digit_upper_boundary(text) {
                let (du_split, du_map) = split_binary_boundaries_with_map(text);
                process_split(&du_split, &du_map);
            }

            if text.contains("_R") || text.contains("_Z") {
                let (mangled_buf, seg_map) = build_mangled_segments_buf(text);
                if !mangled_buf.is_empty() && re.is_match(&mangled_buf) {
                    for (s, e, _) in Self::collect_raw_matches(re, &mangled_buf) {
                        if let Some((orig_s, orig_e)) = map_mangled_match(&seg_map, s, e) {
                            let orig_matched = text[orig_s..orig_e].to_string();
                            if !should_skip_benign_match(
                                rule.def.rule_id,
                                text,
                                orig_s,
                                orig_e,
                                &orig_matched,
                            ) && seen.insert((orig_s, orig_e))
                            {
                                results.push(orig_matched);
                            }
                        }
                    }
                }
                if !mangled_buf.is_empty()
                    && (has_camel_boundary(&mangled_buf)
                        || has_trailing_digit_boundary(&mangled_buf))
                {
                    let (it_split, it_map) = split_camel_and_trailing_digits_with_map(&mangled_buf);
                    if re.is_match(&it_split) {
                        for (s, e, _) in Self::collect_raw_matches(re, &it_split) {
                            let bs = it_map[s];
                            let be = it_map[e];
                            if bs < be
                                && let Some((orig_s, orig_e)) = map_mangled_match(&seg_map, bs, be)
                            {
                                let orig_matched = text[orig_s..orig_e].to_string();
                                if !should_skip_benign_match(
                                    rule.def.rule_id,
                                    text,
                                    orig_s,
                                    orig_e,
                                    &orig_matched,
                                ) && seen.insert((orig_s, orig_e))
                                {
                                    results.push(orig_matched);
                                }
                            }
                        }
                    }
                    if rule.def.rule_id == "R4-API-CRED-05"
                        && self.binary_keymaterial_camel_regex.is_match(&it_split)
                    {
                        for (s, e, _) in Self::collect_raw_matches(
                            &self.binary_keymaterial_camel_regex,
                            &it_split,
                        ) {
                            let bs = it_map[s];
                            let be = it_map[e];
                            if bs < be
                                && let Some((orig_s, orig_e)) = map_mangled_match(&seg_map, bs, be)
                            {
                                let orig_matched = &text[orig_s..orig_e];
                                if !orig_matched.chars().any(char::is_whitespace)
                                    && !should_skip_benign_match(
                                        rule.def.rule_id,
                                        text,
                                        orig_s,
                                        orig_e,
                                        orig_matched,
                                    )
                                    && seen.insert((orig_s, orig_e))
                                {
                                    results.push(orig_matched.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        results
    }
    pub fn scan_all_binary_matches(&self, text: &str) -> Vec<(usize, String)> {
        let ub_matches = self.binary_unbounded_set.matches(text);
        if !ub_matches.matched_any() {
            return Vec::new();
        }

        let bytes = text.as_bytes();
        let mut candidate_lines: std::collections::BTreeSet<(usize, usize)> =
            std::collections::BTreeSet::new();

        for ub_idx in ub_matches.iter() {
            let re = &self.binary_unbounded_regexes[ub_idx];
            for m in re.find_iter(text) {
                let mut ls = m.start();
                while ls > 0 && bytes[ls - 1] != b'\n' {
                    ls -= 1;
                }
                let mut le = m.end();
                while le < bytes.len() && bytes[le] != b'\n' {
                    le += 1;
                }
                if le > ls && bytes[le - 1] == b'\r' {
                    le -= 1;
                }
                if ls < le {
                    candidate_lines.insert((ls, le));
                }
            }
        }

        let mut out = Vec::new();
        for (ls, le) in candidate_lines {
            self.scan_binary_line_into(&text[ls..le], &mut out);
        }
        out
    }

    fn scan_binary_line_into(&self, text: &str, out: &mut Vec<(usize, String)>) {
        let mut rule_indices: Vec<usize> = self
            .binary_set
            .matches(text)
            .into_iter()
            .map(|bin_idx| self.binary_rule_indices[bin_idx])
            .collect();

        let mut need_km_rule = false;

        let split_data = if has_camel_or_mangled_boundary(text) {
            let (split_text, orig_map) = split_camel_and_hash_with_map(text);
            for bin_idx in self.binary_set.matches(&split_text) {
                let r_idx = self.binary_rule_indices[bin_idx];
                if !rule_indices.contains(&r_idx) {
                    rule_indices.push(r_idx);
                }
            }
            if self.binary_keymaterial_camel_regex.is_match(&split_text) {
                need_km_rule = true;
            }

            let digit_upper_data = if has_digit_upper_boundary(text) {
                let (du_text, du_map) = split_binary_boundaries_with_map(text);
                for bin_idx in self.binary_set.matches(&du_text) {
                    let r_idx = self.binary_rule_indices[bin_idx];
                    if !rule_indices.contains(&r_idx) {
                        rule_indices.push(r_idx);
                    }
                }
                if self.binary_keymaterial_camel_regex.is_match(&du_text) {
                    need_km_rule = true;
                }
                Some((du_text, du_map))
            } else {
                None
            };

            let mangled_data = if text.contains("_R") || text.contains("_Z") {
                let (mangled_buf, seg_map) = build_mangled_segments_buf(text);
                if !mangled_buf.is_empty() {
                    for bin_idx in self.binary_set.matches(&mangled_buf) {
                        let r_idx = self.binary_rule_indices[bin_idx];
                        if !rule_indices.contains(&r_idx) {
                            rule_indices.push(r_idx);
                        }
                    }
                    let it_split = if has_camel_boundary(&mangled_buf)
                        || has_trailing_digit_boundary(&mangled_buf)
                    {
                        let (s, m) = split_camel_and_trailing_digits_with_map(&mangled_buf);
                        for bin_idx in self.binary_set.matches(&s) {
                            let r_idx = self.binary_rule_indices[bin_idx];
                            if !rule_indices.contains(&r_idx) {
                                rule_indices.push(r_idx);
                            }
                        }
                        if self.binary_keymaterial_camel_regex.is_match(&s) {
                            need_km_rule = true;
                        }
                        Some((s, m))
                    } else {
                        None
                    };
                    Some((mangled_buf, seg_map, it_split))
                } else {
                    None
                }
            } else {
                None
            };
            Some((split_text, orig_map, digit_upper_data, mangled_data))
        } else {
            None
        };

        if need_km_rule
            && let Some(km_idx) = self
                .rules
                .iter()
                .position(|r| r.def.rule_id == "R4-API-CRED-05")
            && !rule_indices.contains(&km_idx)
        {
            rule_indices.push(km_idx);
        }
        rule_indices.sort_unstable();
        for rule_idx in rule_indices {
            let rule = &self.rules[rule_idx];
            let Some(re) = &rule.binary_regex else {
                continue;
            };
            let mut seen = std::collections::HashSet::new();
            for (s, e, matched) in Self::collect_raw_matches(re, text) {
                if !should_skip_benign_match(rule.def.rule_id, text, s, e, &matched)
                    && seen.insert((s, e))
                {
                    out.push((rule_idx, matched));
                }
            }
            if let Some((ref split_text, ref orig_map, ref digit_upper_data, ref mangled_data)) =
                split_data
            {
                let mut collect_split = |sp_txt: &str, sp_map: &[usize]| {
                    if re.is_match(sp_txt) {
                        for (s, e, _) in Self::collect_raw_matches(re, sp_txt) {
                            let orig_s = sp_map[s];
                            let orig_e = sp_map[e];
                            if orig_s < orig_e
                                && text.is_char_boundary(orig_s)
                                && text.is_char_boundary(orig_e)
                            {
                                let orig_matched = text[orig_s..orig_e].to_string();
                                if !should_skip_benign_match(
                                    rule.def.rule_id,
                                    text,
                                    orig_s,
                                    orig_e,
                                    &orig_matched,
                                ) && seen.insert((orig_s, orig_e))
                                {
                                    out.push((rule_idx, orig_matched));
                                }
                            }
                        }
                    }
                    if rule.def.rule_id == "R4-API-CRED-05"
                        && self.binary_keymaterial_camel_regex.is_match(sp_txt)
                    {
                        for (s, e, _) in
                            Self::collect_raw_matches(&self.binary_keymaterial_camel_regex, sp_txt)
                        {
                            let orig_s = sp_map[s];
                            let orig_e = sp_map[e];
                            if orig_s < orig_e
                                && text.is_char_boundary(orig_s)
                                && text.is_char_boundary(orig_e)
                            {
                                let orig_matched = &text[orig_s..orig_e];
                                if !orig_matched.chars().any(char::is_whitespace)
                                    && !should_skip_benign_match(
                                        rule.def.rule_id,
                                        text,
                                        orig_s,
                                        orig_e,
                                        orig_matched,
                                    )
                                    && seen.insert((orig_s, orig_e))
                                {
                                    out.push((rule_idx, orig_matched.to_string()));
                                }
                            }
                        }
                    }
                };

                collect_split(split_text, orig_map);
                if let Some((ref du_text, ref du_map)) = *digit_upper_data {
                    collect_split(du_text, du_map);
                }

                if let Some((ref mangled_buf, ref seg_map, ref it_split)) = *mangled_data {
                    if re.is_match(mangled_buf) {
                        for (s, e, _) in Self::collect_raw_matches(re, mangled_buf) {
                            if let Some((orig_s, orig_e)) = map_mangled_match(seg_map, s, e) {
                                let orig_matched = text[orig_s..orig_e].to_string();
                                if !should_skip_benign_match(
                                    rule.def.rule_id,
                                    text,
                                    orig_s,
                                    orig_e,
                                    &orig_matched,
                                ) && seen.insert((orig_s, orig_e))
                                {
                                    out.push((rule_idx, orig_matched));
                                }
                            }
                        }
                    }
                    if let Some((ref it_split_text, ref it_map)) = *it_split {
                        if re.is_match(it_split_text) {
                            for (s, e, _) in Self::collect_raw_matches(re, it_split_text) {
                                let bs = it_map[s];
                                let be = it_map[e];
                                if bs < be
                                    && let Some((orig_s, orig_e)) =
                                        map_mangled_match(seg_map, bs, be)
                                {
                                    let orig_matched = text[orig_s..orig_e].to_string();
                                    if !should_skip_benign_match(
                                        rule.def.rule_id,
                                        text,
                                        orig_s,
                                        orig_e,
                                        &orig_matched,
                                    ) && seen.insert((orig_s, orig_e))
                                    {
                                        out.push((rule_idx, orig_matched));
                                    }
                                }
                            }
                        }
                        if rule.def.rule_id == "R4-API-CRED-05"
                            && self.binary_keymaterial_camel_regex.is_match(it_split_text)
                        {
                            for (s, e, _) in Self::collect_raw_matches(
                                &self.binary_keymaterial_camel_regex,
                                it_split_text,
                            ) {
                                let bs = it_map[s];
                                let be = it_map[e];
                                if bs < be
                                    && let Some((orig_s, orig_e)) =
                                        map_mangled_match(seg_map, bs, be)
                                {
                                    let orig_matched = &text[orig_s..orig_e];
                                    if !orig_matched.chars().any(char::is_whitespace)
                                        && !should_skip_benign_match(
                                            rule.def.rule_id,
                                            text,
                                            orig_s,
                                            orig_e,
                                            orig_matched,
                                        )
                                        && seen.insert((orig_s, orig_e))
                                    {
                                        out.push((rule_idx, orig_matched.to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
fn has_digit_upper_boundary(text: &str) -> bool {
    let b = text.as_bytes();
    for i in 1..b.len() {
        if b[i - 1].is_ascii_digit() && b[i].is_ascii_uppercase() {
            return true;
        }
    }
    false
}

fn is_trailing_digit_run(bytes: &[u8], digit_start: usize) -> bool {
    if digit_start == 0
        || digit_start >= bytes.len()
        || !bytes[digit_start - 1].is_ascii_alphabetic()
        || !bytes[digit_start].is_ascii_digit()
    {
        return false;
    }
    let mut j = digit_start;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
    }
    if j == bytes.len() || !bytes[j].is_ascii_alphanumeric() {
        return true;
    }
    let mut k = j;
    while k < bytes.len() && bytes[k].is_ascii_lowercase() && k - j < 3 {
        k += 1;
    }
    (1..=2).contains(&(k - j)) && (k == bytes.len() || !bytes[k].is_ascii_alphanumeric())
}

fn has_trailing_digit_boundary(text: &str) -> bool {
    let b = text.as_bytes();
    (1..b.len()).any(|i| is_trailing_digit_run(b, i))
}

fn has_camel_or_mangled_boundary(text: &str) -> bool {
    has_camel_boundary(text)
        || has_digit_upper_boundary(text)
        || has_trailing_digit_boundary(text)
        || text.contains("_R")
        || text.contains("_Z")
}

fn is_rust_legacy_hash_suffix(bytes: &[u8], digit_start: usize) -> bool {
    let mut j = digit_start;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
    }
    if j == digit_start || j >= bytes.len() || bytes[j] != b'h' {
        return false;
    }
    let hex_start = j + 1;
    let mut k = hex_start;
    while k < bytes.len() && bytes[k].is_ascii_hexdigit() {
        k += 1;
    }
    k >= hex_start + 4
        && (k == bytes.len() || bytes[k] == b'E' || !bytes[k].is_ascii_alphanumeric())
}

fn push_mangled_seg(
    text: &str,
    pos: usize,
    seg_len: usize,
    buf: &mut String,
    seg_map: &mut Vec<(usize, usize, usize)>,
) -> bool {
    if seg_len == 0 || pos + seg_len > text.len() {
        return false;
    }
    if !text.is_char_boundary(pos) || !text.is_char_boundary(pos + seg_len) {
        return false;
    }
    let seg = &text[pos..pos + seg_len];
    if seg.bytes().any(|b| b.is_ascii_whitespace()) {
        return false;
    }
    let buf_s = buf.len();
    buf.push_str(seg);
    let buf_e = buf.len();
    buf.push('\n');
    seg_map.push((buf_s, buf_e, pos));
    true
}

fn skip_base62_term(bytes: &[u8], pos: &mut usize) -> bool {
    let start = *pos;
    while *pos < bytes.len() && bytes[*pos].is_ascii_alphanumeric() {
        *pos += 1;
    }
    if *pos < bytes.len() && bytes[*pos] == b'_' {
        *pos += 1;
        true
    } else {
        *pos = start;
        false
    }
}

fn parse_v0_ident(
    text: &str,
    bytes: &[u8],
    pos: &mut usize,
    buf: &mut String,
    seg_map: &mut Vec<(usize, usize, usize)>,
) -> bool {
    if *pos < bytes.len() && bytes[*pos] == b's' {
        *pos += 1;
        if !skip_base62_term(bytes, pos) {
            return false;
        }
    }
    if *pos + 1 < bytes.len() && bytes[*pos] == b'u' && bytes[*pos + 1].is_ascii_digit() {
        *pos += 1;
    }
    if *pos >= bytes.len() || !bytes[*pos].is_ascii_digit() {
        return false;
    }
    let len_start = *pos;
    let mut seg_len = 0usize;
    while *pos < bytes.len() && bytes[*pos].is_ascii_digit() {
        seg_len = seg_len
            .saturating_mul(10)
            .saturating_add((bytes[*pos] - b'0') as usize);
        *pos += 1;
    }
    if *pos == len_start {
        return false;
    }
    if seg_len == 0 {
        return true;
    }
    if seg_len > bytes.len() - *pos {
        return false;
    }
    if bytes.get(*pos) == Some(&b'_') {
        *pos += 1;
        if seg_len > bytes.len() - *pos {
            return false;
        }
    }
    if !push_mangled_seg(text, *pos, seg_len, buf, seg_map) {
        return false;
    }
    *pos += seg_len;
    true
}

fn parse_v0_impl_path(
    text: &str,
    bytes: &[u8],
    pos: &mut usize,
    buf: &mut String,
    seg_map: &mut Vec<(usize, usize, usize)>,
    depth: usize,
) -> bool {
    if *pos < bytes.len() && bytes[*pos] == b's' {
        *pos += 1;
        if !skip_base62_term(bytes, pos) {
            return false;
        }
    }
    parse_v0_path(text, bytes, pos, buf, seg_map, depth + 1)
}

fn parse_v0_path(
    text: &str,
    bytes: &[u8],
    pos: &mut usize,
    buf: &mut String,
    seg_map: &mut Vec<(usize, usize, usize)>,
    depth: usize,
) -> bool {
    if depth > 64 || *pos >= bytes.len() {
        return false;
    }
    let tag = bytes[*pos];
    match tag {
        b'C' => {
            *pos += 1;
            parse_v0_ident(text, bytes, pos, buf, seg_map)
        }
        b'M' => {
            *pos += 1;
            parse_v0_impl_path(text, bytes, pos, buf, seg_map, depth + 1)
                && parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1)
        }
        b'X' => {
            *pos += 1;
            parse_v0_impl_path(text, bytes, pos, buf, seg_map, depth + 1)
                && parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1)
                && parse_v0_path(text, bytes, pos, buf, seg_map, depth + 1)
        }
        b'Y' => {
            *pos += 1;
            parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1)
                && parse_v0_path(text, bytes, pos, buf, seg_map, depth + 1)
        }
        b'N' => {
            *pos += 1;
            if *pos >= bytes.len() || !bytes[*pos].is_ascii_alphabetic() {
                return false;
            }
            *pos += 1;
            parse_v0_path(text, bytes, pos, buf, seg_map, depth + 1)
                && parse_v0_ident(text, bytes, pos, buf, seg_map)
        }
        b'I' => {
            *pos += 1;
            if !parse_v0_path(text, bytes, pos, buf, seg_map, depth + 1) {
                return false;
            }
            while *pos < bytes.len() && bytes[*pos] != b'E' && !bytes[*pos].is_ascii_whitespace() {
                let prev = *pos;
                if !parse_v0_generic_arg(text, bytes, pos, buf, seg_map, depth + 1) || *pos == prev
                {
                    return false;
                }
            }
            if bytes.get(*pos) == Some(&b'E') {
                *pos += 1;
            }
            true
        }
        b'B' => {
            *pos += 1;
            skip_base62_term(bytes, pos)
        }
        b'0'..=b'9' => parse_v0_ident(text, bytes, pos, buf, seg_map),
        _ => false,
    }
}

fn parse_v0_generic_arg(
    text: &str,
    bytes: &[u8],
    pos: &mut usize,
    buf: &mut String,
    seg_map: &mut Vec<(usize, usize, usize)>,
    depth: usize,
) -> bool {
    if depth > 64 || *pos >= bytes.len() {
        return false;
    }
    match bytes[*pos] {
        b'L' => {
            *pos += 1;
            skip_base62_term(bytes, pos)
        }
        b'K' => {
            *pos += 1;
            parse_v0_const(bytes, pos, depth + 1)
        }
        _ => parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1),
    }
}

fn parse_v0_const(bytes: &[u8], pos: &mut usize, depth: usize) -> bool {
    if depth > 64 || *pos >= bytes.len() {
        return false;
    }
    if bytes[*pos] == b'B' {
        *pos += 1;
        return skip_base62_term(bytes, pos);
    }
    let tag = bytes[*pos];
    *pos += 1;
    if tag == b'p' {
        return true;
    }
    if bytes.get(*pos) == Some(&b'n') {
        *pos += 1;
    }
    while *pos < bytes.len() && bytes[*pos].is_ascii_hexdigit() {
        *pos += 1;
    }
    if bytes.get(*pos) == Some(&b'_') {
        *pos += 1;
        true
    } else {
        false
    }
}

fn parse_v0_type(
    text: &str,
    bytes: &[u8],
    pos: &mut usize,
    buf: &mut String,
    seg_map: &mut Vec<(usize, usize, usize)>,
    depth: usize,
) -> bool {
    if depth > 64 || *pos >= bytes.len() {
        return false;
    }
    match bytes[*pos] {
        b'a'..=b'z' => {
            *pos += 1;
            true
        }
        b'A' => {
            *pos += 1;
            parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1)
                && parse_v0_const(bytes, pos, depth + 1)
        }
        b'S' | b'P' | b'O' => {
            *pos += 1;
            parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1)
        }
        b'R' | b'Q' => {
            *pos += 1;
            if bytes.get(*pos) == Some(&b'L') {
                *pos += 1;
                if !skip_base62_term(bytes, pos) {
                    return false;
                }
            }
            parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1)
        }
        b'T' => {
            *pos += 1;
            while *pos < bytes.len() && bytes[*pos] != b'E' && !bytes[*pos].is_ascii_whitespace() {
                let prev = *pos;
                if !parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1) || *pos == prev {
                    return false;
                }
            }
            if bytes.get(*pos) == Some(&b'E') {
                *pos += 1;
            }
            true
        }
        b'F' => {
            *pos += 1;
            if bytes.get(*pos) == Some(&b'G') {
                *pos += 1;
                if !skip_base62_term(bytes, pos) {
                    return false;
                }
            }
            if bytes.get(*pos) == Some(&b'U') {
                *pos += 1;
            }
            if bytes.get(*pos) == Some(&b'K') {
                *pos += 1;
                if bytes.get(*pos) == Some(&b'C') {
                    *pos += 1;
                } else if !parse_v0_ident(text, bytes, pos, buf, seg_map) {
                    return false;
                }
            }
            while *pos < bytes.len() && bytes[*pos] != b'E' && !bytes[*pos].is_ascii_whitespace() {
                let prev = *pos;
                if !parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1) || *pos == prev {
                    return false;
                }
            }
            if bytes.get(*pos) == Some(&b'E') {
                *pos += 1;
            }
            parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1)
        }
        b'D' => {
            *pos += 1;
            if bytes.get(*pos) == Some(&b'G') {
                *pos += 1;
                if !skip_base62_term(bytes, pos) {
                    return false;
                }
            }
            while *pos < bytes.len() && bytes[*pos] != b'E' && !bytes[*pos].is_ascii_whitespace() {
                let prev = *pos;
                if !parse_v0_path(text, bytes, pos, buf, seg_map, depth + 1) {
                    return false;
                }
                while *pos < bytes.len() && bytes[*pos] == b'p' {
                    *pos += 1;
                    if !parse_v0_ident(text, bytes, pos, buf, seg_map)
                        || !parse_v0_type(text, bytes, pos, buf, seg_map, depth + 1)
                    {
                        return false;
                    }
                }
                if *pos == prev {
                    return false;
                }
            }
            if bytes.get(*pos) == Some(&b'E') {
                *pos += 1;
            }
            if bytes.get(*pos) == Some(&b'L') {
                *pos += 1;
                let _ = skip_base62_term(bytes, pos);
            }
            true
        }
        b'B' => {
            *pos += 1;
            skip_base62_term(bytes, pos)
        }
        b'C' | b'M' | b'X' | b'Y' | b'N' | b'I' => {
            parse_v0_path(text, bytes, pos, buf, seg_map, depth + 1)
        }
        _ => false,
    }
}

fn extract_v0_segments(
    text: &str,
    bytes: &[u8],
    start: usize,
    buf: &mut String,
    seg_map: &mut Vec<(usize, usize, usize)>,
) -> usize {
    let mut pos = start + 2;
    let mut digits = pos;
    while digits < bytes.len() && bytes[digits].is_ascii_digit() {
        digits += 1;
    }
    if digits > pos
        && digits < bytes.len()
        && matches!(
            bytes[digits],
            b'C' | b'M' | b'X' | b'Y' | b'N' | b'I' | b'B'
        )
    {
        pos = digits;
    }
    let _ = parse_v0_path(text, bytes, &mut pos, buf, seg_map, 0);
    pos.max(start + 2)
}

fn extract_itanium_segments(
    text: &str,
    bytes: &[u8],
    start: usize,
    buf: &mut String,
    seg_map: &mut Vec<(usize, usize, usize)>,
) -> usize {
    let mut pos = start + 2;
    if pos >= bytes.len() {
        return pos;
    }

    let mut parse_len_seg = |p: &mut usize| -> bool {
        if *p >= bytes.len() || !bytes[*p].is_ascii_digit() {
            return false;
        }
        let len_start = *p;
        let mut seg_len = 0usize;
        while *p < bytes.len() && bytes[*p].is_ascii_digit() {
            seg_len = seg_len
                .saturating_mul(10)
                .saturating_add((bytes[*p] - b'0') as usize);
            *p += 1;
        }
        if *p == len_start || seg_len == 0 || seg_len > bytes.len() - *p {
            return false;
        }
        if !push_mangled_seg(text, *p, seg_len, buf, seg_map) {
            return false;
        }
        *p += seg_len;
        true
    };

    if matches!(bytes[pos], b'1'..=b'9') {
        if !parse_len_seg(&mut pos) {
            return start + 2;
        }
        if bytes.get(pos) != Some(&b'I') {
            return pos;
        }
    }

    if !matches!(
        bytes[pos],
        b'N' | b'L' | b'Z' | b'T' | b'I' | b'S' | b'U' | b'F'
    ) {
        return pos.max(start + 2);
    }

    let mut nest_depth = 0usize;
    let mut local_scopes = 0usize;
    while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
        match bytes[pos] {
            b'T' => {
                pos += 1;
                if matches!(bytes.get(pos), Some(b'V' | b'I' | b'S' | b'C' | b'D')) {
                    pos += 1;
                }
            }
            b'Z' => {
                local_scopes += 1;
                pos += 1;
            }
            b'L' | b'K' | b'V' | b'r' | b'R' | b'O' | b'P' | b'M' | b'_' => {
                pos += 1;
            }
            b'A' => {
                pos += 1;
                let mut d = pos;
                while d < bytes.len() && bytes[d].is_ascii_digit() {
                    d += 1;
                }
                if d < bytes.len() && bytes[d] == b'_' {
                    pos = d + 1;
                }
            }
            b'B' => {
                pos += 1;
                if bytes.get(pos).is_some_and(|b| matches!(b, b'1'..=b'9')) {
                    let mut seg_len = 0usize;
                    let mut d = pos;
                    while d < bytes.len() && bytes[d].is_ascii_digit() {
                        seg_len = seg_len
                            .saturating_mul(10)
                            .saturating_add((bytes[d] - b'0') as usize);
                        d += 1;
                    }
                    if seg_len > 0 && seg_len <= bytes.len() - d {
                        pos = d + seg_len;
                    }
                }
            }
            b'U' => {
                if bytes.get(pos + 1) == Some(&b'l') {
                    nest_depth += 1;
                    pos += 2;
                } else if bytes.get(pos + 1) == Some(&b't') {
                    pos += 2;
                    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                        pos += 1;
                    }
                    if bytes.get(pos) == Some(&b'_') {
                        pos += 1;
                    }
                } else {
                    pos += 1;
                }
            }
            b'N' | b'I' | b'F' | b'J' => {
                nest_depth += 1;
                pos += 1;
            }
            b'E' => {
                pos += 1;
                if nest_depth > 0 {
                    nest_depth -= 1;
                    if nest_depth == 0 && local_scopes == 0 {
                        break;
                    }
                } else if local_scopes > 0 {
                    local_scopes -= 1;
                } else {
                    break;
                }
            }
            b'1'..=b'9' => {
                if !parse_len_seg(&mut pos) {
                    break;
                }
            }
            b'S' => {
                pos += 1;
                if bytes.get(pos) == Some(&b'_') {
                    pos += 1;
                } else if bytes
                    .get(pos)
                    .is_some_and(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
                {
                    while pos < bytes.len()
                        && (bytes[pos].is_ascii_digit() || bytes[pos].is_ascii_uppercase())
                    {
                        pos += 1;
                    }
                    if bytes.get(pos) == Some(&b'_') {
                        pos += 1;
                    }
                } else if pos < bytes.len() {
                    pos += 1;
                }
            }
            b'C' if matches!(bytes.get(pos + 1), Some(b'0'..=b'9')) => {
                pos += 2;
            }
            b'D' => {
                if matches!(bytes.get(pos + 1), Some(b'0'..=b'9')) {
                    pos += 2;
                } else if matches!(bytes.get(pos + 1), Some(b't' | b'T')) {
                    nest_depth += 1;
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            b'a'..=b'z' => {
                pos += 1;
            }
            _ => break,
        }
    }
    pos.max(start + 2)
}

fn build_mangled_segments_buf(text: &str) -> (String, Vec<(usize, usize, usize)>) {
    let mut buf = String::new();
    let mut seg_map = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        if bytes[i] == b'_'
            && (bytes[i + 1] == b'R' || bytes[i + 1] == b'Z')
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
        {
            let next_i = if bytes[i + 1] == b'R' {
                extract_v0_segments(text, bytes, i, &mut buf, &mut seg_map)
            } else {
                extract_itanium_segments(text, bytes, i, &mut buf, &mut seg_map)
            };
            i = next_i.max(i + 2);
        } else {
            i += 1;
        }
    }
    (buf, seg_map)
}

fn map_mangled_match(
    seg_map: &[(usize, usize, usize)],
    s: usize,
    e: usize,
) -> Option<(usize, usize)> {
    let idx = seg_map
        .partition_point(|&(bs, _, _)| bs <= s)
        .checked_sub(1)?;
    let (bs, be, orig_s) = seg_map[idx];
    if s >= bs && e <= be {
        Some((orig_s + (s - bs), orig_s + (e - bs)))
    } else {
        None
    }
}

fn split_camel_and_hash_with_map(text: &str) -> (String, Vec<usize>) {
    let bytes = text.as_bytes();
    let mut split_text = String::with_capacity(text.len() + 32);
    let mut orig_map = Vec::with_capacity(text.len() + 33);

    if text.is_ascii() {
        let mut split_bytes = Vec::with_capacity(text.len() + 32);
        for idx in 0..bytes.len() {
            let cur = bytes[idx];
            let insert_space = if idx > 0 {
                let prev = bytes[idx - 1];
                (prev.is_ascii_lowercase() && cur.is_ascii_uppercase())
                    || (prev.is_ascii_uppercase()
                        && cur.is_ascii_uppercase()
                        && bytes.get(idx + 1).is_some_and(u8::is_ascii_lowercase))
                    || (prev.is_ascii_alphabetic()
                        && cur.is_ascii_digit()
                        && (is_rust_legacy_hash_suffix(bytes, idx)
                            || is_trailing_digit_run(bytes, idx)))
            } else {
                false
            };
            if insert_space {
                split_bytes.push(b' ');
                orig_map.push(idx);
            }
            split_bytes.push(cur);
            orig_map.push(idx);
        }
        orig_map.push(text.len());
        let split_str = String::from_utf8(split_bytes).unwrap_or_else(|_| text.to_string());
        return (split_str, orig_map);
    }

    let mut prev_byte: Option<u8> = None;
    for (idx, ch) in text.char_indices() {
        let cur_ascii = if ch.is_ascii() { Some(ch as u8) } else { None };
        let next_ascii = bytes.get(idx + ch.len_utf8()).copied();

        let insert_space = match (prev_byte, cur_ascii, next_ascii) {
            (Some(p), Some(c), _) if p.is_ascii_lowercase() && c.is_ascii_uppercase() => true,
            (Some(p), Some(c), Some(n))
                if p.is_ascii_uppercase() && c.is_ascii_uppercase() && n.is_ascii_lowercase() =>
            {
                true
            }
            (Some(p), Some(c), _)
                if p.is_ascii_alphabetic()
                    && c.is_ascii_digit()
                    && (is_rust_legacy_hash_suffix(bytes, idx)
                        || is_trailing_digit_run(bytes, idx)) =>
            {
                true
            }
            _ => false,
        };

        if insert_space {
            split_text.push(' ');
            orig_map.push(idx);
        }
        split_text.push(ch);
        for k in 0..ch.len_utf8() {
            orig_map.push(idx + k);
        }
        prev_byte = cur_ascii;
    }
    orig_map.push(text.len());
    (split_text, orig_map)
}

fn split_binary_boundaries_with_map(text: &str) -> (String, Vec<usize>) {
    let bytes = text.as_bytes();
    let mut split_text = String::with_capacity(text.len() + 32);
    let mut orig_map = Vec::with_capacity(text.len() + 33);

    if text.is_ascii() {
        let mut split_bytes = Vec::with_capacity(text.len() + 32);
        for idx in 0..bytes.len() {
            let cur = bytes[idx];
            let insert_space = if idx > 0 {
                let prev = bytes[idx - 1];
                (prev.is_ascii_lowercase() && cur.is_ascii_uppercase())
                    || (prev.is_ascii_uppercase()
                        && cur.is_ascii_uppercase()
                        && bytes.get(idx + 1).is_some_and(u8::is_ascii_lowercase))
                    || (prev.is_ascii_digit() && cur.is_ascii_uppercase())
                    || (prev.is_ascii_alphabetic()
                        && cur.is_ascii_digit()
                        && (is_rust_legacy_hash_suffix(bytes, idx)
                            || is_trailing_digit_run(bytes, idx)))
            } else {
                false
            };
            if insert_space {
                split_bytes.push(b' ');
                orig_map.push(idx);
            }
            split_bytes.push(cur);
            orig_map.push(idx);
        }
        orig_map.push(text.len());
        let split_str = String::from_utf8(split_bytes).unwrap_or_else(|_| text.to_string());
        return (split_str, orig_map);
    }

    let mut prev_byte: Option<u8> = None;
    for (idx, ch) in text.char_indices() {
        let cur_ascii = if ch.is_ascii() { Some(ch as u8) } else { None };
        let next_ascii = bytes.get(idx + ch.len_utf8()).copied();

        let insert_space = match (prev_byte, cur_ascii, next_ascii) {
            (Some(p), Some(c), _) if p.is_ascii_lowercase() && c.is_ascii_uppercase() => true,
            (Some(p), Some(c), Some(n))
                if p.is_ascii_uppercase() && c.is_ascii_uppercase() && n.is_ascii_lowercase() =>
            {
                true
            }
            (Some(p), Some(c), _) if p.is_ascii_digit() && c.is_ascii_uppercase() => true,
            (Some(p), Some(c), _)
                if p.is_ascii_alphabetic()
                    && c.is_ascii_digit()
                    && (is_rust_legacy_hash_suffix(bytes, idx)
                        || is_trailing_digit_run(bytes, idx)) =>
            {
                true
            }
            _ => false,
        };

        if insert_space {
            split_text.push(' ');
            orig_map.push(idx);
        }
        split_text.push(ch);
        for k in 0..ch.len_utf8() {
            orig_map.push(idx + k);
        }
        prev_byte = cur_ascii;
    }
    orig_map.push(text.len());
    (split_text, orig_map)
}
fn has_camel_boundary(text: &str) -> bool {
    let b = text.as_bytes();
    for i in 1..b.len() {
        if b[i - 1].is_ascii_lowercase() && b[i].is_ascii_uppercase() {
            return true;
        }
        if i + 1 < b.len()
            && b[i - 1].is_ascii_uppercase()
            && b[i].is_ascii_uppercase()
            && b[i + 1].is_ascii_lowercase()
        {
            return true;
        }
    }
    false
}

fn split_camel_and_trailing_digits_with_map(text: &str) -> (String, Vec<usize>) {
    let bytes = text.as_bytes();
    let mut split_text = String::with_capacity(text.len() + 16);
    let mut orig_map = Vec::with_capacity(text.len() + 17);

    let mut prev_byte: Option<u8> = None;
    for (idx, ch) in text.char_indices() {
        let cur_ascii = if ch.is_ascii() { Some(ch as u8) } else { None };
        let next_ascii = bytes.get(idx + ch.len_utf8()).copied();

        let insert_space = match (prev_byte, cur_ascii, next_ascii) {
            (Some(p), Some(c), _) if p.is_ascii_lowercase() && c.is_ascii_uppercase() => true,
            (Some(p), Some(c), Some(n))
                if p.is_ascii_uppercase() && c.is_ascii_uppercase() && n.is_ascii_lowercase() =>
            {
                true
            }
            (Some(p), Some(c), _)
                if p.is_ascii_alphabetic()
                    && c.is_ascii_digit()
                    && is_trailing_digit_run(bytes, idx) =>
            {
                true
            }
            _ => false,
        };

        if insert_space {
            split_text.push(' ');
            orig_map.push(idx);
        }
        split_text.push(ch);
        for k in 0..ch.len_utf8() {
            orig_map.push(idx + k);
        }
        prev_byte = cur_ascii;
    }
    orig_map.push(text.len());
    (split_text, orig_map)
}

fn expand_ident_around(text: &str, m_start: usize, m_end: usize) -> &str {
    let b = text.as_bytes();
    let mut s = m_start;
    while s > 0 && (b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_') {
        s -= 1;
    }
    let mut e = m_end;
    while e < b.len() && (b[e].is_ascii_alphanumeric() || b[e] == b'_') {
        e += 1;
    }
    &text[s..e]
}

fn should_skip_benign_match(
    rule_id: &str,
    text: &str,
    m_start: usize,
    m_end: usize,
    matched: &str,
) -> bool {
    let norm: String = matched
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();

    if (rule_id == "R4-CRED-02" || rule_id == "R4-LEGACY-30") && norm == "netpass" {
        let after = text[m_end..].trim_start_matches(['-', '_', ' ']);
        let after_lower = after.to_ascii_lowercase();
        for kw in ["through", "thru"] {
            if let Some(rest) = after_lower.strip_prefix(kw)
                && (rest.is_empty() || !rest.as_bytes()[0].is_ascii_alphanumeric())
            {
                return true;
            }
        }
    }

    if rule_id == "R4-API-CRED-06" && norm == "syskey" {
        let orig_ident = expand_ident_around(text, m_start, m_end);
        let full_ident = orig_ident.to_ascii_lowercase();
        const UI_SYSKEY_EXACT: &[&str] = &[
            "handle_sys_key",
            "handlesyskey",
            "handle_syskey",
            "on_sys_key",
            "onsyskey",
            "on_syskey",
            "wm_syskey",
            "wm_syskeydown",
            "wm_syskeyup",
            "wm_syskeychar",
            "wm_sysdeadchar",
            "wmsyskeydown",
            "wmsyskeyup",
            "sys_key_down",
            "syskeydown",
            "sys_key_up",
            "syskeyup",
            "sys_key_event",
            "syskeyevent",
            "sys_key_code",
            "syskeycode",
            "sys_key_press",
            "syskeypress",
            "sys_key_char",
            "syskeychar",
            "translate_sys_key",
            "translatesyskey",
            "process_sys_key",
            "processsyskey",
            "dispatch_sys_key",
            "dispatchsyskey",
        ];
        let is_exact_ui_syskey = UI_SYSKEY_EXACT.contains(&full_ident.as_str());
        let is_mangled_ui_syskey = (orig_ident.starts_with("_R") || orig_ident.starts_with("_Z"))
            && {
                let (mbuf, _) = build_mangled_segments_buf(orig_ident);
                let has_winsafe_traits = mbuf.split_whitespace().any(|s| s == "winsafe")
                    && mbuf.split_whitespace().any(|s| s == "traits");
                let from_gui_crate = mbuf.split_whitespace().any(|s| {
                    let sl = s.to_ascii_lowercase();
                    sl == "winsafe"
                        || sl.ends_with("_win32")
                        || sl.ends_with("-win32")
                        || sl.starts_with("winctl2rust")
                        || sl.starts_with("guap_gui")
                });
                from_gui_crate
                    && !mbuf.is_empty()
                    && mbuf
                        .split_whitespace()
                        .any(|seg| UI_SYSKEY_EXACT.contains(&seg.to_ascii_lowercase().as_str()))
                    && !mbuf.split_whitespace().any(|seg| {
                        !(has_winsafe_traits
                            && (seg.eq_ignore_ascii_case("msgsend")
                                || seg.eq_ignore_ascii_case("msgsendrecv")))
                            && has_syskey_offensive_context(seg)
                    })
            };
        if (is_exact_ui_syskey || is_mangled_ui_syskey)
            && !has_syskey_offensive_context(&full_ident)
            && !has_syskey_offensive_context(text)
        {
            return true;
        }
    }

    if rule_id == "R4-LEGACY-32" && norm == "windowsmail" {
        let full_ident = expand_ident_around(text, m_start, m_end).to_ascii_lowercase();
        let is_header_parser = [
            "windows_mail_header",
            "windowsmailheader",
            "windows_mail_subject",
            "windows_mail_from",
            "windows_mail_to",
            "windows_mail_date",
            "windows_mail_mime",
        ]
        .iter()
        .any(|pat| full_ident.contains(pat));
        let line_lower = text.to_ascii_lowercase();
        let is_cmd_or_cred = line_lower.contains("#[command")
            || line_lower.contains("tool_id")
            || line_lower.contains("command_id")
            || line_lower.contains("\"name\"")
            || line_lower.contains("pass")
            || line_lower.contains("dump");
        if is_header_parser && !is_cmd_or_cred {
            return true;
        }
    }

    false
}
pub(crate) fn has_syskey_offensive_context(text: &str) -> bool {
    let cleaned_storage;
    let scan_text = if text.contains("7winsafe") || text.contains("winsafe::") {
        cleaned_storage = text
            .replace("6traits11MsgSendRecv", "")
            .replace("6traits7MsgSend", "")
            .replace("traits::MsgSendRecv", "")
            .replace("traits::MsgSend", "");
        cleaned_storage.as_str()
    } else {
        text
    };
    let lower = scan_text.to_ascii_lowercase();
    if [
        "bootkey", "boot_key", "secret", "decrypt", "dump", "steal", "extract", "exfil", "fetch",
        "retrieve", "grab", "harvest", "leak", "recover", "upload", "transmit", "decode",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
    {
        return true;
    }
    let mut raw_tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let bytes = scan_text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if !b.is_ascii_alphabetic() {
            if !cur.is_empty() {
                raw_tokens.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if i > 0 && bytes[i - 1].is_ascii_alphabetic() {
            let prev = bytes[i - 1];
            let camel = (prev.is_ascii_lowercase() && b.is_ascii_uppercase())
                || (prev.is_ascii_uppercase()
                    && b.is_ascii_uppercase()
                    && bytes.get(i + 1).is_some_and(u8::is_ascii_lowercase));
            if camel && !cur.is_empty() {
                raw_tokens.push(std::mem::take(&mut cur));
            }
        }
        cur.push((b as char).to_ascii_lowercase());
    }
    if !cur.is_empty() {
        raw_tokens.push(cur);
    }
    raw_tokens.iter().any(|tok| {
        matches!(
            tok.as_str(),
            "sam"
                | "security"
                | "lsa"
                | "rc4"
                | "hive"
                | "copy"
                | "send"
                | "read"
                | "write"
                | "log"
                | "print"
                | "emit"
                | "save"
                | "export"
                | "collect"
                | "siphon"
                | "capture"
                | "sniff"
                | "scrape"
                | "store"
                | "persist"
                | "get"
                | "put"
                | "post"
                | "parse"
                | "obtain"
                | "acquire"
                | "pull"
        )
    })
}
