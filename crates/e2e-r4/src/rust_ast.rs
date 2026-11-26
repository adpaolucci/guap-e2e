use std::collections::{HashMap, HashSet};

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, Expr, Fields, FnArg, GenericArgument, ImplItemFn, Item, ItemEnum, ItemFn,
    ItemMacro, ItemMod, ItemStruct, ItemType, ItemUse, Local, Pat, PathArguments, ReturnType, Stmt,
    TraitItemFn, Type, UseTree,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SinkFlags {
    pub exec: bool,
    pub io: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WlanHelperKind {
    PrimarySanitizer,
    Validator,
    TagHelperFn,
}

#[derive(Debug, Clone)]
pub enum SimpleType {
    PrimitiveSafe,
    ByteVec,
    Option(Box<SimpleType>),
    Tuple(Vec<SimpleType>),
    Named(String),
    Unsafe,
}

impl SimpleType {
    pub fn from_syn(ty: &Type) -> Self {
        match ty {
            Type::Path(tp) => {
                if tp.qself.is_some() {
                    return Self::Unsafe;
                }
                let Some(seg) = tp.path.segments.last() else {
                    return Self::Unsafe;
                };
                let ident = seg.ident.to_string();
                if matches!(
                    ident.as_str(),
                    "usize" | "u8" | "u16" | "u32" | "u64" | "isize" | "i32" | "bool" | "char"
                ) && matches!(seg.arguments, PathArguments::None)
                {
                    return Self::PrimitiveSafe;
                }
                if ident == "Vec"
                    && let PathArguments::AngleBracketed(ab) = &seg.arguments
                    && ab.args.len() == 1
                    && let Some(GenericArgument::Type(inner)) = ab.args.first()
                    && compact_type_str(inner) == "u8"
                {
                    return Self::ByteVec;
                }
                if ident == "Option"
                    && let PathArguments::AngleBracketed(ab) = &seg.arguments
                    && ab.args.len() == 1
                    && let Some(GenericArgument::Type(inner)) = ab.args.first()
                {
                    return Self::Option(Box::new(Self::from_syn(inner)));
                }
                if matches!(seg.arguments, PathArguments::None) {
                    return Self::Named(ident);
                }
                Self::Unsafe
            }
            Type::Tuple(tt) => Self::Tuple(tt.elems.iter().map(Self::from_syn).collect()),
            Type::Paren(tp) => Self::from_syn(&tp.elem),
            Type::Group(tg) => Self::from_syn(&tg.elem),
            _ => Self::Unsafe,
        }
    }

    pub fn is_safe_index(&self, safe_enums: &HashSet<String>) -> bool {
        match self {
            Self::PrimitiveSafe => true,
            Self::ByteVec => false,
            Self::Option(inner) => inner.is_safe_index(safe_enums),
            Self::Tuple(elems) => elems.iter().all(|e| e.is_safe_index(safe_enums)),
            Self::Named(n) => safe_enums.contains(n),
            Self::Unsafe => false,
        }
    }
}

pub fn is_known_cross_crate_wlan_ident(ident: &str) -> bool {
    matches!(
        ident,
        "sanitize_wlan_profile_xml"
            | "sanitize_http_header"
            | "sanitize_escaped_keymaterial_in_str"
            | "sanitize_escaped_keymaterial_in_str_with_marker_and_origin"
            | "sanitize_string_r4"
            | "sanitize_string_r4_inner"
            | "sanitize_string_r4_inner_with_origin"
            | "sanitize_html_fragment_r4"
            | "sanitize_html_tag_attributes_r4"
            | "sanitize_json_value_r4"
            | "sanitize_json_value_r4_inner"
            | "sanitize_table_for_report"
            | "sanitize_export_options"
            | "assert_r4_clean_report_text"
            | "assert_r4_clean_json"
            | "assert_r4_clean_str"
            | "assert_r4_clean_html"
            | "assert_r4_clean_csv"
            | "verify_html_document_or_fragment"
    )
}

#[derive(Debug, Clone)]
pub struct FnInfo {
    pub id: usize,
    pub name: String,
    pub is_method: bool,
    pub span: (usize, usize),
    pub header_end: usize,
    pub has_mut_param: bool,
    pub mut_param_types: Vec<String>,
    pub param_names: Vec<String>,
    pub mut_param_names: Vec<String>,
    pub ret_type_str: Option<String>,
    pub direct_exec_sink: bool,
    pub direct_io_sink: bool,
    pub has_exec_sink: bool,
    pub has_io_sink: bool,
    pub has_thread_spawn: bool,
    pub has_global_state_sink: bool,
    pub has_slice_or_split: bool,
    pub callees: Vec<String>,
    pub method_callees: Vec<String>,
    pub wlan_kind: Option<WlanHelperKind>,
    pub is_verified_wlan: bool,
    pub has_unsafe_wlan_extraction: bool,
}

#[derive(Debug, Clone)]
pub struct StructInfo {
    pub name: String,
    pub span: (usize, usize),
    pub fields: Vec<SimpleType>,
    pub is_verified_tag_struct: bool,
}

#[derive(Debug, Clone)]
pub struct StmtEntry {
    pub span: (usize, usize),
    pub fn_id: Option<usize>,
    pub is_rejection_stmt: bool,
    pub is_runtime_rejection: bool,
    pub text_compact: String,
}

#[derive(Debug, Clone)]
pub struct MacroCallSpan {
    pub span: (usize, usize),
    pub name: String,
    pub is_negative_assert: bool,
    pub has_sink: bool,
}

#[derive(Debug, Clone)]
pub struct BindingInfo {
    pub ident: String,
    pub decl_span: (usize, usize),
    pub init_span: (usize, usize),
    pub fn_id: Option<usize>,
    pub is_array_or_vec: bool,
    pub is_const_or_static: bool,
    pub is_denylist_name: bool,
}

#[derive(Debug, Clone)]
pub struct CallArgSpan {
    pub span: (usize, usize),
    pub callee_name: String,
    pub is_empty_str_only: bool,
    pub has_return_or_block: bool,
}

struct AstCtx<'a> {
    content: &'a str,
    line_starts: &'a [usize],
    use_aliases: &'a HashMap<String, String>,
    command_types: &'a HashSet<String>,
    macro_taint: &'a HashMap<String, SinkFlags>,
}

impl<'a> AstCtx<'a> {
    fn span_bytes(&self, sp: Span) -> (usize, usize) {
        let s = lc_to_byte_in_str(self.content, self.line_starts, sp.start());
        let e = lc_to_byte_in_str(self.content, self.line_starts, sp.end());
        (s, e.max(s))
    }

    fn expr_bytes(&self, e: &Expr) -> (usize, usize) {
        let mut b = SpanBounds {
            content: self.content,
            line_starts: self.line_starts,
            min_s: usize::MAX,
            max_e: 0,
        };
        b.visit_expr(e);
        if b.min_s == usize::MAX {
            (0, 0)
        } else {
            (b.min_s, b.max_e.max(b.min_s))
        }
    }

    fn stmt_bytes(&self, st: &Stmt) -> (usize, usize) {
        let mut b = SpanBounds {
            content: self.content,
            line_starts: self.line_starts,
            min_s: usize::MAX,
            max_e: 0,
        };
        b.visit_stmt(st);
        if b.min_s == usize::MAX {
            (0, 0)
        } else {
            (b.min_s, b.max_e.max(b.min_s))
        }
    }
}

struct SpanBounds<'a> {
    content: &'a str,
    line_starts: &'a [usize],
    min_s: usize,
    max_e: usize,
}

impl<'a> SpanBounds<'a> {
    fn extend(&mut self, sp: Span) {
        let s = lc_to_byte_in_str(self.content, self.line_starts, sp.start());
        let e = lc_to_byte_in_str(self.content, self.line_starts, sp.end());
        if s <= e {
            self.min_s = self.min_s.min(s);
            self.max_e = self.max_e.max(e);
        }
    }

    fn extend_delim(&mut self, d: &syn::MacroDelimiter) {
        match d {
            syn::MacroDelimiter::Paren(p) => {
                self.extend(p.span.open());
                self.extend(p.span.close());
            }
            syn::MacroDelimiter::Brace(b) => {
                self.extend(b.span.open());
                self.extend(b.span.close());
            }
            syn::MacroDelimiter::Bracket(b) => {
                self.extend(b.span.open());
                self.extend(b.span.close());
            }
        }
    }
}

impl<'a> Visit<'a> for SpanBounds<'a> {
    fn visit_ident(&mut self, i: &'a syn::Ident) {
        self.extend(i.span());
    }
    fn visit_lit(&mut self, l: &'a syn::Lit) {
        self.extend(l.span());
    }
    fn visit_lifetime(&mut self, l: &'a syn::Lifetime) {
        self.extend(l.apostrophe);
        self.extend(l.ident.span());
    }
    fn visit_attribute(&mut self, a: &'a Attribute) {
        self.extend(a.pound_token.span);
        self.extend(a.bracket_token.span.close());
        visit::visit_attribute(self, a);
    }
    fn visit_block(&mut self, b: &'a Block) {
        self.extend(b.brace_token.span.open());
        self.extend(b.brace_token.span.close());
        visit::visit_block(self, b);
    }
    fn visit_local(&mut self, l: &'a Local) {
        self.extend(l.let_token.span);
        self.extend(l.semi_token.span);
        visit::visit_local(self, l);
    }
    fn visit_stmt(&mut self, s: &'a Stmt) {
        if let Stmt::Expr(_, Some(semi)) = s {
            self.extend(semi.span);
        }
        visit::visit_stmt(self, s);
    }
    fn visit_expr_call(&mut self, i: &'a syn::ExprCall) {
        self.extend(i.paren_token.span.open());
        self.extend(i.paren_token.span.close());
        visit::visit_expr_call(self, i);
    }
    fn visit_expr_method_call(&mut self, i: &'a syn::ExprMethodCall) {
        self.extend(i.paren_token.span.open());
        self.extend(i.paren_token.span.close());
        visit::visit_expr_method_call(self, i);
    }
    fn visit_expr_index(&mut self, i: &'a syn::ExprIndex) {
        self.extend(i.bracket_token.span.open());
        self.extend(i.bracket_token.span.close());
        visit::visit_expr_index(self, i);
    }
    fn visit_expr_array(&mut self, i: &'a syn::ExprArray) {
        self.extend(i.bracket_token.span.open());
        self.extend(i.bracket_token.span.close());
        visit::visit_expr_array(self, i);
    }
    fn visit_expr_tuple(&mut self, i: &'a syn::ExprTuple) {
        self.extend(i.paren_token.span.open());
        self.extend(i.paren_token.span.close());
        visit::visit_expr_tuple(self, i);
    }
    fn visit_expr_paren(&mut self, i: &'a syn::ExprParen) {
        self.extend(i.paren_token.span.open());
        self.extend(i.paren_token.span.close());
        visit::visit_expr_paren(self, i);
    }
    fn visit_expr_macro(&mut self, i: &'a syn::ExprMacro) {
        self.extend_delim(&i.mac.delimiter);
        visit::visit_expr_macro(self, i);
    }
    fn visit_stmt_macro(&mut self, i: &'a syn::StmtMacro) {
        self.extend_delim(&i.mac.delimiter);
        if let Some(semi) = &i.semi_token {
            self.extend(semi.span);
        }
        visit::visit_stmt_macro(self, i);
    }
}

pub struct RustAstIndex {
    pub line_starts: Vec<usize>,
    pub test_spans: Vec<(usize, usize)>,
    pub use_aliases: HashMap<String, String>,
    pub command_types: HashSet<String>,
    pub macro_taint: HashMap<String, SinkFlags>,
    pub fns: Vec<FnInfo>,
    pub structs: Vec<StructInfo>,
    pub safe_enums: HashSet<String>,
    pub stmts: Vec<StmtEntry>,
    pub macro_calls: Vec<MacroCallSpan>,
    pub bindings: Vec<BindingInfo>,
    pub call_arg_spans: Vec<CallArgSpan>,
    pub assign_targets: Vec<(usize, (usize, usize), String)>,
    pub ident_uses: HashMap<String, Vec<(usize, Option<usize>)>>,
    pub file_has_wlan_get_profile: bool,
    pub file_has_verified_wlan: bool,
    pub file_has_verified_primary: bool,
    pub file_has_verified_validator: bool,
    pub verified_wlan_idents: HashSet<String>,
    pub verified_wlan_non_fn_idents: HashSet<String>,
    pub verified_wlan_spans: Vec<(usize, usize)>,
    pub unsafe_wlan_fn_ids: HashSet<usize>,
    pub concat_strings: Vec<(usize, String)>,
    pub include_str_paths: Vec<(usize, String, bool)>,
    pub is_path_test: bool,
    pub src_len: usize,
}
impl RustAstIndex {
    pub fn compute_line_starts(content: &str) -> Vec<usize> {
        let mut starts = vec![0usize];
        for (i, b) in content.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        starts
    }

    pub fn parse(rel_norm: &str, content: &str) -> Option<Self> {
        let file = syn::parse_file(content).ok()?;
        let line_starts = Self::compute_line_starts(content);
        let lower_path = rel_norm.to_ascii_lowercase();
        let is_path_test = lower_path.contains("/tests/")
            || lower_path.ends_with("/tests.rs")
            || lower_path == "tests.rs";

        let mut collector = FileCollector {
            content,
            line_starts: &line_starts,
            test_spans: Vec::new(),
            use_aliases: HashMap::new(),
            command_types: HashSet::from(["Command".to_string()]),
            raw_type_aliases: Vec::new(),
            raw_macros: Vec::new(),
            enums: Vec::new(),
            raw_structs: Vec::new(),
            impl_has_leaking_method: HashSet::new(),
            raw_fns: Vec::new(),
            concat_strings: Vec::new(),
            include_str_paths: Vec::new(),
        };
        collector.visit_file(&file);

        let mut changed = true;
        while changed {
            changed = false;
            for (rename, orig) in &collector.use_aliases {
                if collector.command_types.contains(orig)
                    && collector.command_types.insert(rename.clone())
                {
                    changed = true;
                }
            }
            for (alias_name, target_last) in &collector.raw_type_aliases {
                let target_resolved = collector
                    .use_aliases
                    .get(target_last)
                    .unwrap_or(target_last);
                if (collector.command_types.contains(target_last)
                    || collector.command_types.contains(target_resolved))
                    && collector.command_types.insert(alias_name.clone())
                {
                    changed = true;
                }
            }
        }

        let mut macro_taint: HashMap<String, SinkFlags> = HashMap::new();
        let mut macro_calls_in_macro: HashMap<String, Vec<String>> = HashMap::new();
        for (name, tokens) in &collector.raw_macros {
            let (flags, invoked) =
                scan_tokens_for_sinks(tokens, &collector.command_types, &collector.use_aliases);
            macro_taint.insert(name.clone(), flags);
            macro_calls_in_macro.insert(name.clone(), invoked);
        }
        let mut m_changed = true;
        while m_changed {
            m_changed = false;
            let snapshot = macro_taint.clone();
            for (m_name, invoked) in &macro_calls_in_macro {
                let mut cur = *macro_taint.get(m_name).unwrap_or(&SinkFlags::default());
                for callee_mac in invoked {
                    if let Some(sub) = snapshot.get(callee_mac) {
                        if sub.exec && !cur.exec {
                            cur.exec = true;
                            m_changed = true;
                        }
                        if sub.io && !cur.io {
                            cur.io = true;
                            m_changed = true;
                        }
                    }
                }
                macro_taint.insert(m_name.clone(), cur);
            }
        }

        let mut safe_enums = HashSet::new();
        let mut enum_changed = true;
        while enum_changed {
            enum_changed = false;
            for item_enum in &collector.enums {
                let e_name = item_enum.ident.to_string();
                if safe_enums.contains(&e_name) {
                    continue;
                }
                let all_ok = item_enum.variants.iter().all(|v| match &v.fields {
                    Fields::Unit => true,
                    Fields::Unnamed(u) => u
                        .unnamed
                        .iter()
                        .all(|f| SimpleType::from_syn(&f.ty).is_safe_index(&safe_enums)),
                    Fields::Named(n) => n
                        .named
                        .iter()
                        .all(|f| SimpleType::from_syn(&f.ty).is_safe_index(&safe_enums)),
                });
                if all_ok {
                    safe_enums.insert(e_name);
                    enum_changed = true;
                }
            }
        }

        let ctx = AstCtx {
            content,
            line_starts: &line_starts,
            use_aliases: &collector.use_aliases,
            command_types: &collector.command_types,
            macro_taint: &macro_taint,
        };

        let mut top_visitor = TopBindingVisitor {
            ctx: &ctx,
            bindings: Vec::new(),
            ident_uses: HashMap::new(),
            call_arg_spans: Vec::new(),
            file_has_wlan_get_profile: false,
        };
        top_visitor.visit_file(&file);

        let mut all_bindings = top_visitor.bindings;
        let mut all_ident_uses = top_visitor.ident_uses;
        let mut all_call_arg_spans = top_visitor.call_arg_spans;
        let mut all_assign_targets = Vec::new();
        let mut file_has_wlan_get_profile = top_visitor.file_has_wlan_get_profile;
        let mut all_stmts = Vec::new();
        let mut all_macro_calls = Vec::new();

        let mut fn_entries = Vec::new();
        for (id, raw_fn) in collector.raw_fns.into_iter().enumerate() {
            let mut body_visitor = FnBodyVisitor {
                ctx: &ctx,
                fn_id: id,
                direct_exec_sink: false,
                direct_io_sink: false,
                has_thread_spawn: false,
                has_global_state_sink: false,
                has_slice_or_split: false,
                has_wlan_get_profile: false,
                callees: Vec::new(),
                method_callees: Vec::new(),
                stmts: Vec::new(),
                macro_calls: Vec::new(),
                bindings: Vec::new(),
                call_arg_spans: Vec::new(),
                assign_targets: Vec::new(),
                ident_uses: HashMap::new(),
            };
            body_visitor.visit_block(raw_fn.block);

            if body_visitor.has_wlan_get_profile {
                file_has_wlan_get_profile = true;
            }
            all_stmts.extend(body_visitor.stmts);
            all_macro_calls.extend(body_visitor.macro_calls);
            all_bindings.extend(body_visitor.bindings);
            all_call_arg_spans.extend(body_visitor.call_arg_spans);
            all_assign_targets.extend(body_visitor.assign_targets);
            for (k, v) in body_visitor.ident_uses {
                all_ident_uses.entry(k).or_default().extend(v);
            }

            let lower_name = raw_fn.name.to_ascii_lowercase();
            let wlan_kind = if raw_fn.name.starts_with("test_") {
                None
            } else if !lower_name.contains("unredact")
                && (lower_name.contains("sanitize")
                    || lower_name.starts_with("redact")
                    || lower_name.contains("_redact"))
                && (lower_name.contains("wlan")
                    || lower_name.contains("keymaterial")
                    || lower_name.contains("_r4"))
            {
                Some(WlanHelperKind::PrimarySanitizer)
            } else if lower_name.starts_with("assert_r4_clean")
                || matches!(
                    lower_name.as_str(),
                    "verify_html_document_or_fragment"
                        | "verify_html_document_or_fragment_with_origin"
                        | "verify_unmasked_broken_json_strings_in_html_with_origin"
                        | "flush_html_text_buf"
                        | "flush_html_text_buf_with_origin"
                        | "find_embedded_json_mask_spans"
                )
            {
                Some(WlanHelperKind::Validator)
            } else if lower_name.contains("keymaterial")
                || lower_name.contains("_km_")
                || (raw_fn.name == "build"
                    && raw_fn.ret_type_str.as_deref() == Some("Option<Self>")
                    && body_visitor.callees.iter().any(|c| c == "analyze_cross_cell_segment"))
                || matches!(
                    raw_fn.name.as_str(),
                    "contains_block_html_tag"
                        | "is_inline_prefixed_rfc4180_csv"
                        | "is_html_document_or_fragment"
                        | "scan_unquoted_html_token_end"
                        | "scan_unquoted_html_token_end_cached"
                        | "analyze_cross_cell_segment"
                        | "find_html_close_tag"
                        | "check_html_tag_attributes"
                        | "check_html_tag_attributes_with_depth"
                        | "double_entity_inner_quote_breaks_out"
                        | "find_tag_close_quote_aware"
                        | "find_html_open_tag_end"
                        | "find_html_open_tag_end_with_skip_bound"
                        | "find_next_nl_tag_pos"
                )
            {
                Some(WlanHelperKind::TagHelperFn)
            } else {
                None
            };

            let info = FnInfo {
                id,
                name: raw_fn.name,
                is_method: raw_fn.is_method,
                span: raw_fn.span,
                header_end: raw_fn.header_end,
                has_mut_param: raw_fn.has_mut_param,
                mut_param_types: raw_fn.mut_param_types,
                param_names: raw_fn.param_names,
                mut_param_names: raw_fn.mut_param_names,
                ret_type_str: raw_fn.ret_type_str,
                direct_exec_sink: body_visitor.direct_exec_sink,
                direct_io_sink: body_visitor.direct_io_sink,
                has_exec_sink: body_visitor.direct_exec_sink,
                has_io_sink: body_visitor.direct_io_sink,
                has_thread_spawn: body_visitor.has_thread_spawn,
                has_global_state_sink: body_visitor.has_global_state_sink,
                has_slice_or_split: body_visitor.has_slice_or_split,
                callees: body_visitor.callees,
                method_callees: body_visitor.method_callees,
                wlan_kind,
                is_verified_wlan: false,
                has_unsafe_wlan_extraction: false,
            };
            fn_entries.push((info, raw_fn.block));
        }

        let blocks: Vec<&Block> = fn_entries.iter().map(|(_, b)| *b).collect();
        let fns: Vec<FnInfo> = fn_entries.into_iter().map(|(f, _)| f).collect();
        let test_spans = collector.test_spans;
        let use_aliases = collector.use_aliases;
        let command_types = collector.command_types;
        let structs = collector.raw_structs;
        let impl_has_leaking_method = collector.impl_has_leaking_method;
        let concat_strings = collector.concat_strings;
        let include_str_paths = collector.include_str_paths;

        let mut idx = Self {
            line_starts,
            test_spans,
            use_aliases,
            command_types,
            macro_taint,
            fns,
            structs,
            safe_enums,
            stmts: all_stmts,
            macro_calls: all_macro_calls,
            bindings: all_bindings,
            call_arg_spans: all_call_arg_spans,
            assign_targets: all_assign_targets,
            ident_uses: all_ident_uses,
            file_has_wlan_get_profile,
            file_has_verified_wlan: false,
            file_has_verified_primary: false,
            file_has_verified_validator: false,
            verified_wlan_idents: HashSet::new(),
            verified_wlan_non_fn_idents: HashSet::new(),
            verified_wlan_spans: Vec::new(),
            unsafe_wlan_fn_ids: HashSet::new(),
            concat_strings,
            include_str_paths,
            is_path_test,
            src_len: content.len(),
        };

        idx.propagate_call_graph_sinks();
        idx.verify_wlan_components(&blocks, &impl_has_leaking_method);

        Some(idx)
    }

    pub fn abs_byte_from_line_offset(&self, line_idx: usize, col_byte: usize) -> usize {
        let base = self.line_starts.get(line_idx).copied().unwrap_or(self.src_len);
        (base + col_byte).min(self.src_len)
    }

    pub fn in_test_context(&self, byte_pos: usize) -> bool {
        self.is_path_test
            || self
                .test_spans
                .iter()
                .any(|&(s, e)| byte_pos >= s && byte_pos < e)
    }

    pub fn enclosing_fn(&self, byte_pos: usize) -> Option<&FnInfo> {
        self.fns
            .iter()
            .filter(|f| byte_pos >= f.span.0 && byte_pos < f.span.1)
            .min_by_key(|f| f.span.1 - f.span.0)
    }

    pub fn in_verified_wlan_item(&self, byte_pos: usize) -> bool {
        self.verified_wlan_spans
            .iter()
            .any(|&(s, e)| byte_pos >= s && byte_pos < e)
    }
    fn propagate_call_graph_sinks(&mut self) {
        let mut free_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut method_map: HashMap<String, Vec<usize>> = HashMap::new();
        for f in &self.fns {
            if f.is_method {
                method_map.entry(f.name.clone()).or_default().push(f.id);
            } else {
                free_map.entry(f.name.clone()).or_default().push(f.id);
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            let snapshot: Vec<(bool, bool)> = self
                .fns
                .iter()
                .map(|f| (f.has_exec_sink, f.has_io_sink))
                .collect();

            for f in &mut self.fns {
                for callee in &f.callees {
                    let resolved = self.use_aliases.get(callee).unwrap_or(callee);
                    if let Some(ids) = free_map.get(resolved).or_else(|| free_map.get(callee)) {
                        for &cid in ids {
                            if cid == f.id {
                                continue;
                            }
                            let (c_exec, c_io) = snapshot[cid];
                            if c_exec && !f.has_exec_sink {
                                f.has_exec_sink = true;
                                changed = true;
                            }
                            if c_io && !f.has_io_sink {
                                f.has_io_sink = true;
                                changed = true;
                            }
                        }
                    }
                }
                for m_callee in &f.method_callees {
                    if let Some(ids) = method_map.get(m_callee) {
                        for &cid in ids {
                            if cid == f.id {
                                continue;
                            }
                            let (c_exec, c_io) = snapshot[cid];
                            if c_exec && !f.has_exec_sink {
                                f.has_exec_sink = true;
                                changed = true;
                            }
                            if c_io && !f.has_io_sink {
                                f.has_io_sink = true;
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
    }

    fn verify_wlan_components(
        &mut self,
        blocks: &[&Block],
        impl_has_leaking_method: &HashSet<String>,
    ) {
        if self.file_has_wlan_get_profile {
            return;
        }

        let local_fn_names: HashSet<String> = self.fns.iter().map(|f| f.name.clone()).collect();
        let seed_cross_crate: HashSet<String> = [
            "sanitize_wlan_profile_xml",
            "sanitize_http_header",
            "sanitize_escaped_keymaterial_in_str",
            "sanitize_escaped_keymaterial_in_str_with_marker_and_origin",
            "sanitize_string_r4",
            "sanitize_string_r4_inner",
            "sanitize_string_r4_inner_with_origin",
            "sanitize_html_fragment_r4",
            "sanitize_html_fragment_r4_with_origin",
            "sanitize_html_tag_attributes_r4",
            "sanitize_json_value_r4",
            "sanitize_json_value_r4_inner",
            "sanitize_table_for_report",
            "sanitize_export_options",
            "assert_r4_clean_report_text",
            "assert_r4_clean_json",
            "assert_r4_clean_str",
            "assert_r4_clean_html",
            "assert_r4_clean_csv",
            "verify_html_document_or_fragment",
        ]
        .into_iter()
        .filter(|n| !local_fn_names.contains(*n))
        .map(str::to_string)
        .collect();

        let mut verified_sanitizers: HashSet<String> = seed_cross_crate
            .iter()
            .filter(|n| n.starts_with("sanitize_"))
            .cloned()
            .collect();
        let mut verified_validators: HashSet<String> = seed_cross_crate
            .iter()
            .filter(|n| n.starts_with("assert_r4_clean_") || *n == "verify_html_document_or_fragment")
            .cloned()
            .collect();
        let mut verified_tag_helpers: HashSet<String> = HashSet::new();

        let mut primary_verified = vec![false; self.fns.len()];
        let mut validator_verified = vec![false; self.fns.len()];
        let mut unsafe_extractions = vec![false; self.fns.len()];

        let mut all_tag_helpers = HashSet::new();
        for f in &self.fns {
            if f.wlan_kind == Some(WlanHelperKind::TagHelperFn) {
                all_tag_helpers.insert(f.name.clone());
            }
        }

        let mut fp_changed = true;
        let mut verified_tag_structs = HashSet::new();
        for s in &mut self.structs {
            let lower = s.name.to_ascii_lowercase();
            if (lower.contains("keymaterial") || s.name == "OpeningTagMatch")
                && !impl_has_leaking_method.contains(&s.name)
                && s.fields.iter().all(|ty| ty.is_safe_index(&self.safe_enums))
            {
                verified_tag_structs.insert(s.name.clone());
            }
        }

        let memo_struct_safe = !self.structs.iter().any(|s| {
            s.name == "JsonMarkerMemo"
                && s.fields.iter().any(|ft| match ft {
                    SimpleType::PrimitiveSafe | SimpleType::ByteVec => false,
                    SimpleType::Named(n) => n != "JsonContainerMemo",
                    SimpleType::Option(inner) => !matches!(
                        inner.as_ref(),
                        SimpleType::PrimitiveSafe | SimpleType::ByteVec
                    ) && !matches!(inner.as_ref(), SimpleType::Named(n) if n == "JsonContainerMemo"),
                    _ => true,
                })
        });

        let safe_memo_helpers: HashSet<String> = self
            .fns
            .iter()
            .enumerate()
            .filter(|(idx, fn_i)| {
                memo_struct_safe
                    && !fn_i.has_io_sink
                    && !fn_i.has_exec_sink
                    && !fn_i.has_thread_spawn
                    && !fn_i.has_global_state_sink
                    && !has_dangerous_wlan_fn_verb(&fn_i.name, true)
                    && (fn_i.mut_param_types.iter().any(|t| t == "&mutJsonMarkerMemo")
                        || fn_i.name.ends_with("_memo"))
                    && fn_i
                        .mut_param_types
                        .iter()
                        .all(|t| t == "&mutJsonMarkerMemo" || t == "Option<&mutJsonMarkerMemo>")
                    && fn_i.ret_type_str.as_deref() == Some("bool")
                    && block_is_safe_memo_helper(blocks[*idx], &fn_i.mut_param_names)
            })
            .map(|(_, fn_i)| fn_i.name.clone())
            .collect();

        let mask_json_span_safe = self
            .fns
            .iter()
            .enumerate()
            .find(|(_, fn_i)| fn_i.name == "mask_json_span_preserving_delims")
            .is_some_and(|(idx, fn_i)| {
                !fn_i.has_io_sink
                    && !fn_i.has_exec_sink
                    && !fn_i.has_thread_spawn
                    && !fn_i.has_global_state_sink
                    && fn_i.mut_param_types == ["&mut[u8]"]
                    && fn_i.ret_type_str.as_deref() == Some("bool")
                    && block_is_safe_mask_json_span(blocks[idx], &fn_i.mut_param_names)
            });

        while fp_changed {
            fp_changed = false;

            for (i, f) in self.fns.iter().enumerate() {
                if f.wlan_kind == Some(WlanHelperKind::TagHelperFn)
                    && !verified_tag_helpers.contains(&f.name)
                {
                    let th_mut_ok = !f.has_mut_param
                        || (f.ret_type_str.as_deref() == Some("bool")
                            && f.mut_param_types
                                .iter()
                                .all(|t| t == "&mut[u8]" || t == "&mutJsonMarkerMemo")
                            && block_mut_u8_only_safe_bitmask_or_fill(
                                blocks[i],
                                &f.name,
                                &f.mut_param_names,
                                &f.mut_param_types,
                                &verified_tag_helpers,
                                &safe_memo_helpers,
                            ))
                        || (f.name == "scan_unquoted_html_token_end_cached"
                            && f.ret_type_str.as_deref() == Some("usize")
                            && f.mut_param_types.iter().all(|t| {
                                t == "&mutOption<Vec<u8>>"
                                    || t == "&mut[Option<Option<usize>>;_]"
                                    || t == "&mut[Option<Option<usize>>;2]"
                                    || t == "&mut[bool;_]"
                                    || t == "&mut[bool;2]"
                            }))
                        || (f.name == "analyze_cross_cell_segment"
                            && f.ret_type_str.as_deref() == Some("(bool,bool)")
                            && f.mut_param_types == ["&mutVec<(usize,usize)>"])
                        || (f.name == "mask_clean_km_at"
                            && f.ret_type_str.is_none()
                            && f.mut_param_types == ["&mut[u8]", "&mutVec<(usize,usize)>"]
                            && block_mut_u8_only_safe_bitmask_or_fill(
                                blocks[i],
                                &f.name,
                                &f.mut_param_names,
                                &f.mut_param_types,
                                &verified_tag_helpers,
                                &safe_memo_helpers,
                            ));
                    let sets = VerifiedWlanSets {
                        sanitizers: &verified_sanitizers,
                        validators: &verified_validators,
                        tag_helpers: &verified_tag_helpers,
                        tag_structs: &verified_tag_structs,
                        all_fns: &self.fns,
                    };
                    let has_unsafe_flow = block_has_unsafe_wlan_slice_flow(blocks[i], f, &sets);
                    unsafe_extractions[i] = has_unsafe_flow;
                    if !f.has_exec_sink
                        && !f.has_io_sink
                        && !f.has_thread_spawn
                        && !f.has_global_state_sink
                        && th_mut_ok
                        && !has_dangerous_wlan_fn_verb(&f.name, true)
                        && !has_unsafe_flow
                        && is_safe_tag_helper_return(
                            f,
                            blocks[i],
                            &verified_tag_structs,
                            &self.safe_enums,
                            &verified_tag_helpers,
                        )
                    {
                        verified_tag_helpers.insert(f.name.clone());
                        fp_changed = true;
                    }
                }
            }

            let mut any_primary = false;
            let mut any_validator = false;
            for (i, f) in self.fns.iter().enumerate() {
                if f.has_thread_spawn || f.has_global_state_sink {
                    unsafe_extractions[i] = true;
                    continue;
                }
                let block = blocks[i];
                let sets = VerifiedWlanSets {
                    sanitizers: &verified_sanitizers,
                    validators: &verified_validators,
                    tag_helpers: &verified_tag_helpers,
                    tag_structs: &verified_tag_structs,
                    all_fns: &self.fns,
                };
                let has_unsafe_flow = block_has_unsafe_wlan_slice_flow(block, f, &sets);
                unsafe_extractions[i] = has_unsafe_flow;

                match f.wlan_kind {
                    Some(WlanHelperKind::PrimarySanitizer) => {
                        let calls_unverified_tag_helper = f.callees.iter().any(|c| {
                            all_tag_helpers.contains(c) && !verified_tag_helpers.contains(c)
                        });
                        let primary_ok = block_is_genuine_primary_sanitizer(block, f, &sets);
                        let wrap_ok = !primary_ok
                            && (any_primary || self.file_has_verified_primary)
                            && block_is_valid_sanitizer_wrapper(block, f, &verified_sanitizers, &verified_validators);
                        if !f.has_exec_sink
                            && !f.has_io_sink
                            && !has_dangerous_wlan_fn_verb(&f.name, false)
                            && wlan_mut_params_ok(f, true)
                            && !calls_unverified_tag_helper
                            && !has_unsafe_flow
                            && (primary_ok || wrap_ok)
                        {
                            if !primary_verified[i] {
                                primary_verified[i] = true;
                                fp_changed = true;
                            }
                            if verified_sanitizers.insert(f.name.clone()) {
                                fp_changed = true;
                            }
                            any_primary = true;
                        }
                    }
                    Some(WlanHelperKind::Validator)
                        if is_genuine_validator_fn(f, block, has_unsafe_flow, any_validator || self.file_has_verified_validator, &sets, mask_json_span_safe) =>
                    {
                        if !validator_verified[i] {
                            validator_verified[i] = true;
                            fp_changed = true;
                        }
                        if verified_validators.insert(f.name.clone()) {
                            fp_changed = true;
                        }
                        any_validator = true;
                    }
                    _ => {}
                }
            }

            if any_primary {
                self.file_has_verified_primary = true;
            }
            if any_validator {
                self.file_has_verified_validator = true;
            }
            self.file_has_verified_wlan =
                self.file_has_verified_primary || self.file_has_verified_validator;
        }

        if !self.file_has_verified_wlan {
            verified_tag_helpers.clear();
            verified_tag_structs.clear();
        } else {
            for s in &mut self.structs {
                if verified_tag_structs.contains(&s.name) {
                    s.is_verified_tag_struct = true;
                    self.verified_wlan_idents.insert(s.name.clone());
                    self.verified_wlan_non_fn_idents.insert(s.name.clone());
                    self.verified_wlan_spans.push(s.span);
                }
            }
        }

        {
            let sets = VerifiedWlanSets {
                sanitizers: &verified_sanitizers,
                validators: &verified_validators,
                tag_helpers: &verified_tag_helpers,
                tag_structs: &verified_tag_structs,
                all_fns: &self.fns,
            };
            for (i, f) in self.fns.iter().enumerate() {
                unsafe_extractions[i] = f.has_thread_spawn
                    || f.has_global_state_sink
                    || block_has_unsafe_wlan_slice_flow(blocks[i], f, &sets);
            }
        }

        let mut wrapper_verified = primary_verified.clone();
        let mut w_changed = true;
        while w_changed {
            w_changed = false;
            let known_sanitizers: HashSet<String> = self
                .fns
                .iter()
                .enumerate()
                .filter(|(i, _)| wrapper_verified[*i])
                .map(|(_, f)| f.name.clone())
                .chain(
                    seed_cross_crate
                        .iter()
                        .filter(|n| n.starts_with("sanitize_"))
                        .cloned(),
                )
                .collect();

            {
                let cur_sets = VerifiedWlanSets {
                    sanitizers: &known_sanitizers,
                    validators: &verified_validators,
                    tag_helpers: &verified_tag_helpers,
                    tag_structs: &verified_tag_structs,
                    all_fns: &self.fns,
                };
                for (i, f) in self.fns.iter().enumerate() {
                    if !wrapper_verified[i]
                        && unsafe_extractions[i]
                        && !f.has_thread_spawn
                        && !f.has_global_state_sink
                        && (f.wlan_kind == Some(WlanHelperKind::PrimarySanitizer)
                            || f.name.starts_with("sanitize_")
                            || f.name.starts_with("redact_"))
                    {
                        unsafe_extractions[i] =
                            block_has_unsafe_wlan_slice_flow(blocks[i], f, &cur_sets);
                    }
                }
            }

            for (i, f) in self.fns.iter().enumerate() {
                if wrapper_verified[i] {
                    continue;
                }
                let lower = f.name.to_ascii_lowercase();
                let is_sanitizer_named = f.wlan_kind == Some(WlanHelperKind::PrimarySanitizer)
                    || (!lower.contains("unredact")
                        && (lower.starts_with("sanitize_") || lower.starts_with("redact_")));
                if !is_sanitizer_named {
                    continue;
                }
                if f.has_exec_sink
                    || f.has_io_sink
                    || f.has_thread_spawn
                    || f.has_global_state_sink
                    || has_dangerous_wlan_fn_verb(&f.name, false)
                    || !wlan_mut_params_ok(f, true)
                {
                    continue;
                }
                let calls_unverified_tag_helper = f.callees.iter().any(|c| {
                    all_tag_helpers.contains(c) && !verified_tag_helpers.contains(c)
                });
                if calls_unverified_tag_helper {
                    continue;
                }
                let block = blocks[i];
                let has_unsafe_flow = unsafe_extractions[i];
                let mut_json_ok = self.file_has_verified_primary
                    && !has_unsafe_flow
                    && f.ret_type_str
                        .as_deref()
                        .is_none_or(|r| r == "()" || is_non_secret_error_result(r))
                    && !f.mut_param_types.is_empty()
                    && f.mut_param_types
                        .iter()
                        .all(|t| t == "&mutValue" || t == "&mutserde_json::Value")
                    && !f.has_slice_or_split
                    && f.callees.iter().any(|c| known_sanitizers.contains(c));
                let json_mask_helper_ok = f.name == "sanitize_json_substrings_and_mask"
                    && known_sanitizers.contains("sanitize_json_value_r4_inner")
                    && f.ret_type_str.as_deref() == Some("(String,String,Vec<String>)")
                    && block_has_live_deserializer_cursor_loop(block);
                if mut_json_ok
                    || (!has_unsafe_flow
                        && self.file_has_verified_primary
                        && (json_mask_helper_ok
                            || block_is_valid_sanitizer_wrapper(block, f, &known_sanitizers, &verified_validators)))
                {
                    wrapper_verified[i] = true;
                    verified_sanitizers.insert(f.name.clone());
                    w_changed = true;
                }
            }
        }

        let mut val_wrapper = validator_verified.clone();
        let mut vw_changed = true;
        while vw_changed {
            vw_changed = false;
            let mut newly_verified_vals: Vec<(usize, String)> = Vec::new();
            {
                let sets = VerifiedWlanSets {
                    sanitizers: &verified_sanitizers,
                    validators: &verified_validators,
                    tag_helpers: &verified_tag_helpers,
                    tag_structs: &verified_tag_structs,
                    all_fns: &self.fns,
                };
                for (i, f) in self.fns.iter().enumerate() {
                    if val_wrapper[i]
                        || f.wlan_kind != Some(WlanHelperKind::Validator)
                        || f.has_thread_spawn
                        || f.has_global_state_sink
                    {
                        continue;
                    }
                    if is_genuine_validator_fn(
                        f,
                        blocks[i],
                        unsafe_extractions[i],
                        self.file_has_verified_validator,
                        &sets,
                        mask_json_span_safe,
                    ) && f.callees.iter().any(|c| verified_validators.contains(c))
                    {
                        newly_verified_vals.push((i, f.name.clone()));
                    }
                }
            }
            for (i, name) in newly_verified_vals {
                val_wrapper[i] = true;
                verified_validators.insert(name);
                vw_changed = true;
            }
        }

        let mut mask_verified = vec![false; self.fns.len()];
        for (i, f) in self.fns.iter().enumerate() {
            if f.name.starts_with("mask_")
                && !f.has_exec_sink
                && !f.has_io_sink
                && !f.has_thread_spawn
                && !f.has_global_state_sink
                && !f.has_mut_param
                && !unsafe_extractions[i]
                && (f.ret_type_str.as_deref() == Some("Option<Vec<u8>>")
                    || (f.name == "mask_html_tags_for_json_scan_with_options"
                        && f.ret_type_str.as_deref() == Some("(Vec<u8>,bool)")
                        && self.file_has_verified_wlan)
                    || (f.name == "mask_html_tags_for_json_scan_detailed"
                        && f.ret_type_str.as_deref() == Some("MaskHtmlJsonResult")
                        && self.file_has_verified_wlan))
                && block_is_safe_mask_helper(blocks[i])
            {
                mask_verified[i] = true;
            }
        }

        for i in 0..self.fns.len() {
            let is_ver = wrapper_verified[i]
                || val_wrapper[i]
                || mask_verified[i]
                || verified_tag_helpers.contains(&self.fns[i].name);
            self.fns[i].is_verified_wlan = is_ver;
            self.fns[i].has_unsafe_wlan_extraction = unsafe_extractions[i];
            if unsafe_extractions[i] || (self.fns[i].wlan_kind.is_some() && !is_ver) {
                self.unsafe_wlan_fn_ids.insert(self.fns[i].id);
            }
            if is_ver {
                self.verified_wlan_idents.insert(self.fns[i].name.clone());
                self.verified_wlan_spans.push(self.fns[i].span);
                for p in &self.fns[i].param_names {
                    self.verified_wlan_non_fn_idents.insert(p.clone());
                }
                let fn_id = self.fns[i].id;
                for b in &self.bindings {
                    if b.fn_id == Some(fn_id) {
                        self.verified_wlan_non_fn_idents.insert(b.ident.clone());
                    }
                }
            }
        }
    }

    pub fn is_safe_string_literal(
        &self,
        content: &str,
        lit_start: usize,
        lit_end: usize,
        rule_id: &str,
        matched: &str,
    ) -> bool {
        let in_test = self.in_test_context(lit_start);
        let enc_fn = self.enclosing_fn(lit_start);

        if let Some(f) = enc_fn {
            if f.has_exec_sink || f.has_io_sink {
                return false;
            }
            if rule_id == "R4-API-CRED-05"
                && (f.has_unsafe_wlan_extraction || (in_test && f.has_slice_or_split))
            {
                return false;
            }
        }

        if rule_id == "R4-API-CRED-05"
            && matched.eq_ignore_ascii_case("keymaterial")
            && !self.file_has_wlan_get_profile
        {
            let exact_lit = content.get(lit_start..lit_end).unwrap_or("");
            let exact_lower = exact_lit.to_ascii_lowercase();
            let lit_unprefixed = exact_lower.strip_prefix('b').unwrap_or(&exact_lower);

            if let Some(f) = enc_fn
                && f.is_verified_wlan
                && (exact_lower.contains("[redacted]")
                    || lit_unprefixed == "\"keymaterial\""
                    || lit_unprefixed == "\":keymaterial\""
                    || lit_unprefixed == "\"<keymaterial\""
                    || lit_unprefixed == "\"<keymaterial>\""
                    || lit_unprefixed == "\"<keymaterial/>\""
                    || lit_unprefixed == "\"</keymaterial\""
                    || lit_unprefixed == "\"</keymaterial>\""
                    || (f.wlan_kind == Some(WlanHelperKind::Validator)
                        && self.is_lit_in_safe_assertion_or_rejection_stmt(
                            f.id, lit_start, lit_end, rule_id,
                        )))
            {
                return true;
            }

            if self.call_arg_spans.iter().any(|ca| {
                !ca.is_empty_str_only
                    && !ca.has_return_or_block
                    && lit_start >= ca.span.0
                    && lit_end <= ca.span.1
                    && (ca.callee_name == "sanitize_wlan_profile_xml"
                        || ca.callee_name.starts_with("redact_wlan"))
                    && (self.fns.iter().any(|f| {
                        f.name == ca.callee_name
                            && f.is_verified_wlan
                            && f.wlan_kind == Some(WlanHelperKind::PrimarySanitizer)
                    }) || (!self.fns.iter().any(|f| f.name == ca.callee_name)
                        && is_known_cross_crate_wlan_ident(&ca.callee_name)))
            }) {
                return true;
            }

            if in_test {
                if let Some(f) = enc_fn {
                    if !f.has_exec_sink
                        && !f.has_io_sink
                        && !f.has_slice_or_split
                        && !has_dangerous_wlan_test_fn_verb(&f.name)
                        && (exact_lower.contains("[redacted]")
                            || self.fn_is_genuine_keymaterial_test(f, lit_start, lit_end))
                    {
                        return true;
                    }
                } else if self.is_binding_used_safely_in_keymaterial_tests(lit_start, lit_end) {
                    return true;
                }
            }
        }

        if self.is_denylist_binding_safe(lit_start, lit_end, in_test) {
            return true;
        }

        if in_test && let Some(f) = enc_fn {
            if f.has_exec_sink || f.has_io_sink {
                return false;
            }
            if rule_id == "R4-API-CRED-05" && f.has_slice_or_split {
                return false;
            }
            if self.is_lit_in_safe_assertion_or_rejection_stmt(f.id, lit_start, lit_end, rule_id) {
                return true;
            }
            if self.is_lit_bound_only_to_safe_assertions(f.id, lit_start, lit_end, rule_id) {
                return true;
            }
        }

        false
    }

    pub fn fn_is_genuine_keymaterial_test(&self, f: &FnInfo, lit_start: usize, lit_end: usize) -> bool {
        let fn_has_check = f.callees.iter().any(|c| {
            c.starts_with("sanitize_")
                || c.starts_with("redact_")
                || c.starts_with("parse_wlan")
                || c.starts_with("set_connection_mode")
                || c.starts_with("assert_r4_clean")
                || c == "render_report"
                || c == "verify_markdown_table_cell"
                || c == "check_html_tag_attributes"
                || c == "assert_leaks_redacted"
                || c == "assert_clean_csv_preserved"
        }) || self.macro_calls.iter().any(|m| {
            m.span.0 >= f.span.0
                && m.span.1 <= f.span.1
                && (m.name == "assert" || m.name == "assert_eq" || m.name == "assert_ne")
        });
        if !fn_has_check {
            return false;
        }
        let in_call_or_macro = self
            .call_arg_spans
            .iter()
            .any(|ca| lit_start >= ca.span.0 && lit_end <= ca.span.1)
            || self
                .macro_calls
                .iter()
                .any(|m| lit_start >= m.span.0 && lit_end <= m.span.1);
        if in_call_or_macro {
            return true;
        }
        if let Some(b) = self.bindings.iter().find(|b| {
            b.fn_id == Some(f.id) && lit_start >= b.init_span.0 && lit_end <= b.init_span.1
        }) {
            if b.ident.starts_with('_') {
                return false;
            }
            return self.ident_uses.get(&b.ident).is_some_and(|uses| {
                uses.iter()
                    .any(|&(pos, fid)| fid == Some(f.id) && pos > b.decl_span.1)
            });
        }
        if let Some((_, rsp, base)) = self.assign_targets.iter().find(|(fid, rsp, _)| {
            *fid == f.id && lit_start >= rsp.0 && lit_end <= rsp.1
        }) {
            if base.starts_with('_') {
                return false;
            }
            return self.ident_uses.get(base).is_some_and(|uses| {
                uses.iter()
                    .any(|&(pos, fid)| fid == Some(f.id) && pos > rsp.1)
            });
        }
        false
    }

    fn is_binding_used_safely_in_keymaterial_tests(
        &self,
        lit_start: usize,
        lit_end: usize,
    ) -> bool {
        let Some(b) = self.bindings.iter().find(|b| {
            b.fn_id.is_none() && lit_start >= b.init_span.0 && lit_end <= b.init_span.1
        }) else {
            return false;
        };
        if b.ident.starts_with('_') {
            return false;
        }
        let Some(uses) = self.ident_uses.get(&b.ident) else {
            return false;
        };
        let mut saw_safe_use = false;
        for &(pos, fid) in uses {
            if pos >= b.decl_span.0 && pos <= b.decl_span.1 {
                continue;
            }
            if !self.in_test_context(pos) {
                return false;
            }
            let Some(fid) = fid else {
                return false;
            };
            let f = &self.fns[fid];
            if f.has_exec_sink || f.has_io_sink || f.has_slice_or_split {
                return false;
            }
            if f.callees.iter().any(|c| {
                c.starts_with("sanitize_")
                    || c.starts_with("parse_wlan")
                    || c.starts_with("set_connection_mode")
                    || c.starts_with("assert_r4_clean")
                    || c == "render_report"
            }) {
                saw_safe_use = true;
            }
        }
        saw_safe_use
    }

    fn is_lit_in_safe_assertion_or_rejection_stmt(
        &self,
        fn_id: usize,
        lit_start: usize,
        lit_end: usize,
        rule_id: &str,
    ) -> bool {
        let in_neg_assert_macro = self.macro_calls.iter().any(|m| {
            m.is_negative_assert
                && !m.has_sink
                && lit_start >= m.span.0
                && lit_end <= m.span.1
        });
        if in_neg_assert_macro {
            if rule_id == "R4-API-CRED-05" {
                return self.fns[fn_id].callees.iter().any(|c| {
                    c.starts_with("assert_r4_clean")
                        || c.starts_with("sanitize_")
                        || c.starts_with("parse_wlan")
                        || c.starts_with("set_connection_mode")
                        || c == "render_report"
                }) || self.macro_calls.iter().any(|m| {
                    m.is_negative_assert
                        && lit_start >= m.span.0
                        && lit_end <= m.span.1
                        && !m.has_sink
                });
            }
            return true;
        }

        if let Some(stmt) = self
            .stmts
            .iter()
            .filter(|s| s.fn_id == Some(fn_id) && lit_start >= s.span.0 && lit_end <= s.span.1)
            .min_by_key(|s| s.span.1 - s.span.0)
            && stmt.is_rejection_stmt
        {
            return true;
        }

        false
    }

    fn is_lit_bound_only_to_safe_assertions(
        &self,
        fn_id: usize,
        lit_start: usize,
        lit_end: usize,
        rule_id: &str,
    ) -> bool {
        let Some(b) = self.bindings.iter().find(|b| {
            b.fn_id == Some(fn_id) && lit_start >= b.init_span.0 && lit_end <= b.init_span.1
        }) else {
            return false;
        };
        if b.ident.starts_with('_') {
            return false;
        }
        let Some(uses) = self.ident_uses.get(&b.ident) else {
            return false;
        };
        let mut saw_safe_use = false;
        for &(pos, u_fid) in uses {
            if u_fid != Some(fn_id) {
                continue;
            }
            if pos >= b.decl_span.0 && pos <= b.decl_span.1 {
                continue;
            }
            if self.is_lit_in_safe_assertion_or_rejection_stmt(
                fn_id,
                pos,
                pos + b.ident.len(),
                rule_id,
            ) {
                saw_safe_use = true;
                continue;
            }
            if let Some(stmt) = self
                .stmts
                .iter()
                .filter(|s| s.fn_id == Some(fn_id) && pos >= s.span.0 && pos <= s.span.1)
                .min_by_key(|s| s.span.1 - s.span.0)
                && stmt.is_rejection_stmt
            {
                saw_safe_use = true;
                continue;
            }
            return false;
        }
        saw_safe_use
    }

    fn is_denylist_binding_safe(&self, lit_start: usize, lit_end: usize, in_test: bool) -> bool {
        let Some(root_b) = self
            .bindings
            .iter()
            .filter(|b| {
                b.is_array_or_vec
                    && b.is_denylist_name
                    && lit_start >= b.init_span.0
                    && lit_end <= b.init_span.1
            })
            .min_by_key(|b| b.init_span.1 - b.init_span.0)
        else {
            return false;
        };

        let mut tracked: Vec<(String, Option<usize>, (usize, usize))> = vec![(
            root_b.ident.clone(),
            root_b.fn_id,
            root_b.decl_span,
        )];
        let mut alias_changed = true;
        while alias_changed {
            alias_changed = false;
            let current_names: Vec<String> = tracked.iter().map(|(n, _, _)| n.clone()).collect();
            for b in &self.bindings {
                if tracked
                    .iter()
                    .any(|(n, fid, sp)| *n == b.ident && *fid == b.fn_id && *sp == b.decl_span)
                {
                    continue;
                }
                let references_tracked = current_names.iter().any(|name| {
                    self.ident_uses.get(name).is_some_and(|uses| {
                        uses.iter().any(|&(pos, fid)| {
                            fid == b.fn_id && pos >= b.init_span.0 && pos <= b.init_span.1
                        })
                    })
                });
                if references_tracked {
                    tracked.push((b.ident.clone(), b.fn_id, b.decl_span));
                    alias_changed = true;
                }
            }
        }

        let mut saw_rejection_or_scan_assert = false;

        for (name, scope_fn_id, decl_span) in &tracked {
            let is_const_or_denylist = self.bindings.iter().any(|b| {
                b.ident == *name
                    && b.fn_id == *scope_fn_id
                    && b.decl_span == *decl_span
                    && (b.is_const_or_static || b.is_denylist_name)
            });
            let Some(uses) = self.ident_uses.get(name) else {
                if is_const_or_denylist {
                    return false;
                }
                continue;
            };
            let mut this_binding_has_safe_use = false;
            for &(pos, u_fid) in uses {
                if u_fid == *scope_fn_id && pos >= decl_span.0 && pos <= decl_span.1 {
                    continue;
                }
                let in_tracked_alias_init = tracked.iter().any(|(_, afid, adecl)| {
                    *afid == u_fid
                        && self.bindings.iter().any(|b| {
                            b.fn_id == *afid
                                && b.decl_span == *adecl
                                && pos >= b.init_span.0
                                && pos <= b.init_span.1
                        })
                });
                if in_tracked_alias_init {
                    this_binding_has_safe_use = true;
                    continue;
                }
                let Some(fid) = u_fid else {
                    return false;
                };
                let f = &self.fns[fid];
                if f.has_exec_sink || f.has_io_sink {
                    return false;
                }
                let fn_stmts: Vec<&StmtEntry> = self
                    .stmts
                    .iter()
                    .filter(|s| s.fn_id == Some(fid))
                    .collect();
                let test_asserts_violations_for_fn = in_test
                    && self.in_test_context(f.span.0)
                    && self.fns.iter().any(|tf| {
                        !tf.has_exec_sink
                            && !tf.has_io_sink
                            && self.in_test_context(tf.span.0)
                            && tf.callees.contains(&f.name)
                            && self.stmts.iter().any(|ts| {
                                ts.fn_id == Some(tf.id)
                                    && (ts.text_compact.contains("violations.is_empty()")
                                        || ts.text_compact.contains("assert!(violations.is_empty()")
                                        || ts.text_compact.contains("assert_eq!(violations"))
                            })
                    });
                let fn_has_rejection = fn_stmts.iter().any(|s| {
                    if in_test && self.in_test_context(f.span.0) {
                        s.is_rejection_stmt
                            || s.text_compact.contains("violations.is_empty()")
                            || s.text_compact.contains("assert!(violations")
                            || s.text_compact.contains("assert_eq!(violations")
                            || s.text_compact.contains("assert_r4_clean")
                            || (test_asserts_violations_for_fn
                                && s.text_compact.contains("violations.push("))
                    } else {
                        s.is_runtime_rejection
                            || (test_asserts_violations_for_fn
                                && s.text_compact.contains("violations.push("))
                    }
                }) || (in_test
                    && self.in_test_context(f.span.0)
                    && f.callees.iter().any(|c| {
                        self.fns.iter().any(|hf| {
                            hf.name == *c
                                && self.in_test_context(hf.span.0)
                                && !hf.has_exec_sink
                                && !hf.has_io_sink
                                && self.stmts.iter().any(|hs| {
                                    hs.fn_id == Some(hf.id) && hs.is_rejection_stmt
                                })
                        })
                    }));
                if fn_has_rejection {
                    saw_rejection_or_scan_assert = true;
                    this_binding_has_safe_use = true;
                } else {
                    return false;
                }
            }
            if !this_binding_has_safe_use {
                return false;
            }
        }

        saw_rejection_or_scan_assert
    }
}
fn lc_to_byte_in_str(content: &str, line_starts: &[usize], lc: proc_macro2::LineColumn) -> usize {
    if lc.line == 0 || line_starts.is_empty() {
        return 0;
    }
    let line_idx = (lc.line - 1).min(line_starts.len() - 1);
    let ls = line_starts[line_idx];
    let le = if line_idx + 1 < line_starts.len() {
        line_starts[line_idx + 1]
    } else {
        content.len()
    };
    let line_str = &content[ls..le];
    match line_str.char_indices().nth(lc.column) {
        Some((off, _)) => ls + off,
        None => le,
    }
}

fn attrs_indicate_test(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("test") {
            return true;
        }
        if attr
            .path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "test")
        {
            return true;
        }
        if attr.path().is_ident("cfg")
            && let Ok(list) = attr.meta.require_list()
            && cfg_tokens_have_positive_test(&list.tokens)
        {
            return true;
        }
    }
    false
}

fn split_cfg_predicates(tokens: &TokenStream) -> Vec<Vec<TokenTree>> {
    let mut preds: Vec<Vec<TokenTree>> = Vec::new();
    let mut cur: Vec<TokenTree> = Vec::new();
    for tt in tokens.clone() {
        if let TokenTree::Punct(p) = &tt
            && p.as_char() == ','
        {
            if !cur.is_empty() {
                preds.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(tt);
        }
    }
    if !cur.is_empty() {
        preds.push(cur);
    }
    preds
}

fn single_cfg_pred_is_test_only(tts: &[TokenTree]) -> bool {
    match tts {
        [TokenTree::Ident(id)] => id == "test",
        [TokenTree::Ident(id), TokenTree::Group(g)] => {
            if id == "not" {
                false
            } else if id == "all" {
                cfg_tokens_have_positive_test(&g.stream())
            } else if id == "any" {
                let preds = split_cfg_predicates(&g.stream());
                !preds.is_empty() && preds.iter().all(|p| single_cfg_pred_is_test_only(p))
            } else {
                false
            }
        }
        _ => false,
    }
}

fn cfg_tokens_have_positive_test(tokens: &TokenStream) -> bool {
    let preds = split_cfg_predicates(tokens);
    !preds.is_empty() && preds.iter().any(|p| single_cfg_pred_is_test_only(p))
}

struct RawFnEntry<'a> {
    name: String,
    is_method: bool,
    span: (usize, usize),
    header_end: usize,
    has_mut_param: bool,
    mut_param_types: Vec<String>,
    param_names: Vec<String>,
    mut_param_names: Vec<String>,
    ret_type_str: Option<String>,
    block: &'a Block,
}

struct FileCollector<'b, 'a> {
    content: &'a str,
    line_starts: &'b [usize],
    test_spans: Vec<(usize, usize)>,
    use_aliases: HashMap<String, String>,
    command_types: HashSet<String>,
    raw_type_aliases: Vec<(String, String)>,
    raw_macros: Vec<(String, TokenStream)>,
    enums: Vec<&'a ItemEnum>,
    raw_structs: Vec<StructInfo>,
    impl_has_leaking_method: HashSet<String>,
    raw_fns: Vec<RawFnEntry<'a>>,
    concat_strings: Vec<(usize, String)>,
    include_str_paths: Vec<(usize, String, bool)>,
}

fn eval_const_str_expr(e: &Expr) -> Option<String> {
    match e {
        Expr::Lit(el) => match &el.lit {
            syn::Lit::Str(ls) => Some(ls.value()),
            syn::Lit::Char(lc) => Some(lc.value().to_string()),
            syn::Lit::Int(li) => Some(li.base10_digits().to_string()),
            syn::Lit::Bool(lb) => Some(if lb.value { "true" } else { "false" }.to_string()),
            _ => None,
        },
        Expr::Paren(p) => eval_const_str_expr(&p.expr),
        Expr::Group(g) => eval_const_str_expr(&g.expr),
        Expr::Macro(em) => {
            if em.mac.path.segments.last().is_some_and(|s| s.ident == "concat") {
                eval_concat_tokens(&em.mac.tokens)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn eval_concat_tokens(tokens: &TokenStream) -> Option<String> {
    let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
    let exprs = syn::parse::Parser::parse2(parser, tokens.clone()).ok()?;
    let mut joined = String::new();
    for e in exprs {
        if let Some(part) = eval_const_str_expr(&e) {
            joined.push_str(&part);
        }
    }
    (!joined.is_empty()).then_some(joined)
}

impl<'b, 'a> FileCollector<'b, 'a> {
    fn span_pair(&self, sp_start: Span, sp_end: Span) -> (usize, usize) {
        let s = lc_to_byte_in_str(self.content, self.line_starts, sp_start.start());
        let e = lc_to_byte_in_str(self.content, self.line_starts, sp_end.end());
        (s, e.max(s))
    }

    fn attr_start(&self, attrs: &[Attribute], fallback: Span) -> Span {
        attrs.first().map_or(fallback, |a| a.pound_token.span)
    }

    fn record_test_attrs(&mut self, attrs: &[Attribute], sp_start: Span, sp_end: Span, allow_span: bool) {
        if allow_span && attrs_indicate_test(attrs) {
            self.test_spans.push(self.span_pair(self.attr_start(attrs, sp_start), sp_end));
        }
    }

    fn record_fn(
        &mut self,
        name: String,
        is_method: bool,
        attrs: &[Attribute],
        sig: &syn::Signature,
        block: &'a Block,
    ) {
        let mut has_mut_param = false;
        let mut mut_param_types = Vec::new();
        let mut param_names = Vec::new();
        let mut mut_param_names = Vec::new();
        for arg in &sig.inputs {
            match arg {
                FnArg::Receiver(r) => {
                    param_names.push("self".to_string());
                    if r.mutability.is_some() {
                        has_mut_param = true;
                        mut_param_types.push("&mut self".to_string());
                        mut_param_names.push("self".to_string());
                    }
                }
                FnArg::Typed(pt) => {
                    let mut p_idents = Vec::new();
                    collect_pat_idents(&pt.pat, &mut p_idents);
                    param_names.extend(p_idents.iter().cloned());
                    if let Type::Reference(tr) = pt.ty.as_ref()
                        && tr.mutability.is_some()
                    {
                        has_mut_param = true;
                        mut_param_types.push(compact_type_str(&pt.ty));
                        mut_param_names.extend(p_idents);
                    }
                }
            }
        }
        let ret_type_str = match &sig.output {
            ReturnType::Default => None,
            ReturnType::Type(_, ty) => Some(compact_type_str(ty)),
        };
        let span = self.span_pair(self.attr_start(attrs, sig.fn_token.span), block.brace_token.span.close());
        let header_end = lc_to_byte_in_str(self.content, self.line_starts, block.brace_token.span.open().start());
        self.raw_fns.push(RawFnEntry {
            name,
            is_method,
            span,
            header_end,
            has_mut_param,
            mut_param_types,
            param_names,
            mut_param_names,
            ret_type_str,
            block,
        });
    }

    fn record_macro_name_tokens(&mut self, name: &str, span: Span, tokens: &TokenStream) {
        let pos = lc_to_byte_in_str(self.content, self.line_starts, span.start());
        if name == "concat" {
            if let Some(joined) = eval_concat_tokens(tokens) {
                self.concat_strings.push((pos, joined));
            }
            return;
        }
        if (name == "include_str" || name == "include_bytes")
            && let Ok(expr) = syn::parse2::<syn::Expr>(tokens.clone())
            && let Some(path_str) = eval_const_str_expr(&expr)
        {
            self.include_str_paths
                .push((pos, path_str, name == "include_bytes"));
        }
    }

    fn scan_token_stream_for_macros(&mut self, ts: &TokenStream) {
        let tts: Vec<TokenTree> = ts.clone().into_iter().collect();
        let mut i = 0usize;
        while i < tts.len() {
            match &tts[i] {
                TokenTree::Ident(id)
                    if matches!(tts.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!')
                        && matches!(tts.get(i + 2), Some(TokenTree::Group(_))) =>
                {
                    if let Some(TokenTree::Group(g)) = tts.get(i + 2) {
                        let name = id.to_string();
                        self.record_macro_name_tokens(&name, id.span(), &g.stream());
                        if name != "concat" {
                            self.scan_token_stream_for_macros(&g.stream());
                        }
                        i += 3;
                        continue;
                    }
                }
                TokenTree::Group(g) => {
                    self.scan_token_stream_for_macros(&g.stream());
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn record_concat_or_include(&mut self, mac: &syn::Macro) {
        let Some(last) = mac.path.segments.last() else {
            return;
        };
        let name = last.ident.to_string();
        self.record_macro_name_tokens(&name, last.ident.span(), &mac.tokens);
        if name != "concat" {
            self.scan_token_stream_for_macros(&mac.tokens);
        }
    }
}

impl<'b, 'a> Visit<'a> for FileCollector<'b, 'a> {
    fn visit_item(&mut self, item: &'a Item) {
        match item {
            Item::Mod(m) => {
                let end_sp = m.content.as_ref().map_or_else(
                    || m.semi.as_ref().map_or(m.ident.span(), |s| s.span),
                    |(brace, _)| brace.span.close(),
                );
                self.record_test_attrs(&m.attrs, m.mod_token.span, end_sp, m.content.is_some());
                visit::visit_item_mod(self, m);
            }
            Item::Fn(f) => {
                self.record_test_attrs(&f.attrs, f.sig.fn_token.span, f.block.brace_token.span.close(), true);
                self.record_fn(f.sig.ident.to_string(), false, &f.attrs, &f.sig, &f.block);
                visit::visit_item_fn(self, f);
            }
            Item::Struct(s) => {
                let end_sp = match &s.fields {
                    Fields::Named(n) => n.brace_token.span.close(),
                    Fields::Unnamed(u) => s.semi_token.as_ref().map_or(u.paren_token.span.close(), |sm| sm.span),
                    Fields::Unit => s.semi_token.as_ref().map_or(s.ident.span(), |sm| sm.span),
                };
                self.record_test_attrs(&s.attrs, s.struct_token.span, end_sp, true);
                let fields = match &s.fields {
                    Fields::Named(n) => n.named.iter().map(|f| SimpleType::from_syn(&f.ty)).collect(),
                    Fields::Unnamed(u) => u.unnamed.iter().map(|f| SimpleType::from_syn(&f.ty)).collect(),
                    Fields::Unit => Vec::new(),
                };
                self.raw_structs.push(StructInfo {
                    name: s.ident.to_string(),
                    span: self.span_pair(self.attr_start(&s.attrs, s.struct_token.span), end_sp),
                    fields,
                    is_verified_tag_struct: false,
                });
            }
            Item::Enum(e) => {
                self.record_test_attrs(&e.attrs, e.enum_token.span, e.brace_token.span.close(), true);
                self.enums.push(e);
            }
            Item::Impl(imp) => {
                self.record_test_attrs(&imp.attrs, imp.impl_token.span, imp.brace_token.span.close(), true);
                let self_ty_name = last_path_ident(&imp.self_ty);
                for ii in &imp.items {
                    if let syn::ImplItem::Fn(mf) = ii {
                        if let Some(ref st_name) = self_ty_name
                            && matches!(&mf.sig.output, ReturnType::Type(_, ty) if {
                                let ct = compact_type_str(ty);
                                ct.contains("String") || ct.contains("&str") || ct.contains("Vec<u8>") || ct.contains("&[")
                            })
                        {
                            self.impl_has_leaking_method.insert(st_name.clone());
                        }
                        self.record_test_attrs(&mf.attrs, mf.sig.fn_token.span, mf.block.brace_token.span.close(), true);
                        self.record_fn(mf.sig.ident.to_string(), true, &mf.attrs, &mf.sig, &mf.block);
                        visit::visit_impl_item_fn(self, mf);
                    }
                }
            }
            Item::Trait(tr) => {
                self.record_test_attrs(&tr.attrs, tr.trait_token.span, tr.brace_token.span.close(), true);
                for ti in &tr.items {
                    if let syn::TraitItem::Fn(tf) = ti
                        && let Some(ref blk) = tf.default
                    {
                        self.record_fn(tf.sig.ident.to_string(), true, &tf.attrs, &tf.sig, blk);
                        visit::visit_trait_item_fn(self, tf);
                    }
                }
            }
            Item::Use(u) => {
                self.record_test_attrs(&u.attrs, u.use_token.span, u.semi_token.span, true);
                collect_use_tree(
                    &u.tree,
                    &mut Vec::new(),
                    &mut self.use_aliases,
                    &mut self.command_types,
                );
            }
            Item::Type(t) => {
                self.record_test_attrs(&t.attrs, t.type_token.span, t.semi_token.span, true);
                if let Some(last) = last_path_ident(&t.ty) {
                    self.raw_type_aliases.push((t.ident.to_string(), last));
                }
            }
            Item::Macro(m) => {
                let end_sp = m.semi_token.as_ref().map_or_else(
                    || match &m.mac.delimiter {
                        syn::MacroDelimiter::Paren(p) => p.span.close(),
                        syn::MacroDelimiter::Brace(b) => b.span.close(),
                        syn::MacroDelimiter::Bracket(b) => b.span.close(),
                    },
                    |s| s.span,
                );
                let start_sp = m.mac.path.segments.first().map_or(end_sp, |s| s.ident.span());
                self.record_test_attrs(&m.attrs, start_sp, end_sp, true);
                if m.mac.path.is_ident("macro_rules")
                    && let Some(id) = &m.ident
                {
                    self.raw_macros.push((id.to_string(), m.mac.tokens.clone()));
                } else {
                    self.record_concat_or_include(&m.mac);
                }
            }
            Item::Const(c) => {
                self.record_test_attrs(&c.attrs, c.const_token.span, c.semi_token.span, true);
                visit::visit_item_const(self, c);
            }
            Item::Static(st) => {
                self.record_test_attrs(&st.attrs, st.static_token.span, st.semi_token.span, true);
                visit::visit_item_static(self, st);
            }
            _ => visit::visit_item(self, item),
        }
    }

    fn visit_macro(&mut self, mac: &'a syn::Macro) {
        self.record_concat_or_include(mac);
        visit::visit_macro(self, mac);
    }

    fn visit_item_mod(&mut self, i: &'a ItemMod) {
        let end_sp = i.content.as_ref().map_or_else(
            || i.semi.as_ref().map_or(i.ident.span(), |s| s.span),
            |(brace, _)| brace.span.close(),
        );
        self.record_test_attrs(&i.attrs, i.mod_token.span, end_sp, i.content.is_some());
        visit::visit_item_mod(self, i);
    }

    fn visit_item_fn(&mut self, i: &'a ItemFn) {
        self.record_test_attrs(&i.attrs, i.sig.fn_token.span, i.block.brace_token.span.close(), true);
        self.record_fn(i.sig.ident.to_string(), false, &i.attrs, &i.sig, &i.block);
        visit::visit_item_fn(self, i);
    }

    fn visit_impl_item_fn(&mut self, i: &'a ImplItemFn) {
        self.record_test_attrs(&i.attrs, i.sig.fn_token.span, i.block.brace_token.span.close(), true);
        self.record_fn(i.sig.ident.to_string(), true, &i.attrs, &i.sig, &i.block);
        visit::visit_impl_item_fn(self, i);
    }

    fn visit_trait_item_fn(&mut self, i: &'a TraitItemFn) {
        if let Some(ref blk) = i.default {
            self.record_fn(i.sig.ident.to_string(), true, &i.attrs, &i.sig, blk);
        }
        visit::visit_trait_item_fn(self, i);
    }

    fn visit_item_use(&mut self, i: &'a ItemUse) {
        collect_use_tree(
            &i.tree,
            &mut Vec::new(),
            &mut self.use_aliases,
            &mut self.command_types,
        );
    }

    fn visit_item_type(&mut self, i: &'a ItemType) {
        if let Some(last) = last_path_ident(&i.ty) {
            self.raw_type_aliases.push((i.ident.to_string(), last));
        }
    }

    fn visit_item_struct(&mut self, i: &'a ItemStruct) {
        let end_sp = match &i.fields {
            Fields::Named(n) => n.brace_token.span.close(),
            Fields::Unnamed(u) => i.semi_token.as_ref().map_or(u.paren_token.span.close(), |sm| sm.span),
            Fields::Unit => i.semi_token.as_ref().map_or(i.ident.span(), |sm| sm.span),
        };
        let fields = match &i.fields {
            Fields::Named(n) => n.named.iter().map(|f| SimpleType::from_syn(&f.ty)).collect(),
            Fields::Unnamed(u) => u.unnamed.iter().map(|f| SimpleType::from_syn(&f.ty)).collect(),
            Fields::Unit => Vec::new(),
        };
        self.raw_structs.push(StructInfo {
            name: i.ident.to_string(),
            span: self.span_pair(self.attr_start(&i.attrs, i.struct_token.span), end_sp),
            fields,
            is_verified_tag_struct: false,
        });
    }

    fn visit_item_macro(&mut self, i: &'a ItemMacro) {
        if i.mac.path.is_ident("macro_rules")
            && let Some(id) = &i.ident
        {
            self.raw_macros.push((id.to_string(), i.mac.tokens.clone()));
        }
    }
}
fn collect_use_tree(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    use_aliases: &mut HashMap<String, String>,
    command_types: &mut HashSet<String>,
) {
    match tree {
        UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            collect_use_tree(&p.tree, prefix, use_aliases, command_types);
            prefix.pop();
        }
        UseTree::Name(n) => {
            let name = n.ident.to_string();
            if name == "Command" && prefix.iter().any(|s| s == "process") {
                command_types.insert(name);
            }
        }
        UseTree::Rename(r) => {
            let orig = r.ident.to_string();
            let ren = r.rename.to_string();
            use_aliases.insert(ren.clone(), orig.clone());
            if orig == "Command" {
                command_types.insert(ren);
            }
        }
        UseTree::Group(g) => {
            for item in &g.items {
                collect_use_tree(item, prefix, use_aliases, command_types);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn last_path_ident(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(tp) => tp.path.segments.last().map(|s| s.ident.to_string()),
        Type::Reference(tr) => last_path_ident(&tr.elem),
        Type::Paren(tp) => last_path_ident(&tp.elem),
        Type::Group(tg) => last_path_ident(&tg.elem),
        _ => None,
    }
}

fn compact_type_str(ty: &Type) -> String {
    let ts = quote_type_compact(ty);
    ts.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn quote_type_compact(ty: &Type) -> String {
    match ty {
        Type::Path(tp) => {
            let mut out = String::new();
            for (idx, seg) in tp.path.segments.iter().enumerate() {
                if idx > 0 {
                    out.push_str("::");
                }
                out.push_str(&seg.ident.to_string());
                if let PathArguments::AngleBracketed(ab) = &seg.arguments {
                    out.push('<');
                    for (ai, arg) in ab.args.iter().enumerate() {
                        if ai > 0 {
                            out.push(',');
                        }
                        match arg {
                            GenericArgument::Lifetime(lt) => {
                                out.push('\'');
                                out.push_str(&lt.ident.to_string());
                            }
                            GenericArgument::Type(inner) => out.push_str(&quote_type_compact(inner)),
                            _ => out.push('_'),
                        }
                    }
                    out.push('>');
                }
            }
            out
        }
        Type::Reference(tr) => {
            let mut out = String::from("&");
            if let Some(lt) = &tr.lifetime {
                out.push('\'');
                out.push_str(&lt.ident.to_string());
            }
            if tr.mutability.is_some() {
                out.push_str("mut");
            }
            out.push_str(&quote_type_compact(&tr.elem));
            out
        }
        Type::Tuple(tt) => {
            if tt.elems.is_empty() {
                return "()".to_string();
            }
            let inner: Vec<String> = tt.elems.iter().map(quote_type_compact).collect();
            format!("({})", inner.join(","))
        }
        Type::Slice(ts) => format!("[{}]", quote_type_compact(&ts.elem)),
        Type::Array(ta) => format!("[{};_]", quote_type_compact(&ta.elem)),
        Type::Ptr(tp) => {
            let mut_s = if matches!(tp.mutability, syn::PointerMutability::Mut(_)) { "*mut" } else { "*const" };
            format!("{mut_s}{}", quote_type_compact(&tp.elem))
        }
        _ => "Other".to_string(),
    }
}

#[derive(Debug, Clone)]
enum FlatTok {
    Ident(String),
    Punct(char),
    Group(Delimiter, Vec<FlatTok>),
}

fn flatten_tokens(ts: &TokenStream) -> Vec<FlatTok> {
    let mut out = Vec::new();
    for tt in ts.clone() {
        match tt {
            TokenTree::Ident(id) => out.push(FlatTok::Ident(id.to_string())),
            TokenTree::Punct(p) => out.push(FlatTok::Punct(p.as_char())),
            TokenTree::Group(g) => {
                out.push(FlatTok::Group(g.delimiter(), flatten_tokens(&g.stream())));
            }
            TokenTree::Literal(_) => {}
        }
    }
    out
}

fn scan_tokens_for_sinks(
    ts: &TokenStream,
    command_types: &HashSet<String>,
    use_aliases: &HashMap<String, String>,
) -> (SinkFlags, Vec<String>) {
    let flat = flatten_tokens(ts);
    let mut flags = SinkFlags::default();
    let mut invoked_macros = Vec::new();
    scan_flat_toks(&flat, command_types, use_aliases, &mut flags, &mut invoked_macros);
    (flags, invoked_macros)
}

fn scan_flat_toks(
    toks: &[FlatTok],
    command_types: &HashSet<String>,
    use_aliases: &HashMap<String, String>,
    flags: &mut SinkFlags,
    invoked_macros: &mut Vec<String>,
) {
    for (i, tok) in toks.iter().enumerate() {
        match tok {
            FlatTok::Group(_, inner) => {
                scan_flat_toks(inner, command_types, use_aliases, flags, invoked_macros);
            }
            FlatTok::Ident(id) => {
                if matches!(toks.get(i + 1), Some(FlatTok::Punct('!'))) {
                    if matches!(id.as_str(), "println" | "eprintln" | "print" | "dbg") {
                        flags.io = true;
                    } else if id != "macro_rules" {
                        invoked_macros.push(id.clone());
                    }
                }
                if id.starts_with("CreateProcess")
                    || id.starts_with("ShellExecute")
                    || id.starts_with("WinExec")
                    || id.starts_with("NtCreateProcess")
                    || id.starts_with("NtCreateUserProcess")
                {
                    flags.exec = true;
                }
                let resolved = use_aliases.get(id).unwrap_or(id);
                if (command_types.contains(id) || command_types.contains(resolved))
                    && matches!(toks.get(i + 1), Some(FlatTok::Punct(':')))
                    && matches!(toks.get(i + 2), Some(FlatTok::Punct(':')))
                    && let Some(FlatTok::Ident(m)) = toks.get(i + 3)
                    && matches!(m.as_str(), "new" | "spawn" | "output" | "status")
                {
                    flags.exec = true;
                }
                if matches!(id.as_str(), "spawn" | "output" | "status")
                    && i >= 3
                    && matches!(toks.get(i - 1), Some(FlatTok::Punct(':')))
                    && matches!(toks.get(i - 2), Some(FlatTok::Punct(':')))
                    && let Some(FlatTok::Ident(prev_seg)) = toks.get(i - 3)
                    && prev_seg != "thread"
                    && prev_seg != "Builder"
                {
                    flags.exec = true;
                }
                if matches!(id.as_str(), "spawn" | "output" | "status")
                    && i >= 1
                    && matches!(toks.get(i - 1), Some(FlatTok::Punct('.')))
                    && matches!(toks.get(i + 1), Some(FlatTok::Group(Delimiter::Parenthesis, _)))
                {
                    let is_thread_builder = i >= 4
                        && matches!(toks.get(i - 4), Some(FlatTok::Ident(b)) if b == "Builder");
                    if !is_thread_builder {
                        flags.exec = true;
                    }
                }
                if matches!(
                    id.as_str(),
                    "OpenOptions"
                        | "BufWriter"
                        | "TcpStream"
                        | "UdpSocket"
                        | "Mutex"
                        | "RwLock"
                        | "OnceLock"
                        | "OnceCell"
                        | "RefCell"
                        | "Cell"
                        | "static"
                ) {
                    flags.io = true;
                }
                let prev_resolved = use_aliases.get(id).unwrap_or(id);
                if prev_resolved == "fs"
                    && matches!(toks.get(i + 1), Some(FlatTok::Punct(':')))
                    && matches!(toks.get(i + 2), Some(FlatTok::Punct(':')))
                    && let Some(FlatTok::Ident(m)) = toks.get(i + 3)
                    && matches!(m.as_str(), "write" | "copy" | "rename")
                {
                    flags.io = true;
                }
                if prev_resolved == "File"
                    && matches!(toks.get(i + 1), Some(FlatTok::Punct(':')))
                    && matches!(toks.get(i + 2), Some(FlatTok::Punct(':')))
                    && let Some(FlatTok::Ident(m)) = toks.get(i + 3)
                    && matches!(m.as_str(), "create" | "create_new" | "options")
                {
                    flags.io = true;
                }
                if prev_resolved == "io"
                    && matches!(toks.get(i + 1), Some(FlatTok::Punct(':')))
                    && matches!(toks.get(i + 2), Some(FlatTok::Punct(':')))
                    && let Some(FlatTok::Ident(m)) = toks.get(i + 3)
                    && matches!(m.as_str(), "copy" | "stdout" | "stderr")
                {
                    flags.io = true;
                }
                if prev_resolved == "Write"
                    && matches!(toks.get(i + 1), Some(FlatTok::Punct(':')))
                    && matches!(toks.get(i + 2), Some(FlatTok::Punct(':')))
                    && let Some(FlatTok::Ident(m)) = toks.get(i + 3)
                    && matches!(m.as_str(), "write" | "write_all" | "write_fmt" | "write_vectored")
                {
                    flags.io = true;
                }
                if matches!(prev_resolved.as_str(), "stdout" | "stderr")
                    && matches!(toks.get(i + 1), Some(FlatTok::Group(Delimiter::Parenthesis, _)))
                {
                    flags.io = true;
                }
                if matches!(id.as_str(), "write" | "write_all" | "write_fmt" | "write_vectored")
                    && i >= 1
                    && matches!(toks.get(i - 1), Some(FlatTok::Punct('.')))
                {
                    flags.io = true;
                }
                if id == "from_utf8_unchecked" {
                    flags.io = true;
                }
            }
            FlatTok::Punct(_) => {}
        }
    }
}

struct TopBindingVisitor<'a> {
    ctx: &'a AstCtx<'a>,
    bindings: Vec<BindingInfo>,
    ident_uses: HashMap<String, Vec<(usize, Option<usize>)>>,
    call_arg_spans: Vec<CallArgSpan>,
    file_has_wlan_get_profile: bool,
}

impl<'a> Visit<'a> for TopBindingVisitor<'a> {
    fn visit_item_fn(&mut self, _i: &'a ItemFn) {}
    fn visit_impl_item_fn(&mut self, _i: &'a ImplItemFn) {}
    fn visit_trait_item_fn(&mut self, _i: &'a TraitItemFn) {}

    fn visit_item_const(&mut self, c: &'a syn::ItemConst) {
        let ident = c.ident.to_string();
        let decl_span = (
            lc_to_byte_in_str(self.ctx.content, self.ctx.line_starts, c.const_token.span.start()),
            lc_to_byte_in_str(self.ctx.content, self.ctx.line_starts, c.semi_token.span.end()),
        );
        let init_span = self.ctx.expr_bytes(&c.expr);
        self.bindings.push(BindingInfo {
            is_denylist_name: is_denylist_ident(&ident),
            ident,
            decl_span,
            init_span,
            fn_id: None,
            is_array_or_vec: expr_is_array_or_vec(&c.expr),
            is_const_or_static: true,
        });
        visit::visit_expr(self, &c.expr);
    }

    fn visit_item_static(&mut self, s: &'a syn::ItemStatic) {
        let ident = s.ident.to_string();
        let decl_span = (
            lc_to_byte_in_str(self.ctx.content, self.ctx.line_starts, s.static_token.span.start()),
            lc_to_byte_in_str(self.ctx.content, self.ctx.line_starts, s.semi_token.span.end()),
        );
        let init_span = self.ctx.expr_bytes(&s.expr);
        self.bindings.push(BindingInfo {
            is_denylist_name: is_denylist_ident(&ident),
            ident,
            decl_span,
            init_span,
            fn_id: None,
            is_array_or_vec: expr_is_array_or_vec(&s.expr),
            is_const_or_static: true,
        });
        visit::visit_expr(self, &s.expr);
    }

    fn visit_expr_path(&mut self, ep: &'a syn::ExprPath) {
        if let Some(last) = ep.path.segments.last() {
            let name = last.ident.to_string();
            if name == "WlanGetProfile" || name == "WLAN_PROFILE_GET_PLAINTEXT_KEY" {
                self.file_has_wlan_get_profile = true;
            }
            let pos = self.ctx.span_bytes(last.ident.span()).0;
            self.ident_uses.entry(name).or_default().push((pos, None));
        }
        visit::visit_expr_path(self, ep);
    }

    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let Expr::Path(ep) = call.func.as_ref()
            && let Some(last) = ep.path.segments.last()
        {
            let callee_name = last.ident.to_string();
            for arg in &call.args {
                let sp = self.ctx.expr_bytes(arg);
                self.call_arg_spans.push(CallArgSpan {
                    span: sp,
                    callee_name: callee_name.clone(),
                    is_empty_str_only: is_empty_str_expr(arg),
                    has_return_or_block: matches!(arg, Expr::Block(_) | Expr::Return(_)) || expr_contains_return(arg),
                });
            }
        }
        visit::visit_expr_call(self, call);
    }
}

struct FnBodyVisitor<'a> {
    ctx: &'a AstCtx<'a>,
    fn_id: usize,
    direct_exec_sink: bool,
    direct_io_sink: bool,
    has_thread_spawn: bool,
    has_global_state_sink: bool,
    has_slice_or_split: bool,
    has_wlan_get_profile: bool,
    callees: Vec<String>,
    method_callees: Vec<String>,
    stmts: Vec<StmtEntry>,
    macro_calls: Vec<MacroCallSpan>,
    bindings: Vec<BindingInfo>,
    call_arg_spans: Vec<CallArgSpan>,
    assign_targets: Vec<(usize, (usize, usize), String)>,
    ident_uses: HashMap<String, Vec<(usize, Option<usize>)>>,
}

impl<'a> FnBodyVisitor<'a> {
    fn check_macro(&mut self, mac: &'a syn::Macro, stmt_semi: Option<Span>) {
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if matches!(name.as_str(), "println" | "eprintln" | "print" | "dbg") {
            self.direct_io_sink = true;
        }
        if let Some(taint) = self.ctx.macro_taint.get(&name) {
            if taint.exec {
                self.direct_exec_sink = true;
            }
            if taint.io {
                self.direct_io_sink = true;
            }
        }
        let (tok_flags, invoked) =
            scan_tokens_for_sinks(&mac.tokens, self.ctx.command_types, self.ctx.use_aliases);
        if tok_flags.exec {
            self.direct_exec_sink = true;
        }
        if tok_flags.io {
            self.direct_io_sink = true;
        }
        for m_inv in invoked {
            if let Some(t) = self.ctx.macro_taint.get(&m_inv) {
                if t.exec {
                    self.direct_exec_sink = true;
                }
                if t.io {
                    self.direct_io_sink = true;
                }
            }
        }

        let start_sp = mac
            .path
            .segments
            .first()
            .map_or(mac.bang_token.span, |s| s.ident.span());
        let end_sp = stmt_semi.unwrap_or_else(|| match &mac.delimiter {
            syn::MacroDelimiter::Paren(p) => p.span.close(),
            syn::MacroDelimiter::Brace(b) => b.span.close(),
            syn::MacroDelimiter::Bracket(b) => b.span.close(),
        });
        let sp = (
            self.ctx.span_bytes(start_sp).0,
            self.ctx.span_bytes(end_sp).1,
        );
        let raw_text = self.ctx.content.get(sp.0..sp.1).unwrap_or("");
        let has_sink = tok_flags.exec
            || tok_flags.io
            || matches!(name.as_str(), "println" | "eprintln" | "print" | "dbg");
        let is_assert = matches!(
            name.as_str(),
            "assert" | "assert_eq" | "assert_ne" | "debug_assert" | "debug_assert_eq" | "debug_assert_ne"
        );
        let is_negative_assert =
            is_assert && !has_sink && is_genuine_negative_assert_tokens(&mac.tokens, raw_text);

        self.macro_calls.push(MacroCallSpan {
            span: sp,
            name,
            is_negative_assert,
            has_sink,
        });

        self.record_idents_in_tokens(&mac.tokens);
    }

    fn record_idents_in_tokens(&mut self, ts: &TokenStream) {
        for tt in ts.clone() {
            match tt {
                TokenTree::Ident(id) => {
                    let s = id.to_string();
                    if s == "WlanGetProfile" || s == "WLAN_PROFILE_GET_PLAINTEXT_KEY" {
                        self.has_wlan_get_profile = true;
                    }
                    if s == "set_var" || s == "mpsc" || s.starts_with("Atomic") {
                        self.has_global_state_sink = true;
                    }
                    let pos = self.ctx.span_bytes(id.span()).0;
                    self.ident_uses
                        .entry(s.clone())
                        .or_default()
                        .push((pos, Some(self.fn_id)));
                    self.callees.push(s);
                }
                TokenTree::Group(g) => self.record_idents_in_tokens(&g.stream()),
                _ => {}
            }
        }
    }
}

impl<'a> Visit<'a> for FnBodyVisitor<'a> {
    fn visit_item(&mut self, item: &'a Item) {
        match item {
            Item::Static(_) => {
                self.direct_io_sink = true;
            }
            Item::Const(c) => {
                let ident = c.ident.to_string();
                let decl_span = (
                    self.ctx.span_bytes(c.const_token.span).0,
                    self.ctx.span_bytes(c.semi_token.span).1,
                );
                let init_span = self.ctx.expr_bytes(&c.expr);
                self.bindings.push(BindingInfo {
                    is_denylist_name: is_denylist_ident(&ident),
                    ident,
                    decl_span,
                    init_span,
                    fn_id: Some(self.fn_id),
                    is_array_or_vec: expr_is_array_or_vec(&c.expr),
                    is_const_or_static: true,
                });
                visit::visit_expr(self, &c.expr);
            }
            _ => {}
        }
    }

    fn visit_stmt(&mut self, s: &'a Stmt) {
        let sp = self.ctx.stmt_bytes(s);
        let raw_text = self.ctx.content.get(sp.0..sp.1).unwrap_or("");
        let compact: String = raw_text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let is_rej = stmt_is_rejection_expr(s, &compact);
        let is_rt_rej = expr_or_stmt_is_genuine_rejection(s, false);
        self.stmts.push(StmtEntry {
            span: sp,
            fn_id: Some(self.fn_id),
            is_rejection_stmt: is_rej,
            is_runtime_rejection: is_rt_rej,
            text_compact: compact,
        });

        match s {
            Stmt::Local(loc) => {
                let mut idents = Vec::new();
                collect_pat_idents(&loc.pat, &mut idents);
                if let Some(init) = &loc.init {
                    let decl_span = sp;
                    let init_span = self.ctx.expr_bytes(&init.expr);
                    let is_arr = expr_is_array_or_vec(&init.expr);
                    for ident in idents {
                        self.bindings.push(BindingInfo {
                            is_denylist_name: is_denylist_ident(&ident),
                            ident,
                            decl_span,
                            init_span,
                            fn_id: Some(self.fn_id),
                            is_array_or_vec: is_arr,
                            is_const_or_static: false,
                        });
                    }
                }
                visit::visit_stmt(self, s);
            }
            Stmt::Macro(sm) => {
                self.check_macro(&sm.mac, sm.semi_token.as_ref().map(|t| t.span));
            }
            Stmt::Item(item) => {
                self.visit_item(item);
            }
            _ => visit::visit_stmt(self, s),
        }
    }

    fn visit_expr(&mut self, e: &'a Expr) {
        match e {
            Expr::Unsafe(eu) => {
                let sp = (
                    self.ctx.span_bytes(eu.unsafe_token.span).0,
                    self.ctx.span_bytes(eu.block.brace_token.span.close()).1,
                );
                let raw = self.ctx.content.get(sp.0..sp.1).unwrap_or("");
                if raw.contains("from_utf8_unchecked") {
                    self.direct_io_sink = true;
                }
                visit::visit_expr_unsafe(self, eu);
            }
            Expr::Macro(em) => {
                self.check_macro(&em.mac, None);
            }
            Expr::Index(ei) => {
                if expr_is_range_or_slice_index(&ei.index) {
                    self.has_slice_or_split = true;
                }
                visit::visit_expr_index(self, ei);
            }
            Expr::Call(call) => {
                if let Expr::Path(ep) = call.func.as_ref() {
                    let segs: Vec<String> = ep
                        .path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect();
                    if let Some(last) = segs.last() {
                        let resolved_last = self.ctx.use_aliases.get(last).unwrap_or(last);
                        self.callees.push(resolved_last.clone());

                        if last.starts_with("CreateProcess")
                            || last.starts_with("ShellExecute")
                            || last.starts_with("WinExec")
                            || last.starts_with("NtCreateProcess")
                            || last.starts_with("NtCreateUserProcess")
                        {
                            self.direct_exec_sink = true;
                        }
                        if last == "new" && segs.len() >= 2 {
                            let prev = &segs[segs.len() - 2];
                            let prev_res = self.ctx.use_aliases.get(prev).unwrap_or(prev);
                            if self.ctx.command_types.contains(prev)
                                || self.ctx.command_types.contains(prev_res)
                            {
                                self.direct_exec_sink = true;
                            }
                        }
                        if matches!(last.as_str(), "spawn" | "output" | "status") {
                            let is_thread = segs.len() >= 2
                                && matches!(segs[segs.len() - 2].as_str(), "thread" | "Builder");
                            if is_thread {
                                self.has_thread_spawn = true;
                            } else {
                                self.direct_exec_sink = true;
                            }
                        }
                        if last == "from_utf8_unchecked"
                            || matches!(resolved_last.as_str(), "stdout" | "stderr")
                        {
                            self.direct_io_sink = true;
                        }
                        if last == "set_var"
                            || last == "remove_var"
                            || matches!(last.as_str(), "channel" | "sync_channel")
                                && segs.iter().any(|s| s == "mpsc")
                            || segs.iter().any(|s| {
                                s == "mpsc"
                                    || s == "Sender"
                                    || s == "SyncSender"
                                    || s.starts_with("Atomic")
                            })
                        {
                            self.has_global_state_sink = true;
                        }
                        if last == "from_iter" && segs.iter().any(|s| s == "String") {
                            self.has_slice_or_split = true;
                        }
                        if segs.len() >= 2 {
                            let prev = &segs[segs.len() - 2];
                            let prev_res = self.ctx.use_aliases.get(prev).unwrap_or(prev);
                            if (prev_res == "fs"
                                && matches!(last.as_str(), "write" | "copy" | "rename"))
                                || (prev_res == "File"
                                    && matches!(last.as_str(), "create" | "create_new" | "options"))
                                || (prev_res == "io"
                                    && matches!(last.as_str(), "copy" | "stdout" | "stderr"))
                                || (prev_res == "Write"
                                    && matches!(
                                        last.as_str(),
                                        "write" | "write_all" | "write_fmt" | "write_vectored"
                                    ))
                                || matches!(
                                    prev_res.as_str(),
                                    "OpenOptions"
                                        | "BufWriter"
                                        | "TcpStream"
                                        | "UdpSocket"
                                        | "Mutex"
                                        | "RwLock"
                                        | "OnceLock"
                                        | "OnceCell"
                                        | "RefCell"
                                        | "Cell"
                                )
                            {
                                self.direct_io_sink = true;
                            }
                        }
                        for arg in &call.args {
                            let sp = self.ctx.expr_bytes(arg);
                            self.call_arg_spans.push(CallArgSpan {
                                span: sp,
                                callee_name: resolved_last.clone(),
                                is_empty_str_only: is_empty_str_expr(arg),
                                has_return_or_block: matches!(arg, Expr::Block(_) | Expr::Return(_)) || expr_contains_return(arg),
                            });
                        }
                    }
                }
                visit::visit_expr_call(self, call);
            }
            Expr::MethodCall(mc) => {
                let m = mc.method.to_string();
                self.method_callees.push(m.clone());
                if matches!(m.as_str(), "spawn" | "output" | "status") {
                    let recv_sp = self.ctx.expr_bytes(&mc.receiver);
                    let recv_txt = self.ctx.content.get(recv_sp.0..recv_sp.1).unwrap_or("");
                    let is_thread_builder = recv_txt.contains("thread::Builder")
                        || recv_txt.contains("std::thread");
                    if is_thread_builder {
                        self.has_thread_spawn = true;
                    } else {
                        self.direct_exec_sink = true;
                    }
                }
                if matches!(
                    m.as_str(),
                    "write" | "write_all" | "write_fmt" | "write_vectored"
                ) {
                    self.direct_io_sink = true;
                }
                if matches!(
                    m.as_str(),
                    "split_at"
                        | "split_once"
                        | "rsplit_once"
                        | "split"
                        | "rsplit"
                        | "splitn"
                        | "rsplitn"
                        | "split_inclusive"
                        | "split_terminator"
                        | "rsplit_terminator"
                        | "strip_prefix"
                        | "strip_suffix"
                        | "trim_start_matches"
                        | "trim_end_matches"
                        | "trim_matches"
                        | "matches"
                        | "rmatches"
                ) {
                    self.has_slice_or_split = true;
                }
                if matches!(m.as_str(), "store" | "swap" | "compare_exchange" | "compare_exchange_weak") {
                    self.has_global_state_sink = true;
                }
                if m == "get"
                    && mc
                        .args
                        .first()
                        .is_some_and(expr_is_range_or_slice_index)
                {
                    self.has_slice_or_split = true;
                }
                if m == "collect" && receiver_has_chars_call(&mc.receiver) {
                    self.has_slice_or_split = true;
                }
                if matches!(m.as_str(), "contains" | "starts_with" | "ends_with") {
                    for arg in &mc.args {
                        let sp = self.ctx.expr_bytes(arg);
                        self.call_arg_spans.push(CallArgSpan {
                            span: sp,
                            callee_name: m.clone(),
                            is_empty_str_only: is_empty_str_expr(arg),
                            has_return_or_block: matches!(arg, Expr::Block(_) | Expr::Return(_)) || expr_contains_return(arg),
                        });
                    }
                }
                visit::visit_expr_method_call(self, mc);
            }
            Expr::Path(ep) => {
                let segs: Vec<String> = ep
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                for s in &segs {
                    if s == "WlanGetProfile" || s == "WLAN_PROFILE_GET_PLAINTEXT_KEY" {
                        self.has_wlan_get_profile = true;
                    }
                    if matches!(
                        s.as_str(),
                        "OpenOptions"
                            | "BufWriter"
                            | "TcpStream"
                            | "UdpSocket"
                            | "Mutex"
                            | "RwLock"
                            | "OnceLock"
                            | "OnceCell"
                            | "RefCell"
                            | "Cell"
                    ) {
                        self.direct_io_sink = true;
                    }
                    if s == "mpsc"
                        || s == "Sender"
                        || s == "SyncSender"
                        || s.starts_with("Atomic")
                    {
                        self.has_global_state_sink = true;
                    }
                }
                if let Some(last) = ep.path.segments.last() {
                    let pos = self.ctx.span_bytes(last.ident.span()).0;
                    self.ident_uses
                        .entry(last.ident.to_string())
                        .or_default()
                        .push((pos, Some(self.fn_id)));
                }
                visit::visit_expr_path(self, ep);
            }
            Expr::Assign(ea) => {
                if let Some(base) = expr_base_ident(&ea.left) {
                    let rsp = self.ctx.expr_bytes(&ea.right);
                    self.assign_targets.push((self.fn_id, rsp, base));
                }
                visit::visit_expr_assign(self, ea);
            }
            Expr::ForLoop(fl) => {
                let mut idents = Vec::new();
                collect_pat_idents(&fl.pat, &mut idents);
                let init_span = self.ctx.expr_bytes(&fl.expr);
                let decl_span = (
                    self.ctx.span_bytes(fl.for_token.span).0,
                    init_span.1,
                );
                let is_arr = expr_is_array_or_vec(&fl.expr);
                for ident in idents {
                    self.bindings.push(BindingInfo {
                        is_denylist_name: is_denylist_ident(&ident),
                        ident,
                        decl_span,
                        init_span,
                        fn_id: Some(self.fn_id),
                        is_array_or_vec: is_arr,
                        is_const_or_static: false,
                    });
                }
                visit::visit_expr_for_loop(self, fl);
            }
            _ => visit::visit_expr(self, e),
        }
    }
}
fn is_empty_str_expr(e: &Expr) -> bool {
    if let Expr::Lit(el) = e
        && let syn::Lit::Str(ls) = &el.lit
    {
        return ls.value().is_empty();
    }
    false
}

fn expr_is_range_or_slice_index(e: &Expr) -> bool {
    match e {
        Expr::Range(_) => true,
        Expr::Paren(p) => expr_is_range_or_slice_index(&p.expr),
        Expr::Group(g) => expr_is_range_or_slice_index(&g.expr),
        _ => false,
    }
}

fn receiver_has_chars_call(e: &Expr) -> bool {
    match e {
        Expr::MethodCall(mc) => mc.method == "chars" || receiver_has_chars_call(&mc.receiver),
        Expr::Paren(p) => receiver_has_chars_call(&p.expr),
        _ => false,
    }
}

fn expr_is_array_or_vec(e: &Expr) -> bool {
    match e {
        Expr::Array(_) => true,
        Expr::Reference(r) => expr_is_array_or_vec(&r.expr),
        Expr::Macro(m) => m
            .mac
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "vec"),
        Expr::Paren(p) => expr_is_array_or_vec(&p.expr),
        _ => false,
    }
}

fn is_denylist_ident(ident: &str) -> bool {
    let lower = ident.to_ascii_lowercase();
    lower.contains("r4_forbidden")
        || lower.contains("r4_prohibited")
        || lower.contains("r4_excluded")
        || lower.contains("r4_banned")
        || lower.contains("forbidden")
        || lower.contains("prohibited")
        || lower.contains("excluded_tools")
        || lower.contains("denylist")
        || lower.contains("blocklist")
        || lower.contains("banned")
}

fn collect_pat_idents(pat: &Pat, out: &mut Vec<String>) {
    match pat {
        Pat::Ident(pi) => out.push(pi.ident.to_string()),
        Pat::Tuple(pt) => {
            for p in &pt.elems {
                collect_pat_idents(p, out);
            }
        }
        Pat::TupleStruct(pts) => {
            for p in &pts.elems {
                collect_pat_idents(p, out);
            }
        }
        Pat::Reference(pr) => collect_pat_idents(&pr.pat, out),
        Pat::Type(pt) => collect_pat_idents(&pt.pat, out),
        Pat::Slice(ps) => {
            for p in &ps.elems {
                collect_pat_idents(p, out);
            }
        }
        _ => {}
    }
}

fn assert_non_lit_tokens_before_msg(tokens: &TokenStream, is_eq_or_ne: bool) -> Vec<TokenTree> {
    let max_commas = if is_eq_or_ne { 1usize } else { 0usize };
    let mut commas = 0usize;
    let mut out = Vec::new();
    for tt in tokens.clone() {
        if let TokenTree::Punct(p) = &tt
            && p.as_char() == ','
        {
            commas += 1;
            if commas > max_commas {
                break;
            }
        }
        out.push(tt);
    }
    out
}

fn token_trees_have_rejection_signal(tts: &[TokenTree]) -> bool {
    fn visit_tts(tts: &[TokenTree], saw_violations: &mut bool, saw_is_empty: &mut bool) -> bool {
        for (idx, tt) in tts.iter().enumerate() {
            match tt {
                TokenTree::Ident(id) => {
                    let s = id.to_string();
                    let lower = s.to_ascii_lowercase();
                    if matches!(lower.as_str(), "is_err" | "unwrap_err" | "expect_err" | "policydenied" | "policy_denied")
                        || lower.starts_with("assert_r4_clean")
                    {
                        return true;
                    }
                    if s == "Err"
                        && matches!(tts.get(idx + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis)
                    {
                        return true;
                    }
                    if lower == "violations" {
                        *saw_violations = true;
                    }
                    if lower == "is_empty" {
                        *saw_is_empty = true;
                    }
                    if lower == "false"
                        && idx > 0
                        && matches!(tts.get(idx - 1), Some(TokenTree::Punct(p)) if p.as_char() == ',')
                    {
                        return true;
                    }
                }
                TokenTree::Group(g) => {
                    let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                    if visit_tts(&inner, saw_violations, saw_is_empty) {
                        return true;
                    }
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
        false
    }
    let mut clauses: Vec<&[TokenTree]> = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i + 1 < tts.len() {
        if let (TokenTree::Punct(p1), TokenTree::Punct(p2)) = (&tts[i], &tts[i + 1]) {
            if p1.as_char() == '|' && p2.as_char() == '|' {
                return false;
            }
            if p1.as_char() == '&' && p2.as_char() == '&' {
                clauses.push(&tts[start..i]);
                i += 2;
                start = i;
                continue;
            }
        }
        i += 1;
    }
    clauses.push(&tts[start..]);

    let clause_ok = |clause: &[TokenTree]| -> bool {
        let mut saw_violations = false;
        let mut saw_is_empty = false;
        if visit_tts(clause, &mut saw_violations, &mut saw_is_empty) {
            return true;
        }
        if saw_violations && saw_is_empty {
            return true;
        }
        matches!(clause.first(), Some(TokenTree::Punct(p)) if p.as_char() == '!')
            && !matches!(clause.get(1), Some(TokenTree::Ident(id)) if id == "false" || id == "true")
    };

    !clauses.is_empty() && clauses.iter().all(|c| !c.is_empty() && clause_ok(c))
}

fn is_genuine_negative_assert_tokens(tokens: &TokenStream, raw_text: &str) -> bool {
    let trimmed = raw_text.trim_start();
    let is_eq_or_ne = trimmed.starts_with("assert_eq!")
        || trimmed.starts_with("assert_ne!")
        || trimmed.starts_with("debug_assert_eq!")
        || trimmed.starts_with("debug_assert_ne!");
    let expr_tts = assert_non_lit_tokens_before_msg(tokens, is_eq_or_ne);
    token_trees_have_rejection_signal(&expr_tts)
}

fn expr_or_stmt_is_genuine_rejection(stmt: &Stmt, allow_assert_macros: bool) -> bool {
    struct RejVis {
        hit: bool,
        allow_assert_macros: bool,
    }
    impl<'a> Visit<'a> for RejVis {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_lit(&mut self, _: &'a syn::Lit) {}
        fn visit_expr_method_call(&mut self, mc: &'a syn::ExprMethodCall) {
            let m = mc.method.to_string();
            if matches!(m.as_str(), "unwrap_err" | "expect_err") {
                self.hit = true;
            }
            visit::visit_expr_method_call(self, mc);
        }
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if let Expr::Path(ep) = call.func.as_ref()
                && let Some(last) = ep.path.segments.last()
            {
                let s = last.ident.to_string();
                if s == "Err" || s == "PolicyDenied" || s.starts_with("assert_r4_clean") {
                    self.hit = true;
                }
            }
            visit::visit_expr_call(self, call);
        }
        fn visit_expr_path(&mut self, ep: &'a syn::ExprPath) {
            if let Some(last) = ep.path.segments.last() {
                let s = last.ident.to_string();
                if s == "PolicyDenied" || s == "POLICY_DENIED" {
                    self.hit = true;
                }
            }
            visit::visit_expr_path(self, ep);
        }
        fn visit_expr_macro(&mut self, em: &'a syn::ExprMacro) {
            let name = em
                .mac
                .path
                .segments
                .last()
                .map(|i| i.ident.to_string())
                .unwrap_or_default();
            if name == "matches" {
                let inner: Vec<TokenTree> = em.mac.tokens.clone().into_iter().collect();
                if token_trees_have_rejection_signal(&inner) {
                    self.hit = true;
                }
            } else if self.allow_assert_macros
                && matches!(
                    name.as_str(),
                    "assert" | "assert_eq" | "assert_ne" | "debug_assert" | "debug_assert_eq" | "debug_assert_ne"
                )
            {
                let is_eq = name.ends_with("_eq") || name.ends_with("_ne");
                let expr_tts = assert_non_lit_tokens_before_msg(&em.mac.tokens, is_eq);
                if token_trees_have_rejection_signal(&expr_tts) {
                    self.hit = true;
                }
            }
        }
    }
    let mut v = RejVis {
        hit: false,
        allow_assert_macros,
    };
    v.visit_stmt(stmt);
    v.hit
}

fn stmt_is_rejection_expr(stmt: &Stmt, _compact: &str) -> bool {
    if let Stmt::Macro(sm) = stmt {
        let name = sm
            .mac
            .path
            .segments
            .last()
            .map(|i| i.ident.to_string())
            .unwrap_or_default();
        if matches!(
            name.as_str(),
            "assert" | "assert_eq" | "assert_ne" | "debug_assert" | "debug_assert_eq" | "debug_assert_ne"
        ) {
            let is_eq = name.ends_with("_eq") || name.ends_with("_ne");
            let expr_tts = assert_non_lit_tokens_before_msg(&sm.mac.tokens, is_eq);
            return token_trees_have_rejection_signal(&expr_tts);
        }
        if name == "matches" {
            let inner: Vec<TokenTree> = sm.mac.tokens.clone().into_iter().collect();
            return token_trees_have_rejection_signal(&inner);
        }
    }
    expr_or_stmt_is_genuine_rejection(stmt, true)
}

pub fn has_dangerous_wlan_fn_verb(fn_name: &str, allow_extract_prefix: bool) -> bool {
    let lower = fn_name.to_ascii_lowercase();
    [
        "steal",
        "dump",
        "recover",
        "plaintext",
        "decrypt",
        "exfil",
        "harvest",
        "grab",
        "sniff",
        "scrape",
        "capture",
        "save_",
        "_save",
        "export_",
        "_export",
        "copy_",
        "_copy",
        "collect_",
        "_collect",
        "get_",
        "read_",
        "write_",
        "_write",
        "send_",
        "_send",
        "fetch",
        "retrieve",
        "decode_",
        "transmit",
        "upload",
        "to_disk",
        "to_file",
        "secret",
        "password",
        "passwd",
        "bypass",
        "store",
        "persist",
        "log_",
        "print_",
    ]
    .iter()
    .any(|v| lower.contains(v))
        || (lower.contains("unredact")
            && !(allow_extract_prefix
                && (lower.contains("has_unredacted_") || lower.contains("last_unredacted_"))))
        || (lower.contains("leak")
            && !(allow_extract_prefix
                && (fn_name == "has_unclosed_html_quot_km_leak"
                    || fn_name == "raw_json_span_has_u0027_apos_km_leak")))
        || (lower.contains("extract") && !(allow_extract_prefix && lower.contains("prefix")))
}

pub fn has_dangerous_wlan_test_fn_verb(fn_name: &str) -> bool {
    let lower = fn_name.to_ascii_lowercase();
    [
        "steal",
        "dump",
        "recover",
        "plaintext",
        "decrypt",
        "exfil",
        "harvest",
        "grab",
        "sniff",
        "scrape",
        "capture",
        "save_",
        "_save",
        "export_",
        "_export",
        "copy_",
        "_copy",
        "collect_",
        "_collect",
        "get_",
        "read_",
        "write_",
        "_write",
        "send_",
        "_send",
        "fetch",
        "retrieve",
        "transmit",
        "upload",
        "to_disk",
        "to_file",
        "secret",
        "password",
        "passwd",
        "bypass",
        "store",
        "persist",
        "log_",
        "print_",
    ]
    .iter()
    .any(|v| lower.contains(v))
        || (lower.contains("unredact")
            && !lower.contains("unredacted_caught")
            && !lower.contains("has_unredacted_")
            && !lower.contains("and_unredacted"))
        || (lower.contains("extract")
            && !lower.contains("prefix")
            && !lower.contains("extracts_metadata"))
}

fn wlan_mut_params_ok(f: &FnInfo, allow_json_val_or_mask_slice: bool) -> bool {
    if !f.has_mut_param {
        return true;
    }
    if !allow_json_val_or_mask_slice {
        return false;
    }
    f.mut_param_types
        .iter()
        .all(|t| t == "&mutValue" || t == "&mutserde_json::Value" || t == "&mut[u8]")
}

fn is_non_secret_error_result(compact_ret: &str) -> bool {
    matches!(
        compact_ret,
        "Result<(),&'staticstr>"
            | "Result<(),ReportError>"
            | "Result<(),NetError>"
            | "Result<bool,&'staticstr>"
            | "Result<bool,ReportError>"
            | "Result<bool,NetError>"
            | "Result<Vec<(usize,usize)>,ReportError>"
    )
}

fn verify_find_html_close_tag_body(block: &Block) -> bool {
    struct CloseTagVis {
        in_loop: bool,
        in_lt_slash_guard: bool,
        in_gt_guard: bool,
        saw_valid_some_return: bool,
        saw_bad_len_return: bool,
    }
    impl<'a> Visit<'a> for CloseTagVis {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_while(&mut self, w: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&w.cond) {
                return;
            }
            let prev = self.in_loop;
            self.in_loop = true;
            visit::visit_expr_while(self, w);
            self.in_loop = prev;
        }
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            let cond_c = expr_to_compact(&ei.cond);
            let prev_lt = self.in_lt_slash_guard;
            let prev_gt = self.in_gt_guard;
            if (cond_c.contains("[") || cond_c.contains(".get("))
                && cond_c.contains("b'<'")
                && cond_c.contains("b'/'")
            {
                self.in_lt_slash_guard = true;
            }
            if (cond_c.contains("[") || cond_c.contains(".get(")) && cond_c.contains("b'>'") {
                self.in_gt_guard = true;
            }
            self.visit_block(&ei.then_branch);
            self.in_lt_slash_guard = prev_lt;
            self.in_gt_guard = prev_gt;
            if let Some((_, eb)) = &ei.else_branch {
                self.visit_expr(eb);
            }
        }
        fn visit_expr_return(&mut self, r: &'a syn::ExprReturn) {
            if let Some(ref e) = r.expr {
                let c = expr_to_compact(e);
                if c.starts_with("Some(") {
                    if c.contains(".len()") || c.contains("Some(0") {
                        self.saw_bad_len_return = true;
                    } else if self.in_loop && self.in_lt_slash_guard && self.in_gt_guard {
                        self.saw_valid_some_return = true;
                    }
                }
            }
            visit::visit_expr_return(self, r);
        }
    }
    let mut v = CloseTagVis {
        in_loop: false,
        in_lt_slash_guard: false,
        in_gt_guard: false,
        saw_valid_some_return: false,
        saw_bad_len_return: false,
    };
    v.visit_block(block);
    v.saw_valid_some_return && !v.saw_bad_len_return
}

fn tag_helper_body_is_non_stub(
    f: &FnInfo,
    block: &Block,
    verified_tag_helpers: &HashSet<String>,
) -> bool {
    struct StubCheck<'a> {
        params: &'a [String],
        verified_tag_helpers: &'a HashSet<String>,
        uses_param: bool,
        saw_km_or_tag_inspect: bool,
        saw_non_const_or_positive_ret: bool,
    }
    impl<'a> Visit<'a> for StubCheck<'a> {
        fn visit_item(&mut self, item: &'a Item) {
            if let Item::Const(c) = item {
                visit::visit_item_const(self, c);
            }
        }
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_expr_path(&mut self, ep: &'a syn::ExprPath) {
            if let Some(last) = ep.path.segments.last() {
                let id = last.ident.to_string();
                if self.params.iter().any(|p| p == &id) {
                    self.uses_param = true;
                }
                if self.verified_tag_helpers.contains(&id) {
                    self.saw_km_or_tag_inspect = true;
                }
            }
            visit::visit_expr_path(self, ep);
        }
        fn visit_lit_str(&mut self, ls: &'a syn::LitStr) {
            let v = ls.value().to_ascii_lowercase();
            if v.contains("keymaterial") || v.contains("<") {
                self.saw_km_or_tag_inspect = true;
            }
        }
        fn visit_lit_byte_str(&mut self, lbs: &'a syn::LitByteStr) {
            let v = String::from_utf8_lossy(&lbs.value()).to_ascii_lowercase();
            if v.contains("keymaterial") || v.contains("<") {
                self.saw_km_or_tag_inspect = true;
            }
        }
        fn visit_lit_byte(&mut self, lb: &'a syn::LitByte) {
            if matches!(lb.value(), b'<' | b'>' | b'"' | b'\'') {
                self.saw_km_or_tag_inspect = true;
            }
        }
        fn visit_expr_return(&mut self, r: &'a syn::ExprReturn) {
            if let Some(ref e) = r.expr {
                let c = expr_to_compact(e);
                if c != "false" && c != "None" {
                    self.saw_non_const_or_positive_ret = true;
                }
            }
            visit::visit_expr_return(self, r);
        }
    }
    let mut sc = StubCheck {
        params: &f.param_names,
        verified_tag_helpers,
        uses_param: false,
        saw_km_or_tag_inspect: false,
        saw_non_const_or_positive_ret: false,
    };
    sc.visit_block(block);
    if let Some(Stmt::Expr(tail, None)) = block.stmts.last() {
        let c = expr_to_compact(tail);
        if c != "false" && c != "None" {
            sc.saw_non_const_or_positive_ret = true;
        }
    }
    if !f.param_names.is_empty() && !sc.uses_param {
        return false;
    }
    let is_mut_bitmask_memo = f.has_mut_param
        && f.mut_param_types.iter().all(|t| {
            t == "&mut[u8]"
                || t == "&mutJsonMarkerMemo"
                || (f.name == "mask_clean_km_at" && t == "&mutVec<(usize,usize)>")
        });
    if !sc.saw_non_const_or_positive_ret && !is_mut_bitmask_memo {
        return false;
    }
    let lower_name = f.name.to_ascii_lowercase();
    if (lower_name.contains("keymaterial") || (lower_name.contains("_km_") && !is_mut_bitmask_memo))
        && !sc.saw_km_or_tag_inspect
    {
        return false;
    }
    true
}

fn is_safe_tag_helper_return(
    f: &FnInfo,
    block: &Block,
    verified_tag_structs: &HashSet<String>,
    safe_enums: &HashSet<String>,
    verified_tag_helpers: &HashSet<String>,
) -> bool {
    if f.name == "mask_clean_km_at"
        && f.ret_type_str.is_none()
        && f.mut_param_types == ["&mut[u8]", "&mutVec<(usize,usize)>"]
    {
        let txt = block_compact_text(block);
        return (txt.contains(".fill(b'')") || txt.contains(".fill(b' ')"))
            && !txt.contains("String")
            && !txt.contains("to_vec");
    }
    let Some(ret) = f.ret_type_str.as_deref() else {
        return false;
    };
    if f.name == "build"
        && ret == "Option<Self>"
        && f.callees.iter().any(|c| c == "analyze_cross_cell_segment")
    {
        return true;
    }
    if !tag_helper_body_is_non_stub(f, block, verified_tag_helpers) {
        return false;
    }
    if f.name == "find_html_close_tag" {
        return ret == "Option<(usize,usize)>" && verify_find_html_close_tag_body(block);
    }
    if f.name == "check_html_tag_attributes" {
        let txt = block_compact_text(block);
        return is_non_secret_error_result(ret)
            && (txt.contains("assert_r4_clean_")
                || (txt.contains("check_html_tag_attributes_with_depth")
                    && verified_tag_helpers.contains("check_html_tag_attributes_with_depth")));
    }
    if f.name == "check_html_tag_attributes_with_depth" {
        let txt = block_compact_text(block);
        return is_non_secret_error_result(ret) && txt.contains("assert_r4_clean_");
    }
    if matches!(
        ret,
        "bool"
            | "(bool,bool)"
            | "usize"
            | "Option<usize>"
            | "Option<(usize,usize)>"
            | "(Option<usize>,usize)"
            | "Option<(usize,usize,bool)>"
            | "Vec<(usize,usize)>"
    ) || is_non_secret_error_result(ret)
    {
        return true;
    }
    if let Some(inner) = ret.strip_prefix("Option<").and_then(|s| s.strip_suffix('>'))
        && verified_tag_structs.contains(inner)
    {
        return true;
    }
    if let Some(mid) = ret
        .strip_prefix("Option<(usize,")
        .and_then(|s| s.strip_suffix(",bool)>"))
        && safe_enums.contains(mid)
    {
        return true;
    }
    if ret == "Option<&str>" && f.name.to_ascii_lowercase().contains("prefix") {
        let txt = block_compact_text(block);
        return txt.contains("b':'")
            && txt.contains("colon_pos")
            && txt.contains("prefix_start")
            && !txt.contains(".find(")
            && !txt.contains(".rfind(")
            && !txt.contains(".split_once(")
            && !txt.contains(".split_at(")
            && !txt.contains(".to_string(")
            && !txt.contains(".to_owned(")
            && !txt.contains("format!");
    }
    false
}

struct VerifiedWlanSets<'a> {
    sanitizers: &'a HashSet<String>,
    validators: &'a HashSet<String>,
    tag_helpers: &'a HashSet<String>,
    tag_structs: &'a HashSet<String>,
    all_fns: &'a [FnInfo],
}

fn expr_mentions_mut_param(e: &Expr, mut_params: &[String]) -> bool {
    if expr_base_ident(e).is_some_and(|b| mut_params.iter().any(|p| p == &b)) {
        return true;
    }
    if let Expr::Call(c) = e
        && let Expr::Path(ep) = c.func.as_ref()
        && ep.path.segments.last().is_some_and(|s| s.ident == "Some")
    {
        return c.args.iter().any(|a| expr_mentions_mut_param(a, mut_params));
    }
    false
}

fn is_safe_fill_const_lit(e: &Expr) -> bool {
    matches!(
        unwrap_parens(e),
        Expr::Lit(el)
            if matches!(&el.lit, syn::Lit::Byte(lb) if matches!(lb.value(), b' ' | b'_' | 0))
                || matches!(&el.lit, syn::Lit::Int(li) if li.base10_digits() == "0")
    )
}

fn is_pure_lit_const_expr(e: &Expr) -> bool {
    match unwrap_parens(e) {
        Expr::Lit(el) => matches!(el.lit, syn::Lit::Byte(_) | syn::Lit::Int(_)),
        Expr::If(ei) => {
            let then_ok = ei.then_branch.stmts.len() == 1
                && matches!(
                    ei.then_branch.stmts.first(),
                    Some(syn::Stmt::Expr(inner, None)) if is_pure_lit_const_expr(inner)
                );
            let else_ok = ei
                .else_branch
                .as_ref()
                .is_some_and(|(_, eb)| match eb.as_ref() {
                    Expr::Block(b) => {
                        b.block.stmts.len() == 1
                            && matches!(
                                b.block.stmts.first(),
                                Some(syn::Stmt::Expr(inner, None)) if is_pure_lit_const_expr(inner)
                            )
                    }
                    other => is_pure_lit_const_expr(other),
                });
            then_ok && else_ok
        }
        _ => false,
    }
}

fn is_const_bitmask_expr(e: &Expr, const_u8_vars: &HashSet<String>) -> bool {
    match unwrap_parens(e) {
        Expr::Lit(_) => true,
        Expr::Path(ep) => ep
            .path
            .segments
            .last()
            .is_some_and(|s| const_u8_vars.contains(&s.ident.to_string())),
        Expr::If(ei) => {
            let then_ok = ei.then_branch.stmts.len() == 1
                && matches!(
                    ei.then_branch.stmts.first(),
                    Some(syn::Stmt::Expr(inner, None)) if is_const_bitmask_expr(inner, const_u8_vars)
                );
            let else_ok = ei
                .else_branch
                .as_ref()
                .is_some_and(|(_, eb)| match eb.as_ref() {
                    Expr::Block(b) => {
                        b.block.stmts.len() == 1
                            && matches!(
                                b.block.stmts.first(),
                                Some(syn::Stmt::Expr(inner, None)) if is_const_bitmask_expr(inner, const_u8_vars)
                            )
                    }
                    other => is_const_bitmask_expr(other, const_u8_vars),
                });
            then_ok && else_ok
        }
        _ => false,
    }
}

fn collect_const_u8_vars(block: &Block) -> HashSet<String> {
    let mut vars = HashSet::new();
    struct ConstVis<'a> {
        vars: &'a mut HashSet<String>,
    }
    impl<'a> Visit<'a> for ConstVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_local(&mut self, loc: &'a Local) {
            if let Some(init) = &loc.init
                && is_pure_lit_const_expr(&init.expr)
            {
                let mut ids = Vec::new();
                collect_pat_idents(&loc.pat, &mut ids);
                self.vars.extend(ids);
            }
            visit::visit_local(self, loc);
        }
    }
    let mut v = ConstVis { vars: &mut vars };
    v.visit_block(block);
    vars
}

fn block_is_safe_memo_helper(block: &Block, mut_param_names: &[String]) -> bool {
    let const_u8_vars = collect_const_u8_vars(block);
    struct MemoVis<'a> {
        mut_params: &'a [String],
        const_u8_vars: &'a HashSet<String>,
        bad: bool,
    }
    impl<'a> Visit<'a> for MemoVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_assign(&mut self, ea: &'a syn::ExprAssign) {
            if let Some(base) = expr_base_ident(&ea.left)
                && self.mut_params.iter().any(|p| p == &base)
            {
                let ok_container = matches!(&*ea.left, Expr::Field(ef) if matches!(&ef.member, syn::Member::Named(id) if id == "container"))
                    || expr_to_compact(&ea.left).contains(".container");
                if !(ok_container && is_pure_lit_const_expr(&ea.right)) {
                    self.bad = true;
                }
            }
            visit::visit_expr_assign(self, ea);
        }
        fn visit_expr_binary(&mut self, eb: &'a syn::ExprBinary) {
            if matches!(
                eb.op,
                syn::BinOp::BitOrAssign(_)
                    | syn::BinOp::BitAndAssign(_)
                    | syn::BinOp::BitXorAssign(_)
            ) && let Some(base) = expr_base_ident(&eb.left)
                && self.mut_params.iter().any(|p| p == &base)
            {
                let safe_memo_flags_or = self.mut_params.iter().any(|p| p == &base)
                    && expr_to_compact(&eb.left).contains(".flags")
                    && matches!(unwrap_parens(&eb.right), Expr::Path(_) | Expr::Lit(_));
                if !safe_memo_flags_or && !is_const_bitmask_expr(&eb.right, self.const_u8_vars) {
                    self.bad = true;
                }
                return;
            }
            visit::visit_expr_binary(self, eb);
        }
        fn visit_expr_method_call(&mut self, mc: &'a syn::ExprMethodCall) {
            let m = mc.method.to_string();
            if matches!(
                m.as_str(),
                "copy_from_slice"
                    | "clone_from_slice"
                    | "push_str"
                    | "push"
                    | "extend"
                    | "extend_from_slice"
                    | "to_string"
                    | "to_owned"
                    | "to_vec"
            ) && (expr_mentions_mut_param(&mc.receiver, self.mut_params)
                || mc.args.iter().any(|a| expr_mentions_mut_param(a, self.mut_params)))
            {
                self.bad = true;
            }
            visit::visit_expr_method_call(self, mc);
        }
    }
    let mut v = MemoVis {
        mut_params: mut_param_names,
        const_u8_vars: &const_u8_vars,
        bad: false,
    };
    v.visit_block(block);
    !v.bad
}

fn block_is_safe_mask_json_span(block: &Block, mut_param_names: &[String]) -> bool {
    let mut has_live_fill = false;
    let mut has_bad = false;
    struct MaskJsonVis<'a> {
        mut_params: &'a [String],
        has_live_fill: &'a mut bool,
        has_bad: &'a mut bool,
    }
    impl<'a> Visit<'a> for MaskJsonVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_expr_method_call(&mut self, mc: &'a syn::ExprMethodCall) {
            let m = mc.method.to_string();
            if matches!(m.as_str(), "copy_from_slice" | "clone_from_slice") {
                *self.has_bad = true;
            }
            if m == "fill"
                && expr_base_ident(&mc.receiver)
                    .is_some_and(|b| self.mut_params.iter().any(|p| p == &b))
                && mc.args.first().is_some_and(is_safe_fill_const_lit)
            {
                *self.has_live_fill = true;
            }
            visit::visit_expr_method_call(self, mc);
        }
    }
    let mut v = MaskJsonVis {
        mut_params: mut_param_names,
        has_live_fill: &mut has_live_fill,
        has_bad: &mut has_bad,
    };
    v.visit_block(block);
    has_live_fill && !has_bad
}

fn block_has_live_deserializer_cursor_loop(block: &Block) -> bool {
    let mut has_live_deserializer = false;
    let mut has_cursor_loop = false;
    struct DeserVis<'a> {
        in_while: bool,
        has_live_deserializer: &'a mut bool,
        has_cursor_loop: &'a mut bool,
    }
    impl<'a> Visit<'a> for DeserVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            let prev = self.in_while;
            self.in_while = true;
            visit::visit_expr_while(self, ew);
            self.in_while = prev;
        }
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if let Expr::Path(ep) = call.func.as_ref() {
                let segs: Vec<String> = ep.path.segments.iter().map(|s| s.ident.to_string()).collect();
                if segs.ends_with(&["Deserializer".to_string(), "from_str".to_string()]) {
                    *self.has_live_deserializer = true;
                }
                if self.in_while && segs.last().is_some_and(|s| s == "sanitize_json_value_r4_inner") {
                    *self.has_cursor_loop = true;
                }
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut v = DeserVis {
        in_while: false,
        has_live_deserializer: &mut has_live_deserializer,
        has_cursor_loop: &mut has_cursor_loop,
    };
    v.visit_block(block);
    has_live_deserializer && has_cursor_loop
}

fn block_mut_u8_only_safe_bitmask_or_fill(
    block: &Block,
    own_fn_name: &str,
    mut_param_names: &[String],
    mut_param_types: &[String],
    verified_tag_helpers: &HashSet<String>,
    safe_memo_helpers: &HashSet<String>,
) -> bool {
    let const_u8_vars = collect_const_u8_vars(block);
    let memo_params: Vec<String> = mut_param_names
        .iter()
        .zip(mut_param_types.iter())
        .filter(|(_, ty)| *ty == "&mutJsonMarkerMemo")
        .map(|(n, _)| n.clone())
        .collect();
    struct MutU8Vis<'a> {
        own_fn_name: &'a str,
        mut_params: &'a [String],
        memo_params: &'a [String],
        const_u8_vars: &'a HashSet<String>,
        verified_tag_helpers: &'a HashSet<String>,
        safe_memo_helpers: &'a HashSet<String>,
        bad: bool,
    }
    impl<'a> Visit<'a> for MutU8Vis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_local(&mut self, loc: &'a Local) {
            if let Some(init) = &loc.init {
                let is_alias = match unwrap_parens(&init.expr) {
                    Expr::Path(_) => expr_mentions_mut_param(&init.expr, self.mut_params),
                    Expr::Reference(er) => {
                        er.mutability.is_some()
                            && expr_base_ident(&er.expr)
                                .is_some_and(|b| self.mut_params.iter().any(|p| p == &b))
                    }
                    Expr::Index(ei) => {
                        expr_is_range_or_slice_index(&ei.index)
                            && expr_base_ident(&ei.expr)
                                .is_some_and(|b| self.mut_params.iter().any(|p| p == &b))
                    }
                    _ => false,
                };
                if is_alias {
                    self.bad = true;
                }
            }
            visit::visit_local(self, loc);
        }
        fn visit_expr_reference(&mut self, er: &'a syn::ExprReference) {
            if er.mutability.is_some()
                && matches!(unwrap_parens(&er.expr), Expr::Index(_))
                && expr_base_ident(&er.expr)
                    .is_some_and(|b| self.mut_params.iter().any(|p| p == &b))
            {
                self.bad = true;
            }
            visit::visit_expr_reference(self, er);
        }
        fn visit_expr_assign(&mut self, ea: &'a syn::ExprAssign) {
            if matches!(unwrap_parens(&ea.left), Expr::Unary(syn::ExprUnary { op: syn::UnOp::Deref(_), .. })) {
                if !is_safe_fill_const_lit(&ea.right) {
                    self.bad = true;
                }
            } else if let Some(base) = expr_base_ident(&ea.left)
                && self.mut_params.iter().any(|p| p == &base)
                && !is_safe_fill_const_lit(&ea.right)
            {
                self.bad = true;
            }
            visit::visit_expr_assign(self, ea);
        }
        fn visit_expr_binary(&mut self, eb: &'a syn::ExprBinary) {
            if matches!(
                eb.op,
                syn::BinOp::BitOrAssign(_)
                    | syn::BinOp::BitAndAssign(_)
                    | syn::BinOp::BitXorAssign(_)
            ) && let Some(base) = expr_base_ident(&eb.left)
                && self.mut_params.iter().any(|p| p == &base)
            {
                let safe_memo_flags_or = self.memo_params.iter().any(|p| p == &base)
                    && expr_to_compact(&eb.left).contains(".flags")
                    && matches!(unwrap_parens(&eb.right), Expr::Path(_) | Expr::Lit(_));
                if !safe_memo_flags_or && !is_const_bitmask_expr(&eb.right, self.const_u8_vars) {
                    self.bad = true;
                }
                return;
            }
            visit::visit_expr_binary(self, eb);
        }
        fn visit_expr_method_call(&mut self, mc: &'a syn::ExprMethodCall) {
            if let Some(base) = expr_base_ident(&mc.receiver)
                && self.mut_params.iter().any(|p| p == &base)
            {
                let m = mc.method.to_string();
                let safe_readonly = matches!(
                    m.as_str(),
                    "len"
                        | "is_empty"
                        | "get"
                        | "iter"
                        | "windows"
                        | "chunks"
                        | "starts_with"
                        | "ends_with"
                        | "contains"
                        | "eq_ignore_ascii_case"
                        | "position"
                );
                let safe_fill = m == "fill" && mc.args.first().is_some_and(is_safe_fill_const_lit);
                let safe_span_push = self.own_fn_name == "mask_clean_km_at"
                    && m == "push"
                    && base == "recorded"
                    && mc.args.first().is_some_and(|a| matches!(unwrap_parens(a), Expr::Tuple(_)));
                if !safe_readonly && !safe_fill && !safe_span_push {
                    self.bad = true;
                }
            }
            visit::visit_expr_method_call(self, mc);
        }
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            let is_some_wrap = if let Expr::Path(ep) = call.func.as_ref()
                && let Some(last) = ep.path.segments.last()
            {
                last.ident == "Some"
            } else {
                false
            };
            if !is_some_wrap {
                let passes_mut_param = call
                    .args
                    .iter()
                    .any(|arg| expr_mentions_mut_param(arg, self.mut_params));
                if passes_mut_param {
                    let callee_ok = if let Expr::Path(ep) = call.func.as_ref()
                        && let Some(last) = ep.path.segments.last()
                    {
                        let n = last.ident.to_string();
                        n == self.own_fn_name
                            || self.verified_tag_helpers.contains(&n)
                            || self.safe_memo_helpers.contains(&n)
                    } else {
                        false
                    };
                    if !callee_ok {
                        self.bad = true;
                    }
                }
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut v = MutU8Vis {
        own_fn_name,
        mut_params: mut_param_names,
        memo_params: &memo_params,
        const_u8_vars: &const_u8_vars,
        verified_tag_helpers,
        safe_memo_helpers,
        bad: false,
    };
    v.visit_block(block);
    !v.bad
}

fn is_genuine_validator_fn(
    f: &FnInfo,
    block: &Block,
    has_unsafe_flow: bool,
    file_has_verified_validator: bool,
    sets: &VerifiedWlanSets<'_>,
    mask_json_span_safe: bool,
) -> bool {
    let mut_ok = !f.has_mut_param
        || ((f.name == "assert_r4_clean_embedded_json_in_bytes"
            || f.name == "assert_r4_clean_embedded_json_in_bytes_with_options")
            && mask_json_span_safe
            && f.mut_param_types == ["&mut[u8]"]
            && f.ret_type_str.as_deref() == Some("Result<bool,ReportError>"))
        || (f.name == "assert_r4_clean_embedded_json_in_bytes_cow"
            && mask_json_span_safe
            && f.mut_param_types.iter().all(|t| {
                t == "&mutstd::borrow::Cow<'_,[u8]>" || t == "&mutCow<'_,[u8]>"
            })
            && f.ret_type_str.as_deref() == Some("Result<bool,ReportError>"))
        || ((f.name == "flush_html_text_buf" || f.name == "flush_html_text_buf_with_origin")
            && f.mut_param_types == ["&mutVec<u8>"]
            && f.ret_type_str.as_deref().is_some_and(is_non_secret_error_result));
    if f.has_exec_sink
        || f.has_io_sink
        || f.has_thread_spawn
        || f.has_global_state_sink
        || !mut_ok
        || has_dangerous_wlan_fn_verb(&f.name, false)
        || has_unsafe_flow
    {
        return false;
    }
    if f.name == "mask_clean_km_at"
        && f.ret_type_str.is_none()
        && f.mut_param_types == ["&mut[u8]", "&mutVec<(usize,usize)>"]
    {
        let txt = block_compact_text(block);
        return (txt.contains(".fill(b'')") || txt.contains(".fill(b' ')"))
            && !txt.contains("String")
            && !txt.contains("to_vec");
    }
    let Some(ret) = f.ret_type_str.as_deref() else {
        return false;
    };
    if f.name == "build"
        && ret == "Option<Self>"
        && f.callees.iter().any(|c| c == "analyze_cross_cell_segment")
    {
        return true;
    }
    if !is_non_secret_error_result(ret) {
        return false;
    }

    struct LiveValVis<'a> {
        sets: &'a VerifiedWlanSets<'a>,
        has_live_err: bool,
        has_live_redacted: bool,
        has_live_keymaterial: bool,
        calls_live_validator: bool,
        calls_live_tag_helper: bool,
        in_discard_let: bool,
    }
    impl<'a> Visit<'a> for LiveValVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_local(&mut self, loc: &'a Local) {
            let is_discard = matches!(&loc.pat, Pat::Wild(_))
                || matches!(&loc.pat, Pat::Ident(pi) if pi.ident.to_string().starts_with('_'));
            let prev = self.in_discard_let;
            self.in_discard_let = is_discard;
            visit::visit_local(self, loc);
            self.in_discard_let = prev;
        }
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_lit_str(&mut self, ls: &'a syn::LitStr) {
            if !self.in_discard_let {
                let v = ls.value().to_ascii_lowercase();
                if v.contains("[redacted]") {
                    self.has_live_redacted = true;
                }
                if v.contains("keymaterial") {
                    self.has_live_keymaterial = true;
                }
            }
        }
        fn visit_lit_byte_str(&mut self, lbs: &'a syn::LitByteStr) {
            if !self.in_discard_let {
                let v = String::from_utf8_lossy(&lbs.value()).to_ascii_lowercase();
                if v.contains("[redacted]") {
                    self.has_live_redacted = true;
                }
                if v.contains("keymaterial") {
                    self.has_live_keymaterial = true;
                }
            }
        }
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if !self.in_discard_let
                && let Expr::Path(ep) = call.func.as_ref()
                && let Some(last) = ep.path.segments.last()
            {
                let n = last.ident.to_string();
                if n == "Err" {
                    self.has_live_err = true;
                }
                if self.sets.validators.contains(&n) {
                    self.calls_live_validator = true;
                }
                if self.sets.tag_helpers.contains(&n) {
                    self.calls_live_tag_helper = true;
                }
            }
            visit::visit_expr_call(self, call);
        }
    }

    let mut lv = LiveValVis {
        sets,
        has_live_err: false,
        has_live_redacted: false,
        has_live_keymaterial: false,
        calls_live_validator: false,
        calls_live_tag_helper: false,
        in_discard_let: false,
    };
    lv.visit_block(block);

    if file_has_verified_validator && lv.calls_live_validator {
        return true;
    }
    (lv.has_live_err
        && lv.has_live_redacted
        && (lv.has_live_keymaterial || lv.calls_live_validator))
        || (matches!(
            f.name.as_str(),
            "verify_html_document_or_fragment"
                | "verify_html_document_or_fragment_with_origin"
                | "verify_unmasked_broken_json_strings_in_html_with_origin"
                | "flush_html_text_buf"
                | "flush_html_text_buf_with_origin"
        ) && (lv.calls_live_validator || (lv.has_live_err && lv.calls_live_tag_helper)))
}

fn block_compact_text(block: &Block) -> String {
    let mut ser = AstTextSer::default();
    ser.visit_block(block);
    ser.out
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect()
}

#[derive(Default)]
struct AstTextSer {
    out: String,
}

impl<'a> Visit<'a> for AstTextSer {
    fn visit_ident(&mut self, i: &'a syn::Ident) {
        self.out.push_str(&i.to_string());
        self.out.push(' ');
    }
    fn visit_lit(&mut self, l: &'a syn::Lit) {
        match l {
            syn::Lit::Str(s) => {
                self.out.push('"');
                self.out.push_str(&s.value());
                self.out.push('"');
            }
            syn::Lit::ByteStr(bs) => {
                self.out.push_str("b\"");
                self.out.push_str(&String::from_utf8_lossy(&bs.value()));
                self.out.push('"');
            }
            syn::Lit::Byte(b) => {
                self.out.push_str(&format!("b'{}'", b.value() as char));
            }
            syn::Lit::Char(c) => {
                self.out.push_str(&format!("'{}'", c.value()));
            }
            syn::Lit::Int(i) => self.out.push_str(&i.to_string()),
            _ => {}
        }
    }
    fn visit_expr_macro(&mut self, i: &'a syn::ExprMacro) {
        for seg in &i.mac.path.segments {
            self.out.push_str(&seg.ident.to_string());
        }
        self.out.push_str("!(");
        self.out.push_str(&i.mac.tokens.to_string());
        self.out.push(')');
    }
    fn visit_stmt_macro(&mut self, i: &'a syn::StmtMacro) {
        for seg in &i.mac.path.segments {
            self.out.push_str(&seg.ident.to_string());
        }
        self.out.push_str("!(");
        self.out.push_str(&i.mac.tokens.to_string());
        self.out.push(')');
    }
    fn visit_expr_index(&mut self, i: &'a syn::ExprIndex) {
        self.visit_expr(&i.expr);
        self.out.push('[');
        self.visit_expr(&i.index);
        self.out.push(']');
    }
    fn visit_expr_range(&mut self, i: &'a syn::ExprRange) {
        if let Some(ref s) = i.start {
            self.visit_expr(s);
        }
        self.out.push_str("..");
        if let Some(ref e) = i.end {
            self.visit_expr(e);
        }
    }
    fn visit_expr_reference(&mut self, i: &'a syn::ExprReference) {
        self.out.push('&');
        self.visit_expr(&i.expr);
    }
    fn visit_expr_binary(&mut self, i: &'a syn::ExprBinary) {
        self.visit_expr(&i.left);
        self.out.push_str(binop_str(&i.op));
        self.visit_expr(&i.right);
    }
    fn visit_expr_call(&mut self, i: &'a syn::ExprCall) {
        self.visit_expr(&i.func);
        self.out.push('(');
        for a in &i.args {
            self.visit_expr(a);
            self.out.push(',');
        }
        self.out.push(')');
    }
    fn visit_expr_method_call(&mut self, i: &'a syn::ExprMethodCall) {
        self.visit_expr(&i.receiver);
        self.out.push('.');
        self.out.push_str(&i.method.to_string());
        self.out.push('(');
        for a in &i.args {
            self.visit_expr(a);
            self.out.push(',');
        }
        self.out.push(')');
    }
}

fn binop_str(op: &syn::BinOp) -> &'static str {
    match op {
        syn::BinOp::Add(_) => "+",
        syn::BinOp::Sub(_) => "-",
        syn::BinOp::Eq(_) => "==",
        syn::BinOp::Ne(_) => "!=",
        syn::BinOp::Lt(_) => "<",
        syn::BinOp::Gt(_) => ">",
        syn::BinOp::Le(_) => "<=",
        syn::BinOp::Ge(_) => ">=",
        syn::BinOp::And(_) => "&&",
        syn::BinOp::Or(_) => "||",
        _ => "",
    }
}

fn block_is_safe_mask_helper(block: &Block) -> bool {
    let mut fill_targets: HashSet<String> = HashSet::new();
    let mut returned_fill = false;
    let mut has_bad = false;
    struct MaskVis<'a> {
        fill_targets: &'a mut HashSet<String>,
        returned_fill: &'a mut bool,
        has_bad: &'a mut bool,
    }
    impl<'a> Visit<'a> for MaskVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_expr_method_call(&mut self, mc: &'a syn::ExprMethodCall) {
            if mc.method == "fill"
                && let Some(base) = expr_base_ident(&mc.receiver)
            {
                self.fill_targets.insert(base);
            }
            if mc.method == "from_utf8_lossy" {
                *self.has_bad = true;
            }
            visit::visit_expr_method_call(self, mc);
        }
        fn visit_expr_macro(&mut self, em: &'a syn::ExprMacro) {
            if em.mac.path.is_ident("format") {
                *self.has_bad = true;
            }
        }
        fn visit_expr_return(&mut self, r: &'a syn::ExprReturn) {
            if let Some(ref e) = r.expr
                && expr_refs_any_var(e, self.fill_targets)
            {
                *self.returned_fill = true;
            }
            visit::visit_expr_return(self, r);
        }
    }
    let mut v = MaskVis {
        fill_targets: &mut fill_targets,
        returned_fill: &mut returned_fill,
        has_bad: &mut has_bad,
    };
    v.visit_block(block);
    if let Some(Stmt::Expr(tail, None)) = block.stmts.last()
        && expr_refs_any_var(tail, &fill_targets)
    {
        returned_fill = true;
    }
    !fill_targets.is_empty() && returned_fill && !has_bad
}

fn unwrap_parens(mut e: &Expr) -> &Expr {
    loop {
        match e {
            Expr::Paren(p) => e = &p.expr,
            Expr::Group(g) => e = &g.expr,
            _ => return e,
        }
    }
}

fn eval_const_int(e: &Expr) -> Option<i128> {
    match unwrap_parens(e) {
        Expr::Lit(el) => match &el.lit {
            syn::Lit::Int(li) => li.base10_digits().parse::<i128>().ok(),
            _ => None,
        },
        Expr::Unary(eu) if matches!(eu.op, syn::UnOp::Neg(_)) => {
            eval_const_int(&eu.expr).and_then(|v| v.checked_neg())
        }
        _ => None,
    }
}

fn eval_const_bool(e: &Expr) -> Option<bool> {
    match unwrap_parens(e) {
        Expr::Lit(el) => match &el.lit {
            syn::Lit::Bool(lb) => Some(lb.value),
            _ => None,
        },
        Expr::Unary(eu) if matches!(eu.op, syn::UnOp::Not(_)) => {
            eval_const_bool(&eu.expr).map(|b| !b)
        }
        Expr::Binary(eb) => match eb.op {
            syn::BinOp::And(_) => {
                let l = eval_const_bool(&eb.left);
                let r = eval_const_bool(&eb.right);
                if l == Some(false) || r == Some(false) {
                    Some(false)
                } else if l == Some(true) && r == Some(true) {
                    Some(true)
                } else {
                    None
                }
            }
            syn::BinOp::Or(_) => {
                let l = eval_const_bool(&eb.left);
                let r = eval_const_bool(&eb.right);
                if l == Some(true) || r == Some(true) {
                    Some(true)
                } else if l == Some(false) && r == Some(false) {
                    Some(false)
                } else {
                    None
                }
            }
            syn::BinOp::Eq(_) => {
                if let (Some(a), Some(b)) = (eval_const_int(&eb.left), eval_const_int(&eb.right)) {
                    return Some(a == b);
                }
                if let (Some(a), Some(b)) = (eval_const_bool(&eb.left), eval_const_bool(&eb.right)) {
                    return Some(a == b);
                }
                None
            }
            syn::BinOp::Ne(_) => {
                if let (Some(a), Some(b)) = (eval_const_int(&eb.left), eval_const_int(&eb.right)) {
                    return Some(a != b);
                }
                if let (Some(a), Some(b)) = (eval_const_bool(&eb.left), eval_const_bool(&eb.right)) {
                    return Some(a != b);
                }
                None
            }
            syn::BinOp::Lt(_) => Some(eval_const_int(&eb.left)? < eval_const_int(&eb.right)?),
            syn::BinOp::Gt(_) => Some(eval_const_int(&eb.left)? > eval_const_int(&eb.right)?),
            syn::BinOp::Le(_) => Some(eval_const_int(&eb.left)? <= eval_const_int(&eb.right)?),
            syn::BinOp::Ge(_) => Some(eval_const_int(&eb.left)? >= eval_const_int(&eb.right)?),
            _ => None,
        },
        _ => None,
    }
}

fn is_obviously_dead_cond(cond: &Expr) -> bool {
    if eval_const_bool(cond) == Some(false) {
        return true;
    }
    match unwrap_parens(cond) {
        Expr::Binary(eb) => {
            let c = expr_to_compact(cond);
            if matches!(eb.op, syn::BinOp::And(_)) {
                return is_obviously_dead_cond(&eb.left) || is_obviously_dead_cond(&eb.right);
            }
            if matches!(eb.op, syn::BinOp::Or(_)) {
                return is_obviously_dead_cond(&eb.left) && is_obviously_dead_cond(&eb.right);
            }
            if matches!(eb.op, syn::BinOp::Eq(_)) && c.contains("usize::MAX") {
                return true;
            }
            if matches!(eb.op, syn::BinOp::Gt(_) | syn::BinOp::Ge(_))
                && c.contains("usize::MAX")
                && c.contains(">usize::MAX")
            {
                return true;
            }
            false
        }
        _ => false,
    }
}

fn expr_refs_any_var(expr: &Expr, vars: &HashSet<String>) -> bool {
    struct VarHit<'a> {
        vars: &'a HashSet<String>,
        hit: bool,
    }
    impl<'a> Visit<'a> for VarHit<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_path(&mut self, ep: &'a syn::ExprPath) {
            if let Some(last) = ep.path.segments.last()
                && self.vars.contains(&last.ident.to_string())
            {
                self.hit = true;
            }
            visit::visit_expr_path(self, ep);
        }
    }
    let mut v = VarHit { vars, hit: false };
    v.visit_expr(expr);
    v.hit
}

fn expr_is_replace_redacted_on_var(expr: &Expr, vars: &HashSet<String>) -> bool {
    match unwrap_parens(expr) {
        Expr::MethodCall(mc) => {
            mc.method == "replace"
                && mc.args.iter().nth(1).is_some_and(expr_has_redacted_lit)
                && !matches!(unwrap_parens(&mc.receiver), Expr::Lit(_))
                && (expr_refs_any_var(&mc.receiver, vars)
                    || expr_is_replace_redacted_on_var(&mc.receiver, vars))
        }
        _ => false,
    }
}

fn expr_is_raw_tainted(
    expr: &Expr,
    raw_tainted: &HashSet<String>,
    known_sanitizers: &HashSet<String>,
) -> bool {
    let e = unwrap_parens(expr);
    if expr_is_replace_redacted_on_var(e, raw_tainted)
        || expr_calls_known_sanitizer_on_var(e, known_sanitizers, raw_tainted)
    {
        return false;
    }
    match e {
        Expr::Return(r) => r
            .expr
            .as_ref()
            .is_some_and(|inner| expr_is_raw_tainted(inner, raw_tainted, known_sanitizers)),
        Expr::Path(ep) => ep
            .path
            .segments
            .last()
            .is_some_and(|s| raw_tainted.contains(&s.ident.to_string())),
        Expr::MethodCall(mc) => {
            let m = mc.method.to_string();
            if matches!(
                m.as_str(),
                "len"
                    | "is_empty"
                    | "capacity"
                    | "contains"
                    | "starts_with"
                    | "ends_with"
                    | "is_char_boundary"
                    | "find"
                    | "rfind"
                    | "position"
                    | "count"
                    | "any"
                    | "all"
            ) {
                return false;
            }
            if matches!(
                m.as_str(),
                "to_string" | "to_owned" | "into" | "clone" | "trim" | "trim_start" | "trim_end"
            ) && mc.args.is_empty()
            {
                return expr_is_raw_tainted(&mc.receiver, raw_tainted, known_sanitizers);
            }
            expr_refs_any_var(e, raw_tainted)
                && !expr_calls_known_sanitizer_on_var(e, known_sanitizers, raw_tainted)
                && !expr_is_replace_redacted_on_var(e, raw_tainted)
        }
        Expr::Call(call) => {
            if let Expr::Path(ep) = call.func.as_ref() {
                let segs: Vec<String> = ep.path.segments.iter().map(|s| s.ident.to_string()).collect();
                if let Some(last) = segs.last() {
                    if known_sanitizers.contains(last) {
                        return false;
                    }
                    if last == "with_capacity"
                        && segs.iter().any(|s| s == "String" || s == "Vec")
                    {
                        return false;
                    }
                }
            }
            call.args.iter().any(|a| {
                !matches!(unwrap_parens(a), Expr::Lit(_))
                    && expr_is_raw_tainted(a, raw_tainted, known_sanitizers)
            })
        }
        Expr::Macro(em) => {
            let name = em
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if name == "format" {
                let tok_s = em.mac.tokens.to_string();
                if tok_s.to_ascii_lowercase().contains("[redacted]") {
                    return false;
                }
                return raw_tainted.iter().any(|v| contains_ident_word(&tok_s, v));
            }
            false
        }
        _ => false,
    }
}

fn block_has_raw_param_passthrough(
    block: &Block,
    f: &FnInfo,
    known_sanitizers: &HashSet<String>,
    known_validators: &HashSet<String>,
    allow_tag_gated: bool,
) -> bool {
    let non_string_struct_ret = f.ret_type_str.as_deref().is_some_and(|r| {
        !r.contains("String") && !r.contains("str") && !r.contains("Vec<u8>") && !r.contains("[u8]")
    });
    let mut raw_tainted: HashSet<String> = f.param_names.iter().cloned().collect();
    let mut changed = true;
    while changed {
        changed = false;
        for stmt in &block.stmts {
            if let Stmt::Local(loc) = stmt
                && let Some(init) = &loc.init
                && !(non_string_struct_ret
                    && matches!(unwrap_parens(&init.expr), Expr::MethodCall(mc) if mc.method == "clone" && mc.args.is_empty()))
                && expr_is_raw_tainted(&init.expr, &raw_tainted, known_sanitizers)
            {
                let mut ids = Vec::new();
                collect_pat_idents(&loc.pat, &mut ids);
                for id in ids {
                    if !id.starts_with('_') && raw_tainted.insert(id) {
                        changed = true;
                    }
                }
            }
        }
    }

    struct PassVis<'a> {
        raw_tainted: &'a HashSet<String>,
        own_fn_name: &'a str,
        known_sanitizers: &'a HashSet<String>,
        known_validators: &'a HashSet<String>,
        in_safe_early_guard: bool,
        unsafe_return: bool,
    }
    impl<'a> PassVis<'a> {
        fn is_safe_guard_if(&self, ei: &syn::ExprIf) -> bool {
            let cond_s = expr_to_compact(&ei.cond);
            if cond_s.contains("depth>=") || cond_s.contains("depth>") {
                return true;
            }
            if cond_s.contains("contains_keymaterial") {
                return true;
            }
            if self
                .known_validators
                .iter()
                .any(|v| contains_ident_word(&cond_s, v))
                && cond_s.contains(".is_ok()")
            {
                return true;
            }
            let then_c = block_compact_text(&ei.then_branch);
            self.known_sanitizers
                .iter()
                .any(|s| contains_ident_word(&then_c, s))
                || (cond_s.contains("serde_jsonfrom_strString")
                    && then_c.contains(&format!("{}(", self.own_fn_name))
                    && then_c.contains("!=inner"))
                || (cond_s.contains("!=") && then_c.contains("return"))
        }
    }
    impl<'a> Visit<'a> for PassVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            let prev = self.in_safe_early_guard;
            if self.is_safe_guard_if(ei) {
                self.in_safe_early_guard = true;
            }
            self.visit_block(&ei.then_branch);
            self.in_safe_early_guard = prev;
            if let Some((_, eb)) = &ei.else_branch {
                self.visit_expr(eb);
            }
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_expr_return(&mut self, r: &'a syn::ExprReturn) {
            if !self.in_safe_early_guard
                && let Some(ref e) = r.expr
                && expr_is_raw_tainted(e, self.raw_tainted, self.known_sanitizers)
            {
                self.unsafe_return = true;
            }
            visit::visit_expr_return(self, r);
        }
    }

    let mut pv = PassVis {
        raw_tainted: &raw_tainted,
        own_fn_name: &f.name,
        known_sanitizers,
        known_validators,
        in_safe_early_guard: false,
        unsafe_return: false,
    };
    pv.visit_block(block);
    if pv.unsafe_return {
        return true;
    }
    if !allow_tag_gated
        && let Some(Stmt::Expr(tail, None)) = block.stmts.last()
        && expr_is_raw_tainted(tail, &raw_tainted, known_sanitizers)
    {
        return true;
    }
    false
}

fn block_has_direct_redacted_return(block: &Block) -> bool {
    struct RetRedVis {
        hit: bool,
    }
    impl<'a> Visit<'a> for RetRedVis {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_return(&mut self, r: &'a syn::ExprReturn) {
            if let Some(ref e) = r.expr {
                let c = expr_to_compact(e).to_ascii_lowercase();
                if c.contains("[redacted]") && c.contains("keymaterial") {
                    self.hit = true;
                }
            }
        }
    }
    let mut v = RetRedVis { hit: false };
    v.visit_block(block);
    if v.hit {
        return true;
    }
    if let Some(Stmt::Expr(tail, None)) = block.stmts.last() {
        let c = expr_to_compact(tail).to_ascii_lowercase();
        if c.contains("[redacted]") && c.contains("keymaterial") {
            return true;
        }
    }
    false
}

fn block_is_genuine_primary_sanitizer(
    block: &Block,
    f: &FnInfo,
    sets: &VerifiedWlanSets<'_>,
) -> bool {
    let mut param_tainted: HashSet<String> = f.param_names.iter().cloned().collect();
    for stmt in &block.stmts {
        if let Stmt::Local(loc) = stmt
            && let Some(init) = &loc.init
            && expr_refs_any_var(&init.expr, &param_tainted)
        {
            let mut ids = Vec::new();
            collect_pat_idents(&loc.pat, &mut ids);
            param_tainted.extend(ids);
        }
    }

    let mut replace_redacted_vars: HashSet<String> = HashSet::new();
    let mut rep_changed = true;
    while rep_changed {
        rep_changed = false;
        for stmt in &block.stmts {
            if let Stmt::Local(loc) = stmt
                && let Some(init) = &loc.init
            {
                let rhs_rep = expr_is_replace_redacted_on_var(&init.expr, &param_tainted)
                    || expr_is_replace_redacted_on_var(&init.expr, &replace_redacted_vars)
                    || expr_refs_any_var(&init.expr, &replace_redacted_vars);
                if rhs_rep {
                    let mut ids = Vec::new();
                    collect_pat_idents(&loc.pat, &mut ids);
                    for id in ids {
                        if !id.starts_with('_') && replace_redacted_vars.insert(id) {
                            rep_changed = true;
                        }
                    }
                }
            }
        }
    }

    struct PrimVis<'a> {
        param_tainted: &'a HashSet<String>,
        replace_redacted_vars: &'a HashSet<String>,
        sets: &'a VerifiedWlanSets<'a>,
        has_cursor_loop_redacted: bool,
        has_replace_redacted: bool,
        has_tag_gated_redacted_return: bool,
        has_assert_clean: bool,
        has_sanitize_call: bool,
        has_redacted_lit: bool,
        in_discard_let: bool,
    }
    impl<'a> Visit<'a> for PrimVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_local(&mut self, loc: &'a Local) {
            let is_discard = matches!(&loc.pat, Pat::Wild(_))
                || matches!(&loc.pat, Pat::Ident(pi) if pi.ident.to_string().starts_with('_'));
            let prev = self.in_discard_let;
            self.in_discard_let = is_discard;
            visit::visit_local(self, loc);
            self.in_discard_let = prev;
        }
        fn visit_lit_str(&mut self, ls: &'a syn::LitStr) {
            if !self.in_discard_let && ls.value().to_ascii_lowercase().contains("[redacted]") {
                self.has_redacted_lit = true;
            }
        }
        fn visit_expr_while(&mut self, w: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&w.cond) {
                return;
            }
            let cond_s = expr_to_compact(&w.cond);
            if cond_s.contains("find_opening_keymaterial_tag")
                && while_body_emits_redacted_and_advances_cursor(&w.body)
            {
                self.has_cursor_loop_redacted = true;
            }
            visit::visit_expr_while(self, w);
        }
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            let cond_s = expr_to_compact(&ei.cond);
            if !self.in_discard_let
                && ((cond_s.contains("find_opening_keymaterial_tag")
                    && self.sets.tag_helpers.contains("find_opening_keymaterial_tag"))
                    || (cond_s.contains("contains_keymaterial_tag")
                        && self.sets.tag_helpers.contains("contains_keymaterial_tag")))
                && !cond_s.contains("is_empty")
                && expr_refs_any_var(&ei.cond, self.param_tainted)
                && block_has_direct_redacted_return(&ei.then_branch)
            {
                self.has_tag_gated_redacted_return = true;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_return(&mut self, ret: &'a syn::ExprReturn) {
            if let Some(ref e) = ret.expr
                && (expr_is_replace_redacted_on_var(e, self.param_tainted)
                    || expr_is_replace_redacted_on_var(e, self.replace_redacted_vars)
                    || expr_refs_any_var(e, self.replace_redacted_vars))
            {
                self.has_replace_redacted = true;
            }
            visit::visit_expr_return(self, ret);
        }
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if !self.in_discard_let
                && let Expr::Path(ep) = call.func.as_ref()
                && let Some(last) = ep.path.segments.last()
            {
                let name = last.ident.to_string();
                if self.sets.validators.contains(&name) {
                    self.has_assert_clean = true;
                }
                if self.sets.sanitizers.contains(&name) {
                    self.has_sanitize_call = true;
                }
            }
            visit::visit_expr_call(self, call);
        }
    }

    let mut vis = PrimVis {
        param_tainted: &param_tainted,
        replace_redacted_vars: &replace_redacted_vars,
        sets,
        has_cursor_loop_redacted: false,
        has_replace_redacted: false,
        has_tag_gated_redacted_return: false,
        has_assert_clean: false,
        has_sanitize_call: false,
        has_redacted_lit: false,
        in_discard_let: false,
    };
    vis.visit_block(block);
    if !vis.has_replace_redacted
        && let Some(Stmt::Expr(tail, None)) = block.stmts.last()
        && (expr_is_replace_redacted_on_var(tail, &param_tainted)
            || expr_is_replace_redacted_on_var(tail, &replace_redacted_vars)
            || expr_refs_any_var(tail, &replace_redacted_vars))
    {
        vis.has_replace_redacted = true;
    }
    if block_has_raw_param_passthrough(
        block,
        f,
        sets.sanitizers,
        sets.validators,
        vis.has_tag_gated_redacted_return,
    ) {
        return false;
    }
    let has_html_sanitizer_gates =
        vis.has_assert_clean && vis.has_sanitize_call && vis.has_redacted_lit;
    vis.has_cursor_loop_redacted
        || vis.has_replace_redacted
        || vis.has_tag_gated_redacted_return
        || has_html_sanitizer_gates
}

fn block_is_valid_sanitizer_wrapper(
    block: &Block,
    f: &FnInfo,
    known_sanitizers: &HashSet<String>,
    known_validators: &HashSet<String>,
) -> bool {
    if block_has_raw_param_passthrough(block, f, known_sanitizers, known_validators, false) {
        return false;
    }

    let mut param_tainted: HashSet<String> = f.param_names.iter().cloned().collect();
    struct TaintCollect<'a> {
        param_tainted: &'a mut HashSet<String>,
        changed: bool,
    }
    impl<'a> Visit<'a> for TaintCollect<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_local(&mut self, loc: &'a Local) {
            if let Some(init) = &loc.init
                && expr_refs_any_var(&init.expr, self.param_tainted)
            {
                let mut ids = Vec::new();
                collect_pat_idents(&loc.pat, &mut ids);
                for id in ids {
                    if self.param_tainted.insert(id) {
                        self.changed = true;
                    }
                }
            }
            visit::visit_local(self, loc);
        }
        fn visit_expr_assign(&mut self, ea: &'a syn::ExprAssign) {
            if expr_refs_any_var(&ea.right, self.param_tainted)
                && let Some(base) = expr_base_ident(&ea.left)
                && self.param_tainted.insert(base)
            {
                self.changed = true;
            }
            visit::visit_expr_assign(self, ea);
        }
    }
    for _ in 0..8 {
        let mut tc = TaintCollect {
            param_tainted: &mut param_tainted,
            changed: false,
        };
        tc.visit_block(block);
        if !tc.changed {
            break;
        }
    }

    let mut sanitized_vars: HashSet<String> = HashSet::new();
    struct SanCollect<'a> {
        known_sanitizers: &'a HashSet<String>,
        param_tainted: &'a HashSet<String>,
        sanitized_vars: &'a mut HashSet<String>,
        changed: bool,
    }
    impl<'a> Visit<'a> for SanCollect<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_local(&mut self, loc: &'a Local) {
            if let Some(init) = &loc.init {
                let rhs_san = expr_calls_known_sanitizer_on_var(
                    &init.expr,
                    self.known_sanitizers,
                    self.param_tainted,
                ) || expr_refs_any_var(&init.expr, self.sanitized_vars);
                if rhs_san {
                    let mut ids = Vec::new();
                    collect_pat_idents(&loc.pat, &mut ids);
                    for id in ids {
                        if !id.starts_with('_') && self.sanitized_vars.insert(id) {
                            self.changed = true;
                        }
                    }
                }
            }
            visit::visit_local(self, loc);
        }
        fn visit_expr_method_call(&mut self, mc: &'a syn::ExprMethodCall) {
            if matches!(mc.method.to_string().as_str(), "push_str" | "push")
                && mc.args.iter().any(|a| {
                    expr_calls_known_sanitizer_on_var(
                        a,
                        self.known_sanitizers,
                        self.param_tainted,
                    ) || expr_refs_any_var(a, self.sanitized_vars)
                        || expr_has_redacted_lit(a)
                })
                && let Some(base) = expr_base_ident(&mc.receiver)
                && !base.starts_with('_')
                && self.sanitized_vars.insert(base)
            {
                self.changed = true;
            }
            visit::visit_expr_method_call(self, mc);
        }
        fn visit_expr_assign(&mut self, ea: &'a syn::ExprAssign) {
            if (expr_calls_known_sanitizer_on_var(
                &ea.right,
                self.known_sanitizers,
                self.param_tainted,
            ) || expr_refs_any_var(&ea.right, self.sanitized_vars))
                && let Some(base) = expr_base_ident(&ea.left)
                && !base.starts_with('_')
                && self.sanitized_vars.insert(base)
            {
                self.changed = true;
            }
            visit::visit_expr_assign(self, ea);
        }
    }
    for _ in 0..8 {
        let mut sc = SanCollect {
            known_sanitizers,
            param_tainted: &param_tainted,
            sanitized_vars: &mut sanitized_vars,
            changed: false,
        };
        sc.visit_block(block);
        if !sc.changed {
            break;
        }
    }

    struct WrapVis<'a> {
        known: &'a HashSet<String>,
        param_tainted: &'a HashSet<String>,
        sanitized_vars: &'a HashSet<String>,
        found_valid_propagated_call: bool,
        in_discard_let: bool,
    }
    impl<'a> Visit<'a> for WrapVis<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_local(&mut self, loc: &'a Local) {
            let is_discard = matches!(&loc.pat, Pat::Wild(_))
                || matches!(&loc.pat, Pat::Ident(pi) if pi.ident.to_string().starts_with('_'));
            let prev = self.in_discard_let;
            self.in_discard_let = is_discard;
            visit::visit_local(self, loc);
            self.in_discard_let = prev;
        }
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if is_obviously_dead_cond(&ei.cond) {
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if is_obviously_dead_cond(&ew.cond) {
                return;
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_expr_return(&mut self, ret: &'a syn::ExprReturn) {
            if let Some(ref e) = ret.expr
                && (expr_calls_known_sanitizer_on_var(e, self.known, self.param_tainted)
                    || expr_refs_any_var(e, self.sanitized_vars))
            {
                self.found_valid_propagated_call = true;
            }
            visit::visit_expr_return(self, ret);
        }
    }
    let mut v = WrapVis {
        known: known_sanitizers,
        param_tainted: &param_tainted,
        sanitized_vars: &sanitized_vars,
        found_valid_propagated_call: false,
        in_discard_let: false,
    };
    v.visit_block(block);
    if !v.found_valid_propagated_call
        && let Some(Stmt::Expr(tail, None)) = block.stmts.last()
        && (expr_calls_known_sanitizer_on_var(tail, known_sanitizers, &param_tainted)
            || expr_refs_any_var(tail, &sanitized_vars))
    {
        v.found_valid_propagated_call = true;
    }
    v.found_valid_propagated_call
}

fn expr_calls_known_sanitizer_on_var(
    expr: &Expr,
    known: &HashSet<String>,
    param_tainted: &HashSet<String>,
) -> bool {
    struct Hit<'a> {
        known: &'a HashSet<String>,
        param_tainted: &'a HashSet<String>,
        hit: bool,
    }
    impl<'a> Visit<'a> for Hit<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if let Expr::Path(ep) = call.func.as_ref()
                && let Some(last) = ep.path.segments.last()
                && self.known.contains(&last.ident.to_string())
                && call.args.iter().any(|a| {
                    !matches!(unwrap_parens(a), Expr::Lit(_))
                        && expr_refs_any_var(a, self.param_tainted)
                })
            {
                self.hit = true;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut h = Hit {
        known,
        param_tainted,
        hit: false,
    };
    h.visit_expr(expr);
    h.hit
}

fn expr_has_redacted_lit(e: &Expr) -> bool {
    match e {
        Expr::Lit(el) => match &el.lit {
            syn::Lit::Str(ls) => ls.value().to_ascii_lowercase().contains("[redacted]"),
            syn::Lit::ByteStr(lbs) => String::from_utf8_lossy(&lbs.value())
                .to_ascii_lowercase()
                .contains("[redacted]"),
            _ => false,
        },
        Expr::Reference(r) => expr_has_redacted_lit(&r.expr),
        Expr::Paren(p) => expr_has_redacted_lit(&p.expr),
        _ => false,
    }
}

fn expr_to_compact(e: &Expr) -> String {
    let mut ser = AstTextSer::default();
    ser.visit_expr(e);
    ser.out.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}
struct FlowChecker<'a> {
    f: &'a FnInfo,
    sets: &'a VerifiedWlanSets<'a>,
    slice_vars: &'a HashSet<String>,
    trim_len_vars: &'a HashSet<String>,
    has_verified_cursor_loop: bool,
    has_live_deserializer_loop: bool,
    is_prefix_helper: bool,
    is_non_secret_return: bool,
    in_self_closing_if: bool,
    in_already_redacted_if: bool,
    in_validator_clean_if: bool,
    in_redacted_ns_format: bool,
    in_html_closing_slash_if: bool,
    in_html_open_tag_end_if: bool,
    in_html_bang_if: bool,
    in_html_tag_attr_dirty_if: bool,
    in_html_close_tag_if: bool,
    in_html_json_text_buf_if: bool,
    in_clean_cross_cell_if: bool,
    in_safe_sanitizer_arg: bool,
    in_safe_strip_closure: bool,
    in_discard_let: bool,
    unsafe_found: bool,
}

impl<'a> FlowChecker<'a> {
    fn is_html_frag_fn(&self) -> bool {
        matches!(
            self.f.name.as_str(),
            "sanitize_html_fragment_r4" | "sanitize_html_fragment_r4_with_origin"
        )
    }

    fn is_verified_validator_call(&self, cond_s: &str) -> bool {
        self.sets
            .validators
            .iter()
            .any(|v| contains_ident_word(cond_s, v))
    }

    fn is_safe_slice_expr(&self, expr: &Expr) -> bool {
        let compact = expr_to_compact(expr);

        if self.trim_len_vars.iter().any(|tv| {
            compact == format!("&s[..{tv}]")
                || compact == format!("&s[{tv}..]")
                || compact.contains(&format!("[..{tv}]"))
                || compact.contains(&format!("[{tv}..]"))
        }) {
            return true;
        }

        if self.in_redacted_ns_format
            && (compact.contains("[ps..pe]")
                || compact.contains("prefix")
                || compact.contains("ns"))
        {
            return true;
        }

        if self.has_verified_cursor_loop
            && (compact.contains("[cursor..open_start]")
                || compact.contains("[cursor..after_name]")
                || compact.contains("[cursor..]")
                || (self.in_clean_cross_cell_if && compact.contains("[cursor..ce]")))
        {
            return true;
        }

        if self.in_self_closing_if
            && (compact.contains("[open_start..open_end]")
                || compact.contains("[cursor..open_end]"))
        {
            return true;
        }

        if self.in_already_redacted_if && compact.contains("[cursor..close_tag_end]") {
            return true;
        }

        if (self.in_validator_clean_if || self.in_safe_sanitizer_arg)
            && !compact.contains("open_end..close")
        {
            return true;
        }

        if self.is_html_frag_fn() {
            if self.in_safe_strip_closure
                && (compact == "rest" || compact == "enc[1..enc.len()-1]")
            {
                return true;
            }
            if self.in_html_closing_slash_if
                && self.in_html_open_tag_end_if
                && compact.contains("[i..end]")
            {
                return true;
            }
            if self.in_html_bang_if
                && (compact.contains("[i..i+rel+1]") || compact == "&bytes[i..]" || compact == "bytes[i..]")
            {
                return true;
            }
            if self.in_html_tag_attr_dirty_if && compact.contains("[i..tag_name_end]") {
                return true;
            }
            if self.in_html_close_tag_if && compact.contains("[close_start..close_end]") {
                return true;
            }
        }

        if self.f.name == "sanitize_html_tag_attributes_r4"
            && (self.sets.tag_helpers.contains("scan_unquoted_html_token_end")
                || self.sets.all_fns.iter().any(|fn_i| {
                    fn_i.name == "scan_unquoted_html_token_end_cached"
                        && fn_i.ret_type_str.as_deref() == Some("usize")
                        && !fn_i.has_exec_sink
                        && !fn_i.has_io_sink
                        && !fn_i.has_thread_spawn
                        && !fn_i.has_global_state_sink
                }))
            && (compact.contains("[ws_start..k]")
                || compact.contains("[eq_ws_start..k]")
                || compact.contains("[post_eq_ws..k]")
                || compact.contains("[k..next]"))
        {
            return true;
        }

        if self.is_prefix_helper && compact.contains("[prefix_start..colon_pos]") {
            return true;
        }

        if self.f.name == "sanitize_json_substrings_and_mask"
            && self.has_live_deserializer_loop
            && self.sets.sanitizers.contains("sanitize_json_value_r4_inner")
            && (compact.contains("[i..i+consumed]")
                || compact.contains("[cursor..i]")
                || compact.contains("[cursor..]")
                || compact == "rep")
        {
            return true;
        }

        false
    }

    fn check_sink_expr(&mut self, expr: &Expr) {
        if self.unsafe_found {
            return;
        }
        if contains_unsafe_slice_flow_in_expr(expr, self) {
            self.unsafe_found = true;
        }
    }
}

impl<'a> Visit<'a> for FlowChecker<'a> {
    fn visit_item(&mut self, _: &'a Item) {}

    fn visit_expr_closure(&mut self, ec: &'a syn::ExprClosure) {
        let prev_strip = self.in_safe_strip_closure;
        if self.is_html_frag_fn()
            && self.sets.sanitizers.contains("sanitize_string_r4_inner_with_origin")
            && let Some(first_pat) = ec.inputs.first()
        {
            let mut ids = Vec::new();
            collect_pat_idents(first_pat, &mut ids);
            let body_c = expr_to_compact(&ec.body);
            if ids.iter().any(|id| id == "sanitized")
                && body_c.contains("sanitize_string_r4_inner_with_origin")
                && body_c.contains("sanitized.strip_prefix")
            {
                self.in_safe_strip_closure = true;
            }
        }
        visit::visit_expr_closure(self, ec);
        self.in_safe_strip_closure = prev_strip;
    }

    fn visit_local(&mut self, loc: &'a Local) {
        let is_discard = matches!(&loc.pat, Pat::Wild(_))
            || matches!(&loc.pat, Pat::Ident(pi) if pi.ident.to_string().starts_with('_'));
        let prev = self.in_discard_let;
        self.in_discard_let = is_discard;
        visit::visit_local(self, loc);
        self.in_discard_let = prev;
    }

    fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
        if is_obviously_dead_cond(&ei.cond) {
            if let Some((_, eb)) = &ei.else_branch {
                self.visit_expr(eb);
            }
            return;
        }
        let cond_s = expr_to_compact(&ei.cond);
        let prev_sc = self.in_self_closing_if;
        let prev_ar = self.in_already_redacted_if;
        let prev_vc = self.in_validator_clean_if;
        let prev_cs = self.in_html_closing_slash_if;
        let prev_ote = self.in_html_open_tag_end_if;
        let prev_bg = self.in_html_bang_if;
        let prev_ta = self.in_html_tag_attr_dirty_if;
        let prev_hct = self.in_html_close_tag_if;
        let prev_jtb = self.in_html_json_text_buf_if;
        let prev_ccc = self.in_clean_cross_cell_if;

        if cond_s.contains("is_self_closing")
            || (cond_s.contains("gt_pos") && cond_s.contains("b'/'"))
        {
            self.in_self_closing_if = true;
        }
        if cond_s.contains("open_end..close_tag_start") && cond_s.contains("[REDACTED]") {
            self.in_already_redacted_if = true;
        }
        if self.is_verified_validator_call(&cond_s) && cond_s.contains(".is_ok()") {
            self.in_validator_clean_if = true;
        }
        let has_or = cond_s.contains("||");
        if !has_or
            && self.has_verified_cursor_loop
            && cond_s.contains("clean_cross_cell_km_spans.get(")
        {
            self.in_clean_cross_cell_if = true;
        }
        if self.is_html_frag_fn() {
            if !has_or && cond_s.starts_with("bytes.get(") && cond_s.contains("==Some(&b'/'") {
                self.in_html_closing_slash_if = true;
            }
            if !has_or && cond_s.contains("find_html_open_tag_end") {
                self.in_html_open_tag_end_if = true;
            }
            if !has_or && cond_s.starts_with("bytes.get(") && cond_s.contains("==Some(&b'!'") {
                self.in_html_bang_if = true;
            }
            if cond_s.contains("check_html_tag_attributes")
                && cond_s.contains(".is_err()")
                && (self.sets.validators.contains("check_html_tag_attributes")
                    || self.sets.tag_helpers.contains("check_html_tag_attributes")
                    || self.sets.tag_helpers.contains("check_html_tag_attributes_with_depth"))
            {
                self.in_html_tag_attr_dirty_if = true;
            }
            if !has_or
                && cond_s.contains("find_html_close_tag")
                && self.sets.tag_helpers.contains("find_html_close_tag")
                && cond_s.contains("close_start")
                && cond_s.contains("close_end")
            {
                self.in_html_close_tag_if = true;
            }
            if (cond_s == "in_json_string" || (!has_or && cond_s == "bytes[i]!=b'<'"))
                && self.f.callees.iter().any(|c| self.sets.validators.contains(c))
            {
                self.in_html_json_text_buf_if = true;
            }
        } else if matches!(
            self.f.name.as_str(),
            "verify_html_document_or_fragment" | "verify_html_document_or_fragment_with_origin"
        ) && (cond_s == "in_json_string" || (!has_or && cond_s == "bytes[i]!=b'<'"))
            && self.f.callees.iter().any(|c| self.sets.validators.contains(c))
        {
            self.in_html_json_text_buf_if = true;
        }

        self.visit_expr(&ei.cond);
        self.visit_block(&ei.then_branch);

        self.in_self_closing_if = prev_sc;
        self.in_already_redacted_if = prev_ar;
        self.in_validator_clean_if = prev_vc;
        self.in_html_closing_slash_if = prev_cs;
        self.in_html_open_tag_end_if = prev_ote;
        self.in_html_bang_if = prev_bg;
        self.in_html_tag_attr_dirty_if = prev_ta;
        self.in_html_close_tag_if = prev_hct;
        self.in_html_json_text_buf_if = prev_jtb;
        self.in_clean_cross_cell_if = prev_ccc;

        if let Some((_, else_branch)) = &ei.else_branch {
            let prev_vc2 = self.in_validator_clean_if;
            let prev_ssa2 = self.in_safe_sanitizer_arg;
            if ((self.is_verified_validator_call(&cond_s)
                || (cond_s.contains("check_html_tag_attributes")
                    && (self.sets.tag_helpers.contains("check_html_tag_attributes")
                        || self.sets.tag_helpers.contains("check_html_tag_attributes_with_depth"))))
                && cond_s.contains(".is_err()"))
                || cond_s.contains("name_raw_dirty")
                || cond_s.contains("name_u003c_dirty")
            {
                self.in_validator_clean_if = true;
            }
            if self.is_html_frag_fn()
                && self.sets.validators.iter().any(|v| {
                    (v == "flush_html_text_buf" || v == "flush_html_text_buf_with_origin")
                        && contains_ident_word(&cond_s, v)
                })
            {
                self.in_safe_sanitizer_arg = true;
            }
            self.visit_expr(else_branch);
            self.in_validator_clean_if = prev_vc2;
            self.in_safe_sanitizer_arg = prev_ssa2;
        }
    }

    fn visit_expr_return(&mut self, ret: &'a syn::ExprReturn) {
        let prev_ssa = self.in_safe_sanitizer_arg;
        self.in_safe_sanitizer_arg = false;
        if !self.is_non_secret_return
            && let Some(ref e) = ret.expr
        {
            self.check_sink_expr(e);
        }
        visit::visit_expr_return(self, ret);
        self.in_safe_sanitizer_arg = prev_ssa;
    }

    fn visit_expr_assign(&mut self, ea: &'a syn::ExprAssign) {
        if matches!(
            unwrap_parens(&ea.left),
            Expr::Index(_) | Expr::Unary(syn::ExprUnary { op: syn::UnOp::Deref(_), .. })
        ) {
            let rhs_safe = matches!(&*ea.right, Expr::Lit(el) if matches!(&el.lit, syn::Lit::Byte(lb) if matches!(lb.value(), b' ' | b'_' | 0)) || matches!(&el.lit, syn::Lit::Int(_)));
            if !rhs_safe {
                self.check_sink_expr(&ea.right);
            }
        }
        visit::visit_expr_assign(self, ea);
    }

    fn visit_expr_binary(&mut self, eb: &'a syn::ExprBinary) {
        if matches!(eb.op, syn::BinOp::AddAssign(_)) {
            self.check_sink_expr(&eb.right);
        }
        visit::visit_expr_binary(self, eb);
    }

    fn visit_expr_method_call(&mut self, mc: &'a syn::ExprMethodCall) {
        let m = mc.method.to_string();
        let recv_compact = expr_to_compact(&mc.receiver);
        let full_compact = {
            let mut ser = AstTextSer::default();
            ser.visit_expr_method_call(mc);
            ser.out.chars().filter(|c| !c.is_ascii_whitespace()).collect::<String>()
        };
        let is_lower_byte_collect = m == "collect"
            && !receiver_has_chars_call(&mc.receiver)
            && (recv_compact.contains("u8::to_ascii_lowercase")
                || recv_compact.contains("u8to_ascii_lowercase"))
            && !full_compact.contains("::<String>");
        if matches!(
            m.as_str(),
            "to_string" | "to_owned" | "into" | "collect" | "concat" | "join" | "to_vec"
        ) && !is_lower_byte_collect
        {
            self.check_sink_expr(&mc.receiver);
        }
        if matches!(
            m.as_str(),
            "push"
                | "push_str"
                | "insert_str"
                | "replace_range"
                | "extend"
                | "extend_from_slice"
                | "copy_from_slice"
                | "clone_from_slice"
        ) {
            let safe_text_buf = m == "extend_from_slice"
                && self.in_html_json_text_buf_if
                && recv_compact == "text_buf"
                && mc.args.first().is_some_and(|a| {
                    let ac = expr_to_compact(a);
                    ac == "&bytes[i..end]" || ac == "&bytes[i..next_lt]"
                });
            let safe_tag_elem = m == "push"
                && (recv_compact == "out" || recv_compact == "text_buf")
                && mc.args.first().is_some_and(|a| {
                    let ac = expr_to_compact(a);
                    ac == "bytes[i]" || ac == "bytes[i]aschar" || matches!(a, Expr::Lit(_))
                });
            if !safe_text_buf && !safe_tag_elem {
                for arg in &mc.args {
                    self.check_sink_expr(arg);
                }
            }
        }
        visit::visit_expr_method_call(self, mc);
    }

    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let Expr::Path(ep) = call.func.as_ref() {
            let compact_callee = ep
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            let safe_validator_utf8_norm = self.f.wlan_kind == Some(WlanHelperKind::Validator)
                && self.is_non_secret_return
                && !self.f.has_io_sink
                && !self.f.has_exec_sink
                && !self.f.has_thread_spawn
                && !self.f.has_global_state_sink
                && (compact_callee == "String::from_utf8"
                    || compact_callee == "String::from_utf8_lossy");
            if (compact_callee == "String::from"
                || compact_callee == "String::from_utf8"
                || compact_callee == "String::from_utf8_lossy"
                || compact_callee == "String::from_iter"
                || compact_callee == "Vec::from"
                || compact_callee == "Cow::from")
                && !self.in_safe_sanitizer_arg
                && !safe_validator_utf8_norm
            {
                for arg in &call.args {
                    self.check_sink_expr(arg);
                }
            }
            if let Some(last) = ep.path.segments.last() {
                let lname = last.ident.to_string();
                let verified_callee = !self.in_discard_let
                    && (self.sets.sanitizers.contains(&lname)
                        || ((self.f.wlan_kind == Some(WlanHelperKind::Validator)
                            || self.is_html_frag_fn()
                            || (self.f.wlan_kind == Some(WlanHelperKind::TagHelperFn)
                                && self.is_non_secret_return))
                            && self.sets.validators.contains(&lname)));
                if verified_callee {
                    let prev = self.in_safe_sanitizer_arg;
                    for arg in &call.args {
                        let has_ret_or_blk = matches!(unwrap_parens(arg), Expr::Block(_))
                            || expr_contains_return(arg);
                        self.in_safe_sanitizer_arg = !has_ret_or_blk;
                        visit::visit_expr(self, arg);
                    }
                    self.in_safe_sanitizer_arg = prev;
                    return;
                }
                if (lname == "Err" || lname == "Some")
                    && !self.is_prefix_helper
                    && (self.f.wlan_kind == Some(WlanHelperKind::TagHelperFn)
                        || self.f.wlan_kind == Some(WlanHelperKind::Validator))
                {
                    for arg in &call.args {
                        self.check_sink_expr(arg);
                    }
                }
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_macro(&mut self, em: &'a syn::ExprMacro) {
        let name = em
            .mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if matches!(name.as_str(), "format" | "write" | "writeln") {
            let tok_str = em.mac.tokens.to_string();
            let is_redacted_ns = name == "format"
                && tok_str.to_ascii_lowercase().contains("[redacted]")
                && (tok_str.contains("keyMaterial") || tok_str.contains("keymaterial"));
            let prev = self.in_redacted_ns_format;
            if is_redacted_ns {
                self.in_redacted_ns_format = true;
            }
            let skip_args = if name == "format" { 1 } else { 2 };
            if let Ok(args) = syn::parse::Parser::parse2(
                syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated,
                em.mac.tokens.clone(),
            ) {
                for arg in args.iter().skip(skip_args) {
                    self.check_sink_expr(arg);
                }
            } else if !is_redacted_ns {
                let compact_toks: String =
                    tok_str.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                if compact_toks.contains("..")
                    || self
                        .slice_vars
                        .iter()
                        .any(|sv| contains_ident_word(&tok_str, sv))
                {
                    self.unsafe_found = true;
                }
            }
            self.in_redacted_ns_format = prev;
        }
    }
}

fn contains_unsafe_slice_flow_in_expr<'a>(expr: &'a Expr, fc: &FlowChecker<'a>) -> bool {
    struct SubCheck<'b, 'a> {
        fc: &'b FlowChecker<'a>,
        unsafe_hit: bool,
    }
    impl<'b, 'a> Visit<'a> for SubCheck<'b, 'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr(&mut self, e: &'a Expr) {
            if self.unsafe_hit {
                return;
            }
            match e {
                Expr::Call(call) => {
                    if let Expr::Path(ep) = call.func.as_ref()
                        && let Some(last) = ep.path.segments.last()
                    {
                        let lname = last.ident.to_string();
                        if !self.fc.in_discard_let
                            && (self.fc.sets.sanitizers.contains(&lname)
                                || ((self.fc.f.wlan_kind == Some(WlanHelperKind::Validator)
                                    || self.fc.is_html_frag_fn()
                                    || (self.fc.f.wlan_kind == Some(WlanHelperKind::TagHelperFn)
                                        && self.fc.is_non_secret_return))
                                    && self.fc.sets.validators.contains(&lname)))
                        {
                            return;
                        }
                    }
                }
                Expr::Index(ei) if expr_is_range_or_slice_index(&ei.index) => {
                    if !self.fc.is_safe_slice_expr(e) {
                        self.unsafe_hit = true;
                    }
                    return;
                }
                Expr::MethodCall(mc) => {
                    let m = mc.method.to_string();
                    if (matches!(
                        m.as_str(),
                        "split_at"
                            | "split_once"
                            | "rsplit_once"
                            | "split"
                            | "rsplit"
                            | "splitn"
                            | "rsplitn"
                            | "split_inclusive"
                            | "split_terminator"
                            | "rsplit_terminator"
                            | "strip_prefix"
                            | "strip_suffix"
                            | "trim_start_matches"
                            | "trim_end_matches"
                            | "trim_matches"
                            | "matches"
                            | "rmatches"
                    ) || (m == "get"
                        && mc
                            .args
                            .first()
                            .is_some_and(expr_is_range_or_slice_index))
                        || (m == "collect" && receiver_has_chars_call(&mc.receiver)))
                        && !self.fc.is_safe_slice_expr(e)
                    {
                        self.unsafe_hit = true;
                        return;
                    }
                }
                Expr::Path(ep) => {
                    if let Some(last) = ep.path.segments.last()
                        && self.fc.slice_vars.contains(&last.ident.to_string())
                        && !self.fc.is_safe_slice_expr(e)
                    {
                        self.unsafe_hit = true;
                        return;
                    }
                }
                _ => {}
            }
            visit::visit_expr(self, e);
        }
    }
    let mut sc = SubCheck {
        fc,
        unsafe_hit: false,
    };
    sc.visit_expr(expr);
    sc.unsafe_hit
}

fn block_has_unsafe_wlan_slice_flow(
    block: &Block,
    f: &FnInfo,
    sets: &VerifiedWlanSets<'_>,
) -> bool {
    let mut slice_vars: HashSet<String> = HashSet::new();
    let mut trim_len_vars: HashSet<String> = HashSet::new();
    let mut cursor_vars: HashSet<String> = HashSet::new();
    let mut cursor_updates_safe = true;
    let mut loop_emits_redacted = false;

    let is_prefix_helper = f.wlan_kind == Some(WlanHelperKind::TagHelperFn)
        && f.ret_type_str.as_deref() == Some("Option<&str>")
        && f.name.to_ascii_lowercase().contains("prefix");

    let tag_helper_struct_ret = f
        .ret_type_str
        .as_deref()
        .and_then(|r| r.strip_prefix("Option<")?.strip_suffix('>'))
        .is_some_and(|inner| sets.tag_structs.contains(inner));
    if f.wlan_kind == Some(WlanHelperKind::TagHelperFn)
        && !f.has_io_sink
        && !f.has_exec_sink
        && !f.has_thread_spawn
        && !f.has_global_state_sink
        && !has_dangerous_wlan_fn_verb(&f.name, true)
        && !matches!(
            f.name.as_str(),
            "find_html_close_tag" | "check_html_tag_attributes"
        )
        && ((!f.has_mut_param
            && (tag_helper_struct_ret
                || (f.name == "build"
                    && f.ret_type_str.as_deref() == Some("Option<Self>")
                    && f.callees.iter().any(|c| c == "analyze_cross_cell_segment"))
                || matches!(
                    f.ret_type_str.as_deref(),
                    Some("bool")
                        | Some("usize")
                        | Some("Option<usize>")
                        | Some("Option<(usize,usize)>")
                        | Some("(Option<usize>,usize)")
                        | Some("Option<(usize,usize,bool)>")
                        | Some("Vec<(usize,usize)>")
                        | Some("(bool,bool)")
                        | Some("Option<(usize,TagSyntax,bool)>")
                )))
            || (f.name == "scan_unquoted_html_token_end_cached"
                && f.ret_type_str.as_deref() == Some("usize"))
            || (f.name == "analyze_cross_cell_segment"
                && f.ret_type_str.as_deref() == Some("(bool,bool)")
                && f.mut_param_types == ["&mutVec<(usize,usize)>"])
            || (f.name == "mask_clean_km_at"
                && f.ret_type_str.is_none()
                && f.mut_param_types == ["&mut[u8]", "&mutVec<(usize,usize)>"]))
    {
        return false;
    }

    struct VarCollector<'a> {
        sets: &'a VerifiedWlanSets<'a>,
        slice_vars: &'a mut HashSet<String>,
        trim_len_vars: &'a mut HashSet<String>,
        cursor_vars: &'a mut HashSet<String>,
        changed: bool,
    }
    impl<'a> VarCollector<'a> {
        fn record_pat_if_slice(&mut self, pat: &Pat, expr: &Expr) {
            if expr_is_or_derives_slice(expr, self.slice_vars, self.sets) {
                let mut idents = Vec::new();
                collect_pat_idents(pat, &mut idents);
                for id in idents {
                    if self.slice_vars.insert(id) {
                        self.changed = true;
                    }
                }
            }
        }
    }
    impl<'a> Visit<'a> for VarCollector<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_local(&mut self, loc: &'a Local) {
            if let Some(init) = &loc.init {
                let mut idents = Vec::new();
                collect_pat_idents(&loc.pat, &mut idents);
                let rhs_compact = expr_to_compact(&init.expr);
                if rhs_compact.contains(".trim_start()") || rhs_compact.contains(".trim_end()") {
                    for id in &idents {
                        if self.trim_len_vars.insert(id.clone()) {
                            self.changed = true;
                        }
                    }
                }
                if (rhs_compact == "0" || rhs_compact == "0usize")
                    && idents.iter().any(|id| id == "cursor")
                    && self.cursor_vars.insert("cursor".to_string())
                {
                    self.changed = true;
                }
                self.record_pat_if_slice(&loc.pat, &init.expr);
            }
            visit::visit_local(self, loc);
        }
        fn visit_expr_assign(&mut self, ea: &'a syn::ExprAssign) {
            if let Some(base) = expr_base_ident(&ea.left)
                && expr_is_or_derives_slice(&ea.right, self.slice_vars, self.sets)
                && self.slice_vars.insert(base)
            {
                self.changed = true;
            }
            visit::visit_expr_assign(self, ea);
        }
        fn visit_expr_for_loop(&mut self, fl: &'a syn::ExprForLoop) {
            self.record_pat_if_slice(&fl.pat, &fl.expr);
            visit::visit_expr_for_loop(self, fl);
        }
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            if let Expr::Let(el) = unwrap_parens(&ei.cond) {
                self.record_pat_if_slice(&el.pat, &el.expr);
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_expr_while(&mut self, ew: &'a syn::ExprWhile) {
            if let Expr::Let(el) = unwrap_parens(&ew.cond) {
                self.record_pat_if_slice(&el.pat, &el.expr);
            }
            visit::visit_expr_while(self, ew);
        }
        fn visit_expr_match(&mut self, em: &'a syn::ExprMatch) {
            if expr_is_or_derives_slice(&em.expr, self.slice_vars, self.sets) {
                for arm in &em.arms {
                    if let Pat::TupleStruct(pts) = &arm.pat
                        && pts.path.segments.last().is_some_and(|s| s.ident == "Err")
                    {
                        continue;
                    }
                    self.record_pat_if_slice(&arm.pat, &em.expr);
                }
            }
            visit::visit_expr_match(self, em);
        }
    }

    for _ in 0..16 {
        let mut vc = VarCollector {
            sets,
            slice_vars: &mut slice_vars,
            trim_len_vars: &mut trim_len_vars,
            cursor_vars: &mut cursor_vars,
            changed: false,
        };
        vc.visit_block(block);
        if !vc.changed {
            break;
        }
    }

    if cursor_vars.contains("cursor") {
        let has_detailed_cross_cell_spans =
            block_compact_text(block).contains("mask_html_tags_for_json_scan_detailed");
        struct CursorChecker<'a> {
            in_km_while: bool,
            in_clean_cross_cell_if: bool,
            has_detailed_cross_cell_spans: bool,
            cursor_updates_safe: &'a mut bool,
            loop_emits_redacted: &'a mut bool,
        }
        impl<'a> Visit<'a> for CursorChecker<'a> {
            fn visit_item(&mut self, _: &'a Item) {}
            fn visit_expr_while(&mut self, w: &'a syn::ExprWhile) {
                let cond_s = expr_to_compact(&w.cond);
                let prev = self.in_km_while;
                if cond_s.contains("find_opening_keymaterial_tag") {
                    self.in_km_while = true;
                    if while_body_emits_redacted_and_advances_cursor(&w.body) {
                        *self.loop_emits_redacted = true;
                    }
                }
                visit::visit_expr_while(self, w);
                self.in_km_while = prev;
            }
            fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
                let cond_s = expr_to_compact(&ei.cond);
                let prev = self.in_clean_cross_cell_if;
                if self.in_km_while
                    && self.has_detailed_cross_cell_spans
                    && !cond_s.contains("||")
                    && cond_s.contains("clean_cross_cell_km_spans.get(")
                {
                    self.in_clean_cross_cell_if = true;
                }
                self.visit_expr(&ei.cond);
                self.visit_block(&ei.then_branch);
                self.in_clean_cross_cell_if = prev;
                if let Some((_, eb)) = &ei.else_branch {
                    self.visit_expr(eb);
                }
            }
            fn visit_expr_assign(&mut self, a: &'a syn::ExprAssign) {
                if expr_to_compact(&a.left) == "cursor" {
                    let rhs = expr_to_compact(&a.right);
                    let ce_ok = rhs == "ce" && self.in_clean_cross_cell_if;
                    if !self.in_km_while
                        || (!ce_ok
                            && !matches!(
                                rhs.as_str(),
                                "after_name" | "open_end" | "close_end" | "close_tag_end"
                            ))
                    {
                        *self.cursor_updates_safe = false;
                    }
                }
                visit::visit_expr_assign(self, a);
            }
        }
        let mut cc = CursorChecker {
            in_km_while: false,
            in_clean_cross_cell_if: false,
            has_detailed_cross_cell_spans,
            cursor_updates_safe: &mut cursor_updates_safe,
            loop_emits_redacted: &mut loop_emits_redacted,
        };
        cc.visit_block(block);
    }
    let has_verified_cursor_loop =
        cursor_vars.contains("cursor") && cursor_updates_safe && loop_emits_redacted;
    let has_live_deserializer_loop = f.name == "sanitize_json_substrings_and_mask"
        && block_has_live_deserializer_cursor_loop(block);

    let is_non_secret_return = (f.wlan_kind == Some(WlanHelperKind::Validator)
        && f.ret_type_str.as_deref().is_some_and(is_non_secret_error_result))
        || (f.wlan_kind == Some(WlanHelperKind::TagHelperFn)
            && (matches!(
                f.ret_type_str.as_deref(),
                Some("bool") | Some("usize") | Some("Option<usize>") | Some("Option<(usize,usize)>")
            ) || f.ret_type_str.as_deref().is_some_and(is_non_secret_error_result)));
    let mut fc = FlowChecker {
        f,
        sets,
        slice_vars: &slice_vars,
        trim_len_vars: &trim_len_vars,
        has_verified_cursor_loop,
        has_live_deserializer_loop,
        is_prefix_helper,
        is_non_secret_return,
        in_self_closing_if: false,
        in_already_redacted_if: false,
        in_validator_clean_if: false,
        in_redacted_ns_format: false,
        in_html_closing_slash_if: false,
        in_html_open_tag_end_if: false,
        in_html_bang_if: false,
        in_html_tag_attr_dirty_if: false,
        in_html_close_tag_if: false,
        in_html_json_text_buf_if: false,
        in_clean_cross_cell_if: false,
        in_safe_sanitizer_arg: false,
        in_safe_strip_closure: false,
        in_discard_let: false,
        unsafe_found: false,
    };
    fc.visit_block(block);
    if !is_non_secret_return
        && let Some(Stmt::Expr(tail, None)) = block.stmts.last()
    {
        fc.check_sink_expr(tail);
    }
    fc.unsafe_found
}

fn expr_base_ident(e: &Expr) -> Option<String> {
    match e {
        Expr::Path(ep) => ep.path.segments.last().map(|s| s.ident.to_string()),
        Expr::Field(ef) => expr_base_ident(&ef.base),
        Expr::Index(ei) => expr_base_ident(&ei.expr),
        Expr::Paren(p) => expr_base_ident(&p.expr),
        _ => None,
    }
}

fn expr_contains_return(expr: &Expr) -> bool {
    struct RetVis {
        hit: bool,
    }
    impl<'a> Visit<'a> for RetVis {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_closure(&mut self, _: &'a syn::ExprClosure) {}
        fn visit_expr_return(&mut self, _: &'a syn::ExprReturn) {
            self.hit = true;
        }
    }
    let mut rv = RetVis { hit: false };
    rv.visit_expr(expr);
    rv.hit
}

fn receiver_has_iter_or_split(expr: &Expr) -> bool {
    match unwrap_parens(expr) {
        Expr::MethodCall(mc) => {
            let m = mc.method.to_string();
            matches!(
                m.as_str(),
                "iter"
                    | "into_iter"
                    | "split"
                    | "rsplit"
                    | "splitn"
                    | "rsplitn"
                    | "split_inclusive"
                    | "split_terminator"
                    | "rsplit_terminator"
                    | "lines"
                    | "chunks"
                    | "windows"
                    | "bytes"
                    | "chars"
            ) || receiver_has_iter_or_split(&mc.receiver)
        }
        _ => false,
    }
}

fn expr_is_or_derives_slice(
    expr: &Expr,
    slice_vars: &HashSet<String>,
    sets: &VerifiedWlanSets<'_>,
) -> bool {
    struct SliceHit<'a> {
        slice_vars: &'a HashSet<String>,
        sets: &'a VerifiedWlanSets<'a>,
        hit: bool,
    }
    impl<'a> Visit<'a> for SliceHit<'a> {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr(&mut self, e: &'a Expr) {
            if self.hit {
                return;
            }
            match e {
                Expr::Binary(_) | Expr::Unary(_) => return,
                Expr::If(ei) => {
                    self.visit_block(&ei.then_branch);
                    if let Some((_, eb)) = &ei.else_branch {
                        self.visit_expr(eb);
                    }
                    return;
                }
                Expr::Match(em) => {
                    for arm in &em.arms {
                        self.visit_expr(&arm.body);
                    }
                    return;
                }
                Expr::Call(call) => {
                    if let Expr::Path(ep) = call.func.as_ref()
                        && let Some(last) = ep.path.segments.last()
                    {
                        let lname = last.ident.to_string();
                        let verified_index_fn = self.sets.all_fns.iter().any(|fn_i| {
                            fn_i.name == lname
                                && !fn_i.has_exec_sink
                                && !fn_i.has_io_sink
                                && !fn_i.has_thread_spawn
                                && !fn_i.has_global_state_sink
                                && !fn_i.has_mut_param
                                && !has_dangerous_wlan_fn_verb(&fn_i.name, true)
                                && matches!(
                                    fn_i.ret_type_str.as_deref(),
                                    Some("usize" | "bool" | "Option<usize>" | "Option<(usize,usize)>")
                                )
                        });
                        if self.sets.sanitizers.contains(&lname)
                            || self.sets.validators.contains(&lname)
                            || self.sets.tag_helpers.contains(&lname)
                            || is_known_cross_crate_wlan_ident(&lname)
                            || verified_index_fn
                        {
                            return;
                        }
                    }
                }
                Expr::MethodCall(mc) => {
                    let m = mc.method.to_string();
                    if matches!(
                        m.as_str(),
                        "starts_with"
                            | "ends_with"
                            | "contains"
                            | "is_empty"
                            | "len"
                            | "position"
                            | "is_ok"
                            | "is_err"
                            | "is_some"
                            | "is_none"
                            | "is_char_boundary"
                            | "eq_ignore_ascii_case"
                            | "any"
                            | "all"
                            | "count"
                    ) {
                        return;
                    }
                    if matches!(m.as_str(), "byte_offset" | "valid_up_to" | "error_len")
                        && !self.sets.all_fns.iter().any(|fn_i| {
                            fn_i.name == m
                                && !matches!(fn_i.ret_type_str.as_deref(), Some("usize" | "Option<usize>"))
                        })
                        && !matches!(unwrap_parens(&mc.receiver), Expr::Index(_) | Expr::Lit(_))
                    {
                        return;
                    }
                    if matches!(m.as_str(), "find" | "rfind")
                        && !receiver_has_iter_or_split(&mc.receiver)
                    {
                        return;
                    }
                }
                _ => {}
            }
            visit::visit_expr(self, e);
        }
        fn visit_expr_index(&mut self, ei: &'a syn::ExprIndex) {
            if expr_is_range_or_slice_index(&ei.index) {
                self.hit = true;
            }
            visit::visit_expr_index(self, ei);
        }
        fn visit_expr_method_call(&mut self, mc: &'a syn::ExprMethodCall) {
            let m = mc.method.to_string();
            if matches!(
                m.as_str(),
                "split_at"
                    | "split_once"
                    | "rsplit_once"
                    | "split"
                    | "rsplit"
                    | "splitn"
                    | "rsplitn"
                    | "split_inclusive"
                    | "split_terminator"
                    | "rsplit_terminator"
                    | "strip_prefix"
                    | "strip_suffix"
                    | "trim_start_matches"
                    | "trim_end_matches"
                    | "trim_matches"
                    | "matches"
                    | "rmatches"
            ) || (m == "get"
                && mc
                    .args
                    .first()
                    .is_some_and(expr_is_range_or_slice_index))
                || (m == "collect" && receiver_has_chars_call(&mc.receiver))
            {
                self.hit = true;
            }
            visit::visit_expr_method_call(self, mc);
        }
        fn visit_expr_path(&mut self, ep: &'a syn::ExprPath) {
            if let Some(last) = ep.path.segments.last()
                && self.slice_vars.contains(&last.ident.to_string())
            {
                self.hit = true;
            }
            visit::visit_expr_path(self, ep);
        }
    }
    let mut sh = SliceHit {
        slice_vars,
        sets,
        hit: false,
    };
    sh.visit_expr(expr);
    sh.hit
}

fn contains_ident_word(haystack: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let mut pos = 0usize;
    while let Some(rel) = haystack[pos..].find(ident) {
        let s = pos + rel;
        let e = s + ident.len();
        let left_ok = s == 0 || !(bytes[s - 1].is_ascii_alphanumeric() || bytes[s - 1] == b'_');
        let right_ok = e == bytes.len() || !(bytes[e].is_ascii_alphanumeric() || bytes[e] == b'_');
        if left_ok && right_ok {
            return true;
        }
        pos = s + 1;
    }
    false
}

fn while_body_emits_redacted_and_advances_cursor(body: &Block) -> bool {
    struct BodyVis {
        saw_redacted: bool,
        saw_cursor_assign: bool,
    }
    impl<'a> Visit<'a> for BodyVis {
        fn visit_item(&mut self, _: &'a Item) {}
        fn visit_expr_if(&mut self, ei: &'a syn::ExprIf) {
            let cond_s = expr_to_compact(&ei.cond);
            if cond_s.contains("is_empty") {
                if let Some((_, else_e)) = &ei.else_branch {
                    self.visit_expr(else_e);
                }
                return;
            }
            visit::visit_expr_if(self, ei);
        }
        fn visit_lit_str(&mut self, ls: &'a syn::LitStr) {
            if ls.value().to_ascii_lowercase().contains("[redacted]") {
                self.saw_redacted = true;
            }
        }
        fn visit_lit_byte_str(&mut self, lbs: &'a syn::LitByteStr) {
            if String::from_utf8_lossy(&lbs.value())
                .to_ascii_lowercase()
                .contains("[redacted]")
            {
                self.saw_redacted = true;
            }
        }
        fn visit_expr_assign(&mut self, a: &'a syn::ExprAssign) {
            if expr_to_compact(&a.left) == "cursor" {
                let rhs = expr_to_compact(&a.right);
                if matches!(
                    rhs.as_str(),
                    "after_name" | "open_end" | "close_end" | "close_tag_end"
                ) {
                    self.saw_cursor_assign = true;
                }
            }
            visit::visit_expr_assign(self, a);
        }
    }
    let mut bv = BodyVis {
        saw_redacted: false,
        saw_cursor_assign: false,
    };
    bv.visit_block(body);
    bv.saw_redacted && bv.saw_cursor_assign
}
