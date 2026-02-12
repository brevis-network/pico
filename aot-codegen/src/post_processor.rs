//! Post-processing optimizations for generated AOT code

use proc_macro2::Span;
use std::collections::VecDeque;
use syn::{
    parse_quote,
    visit::{self, Visit},
    visit_mut::VisitMut,
    Block, Expr, ExprField, ExprMethodCall, ExprPath, ExprReturn, File, Ident, ImplItem,
    ImplItemFn, Item, ItemImpl, Member, Stmt, Type,
};

pub struct AotPostProcessor {
    clock_ident: Ident,
}

impl Default for AotPostProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl AotPostProcessor {
    pub fn new() -> Self {
        Self {
            clock_ident: syn::Ident::new("__block_clock", Span::call_site()),
        }
    }

    pub fn process(&mut self, file: &mut File) {
        for item in &mut file.items {
            if let Item::Impl(item_impl) = item {
                if self.is_target_impl(item_impl) {
                    self.process_impl(item_impl);
                }
            }
        }
    }

    fn is_target_impl(&self, item_impl: &ItemImpl) -> bool {
        // Check if this is impl pico_aot_runtime::AotEmulatorCore
        match item_impl.self_ty.as_ref() {
            Type::Path(path) => {
                // Check if the last segment is AotEmulatorCore
                path.path
                    .segments
                    .last()
                    .map(|seg| seg.ident == "AotEmulatorCore")
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    fn process_impl(&mut self, item_impl: &mut ItemImpl) {
        for impl_item in &mut item_impl.items {
            if let ImplItem::Fn(method) = impl_item {
                if Self::is_block_function(&method.sig.ident) {
                    self.rewrite_block_method(method);
                }
            }
        }
    }

    fn is_block_function(ident: &syn::Ident) -> bool {
        ident.to_string().starts_with("block_0x")
    }

    fn rewrite_block_method(&mut self, method: &mut ImplItemFn) {
        self.insert_clock_init(&mut method.block);
        self.remove_guard_sequences(&mut method.block);
        let mut expr_rewriter = BlockExprRewriter {
            clock_ident: self.clock_ident.clone(),
        };
        expr_rewriter.visit_block_mut(&mut method.block);
        self.prune_unreachable_tail(&mut method.block);
        self.remove_dead_pc_assignments(&mut method.block);
    }

    fn insert_clock_init(&self, block: &mut Block) {
        let clock_ident = &self.clock_ident;
        let clock_decl: Stmt = parse_quote! {
            let mut #clock_ident = crate::BlockClock::new();
        };
        let mut insert_pos = None;
        for (idx, stmt) in block.stmts.iter().enumerate() {
            if matches_can_fit_guard(stmt) {
                insert_pos = Some(idx + 1);
                break;
            }
        }
        let pos = insert_pos.unwrap_or(0);
        block.stmts.insert(pos, clock_decl);
    }

    fn remove_guard_sequences(&self, block: &mut Block) {
        for stmt in &mut block.stmts {
            self.scrub_guard_stmt(stmt);
        }

        let mut remaining: VecDeque<Stmt> = block.stmts.drain(..).collect();
        let mut new_stmts = Vec::new();
        while let Some(stmt) = remaining.pop_front() {
            if is_check_boundary_stmt(&stmt) {
                if let Some(next) = remaining.front() {
                    if is_should_yield_guard(next) {
                        remaining.pop_front();
                        continue;
                    }
                }
            }
            new_stmts.push(stmt);
        }
        block.stmts = new_stmts;
    }

    fn prune_unreachable_tail(&self, block: &mut Block) {
        let mut new_stmts = Vec::new();
        let mut terminated = false;
        for stmt in block.stmts.drain(..) {
            if terminated {
                continue;
            }
            if is_return_stmt(&stmt) {
                terminated = true;
            }
            new_stmts.push(stmt);
        }
        block.stmts = new_stmts;
    }

    fn remove_dead_pc_assignments(&self, block: &mut Block) {
        let mut pc_live = true;
        let mut new_stmts = Vec::new();
        let stmts: Vec<Stmt> = block.stmts.drain(..).collect();
        for stmt in stmts.into_iter().rev() {
            if stmt_reads_pc(&stmt) {
                pc_live = true;
            }
            if stmt_writes_pc(&stmt) {
                if pc_live {
                    pc_live = false;
                    new_stmts.push(stmt);
                }
            } else {
                new_stmts.push(stmt);
            }
        }
        new_stmts.reverse();
        block.stmts = new_stmts;
    }

    fn scrub_guard_stmt(&self, stmt: &mut Stmt) {
        match stmt {
            Stmt::Expr(expr, _) => self.scrub_guard_expr(expr),
            Stmt::Local(local) => {
                if let Some(init) = &mut local.init {
                    self.scrub_guard_expr(init.expr.as_mut());
                    if let Some((_, else_expr)) = &mut init.diverge {
                        self.scrub_guard_expr(else_expr.as_mut());
                    }
                }
            }
            _ => {}
        }
    }

    fn scrub_guard_expr(&self, expr: &mut Expr) {
        match expr {
            Expr::If(if_expr) => {
                self.remove_guard_sequences(&mut if_expr.then_branch);
                if let Some((_, else_branch)) = &mut if_expr.else_branch {
                    self.scrub_guard_expr(else_branch);
                }
            }
            Expr::Block(block) => self.remove_guard_sequences(&mut block.block),
            Expr::Match(expr_match) => {
                for arm in &mut expr_match.arms {
                    self.scrub_guard_expr(&mut arm.body);
                }
            }
            _ => {}
        }
    }
}

struct BlockExprRewriter {
    clock_ident: Ident,
}

impl VisitMut for BlockExprRewriter {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        match expr {
            Expr::Return(ret) => {
                if rewrite_result_return(ret, &self.clock_ident) {
                    return;
                }
            }
            Expr::MethodCall(method_call) => {
                if let Some(new_expr) = rewrite_syscall_call_expr(method_call, &self.clock_ident) {
                    *expr = new_expr;
                    return;
                }
                if let Some(new_expr) = rewrite_clock_call_expr(method_call, &self.clock_ident) {
                    *expr = new_expr;
                    return;
                }
            }
            _ => {}
        }
        syn::visit_mut::visit_expr_mut(self, expr);
    }
}

fn matches_can_fit_guard(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(Expr::If(if_expr), _) => contains_can_fit_call(&if_expr.cond),
        _ => false,
    }
}

fn contains_can_fit_call(expr: &Expr) -> bool {
    match expr {
        Expr::Unary(unary) => contains_can_fit_call(&unary.expr),
        Expr::Paren(paren) => contains_can_fit_call(&paren.expr),
        Expr::MethodCall(method_call) => method_call.method == "can_fit_instructions",
        _ => false,
    }
}

fn is_check_boundary_stmt(stmt: &Stmt) -> bool {
    matches_method_call(stmt, "check_chunk_boundary")
}

fn is_should_yield_guard(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(Expr::If(if_expr), _) => {
            if if_expr.else_branch.is_some() {
                return false;
            }
            if !matches_should_yield(&if_expr.cond) {
                return false;
            }
            if_expr.then_branch.stmts.len() == 1
                && matches_return_dynamic(&if_expr.then_branch.stmts[0])
        }
        _ => false,
    }
}

fn matches_should_yield(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::MethodCall(method_call)
            if method_call.method == "should_yield"
                && is_self_expr(&method_call.receiver)
    )
}

fn matches_return_dynamic(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(Expr::Return(ret), _) => {
            if let Some(expr) = &ret.expr {
                if let Some(arg) = extract_result_arg(expr, "Ok") {
                    return matches_dynamic_step(&arg);
                }
            }
            false
        }
        _ => false,
    }
}

fn matches_dynamic_step(expr: &Expr) -> bool {
    if let Expr::Call(call) = expr {
        if let Expr::Path(path) = call.func.as_ref() {
            if path
                .path
                .segments
                .last()
                .map(|seg| seg.ident == "Dynamic")
                .unwrap_or(false)
                && call.args.len() == 1
            {
                if let Some(arg) = call.args.first() {
                    return matches!(
                        arg,
                        Expr::Field(field)
                            if matches!(field.member, Member::Named(ref ident) if ident == "pc")
                                && is_self_expr(&field.base)
                    );
                }
            }
        }
    }
    false
}

fn matches_method_call(stmt: &Stmt, method: &str) -> bool {
    match stmt {
        Stmt::Expr(Expr::MethodCall(method_call), _) => {
            method_call.method == method && is_self_expr(&method_call.receiver)
        }
        _ => false,
    }
}

fn is_self_expr(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Path(ExprPath { path, .. })
            if path.segments.len() == 1 && path.segments[0].ident == "self"
    )
}

fn stmt_reads_pc(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(expr, _) => expr_reads_pc(expr),
        Stmt::Local(local) => {
            if let Some(init) = &local.init {
                if expr_reads_pc(init.expr.as_ref()) {
                    return true;
                }
                if let Some((_, diverge)) = &init.diverge {
                    if expr_reads_pc(diverge.as_ref()) {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn stmt_writes_pc(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(Expr::Assign(assign), _) => is_self_pc_expr(&assign.left),
        _ => false,
    }
}

fn expr_reads_pc(expr: &Expr) -> bool {
    let mut detector = PcReadDetector { found: false };
    detector.visit_expr(expr);
    detector.found
}

struct PcReadDetector {
    found: bool,
}

impl<'ast> Visit<'ast> for PcReadDetector {
    fn visit_expr_field(&mut self, expr_field: &'ast ExprField) {
        if is_self_pc_field(expr_field) {
            self.found = true;
            return;
        }
        visit::visit_expr_field(self, expr_field);
    }
}

fn is_self_pc_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Field(field) if is_self_pc_field(field))
}

fn is_self_pc_field(field: &ExprField) -> bool {
    matches!(
        field.member,
        Member::Named(ref ident) if ident == "pc" && is_self_expr(&field.base)
    )
}

fn rewrite_result_return(ret: &mut ExprReturn, clock_ident: &Ident) -> bool {
    if let Some(expr) = &ret.expr {
        if let Some(arg) = extract_result_arg(expr, "Ok") {
            ret.expr = Some(Box::new(parse_quote! {
                self.finalize_block(&mut #clock_ident, #arg)
            }));
            return true;
        }
        if let Some(arg) = extract_result_arg(expr, "Err") {
            ret.expr = Some(Box::new(parse_quote! {
                self.fail_block(&mut #clock_ident, #arg)
            }));
            return true;
        }
    }
    false
}

fn extract_result_arg(expr: &Expr, name: &str) -> Option<Expr> {
    if let Expr::Call(call) = expr {
        if path_is_ident(call.func.as_ref(), name) && call.args.len() == 1 {
            return call.args.first().cloned();
        }
    }
    None
}

fn path_is_ident(expr: &Expr, name: &str) -> bool {
    matches!(
        expr,
        Expr::Path(ExprPath { path, .. })
            if path.segments.len() == 1 && path.segments[0].ident == name
    )
}

fn rewrite_clock_call_expr(method_call: &ExprMethodCall, clock_ident: &Ident) -> Option<Expr> {
    let _ = clock_ident;
    let _ = method_call;
    None
}

fn rewrite_syscall_call_expr(method_call: &ExprMethodCall, clock_ident: &Ident) -> Option<Expr> {
    if !is_self_expr(&method_call.receiver) || !is_syscall_like_method(method_call) {
        return None;
    }
    let method = &method_call.method;
    let args: Vec<Expr> = method_call.args.iter().cloned().collect();
    Some(parse_quote! {{
        #clock_ident.flush_into(self);
        self.#method(#(#args),*)
    }})
}

fn is_syscall_like_method(method_call: &ExprMethodCall) -> bool {
    method_call.method == "execute_syscall" || method_call.method == "execute_ebreak"
}

fn is_return_stmt(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Expr(Expr::Return(_), _))
}
