use p3_air::{AirBuilder, FilteredAirBuilder};

pub trait ScopedBuilder {
    #[allow(unused)]
    fn enter_scope(&mut self, scope: impl AsRef<str>) {}
    fn exit_scope(&mut self) {}

    fn with_scope<T>(&mut self, scope: impl AsRef<str>, f: impl FnOnce(&mut Self) -> T) -> T {
        self.enter_scope(scope);
        let result = f(self);
        self.exit_scope();
        result
    }
}

impl<AB: AirBuilder + ScopedBuilder> ScopedBuilder for FilteredAirBuilder<'_, AB> {
    fn enter_scope(&mut self, scope: impl AsRef<str>) {
        self.inner.enter_scope(scope)
    }

    fn exit_scope(&mut self) {
        self.inner.exit_scope()
    }
}
