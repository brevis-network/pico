use crate::cuda_adaptor::{HashMap, SepticDigest};
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    Field, FieldAlgebra, FieldExtensionAlgebra,
};
use serde::{
    de,
    de::{DeserializeOwned, VariantAccess, Visitor},
    ser::SerializeTupleVariant,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    cmp::PartialEq,
    fmt,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
//

#[derive(Debug, Clone, Copy)]
enum MapEntry<F: Copy + Clone> {
    Uninit,
    Scalar(F),
    NewItmd(usize),
}

pub fn prepare_scalars<F: BinomiallyExtendable<D> + PartialOrd, const D: usize>(
    public_vars: &[F],
    perm_randomness: &[BinomialExtensionField<F, D>],
    local_cumulative_sum: BinomialExtensionField<F, D>,
    global_cumulative_sum: SepticDigest<F>,
) -> Vec<F> {
    let mut ret = vec![];
    ret.extend_from_slice(public_vars);
    for b in perm_randomness {
        ret.extend_from_slice(FieldExtensionAlgebra::<F>::as_base_slice(b));
    }

    ret.extend_from_slice(FieldExtensionAlgebra::<F>::as_base_slice(
        &local_cumulative_sum,
    ));
    ret.extend_from_slice(&global_cumulative_sum.0.x.0);
    ret.extend_from_slice(&global_cumulative_sum.0.y.0);
    ret
}

pub fn compute_scalar<F: BinomiallyExtendable<D> + PartialOrd, const D: usize>(
    all_caculations: &Vec<Calculation<F>>,
    value_base: &Vec<(usize, ValueSource<F>)>,
    value_ext: &Vec<(usize, [ValueSource<F>; D])>,
    scalars: &[F],
) -> (
    Vec<Calculation<F>>,
    Vec<(usize, ValueSource<F>)>,
    Vec<(usize, [ValueSource<F>; D])>,
) {
    let mut all_caculations_new: Vec<Calculation<F>> = vec![];
    let mut mapped_entrys = vec![MapEntry::<F>::Uninit; all_caculations.len()];
    let map_value = |v: ValueSource<F>, mapped_entrys_ref: &Vec<MapEntry<F>>| match v {
        ValueSource::MatrixVar(_, _, _) => v,
        ValueSource::ScalarVar(i) => ValueSource::ConstsVar(scalars[i]),
        ValueSource::ConstsVar(_) => v,
        ValueSource::IsFirstRow => v,
        ValueSource::IsLastRow => v,
        ValueSource::IsTransition => v,
        ValueSource::Intermediate(i) => match mapped_entrys_ref[i] {
            MapEntry::Uninit => panic!("Uninit itmd"),
            MapEntry::Scalar(c) => ValueSource::ConstsVar(c),
            MapEntry::NewItmd(j) => ValueSource::Intermediate(j),
        },
    };

    for (i, c) in all_caculations.into_iter().enumerate() {
        let temp = match c {
            Calculation::Add(v0, v1) => {
                let (v0, v1) = (
                    map_value(*v0, &mapped_entrys),
                    map_value(*v1, &mapped_entrys),
                );
                if let (ValueSource::ConstsVar(_v0), ValueSource::ConstsVar(_v1)) = (v0, v1) {
                    MapEntry::Scalar(_v0 + _v1)
                } else {
                    all_caculations_new.push(Calculation::Add(v0, v1));
                    MapEntry::NewItmd(all_caculations_new.len() - 1)
                }
            }
            Calculation::Sub(v0, v1) => {
                let (v0, v1) = (
                    map_value(*v0, &mapped_entrys),
                    map_value(*v1, &mapped_entrys),
                );
                if let (ValueSource::ConstsVar(_v0), ValueSource::ConstsVar(_v1)) = (v0, v1) {
                    MapEntry::Scalar(_v0 - _v1)
                } else {
                    all_caculations_new.push(Calculation::Sub(v0, v1));
                    MapEntry::NewItmd(all_caculations_new.len() - 1)
                }
            }
            Calculation::Mul(v0, v1) => {
                let (v0, v1) = (
                    map_value(*v0, &mapped_entrys),
                    map_value(*v1, &mapped_entrys),
                );
                if let (ValueSource::ConstsVar(_v0), ValueSource::ConstsVar(_v1)) = (v0, v1) {
                    MapEntry::Scalar(_v0 * _v1)
                } else {
                    all_caculations_new.push(Calculation::Mul(v0, v1));
                    MapEntry::NewItmd(all_caculations_new.len() - 1)
                }
            }
            Calculation::Neg(v0) => {
                let v0 = map_value(*v0, &mapped_entrys);
                if let ValueSource::ConstsVar(_v0) = v0 {
                    MapEntry::Scalar(-_v0)
                } else {
                    all_caculations_new.push(Calculation::Neg(v0));
                    MapEntry::NewItmd(all_caculations_new.len() - 1)
                }
            }
        };
        mapped_entrys[i] = temp;
    }

    let value_base_new = value_base
        .into_iter()
        .map(|(i, v)| (*i, map_value(v.clone(), &mapped_entrys)))
        .collect::<Vec<_>>();
    let value_ext_new = value_ext
        .into_iter()
        .map(|(i, v)| {
            let v = v.clone().map(|v| map_value(v, &mapped_entrys));
            (*i, v)
        })
        .collect::<Vec<_>>();
    return (all_caculations_new, value_base_new, value_ext_new);
}

pub fn reduce_register<F: BinomiallyExtendable<D> + PartialOrd, const D: usize>(
    all_caculations: &Vec<Calculation<F>>,
    value_base: &Vec<(usize, ValueSource<F>)>,
    value_ext: &Vec<(usize, [ValueSource<F>; D])>,
) -> (
    usize,
    Vec<usize>,
    Vec<Calculation<F>>,
    Vec<(usize, ValueSource<F>)>,
    Vec<(usize, [ValueSource<F>; D])>,
) {
    let len_cclts = all_caculations.len();
    let mut itmd_end_index: Vec<usize> = vec![0; len_cclts];
    let mut update_end_index = |i: usize, v: ValueSource<F>| {
        if let ValueSource::Intermediate(j) = v {
            itmd_end_index[j] = i;
        }
    };
    for i in 0..len_cclts {
        match all_caculations[i] {
            Calculation::Add(v0, v1) => {
                update_end_index(i, v0);
                update_end_index(i, v1)
            }
            Calculation::Sub(v0, v1) => {
                update_end_index(i, v0);
                update_end_index(i, v1)
            }
            Calculation::Mul(v0, v1) => {
                update_end_index(i, v0);
                update_end_index(i, v1)
            }
            Calculation::Neg(v0) => {
                update_end_index(i, v0);
            }
        }
    }
    // assert final itmd is exported
    let mut export_final_itmd = |v: ValueSource<F>| {
        if let ValueSource::Intermediate(j) = v {
            itmd_end_index[j] = 0;
        }
    };
    for vb in value_base {
        export_final_itmd(vb.1);
    }
    for ve in value_ext {
        for temp in ve.1.iter() {
            export_final_itmd(temp.clone());
        }
    }

    let mut itmds_drop_record: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, &end_index) in itmd_end_index.iter().enumerate() {
        itmds_drop_record.entry(end_index).or_insert(vec![]).push(i);
    }
    let _final_itmds = itmds_drop_record.remove(&0).unwrap();

    // register[i] store itmds[j] => regisers[i] = Some(j) (temp0rary)
    let mut regisers: Vec<Option<usize>> = vec![];
    // register[i] store itmds[j] => itmds_map[j] = i
    let mut itmds_map: Vec<usize> = Vec::with_capacity(len_cclts);
    for i in 0..len_cclts {
        //drop unused register
        if let Some(temp) = itmds_drop_record.get(&i) {
            for &itmd in temp {
                let register_drop = itmds_map[itmd];
                regisers[register_drop] = None;
            }
        }
        if regisers.is_empty() || regisers.iter().all(|temp| temp.is_some()) {
            regisers.push(Some(i));
            itmds_map.push(regisers.len() - 1);
        } else {
            let (r_id, first_unused_register) = regisers
                .iter_mut()
                .enumerate()
                .find(|(_, temp)| temp.is_none())
                .unwrap();
            *first_unused_register = Some(i);
            itmds_map.push(r_id);
        }
    }

    let update_value = |v: ValueSource<F>| -> ValueSource<F> {
        if let ValueSource::Intermediate(j) = v {
            ValueSource::Intermediate(itmds_map[j])
        } else {
            v
        }
    };

    let all_caculations: Vec<Calculation<F>> = all_caculations
        .into_iter()
        .map(|&c| match c {
            Calculation::Add(v0, v1) => Calculation::Add(update_value(v0), update_value(v1)),
            Calculation::Sub(v0, v1) => Calculation::Sub(update_value(v0), update_value(v1)),
            Calculation::Mul(v0, v1) => Calculation::Mul(update_value(v0), update_value(v1)),
            Calculation::Neg(v0) => Calculation::Neg(update_value(v0)),
        })
        .collect();

    let value_base: Vec<_> = value_base
        .into_iter()
        .map(|temp| (temp.0, update_value(temp.1)))
        .collect();
    let value_ext: Vec<_> = value_ext
        .into_iter()
        .map(|temp| (temp.0, temp.1.map(update_value)))
        .collect();
    (
        regisers.len(),
        itmds_map,
        all_caculations,
        value_base,
        value_ext,
    )
}

//
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValueSource<F: Field + PartialOrd> {
    /// (prep, main, perm) poly_index (local, next)
    MatrixVar(usize, usize, usize),
    ScalarVar(usize),
    ConstsVar(F),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Intermediate(usize),
}

impl<F> Serialize for ValueSource<F>
where
    F: Field + PartialOrd + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ValueSource::MatrixVar(x, y, z) => {
                let mut tv =
                    serializer.serialize_tuple_variant("ValueSource", 0, "MatrixVar", 3)?;
                tv.serialize_field(x)?;
                tv.serialize_field(y)?;
                tv.serialize_field(z)?;
                tv.end()
            }

            ValueSource::ScalarVar(idx) => {
                let mut tv =
                    serializer.serialize_tuple_variant("ValueSource", 1, "ScalarVar", 1)?;
                tv.serialize_field(idx)?;
                tv.end()
            }

            ValueSource::ConstsVar(value) => {
                let mut tv =
                    serializer.serialize_tuple_variant("ValueSource", 2, "ConstsVar", 1)?;
                tv.serialize_field(value)?;
                tv.end()
            }

            ValueSource::IsFirstRow => {
                serializer.serialize_unit_variant("ValueSource", 3, "IsFirstRow")
            }

            ValueSource::IsLastRow => {
                serializer.serialize_unit_variant("ValueSource", 4, "IsLastRow")
            }

            ValueSource::IsTransition => {
                serializer.serialize_unit_variant("ValueSource", 5, "IsTransition")
            }

            ValueSource::Intermediate(idx) => {
                let mut tv =
                    serializer.serialize_tuple_variant("ValueSource", 6, "Intermediate", 1)?;
                tv.serialize_field(idx)?;
                tv.end()
            }
        }
    }
}

// Visitor for deserializing ValueSource
struct ValueSourceVisitor<F> {
    phantom: std::marker::PhantomData<F>,
}

impl<'de, F> Visitor<'de> for ValueSourceVisitor<F>
where
    F: Field + PartialOrd + DeserializeOwned,
{
    type Value = ValueSource<F>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an enum variant of ValueSource")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: de::EnumAccess<'de>,
    {
        let (variant, field_access) = data.variant()?;
        match variant {
            "MatrixVar" => {
                let (x, y, z) = field_access.newtype_variant::<(usize, usize, usize)>()?;
                Ok(ValueSource::MatrixVar(x, y, z))
            }
            "ScalarVar" => {
                let [idx] = field_access.newtype_variant::<[usize; 1]>()?;
                Ok(ValueSource::ScalarVar(idx))
            }
            "ConstsVar" => {
                let [value] = field_access.newtype_variant::<[F; 1]>()?;
                Ok(ValueSource::ConstsVar(value))
            }
            "IsFirstRow" => {
                let () = field_access.unit_variant()?;
                Ok(ValueSource::IsFirstRow)
            }
            "IsLastRow" => {
                let () = field_access.unit_variant()?;
                Ok(ValueSource::IsLastRow)
            }
            "IsTransition" => {
                let () = field_access.unit_variant()?;
                Ok(ValueSource::IsTransition)
            }
            "Intermediate" => {
                let [idx] = field_access.newtype_variant::<[usize; 1]>()?;
                Ok(ValueSource::Intermediate(idx))
            }
            _ => Err(de::Error::unknown_variant(
                variant,
                &[
                    "MatrixVar",
                    "ScalarVar",
                    "ConstsVar",
                    "IsFirstRow",
                    "IsLastRow",
                    "IsTransition",
                    "Intermediate",
                ],
            )),
        }
    }
}

impl<'de, F> Deserialize<'de> for ValueSource<F>
where
    F: Field + PartialOrd + DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const VARIANTS: &[&str] = &[
            "MatrixVar",
            "ScalarVar",
            "ConstsVar",
            "IsFirstRow",
            "IsLastRow",
            "IsTransition",
            "Intermediate",
        ];
        deserializer.deserialize_enum(
            "ValueSource",
            VARIANTS,
            ValueSourceVisitor {
                phantom: Default::default(),
            },
        )
    }
}

impl<F: Field + PartialOrd> From<F> for ValueSource<F> {
    fn from(value: F) -> Self {
        ValueSource::ConstsVar(value)
    }
}
impl<F: Field + PartialOrd> ValueSource<F> {
    pub fn degree_multiple(&self) -> usize {
        match self {
            ValueSource::MatrixVar(_, _, _) => 1,
            ValueSource::ScalarVar(_) => 0,
            ValueSource::ConstsVar(_) => 0,
            ValueSource::IsFirstRow => 1,
            ValueSource::IsLastRow => 1,
            ValueSource::IsTransition => 0,
            ValueSource::Intermediate(_) => panic!("caculate degree_multiple for Intermediate"),
        }
    }
}

//
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Calculation<F: Field + PartialOrd> {
    Add(ValueSource<F>, ValueSource<F>),
    Sub(ValueSource<F>, ValueSource<F>),
    Mul(ValueSource<F>, ValueSource<F>),
    Neg(ValueSource<F>),
}

impl<F> Serialize for Calculation<F>
where
    F: Field + PartialOrd + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Add(lhs, rhs) => {
                let mut tv = serializer.serialize_tuple_variant("Calculation", 0, "Add", 2)?;
                tv.serialize_field(lhs)?;
                tv.serialize_field(rhs)?;
                tv.end()
            }
            Self::Sub(lhs, rhs) => {
                let mut tv = serializer.serialize_tuple_variant("Calculation", 1, "Sub", 2)?;
                tv.serialize_field(lhs)?;
                tv.serialize_field(rhs)?;
                tv.end()
            }
            Self::Mul(lhs, rhs) => {
                let mut tv = serializer.serialize_tuple_variant("Calculation", 2, "Mul", 2)?;
                tv.serialize_field(lhs)?;
                tv.serialize_field(rhs)?;
                tv.end()
            }
            Self::Neg(value) => {
                let mut tv = serializer.serialize_tuple_variant("Calculation", 3, "Neg", 1)?;
                tv.serialize_field(value)?;
                tv.end()
            }
        }
    }
}

struct CalculationVisitor<F> {
    phantom: std::marker::PhantomData<F>,
}

impl<'de, F> Visitor<'de> for CalculationVisitor<F>
where
    F: Field + PartialOrd + DeserializeOwned,
{
    type Value = Calculation<F>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an enum variant of Calculation")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: de::EnumAccess<'de>,
    {
        let (variant, field_access) = data.variant()?;
        match variant {
            "Add" => {
                let (lhs, rhs) =
                    field_access.newtype_variant::<(ValueSource<F>, ValueSource<F>)>()?;
                Ok(Calculation::Add(lhs, rhs))
            }
            "Sub" => {
                let (lhs, rhs) =
                    field_access.newtype_variant::<(ValueSource<F>, ValueSource<F>)>()?;
                Ok(Calculation::Sub(lhs, rhs))
            }
            "Mul" => {
                let (lhs, rhs) =
                    field_access.newtype_variant::<(ValueSource<F>, ValueSource<F>)>()?;
                Ok(Calculation::Mul(lhs, rhs))
            }
            "Neg" => {
                let (value,) = field_access.newtype_variant::<(ValueSource<F>,)>()?;
                Ok(Calculation::Neg(value))
            }
            _ => Err(de::Error::unknown_variant(
                variant,
                &["Add", "Sub", "Mul", "Neg"],
            )),
        }
    }
}

impl<'de, F> Deserialize<'de> for Calculation<F>
where
    F: Field + PartialOrd + DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const VARIANTS: &[&str] = &["Add", "Sub", "Mul", "Neg"];
        deserializer.deserialize_enum(
            "Calculation",
            VARIANTS,
            CalculationVisitor {
                phantom: Default::default(),
            },
        )
    }
}

//
//
impl<F: Field + PartialOrd> Calculation<F> {
    pub fn map_intermediate(&self, mapped_values: &[ValueSource<F>]) -> Self {
        let oprand_map = |a: ValueSource<F>| match a {
            ValueSource::Intermediate(i) => mapped_values[i],
            _ => a,
        };
        match self {
            Calculation::Add(value_source, value_source1) => {
                Calculation::Add(oprand_map(*value_source), oprand_map(*value_source1))
            }
            Calculation::Sub(value_source, value_source1) => {
                Calculation::Sub(oprand_map(*value_source), oprand_map(*value_source1))
            }
            Calculation::Mul(value_source, value_source1) => {
                Calculation::Mul(oprand_map(*value_source), oprand_map(*value_source1))
            }
            Calculation::Neg(value_source) => Calculation::Neg(oprand_map(*value_source)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Expression<F: Field + PartialOrd> {
    Complex(Vec<Calculation<F>>, usize),
    Simple(ValueSource<F>),
}

impl<F: Field + PartialOrd> Expression<F> {
    pub fn degree_multiple(&self) -> usize {
        match self {
            Expression::Complex(_, d) => *d,
            Expression::Simple(value_source) => value_source.degree_multiple(),
        }
    }
    pub fn combine_cclt(
        cclt0: &[Calculation<F>],
        cclt1: &[Calculation<F>],
    ) -> (Vec<Calculation<F>>, ValueSource<F>, ValueSource<F>) {
        let mut ret: Vec<Calculation<F>> = cclt0.to_vec();
        let value0 = ValueSource::<F>::Intermediate(ret.len() - 1);
        let mut mapped_value1: Vec<ValueSource<F>> = vec![];
        for c in cclt1 {
            let c = c.map_intermediate(&mapped_value1);
            let temp_value = match ret.iter().enumerate().find(|i| *(i.1) == c) {
                Some((i, _)) => ValueSource::<F>::Intermediate(i),
                None => {
                    ret.push(c);
                    ValueSource::<F>::Intermediate(ret.len() - 1)
                }
            };
            mapped_value1.push(temp_value);
        }
        (ret, value0, *mapped_value1.last().unwrap())
    }
}

impl<F: Field + PartialOrd> Default for Expression<F> {
    fn default() -> Self {
        Expression::Simple(ValueSource::ConstsVar(F::default()))
    }
}

impl<F: Field + PartialOrd> From<F> for Expression<F> {
    fn from(value: F) -> Self {
        Expression::Simple(value.into())
    }
}
impl<F: Field + PartialOrd> From<ValueSource<F>> for Expression<F> {
    fn from(value: ValueSource<F>) -> Self {
        Expression::Simple(value)
    }
}

impl<F: Field + PartialOrd, T> Add<T> for Expression<F>
where
    T: Into<Self>,
{
    type Output = Self;

    fn add(self, rhs: T) -> Self::Output {
        let rhs: Self = rhs.into();
        if self == Expression::Simple(ValueSource::ConstsVar(F::ZERO)) {
            return rhs;
        }
        if rhs == Expression::Simple(ValueSource::ConstsVar(F::ZERO)) {
            return self;
        }
        match (self, rhs) {
            (Expression::Complex(c0, d0), Expression::Complex(c1, d1)) => {
                let degree = std::cmp::max(d0, d1);
                let (mut cclt, v0, v1) = Self::combine_cclt(&c0, &c1);
                if v0 < v1 {
                    cclt.push(Calculation::Add(v0, v1));
                } else {
                    cclt.push(Calculation::Add(v1, v0));
                }
                Expression::Complex(cclt, degree)
            }
            (Expression::Complex(mut cclt, d0), Expression::Simple(v1)) => {
                let d1 = v1.degree_multiple();
                let degree = std::cmp::max(d0, d1);
                let v0 = ValueSource::Intermediate(cclt.len() - 1);
                if v0 < v1 {
                    cclt.push(Calculation::Add(v0, v1));
                } else {
                    cclt.push(Calculation::Add(v1, v0));
                }
                Expression::Complex(cclt, degree)
            }
            (Expression::Simple(v0), Expression::Complex(mut cclt, d1)) => {
                let d0 = v0.degree_multiple();
                let degree = std::cmp::max(d0, d1);
                let v1 = ValueSource::Intermediate(cclt.len() - 1);
                if v0 < v1 {
                    cclt.push(Calculation::Add(v0, v1));
                } else {
                    cclt.push(Calculation::Add(v1, v0));
                }
                Expression::Complex(cclt, degree)
            }
            (Expression::Simple(v0), Expression::Simple(v1)) => {
                if let (ValueSource::ConstsVar(v0), ValueSource::ConstsVar(v1)) = (v0, v1) {
                    return Expression::Simple(ValueSource::ConstsVar(v0 + v1));
                }
                let d0 = v0.degree_multiple();
                let d1 = v1.degree_multiple();
                let degree = std::cmp::max(d0, d1);
                let mut cclt = vec![];
                if v0 < v1 {
                    cclt.push(Calculation::Add(v0, v1));
                } else {
                    cclt.push(Calculation::Add(v1, v0));
                }
                Expression::Complex(cclt, degree)
            }
        }
    }
}

impl<F: Field + PartialOrd, T> AddAssign<T> for Expression<F>
where
    T: Into<Self>,
{
    fn add_assign(&mut self, rhs: T) {
        *self = self.clone() + rhs.into();
    }
}

impl<F: Field + PartialOrd, T> Sum<T> for Expression<F>
where
    T: Into<Self>,
{
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        let mut ret = Expression::Simple(ValueSource::ConstsVar(F::ZERO));
        for i in iter {
            ret += i;
        }
        ret
    }
}

impl<F: Field + PartialOrd, T> Sub<T> for Expression<F>
where
    T: Into<Self>,
{
    type Output = Self;

    fn sub(self, rhs: T) -> Self::Output {
        let rhs: Self = rhs.into();
        if self == Expression::Simple(ValueSource::ConstsVar(F::ZERO)) {
            return rhs.neg();
        }
        if rhs == Expression::Simple(ValueSource::ConstsVar(F::ZERO)) {
            return self;
        }
        match (self, rhs) {
            (Expression::Complex(c0, d0), Expression::Complex(c1, d1)) => {
                let degree = std::cmp::max(d0, d1);
                let (mut cclts, v0, v1) = Self::combine_cclt(&c0, &c1);
                cclts.push(Calculation::Sub(v0, v1));
                Expression::Complex(cclts, degree)
            }
            (Expression::Complex(mut cclt, d0), Expression::Simple(v1)) => {
                let d1 = v1.degree_multiple();
                let degree = std::cmp::max(d0, d1);
                let v0 = ValueSource::Intermediate(cclt.len() - 1);
                cclt.push(Calculation::Sub(v0, v1));
                Expression::Complex(cclt, degree)
            }
            (Expression::Simple(v0), Expression::Complex(mut cclt, d1)) => {
                let d0 = v0.degree_multiple();
                let degree = std::cmp::max(d0, d1);
                let v1 = ValueSource::Intermediate(cclt.len() - 1);
                cclt.push(Calculation::Sub(v0, v1));
                Expression::Complex(cclt, degree)
            }
            (Expression::Simple(v0), Expression::Simple(v1)) => {
                if let (ValueSource::ConstsVar(v0), ValueSource::ConstsVar(v1)) = (v0, v1) {
                    return Expression::Simple(ValueSource::ConstsVar(v0 - v1));
                }
                let d0 = v0.degree_multiple();
                let d1 = v1.degree_multiple();
                let degree = std::cmp::max(d0, d1);
                let mut cclt = vec![];
                cclt.push(Calculation::Sub(v0, v1));
                Expression::Complex(cclt, degree)
            }
        }
    }
}

impl<F: Field + PartialOrd, T> SubAssign<T> for Expression<F>
where
    T: Into<Self>,
{
    fn sub_assign(&mut self, rhs: T) {
        *self = self.clone() - rhs.into();
    }
}

impl<F: Field + PartialOrd> Neg for Expression<F> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        match self {
            Expression::Complex(mut calculations, degree) => {
                let v = ValueSource::Intermediate(calculations.len() - 1);
                calculations.push(Calculation::Neg(v));
                Expression::Complex(calculations, degree)
            }
            Expression::Simple(value_source) => {
                if let ValueSource::ConstsVar(v0) = value_source {
                    return Expression::Simple(ValueSource::ConstsVar(-v0));
                }
                let mut calculations = vec![];
                let degree = value_source.degree_multiple();
                calculations.push(Calculation::Neg(value_source));
                Expression::Complex(calculations, degree)
            }
        }
    }
}

impl<F: Field + PartialOrd, T> Mul<T> for Expression<F>
where
    T: Into<Self>,
{
    type Output = Self;
    fn mul(self, rhs: T) -> Self::Output {
        let rhs: Self = rhs.into();
        if self == Expression::Simple(ValueSource::ConstsVar(F::ZERO))
            || rhs == Expression::Simple(ValueSource::ConstsVar(F::ONE))
        {
            return self;
        }
        if rhs == Expression::Simple(ValueSource::ConstsVar(F::ZERO))
            || self == Expression::Simple(ValueSource::ConstsVar(F::ONE))
        {
            return rhs;
        }
        match (self, rhs) {
            (Expression::Complex(c0, d0), Expression::Complex(c1, d1)) => {
                let degree = d0 + d1;
                let (mut cclt, v0, v1) = Self::combine_cclt(&c0, &c1);
                if v0 < v1 {
                    cclt.push(Calculation::Mul(v0, v1));
                } else {
                    cclt.push(Calculation::Mul(v1, v0));
                }
                Expression::Complex(cclt, degree)
            }
            (Expression::Complex(mut cclt, d0), Expression::Simple(v1)) => {
                let d1 = v1.degree_multiple();
                let degree = d0 + d1;
                let v0 = ValueSource::Intermediate(cclt.len() - 1);
                if v0 < v1 {
                    cclt.push(Calculation::Mul(v0, v1));
                } else {
                    cclt.push(Calculation::Mul(v1, v0));
                }
                Expression::Complex(cclt, degree)
            }
            (Expression::Simple(v0), Expression::Complex(mut cclt, d1)) => {
                let d0 = v0.degree_multiple();
                let degree = d0 + d1;
                let v1 = ValueSource::Intermediate(cclt.len() - 1);
                if v0 < v1 {
                    cclt.push(Calculation::Mul(v0, v1));
                } else {
                    cclt.push(Calculation::Mul(v1, v0));
                }
                Expression::Complex(cclt, degree)
            }
            (Expression::Simple(v0), Expression::Simple(v1)) => {
                if let (ValueSource::ConstsVar(v0), ValueSource::ConstsVar(v1)) = (v0, v1) {
                    return Expression::Simple(ValueSource::ConstsVar(v0 * v1));
                }
                let d0 = v0.degree_multiple();
                let d1 = v1.degree_multiple();
                let degree = d0 + d1;
                let mut cclt = vec![];
                if v0 < v1 {
                    cclt.push(Calculation::Mul(v0, v1));
                } else {
                    cclt.push(Calculation::Mul(v1, v0));
                }
                Expression::Complex(cclt, degree)
            }
        }
    }
}

impl<F: Field + PartialOrd, T> MulAssign<T> for Expression<F>
where
    T: Into<Self>,
{
    fn mul_assign(&mut self, rhs: T) {
        *self = self.clone() * rhs.into();
    }
}

impl<F: Field + PartialOrd, T> Product<T> for Expression<F>
where
    T: Into<Self>,
{
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        let mut ret = Expression::Simple(ValueSource::ConstsVar(F::ONE));
        for i in iter {
            ret += i;
        }
        ret
    }
}
impl<F: Field + PartialOrd, T> Add<T> for ValueSource<F>
where
    T: Into<Expression<F>>,
{
    type Output = Expression<F>;
    fn add(self, rhs: T) -> Self::Output {
        Expression::from(self) + rhs.into()
    }
}

impl<F: Field + PartialOrd, T> Sub<T> for ValueSource<F>
where
    T: Into<Expression<F>>,
{
    type Output = Expression<F>;
    fn sub(self, rhs: T) -> Self::Output {
        Expression::from(self) - rhs.into()
    }
}

impl<F: Field + PartialOrd, T> Mul<T> for ValueSource<F>
where
    T: Into<Expression<F>>,
{
    type Output = Expression<F>;
    fn mul(self, rhs: T) -> Self::Output {
        Expression::from(self) * rhs.into()
    }
}

impl<F: Field + PartialOrd> FieldAlgebra for Expression<F> {
    type F = F;

    const ZERO: Self = Expression::Simple(ValueSource::ConstsVar(F::ZERO));

    const ONE: Self = Expression::Simple(ValueSource::ConstsVar(F::ONE));

    const TWO: Self = Expression::Simple(ValueSource::ConstsVar(F::TWO));

    const NEG_ONE: Self = Expression::Simple(ValueSource::ConstsVar(F::NEG_ONE));

    const FOUR: Self = Expression::Simple(ValueSource::ConstsVar(F::FOUR));

    const FIVE: Self = Expression::Simple(ValueSource::ConstsVar(F::FIVE));

    fn from_f(f: Self::F) -> Self {
        f.into()
    }

    fn from_bool(b: bool) -> Self {
        F::from_bool(b).into()
    }

    fn from_canonical_u8(n: u8) -> Self {
        F::from_canonical_u8(n).into()
    }

    fn from_canonical_u16(n: u16) -> Self {
        F::from_canonical_u16(n).into()
    }

    fn from_canonical_u32(n: u32) -> Self {
        F::from_canonical_u32(n).into()
    }

    fn from_canonical_u64(n: u64) -> Self {
        F::from_canonical_u64(n).into()
    }

    fn from_canonical_usize(n: usize) -> Self {
        F::from_canonical_usize(n).into()
    }

    fn from_wrapped_u32(n: u32) -> Self {
        F::from_wrapped_u32(n).into()
    }

    fn from_wrapped_u64(n: u64) -> Self {
        F::from_wrapped_u64(n).into()
    }
}

//
//
#[cfg(test)]
mod tests {
    use super::*;
    use p3_koala_bear::KoalaBear;
    use serde_json;
    #[test]
    fn test_value_source_roundtrip() {
        let test_cases = vec![
            ValueSource::MatrixVar(1, 2, 3),
            ValueSource::ScalarVar(42),
            ValueSource::ConstsVar(KoalaBear::from_canonical_u32(123)),
            ValueSource::IsFirstRow,
            ValueSource::IsLastRow,
            ValueSource::IsTransition,
            ValueSource::Intermediate(7),
        ];
        for source in test_cases {
            let serialized =
                serde_json::to_string(&source).expect(&format!("Failed to serialize {:?}", source));

            let deserialized: ValueSource<KoalaBear> = serde_json::from_str(&serialized)
                .expect(&format!("Failed to deserialize {}", serialized));

            assert_eq!(source, deserialized, "Roundtrip failed for {:?}", source);

            println!("Success: {} => {:?}", serialized, deserialized);
        }
    }
    #[test]
    fn test_specific_formats() {
        let matrix = ValueSource::<KoalaBear>::MatrixVar(1, 2, 3);
        let json = serde_json::to_string(&matrix).unwrap();
        assert_eq!(json, r#"{"MatrixVar":[1,2,3]}"#);
        let first_row = ValueSource::<KoalaBear>::IsFirstRow;
        let json = serde_json::to_string(&first_row).unwrap();
        assert_eq!(json, r#""IsFirstRow""#);
        let consts = ValueSource::<KoalaBear>::ConstsVar(KoalaBear::from_canonical_u32(256));
        let json = serde_json::to_string(&consts).unwrap();
        assert!(json.contains(r#"{"ConstsVar":"#)); // 具体格式取决于Fr的序列化实现
    }
    #[test]
    fn test_error_handling() {
        let invalid_json = r#""InvalidVariant""#;
        let result: Result<ValueSource<KoalaBear>, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        let bad_matrix_json = r#"{"MatrixVar":["a","b","c"]}"#;
        let result: Result<ValueSource<KoalaBear>, _> = serde_json::from_str(bad_matrix_json);
        assert!(result.is_err());
    }

    //
    //
    //

    fn test_source1() -> ValueSource<KoalaBear> {
        ValueSource::ScalarVar(42)
    }
    fn test_source2() -> ValueSource<KoalaBear> {
        ValueSource::MatrixVar(1, 2, 3)
    }
    #[test]
    fn test_calculation_roundtrip() {
        let test_cases = vec![
            Calculation::Add(test_source1(), test_source2()),
            Calculation::Sub(test_source2(), test_source1()),
            Calculation::Mul(test_source1(), test_source1()),
            Calculation::Neg(test_source2()),
        ];
        for calc in test_cases {
            let serialized =
                serde_json::to_string(&calc).expect(&format!("Failed to serialize {:?}", calc));

            let deserialized: Calculation<KoalaBear> = serde_json::from_str(&serialized)
                .expect(&format!("Failed to deserialize {}", serialized));

            assert_eq!(calc, deserialized, "Roundtrip failed for {:?}", calc);

            println!("Success: {} => {:?}", serialized, deserialized);
        }
    }
    #[test]
    fn test_json_format() {
        let add = Calculation::Add(test_source1(), test_source2());
        let json = serde_json::to_string(&add).unwrap();
        assert_eq!(
            json,
            r#"{"Add":[{"ScalarVar":[42]},{"MatrixVar":[1,2,3]}]}"#
        );
        let neg = Calculation::Neg(test_source1());
        let json = serde_json::to_string(&neg).unwrap();
        assert_eq!(json, r#"{"Neg":[{"ScalarVar":[42]}]}"#);
    }
    #[test]
    fn test_error_handling_2() {
        let invalid_json = r#"{"InvalidVariant":{}}"#;
        let result: Result<Calculation<KoalaBear>, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        let bad_add_json = r#"{"Add":{"lhs":{"ScalarVar":[42]}}}"#; // 缺少rhs字段
        let result: Result<Calculation<KoalaBear>, _> = serde_json::from_str(bad_add_json);
        assert!(result.is_err());
        let bad_neg_json = r#"{"Neg":{"value":"invalid"}}"#;
        let result: Result<Calculation<KoalaBear>, _> = serde_json::from_str(bad_neg_json);
        assert!(result.is_err());
    }
}
