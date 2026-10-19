mod batch_inverse;
pub use batch_inverse::*;

#[macro_export]
#[cfg(feature = "parallel")]
macro_rules! parizip {
    ( $first:expr $( , $rest:expr )* $(,)* ) => {
        {
            use rayon::iter::*;
            ( $first $( , $rest)* ).into_par_iter()
        }
    };
}
#[macro_export]
#[cfg(not(feature = "parallel"))]
macro_rules! parizip {
    ( $first:expr $( , $rest:expr )* $(,)* ) => {
        itertools::izip!( $first $( , $rest)* )
    };
}
