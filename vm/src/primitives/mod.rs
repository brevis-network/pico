pub mod consts;
pub mod poseidon2;

use crate::{
    configs::stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2, M31Poseidon2},
    primitives::consts::{
        DIGEST_SIZE, MERSENNE31_NUM_EXTERNAL_ROUNDS, MERSENNE31_NUM_INTERNAL_ROUNDS,
    },
};
use consts::{
    BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
};
use ff::PrimeField;
pub use halo2curves::bn256::Fr as FFBn254Fr;
use lazy_static::lazy_static;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_bn254_fr::{Bn254Fr, Poseidon2Bn254};
use p3_field::FieldAlgebra;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_mersenne_31::{Mersenne31, Poseidon2Mersenne31};
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use zkhash::{
    ark_ff::{BigInteger, PrimeField as ark_PrimeField},
    fields::bn256::FpBN256 as ark_FpBN256,
    poseidon2::poseidon2_instance_bn256::RC3,
};

pub type PicoPoseidon2BabyBear = Poseidon2BabyBear<PERMUTATION_WIDTH>;
pub type PicoPoseidon2KoalaBear = Poseidon2KoalaBear<PERMUTATION_WIDTH>;
pub type PicoPoseidon2Mersenne31 = Poseidon2Mersenne31<PERMUTATION_WIDTH>;
pub type PicoPoseidon2Bn254 = Poseidon2Bn254<3>;

lazy_static! {
    // Define the base constants once
    pub static ref RC_16_30_U32: [[u32; 16]; 30] = [
        [
            2110014213, 3964964605, 2190662774, 2732996483,
            640767983, 3403899136, 1716033721, 1606702601,
            3759873288, 1466015491, 1498308946, 2844375094,
            3042463841, 1969905919, 4109944726, 3925048366,
        ],
        [
            3706859504, 759122502, 3167665446, 1131812921,
            1080754908, 4080114493, 893583089, 2019677373,
            3128604556, 580640471, 3277620260, 842931656,
            548879852, 3608554714, 3575647916, 81826002,
        ],
        [
            4289086263, 1563933798, 1440025885, 184445025,
            2598651360, 1396647410, 1575877922, 3303853401,
            137125468, 765010148, 633675867, 2037803363,
            2573389828, 1895729703, 541515871, 1783382863,
        ],
        [
            2641856484, 3035743342, 3672796326, 245668751,
            2025460432, 201609705, 286217151, 4093475563,
            2519572182, 3080699870, 2762001832, 1244250808,
            606038199, 3182740831, 73007766, 2572204153,
        ],
        [
            1196780786, 3447394443, 747167305, 2968073607,
            1053214930, 1074411832, 4016794508, 1570312929,
            113576933, 4042581186, 3634515733, 1032701597,
            2364839308, 3840286918, 888378655, 2520191583,
        ],
        [
            36046858, 2927525953, 3912129105, 4004832531,
            193772436, 1590247392, 4125818172, 2516251696,
            4050945750, 269498914, 1973292656, 891403491,
            1845429189, 2611996363, 2310542653, 4071195740,
        ],
        [
            3505307391, 786445290, 3815313971, 1111591756,
            4233279834, 2775453034, 1991257625, 2940505809,
            2751316206, 1028870679, 1282466273, 1059053371,
            834521354, 138721483, 3100410803, 3843128331,
        ],
        [
            3878220780, 4058162439, 1478942487, 799012923,
            496734827, 3521261236, 755421082, 1361409515,
            392099473, 3178453393, 4068463721, 7935614,
            4140885645, 2150748066, 1685210312, 3852983224,
        ],
        [
            2896943075, 3087590927, 992175959, 970216228,
            3473630090, 3899670400, 3603388822, 2633488197,
            2479406964, 2420952999, 1852516800, 4253075697,
            979699862, 1163403191, 1608599874, 3056104448,
        ],
        [
            3779109343, 536205958, 4183458361, 1649720295,
            1444912244, 3122230878, 384301396, 4228198516,
            1662916865, 4082161114, 2121897314, 1706239958,
            4166959388, 1626054781, 3005858978, 1431907253,
        ],
        [
            1418914503, 1365856753, 3942715745, 1429155552,
            3545642795, 3772474257, 1621094396, 2154399145,
            826697382, 1700781391, 3539164324, 652815039,
            442484755, 2055299391, 1064289978, 1152335780,
        ],
        [
            3417648695, 186040114, 3475580573, 2113941250,
            1779573826, 1573808590, 3235694804, 2922195281,
            1119462702, 3688305521, 1849567013, 667446787,
            753897224, 1896396780, 3143026334, 3829603876,
        ],
        [
            859661334, 3898844357, 180258337, 2321867017,
            3599002504, 2886782421, 3038299378, 1035366250,
            2038912197, 2920174523, 1277696101, 2785700290,
            3806504335, 3518858933, 654843672, 2127120275,
        ],
        [
            1548195514, 2378056027, 390914568, 1472049779,
            1552596765, 1905886441, 1611959354, 3653263304,
            3423946386, 340857935, 2208879480, 139364268,
            3447281773, 3777813707, 55640413, 4101901741,
        ],
        [
            104929687, 1459980974, 1831234737, 457139004,
            2581487628, 2112044563, 3567013861, 2792004347,
            576325418, 41126132, 2713562324, 151213722,
            2891185935, 546846420, 2939794919, 2543469905,
        ],
        [
            2191909784, 3315138460, 530414574, 1242280418,
            1211740715, 3993672165, 2505083323, 3845798801,
            538768466, 2063567560, 3366148274, 1449831887,
            2408012466, 294726285, 3943435493, 924016661,
        ],
        [
            3633138367, 3222789372, 809116305, 30100013,
            2655172876, 2564247117, 2478649732, 4113689151,
            4120146082, 2512308515, 650406041, 4240012393,
            2683508708, 951073977, 3460081988, 339124269,
        ],
        [
            130182653, 2755946749, 542600513, 2816103022,
            1931786340, 2044470840, 1709908013, 2938369043,
            3640399693, 1374470239, 2191149676, 2637495682,
            4236394040, 2289358846, 3833368530, 974546524,
        ],
        [
            3306659113, 2234814261, 1188782305, 223782844,
            2248980567, 2309786141, 2023401627, 3278877413,
            2022138149, 575851471, 1612560780, 3926656936,
            3318548977, 2591863678, 188109355, 4217723909,
        ],
        [
            1564209905, 2154197895, 2459687029, 2870634489,
            1375012945, 1529454825, 306140690, 2855578299,
            1246997295, 3024298763, 1915270363, 1218245412,
            2479314020, 2989827755, 814378556, 4039775921,
        ],
        [
            1165280628, 1203983801, 3814740033, 1919627044,
            600240215, 773269071, 486685186, 4254048810,
            1415023565, 502840102, 4225648358, 510217063,
            166444818, 1430745893, 1376516190, 1775891321,
        ],
        [
            1170945922, 1105391877, 261536467, 1401687994,
            1022529847, 2476446456, 2603844878, 3706336043,
            3463053714, 1509644517, 588552318, 65252581,
            3696502656, 2183330763, 3664021233, 1643809916,
        ],
        [
            2922875898, 3740690643, 3932461140, 161156271,
            2619943483, 4077039509, 2921201703, 2085619718,
            2065264646, 2615693812, 3116555433, 246100007,
            4281387154, 4046141001, 4027749321, 111611860,
        ],
        [
            2066954820, 2502099969, 2915053115, 2362518586,
            366091708, 2083204932, 4138385632, 3195157567,
            1318086382, 521723799, 702443405, 2507670985,
            1760347557, 2631999893, 1672737554, 1060867760,
        ],
        [
            2359801781, 2800231467, 3010357035, 1035997899,
            1210110952, 1018506770, 2799468177, 1479380761,
            1536021911, 358993854, 579904113, 3432144800,
            3625515809, 199241497, 4058304109, 2590164234,
        ],
        [
            1688530738, 1580733335, 2443981517, 2206270565,
            2780074229, 2628739677, 2940123659, 4145206827,
            3572278009, 2779607509, 1098718697, 1424913749,
            2224415875, 1108922178, 3646272562, 3935186184,
        ],
        [
            820046587, 1393386250, 2665818575, 2231782019,
            672377010, 1920315467, 1913164407, 2029526876,
            2629271820, 384320012, 4112320585, 3131824773,
            2347818197, 2220997386, 1772368609, 2579960095,
        ],
        [
            3544930873, 225847443, 3070082278, 95643305,
            3438572042, 3312856509, 615850007, 1863868773,
            803582265, 3461976859, 2903025799, 1482092434,
            3902972499, 3872341868, 1530411808, 2214923584,
        ],
        [
            3118792481, 2241076515, 3983669831, 3180915147,
            3838626501, 1921630011, 3415351771, 2249953859,
            3755081630, 486327260, 1227575720, 3643869379,
            2982026073, 2466043731, 1982634375, 3769609014,
        ],
        [
            2195455495, 2596863283, 4244994973, 1983609348,
            4019674395, 3469982031, 1458697570, 1593516217,
            1963896497, 3115309118, 1659132465, 2536770756,
            3059294171, 2618031334, 2040903247, 3799795076,
        ]
    ];

    // Derive BabyBear array from base constants
    pub static ref RC_16_30_BabyBear: [[BabyBear; 16]; 30] = {
        let mut result = [[BabyBear::ZERO; 16]; 30];
        for i in 0..30 {
            for j in 0..16 {
                result[i][j] = BabyBear::from_wrapped_u32(RC_16_30_U32[i][j]);
            }
        }
        result
    };

    // Derive KoalaBear array from base constants
    pub static ref RC_16_30_KoalaBear: [[KoalaBear; 16]; 30] = {
        let mut result = [[KoalaBear::ZERO; 16]; 30];
        for i in 0..30 {
            for j in 0..16 {
                result[i][j] = KoalaBear::from_wrapped_u32(RC_16_30_U32[i][j]);
            }
        }
        result
    };

    // Derive Mersenne31 array from base constants
    pub static ref RC_16_30_M31: [[Mersenne31; 16]; 30] = {
        let mut result = [[Mersenne31::ZERO; 16]; 30];
        for i in 0..30 {
            for j in 0..16 {
                result[i][j] = Mersenne31::from_wrapped_u32(RC_16_30_U32[i][j]);
            }
        }
        result
    };
}

pub trait Poseidon2Init {
    type Poseidon2;

    fn init() -> Self::Poseidon2;
}

impl Poseidon2Init for BabyBearPoseidon2 {
    type Poseidon2 = PicoPoseidon2BabyBear;
    fn init() -> Self::Poseidon2 {
        pico_poseidon2bb_init()
    }
}

impl Poseidon2Init for BabyBear {
    type Poseidon2 = PicoPoseidon2BabyBear;
    fn init() -> Self::Poseidon2 {
        pico_poseidon2bb_init()
    }
}

impl Poseidon2Init for KoalaBearPoseidon2 {
    type Poseidon2 = PicoPoseidon2KoalaBear;
    fn init() -> Self::Poseidon2 {
        pico_poseidon2kb_init()
    }
}

impl Poseidon2Init for KoalaBear {
    type Poseidon2 = PicoPoseidon2KoalaBear;
    fn init() -> Self::Poseidon2 {
        pico_poseidon2kb_init()
    }
}

impl Poseidon2Init for M31Poseidon2 {
    type Poseidon2 = PicoPoseidon2Mersenne31;
    fn init() -> Self::Poseidon2 {
        pico_poseidon2m31_init()
    }
}

impl Poseidon2Init for Mersenne31 {
    type Poseidon2 = PicoPoseidon2Mersenne31;
    fn init() -> Self::Poseidon2 {
        pico_poseidon2m31_init()
    }
}

/*
Poseidon2 on BabyBear
 */
fn pico_poseidon2bb_init() -> PicoPoseidon2BabyBear {
    const ROUNDS_F: usize = BABYBEAR_NUM_EXTERNAL_ROUNDS;
    const ROUNDS_P: usize = BABYBEAR_NUM_INTERNAL_ROUNDS;

    let mut round_constants = RC_16_30_BabyBear.to_vec();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();

    let external_round_constants = ExternalLayerConstants::new(
        round_constants[..(ROUNDS_F / 2)].to_vec(),
        round_constants[(ROUNDS_F / 2)..ROUNDS_F].to_vec(),
    );

    PicoPoseidon2BabyBear::new(external_round_constants, internal_round_constants)
}

/*
Poseidon2 on KoalaBear
 */
fn pico_poseidon2kb_init() -> PicoPoseidon2KoalaBear {
    const ROUNDS_F: usize = KOALABEAR_NUM_EXTERNAL_ROUNDS;
    const ROUNDS_P: usize = KOALABEAR_NUM_INTERNAL_ROUNDS;

    let mut round_constants = RC_16_30_KoalaBear.to_vec();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();

    let external_round_constants = ExternalLayerConstants::new(
        round_constants[..(ROUNDS_F / 2)].to_vec(),
        round_constants[(ROUNDS_F / 2)..ROUNDS_F].to_vec(),
    );

    PicoPoseidon2KoalaBear::new(external_round_constants, internal_round_constants)
}

pub fn poseidon2_bb_hasher() -> PaddingFreeSponge<PicoPoseidon2BabyBear, 16, 8, 8> {
    let hasher = pico_poseidon2bb_init();
    PaddingFreeSponge::<PicoPoseidon2BabyBear, 16, 8, 8>::new(hasher)
}

pub fn poseidon2_kb_hasher() -> PaddingFreeSponge<PicoPoseidon2KoalaBear, 16, 8, 8> {
    let hasher = pico_poseidon2kb_init();
    PaddingFreeSponge::<PicoPoseidon2KoalaBear, 16, 8, 8>::new(hasher)
}

pub fn poseidon2_m31_hasher() -> PaddingFreeSponge<PicoPoseidon2Mersenne31, 16, 8, 8> {
    let hasher = pico_poseidon2m31_init();
    PaddingFreeSponge::<PicoPoseidon2Mersenne31, 16, 8, 8>::new(hasher)
}

lazy_static! {
    pub static ref POSEIDON2_BB_HASHER: PaddingFreeSponge::<PicoPoseidon2BabyBear, 16, 8, 8> =
        poseidon2_bb_hasher();
    pub static ref POSEIDON2_KB_HASHER: PaddingFreeSponge::<PicoPoseidon2KoalaBear, 16, 8, 8> =
        poseidon2_kb_hasher();
    pub static ref POSEIDON2_M31_HASHER: PaddingFreeSponge::<PicoPoseidon2Mersenne31, 16, 8, 8> =
        poseidon2_m31_hasher();
}

/*
Poseidon2 on M31
 */
fn pico_poseidon2m31_init() -> PicoPoseidon2Mersenne31 {
    const ROUNDS_F: usize = MERSENNE31_NUM_EXTERNAL_ROUNDS;
    const ROUNDS_P: usize = MERSENNE31_NUM_INTERNAL_ROUNDS;

    let mut round_constants = RC_16_30_M31.to_vec();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();

    let external_round_constants = ExternalLayerConstants::new(
        round_constants[..(ROUNDS_F / 2)].to_vec(),
        round_constants[(ROUNDS_F / 2)..ROUNDS_F].to_vec(),
    );

    PicoPoseidon2Mersenne31::new(external_round_constants, internal_round_constants)
}

/*
Poseidon2 on Bn254
 */

pub fn bn254_from_ark_ff(input: ark_FpBN256) -> Bn254Fr {
    let bytes = input.into_bigint().to_bytes_le();

    let mut res = <FFBn254Fr as PrimeField>::Repr::default();

    for (i, digit) in res.as_mut().iter_mut().enumerate() {
        *digit = bytes[i];
    }

    let value = FFBn254Fr::from_repr(res);

    if value.is_some().into() {
        Bn254Fr {
            value: value.unwrap(),
        }
    } else {
        panic!("Invalid field element")
    }
}

pub fn pico_poseidon2bn254_init() -> PicoPoseidon2Bn254 {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 56;

    // Copy over round constants from zkhash.
    let mut round_constants: Vec<[Bn254Fr; 3]> = RC3
        .iter()
        .map(|vec| {
            vec.iter()
                .cloned()
                .map(bn254_from_ark_ff)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect();

    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();
    let external_round_constants = ExternalLayerConstants::new(
        round_constants[..(ROUNDS_F / 2)].to_vec(),
        round_constants[(ROUNDS_F / 2)..].to_vec(),
    );
    // Pico Poseidon2 implementation.
    PicoPoseidon2Bn254::new(external_round_constants, internal_round_constants)
}

pub fn hash_deferred_proof<F>(
    prev_digest: &[F; DIGEST_SIZE],
    vk_digest: &[F; DIGEST_SIZE],
    pv_digest: &[F; 32],
) -> [F; DIGEST_SIZE]
where
    F: Poseidon2HashField + Copy,
{
    let mut inputs = Vec::with_capacity(DIGEST_SIZE * 2 + 32);
    inputs.extend_from_slice(prev_digest);
    inputs.extend_from_slice(vk_digest);
    inputs.extend_from_slice(pv_digest);
    F::poseidon2_hash_iter(inputs)
}

pub trait Poseidon2HashField: p3_field::Field + Sized {
    fn poseidon2_hash_iter(inputs: Vec<Self>) -> [Self; DIGEST_SIZE];
}

impl Poseidon2HashField for BabyBear {
    fn poseidon2_hash_iter(inputs: Vec<Self>) -> [Self; DIGEST_SIZE] {
        POSEIDON2_BB_HASHER.hash_iter(inputs)
    }
}
impl Poseidon2HashField for KoalaBear {
    fn poseidon2_hash_iter(inputs: Vec<Self>) -> [Self; DIGEST_SIZE] {
        POSEIDON2_KB_HASHER.hash_iter(inputs)
    }
}
impl Poseidon2HashField for Mersenne31 {
    fn poseidon2_hash_iter(inputs: Vec<Self>) -> [Self; DIGEST_SIZE] {
        POSEIDON2_M31_HASHER.hash_iter(inputs)
    }
}
