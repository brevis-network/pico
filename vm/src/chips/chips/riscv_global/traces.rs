use super::{
    columns::{GlobalCols, NUM_GLOBAL_COLS},
    event::GlobalInteractionEvent,
    GlobalChip,
};
use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_poseidon2::Poseidon2Event,
        },
        gadgets::global_interaction::GlobalInteractionOperation,
        utils::{next_power_of_two, zeroed_f_vec},
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    iter::{
        IndexedPicoIterator, IntoPicoIterator, IntoPicoRefMutIterator, PicoBridge, PicoIterator,
        PicoScanIterator,
    },
    machine::{
        chip::ChipBehavior,
        lookup::LookupScope,
        septic::{SepticBlock, SepticCurve, SepticCurveComplete, SepticDigest, SepticExtension},
    },
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for GlobalChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Global".to_string()
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = &input.global_lookup_events;

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let (blu_batches, poseidon2_events): (Vec<_>, Vec<_>) = events
            .chunks(chunk_size)
            .pico_bridge()
            .map(|events| {
                let mut blu: Vec<ByteLookupEvent> = vec![];
                let mut poseidon2: Vec<Poseidon2Event> = vec![];
                events.iter().for_each(|event| {
                    blu.add_u16_range_check(event.message[0].try_into().unwrap());

                    poseidon2.push(
                        GlobalInteractionOperation::<F>::default()
                            .populate(
                                SepticBlock(event.message),
                                event.is_receive,
                                true,
                                event.kind,
                            )
                            .unwrap(),
                    );
                });

                (blu, poseidon2)
            })
            .unzip();

        output.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());
        output
            .poseidon2_events
            .extend(poseidon2_events.into_iter().flatten());
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.global_lookup_events;

        let nb_rows = events.len();
        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = next_power_of_two(nb_rows, log_rows);

        let mut values = zeroed_f_vec(padded_nb_rows * NUM_GLOBAL_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_GLOBAL_COLS]
            .chunks_mut(chunk_size * NUM_GLOBAL_COLS)
            .collect::<Vec<_>>();

        let point_chunks = chunks
            .pico_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut point_chunks = Vec::with_capacity(chunk_size * NUM_GLOBAL_COLS + 1);
                if i == 0 {
                    point_chunks.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
                }
                rows.chunks_mut(NUM_GLOBAL_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut GlobalCols<F> = row.borrow_mut();
                        let event: &GlobalInteractionEvent = &events[idx];
                        cols.message = event.message.map(F::from_canonical_u32);
                        cols.kind = F::from_canonical_u8(event.kind);
                        cols.interaction.populate(
                            SepticBlock(event.message),
                            event.is_receive,
                            true,
                            event.kind,
                        );
                        cols.is_real = F::ONE;
                        if event.is_receive {
                            cols.is_receive = F::ONE;
                        } else {
                            cols.is_send = F::ONE;
                        }
                        point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                            x: SepticExtension(cols.interaction.x_coordinate.0),
                            y: SepticExtension(cols.interaction.y_coordinate.0),
                        }));
                    });
                point_chunks
            })
            .collect::<Vec<_>>();

        let points = point_chunks.into_iter().flatten().collect::<Vec<_>>();
        let cumulative_sum = points
            .into_pico_iter()
            .with_min_len(1 << 15)
            .pico_scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
            .collect::<Vec<SepticCurveComplete<F>>>();

        let final_digest = match cumulative_sum.last() {
            Some(digest) => digest.point(),
            None => SepticCurve::<F>::dummy(),
        };
        let dummy = SepticCurve::<F>::dummy();
        let final_sum_checker = SepticCurve::<F>::sum_checker_x(final_digest, dummy, final_digest);

        let chunk_size = std::cmp::max(padded_nb_rows / num_cpus::get(), 0) + 1;
        values
            .chunks_mut(chunk_size * NUM_GLOBAL_COLS)
            .enumerate()
            .pico_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_GLOBAL_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut GlobalCols<F> = row.borrow_mut();
                        if idx < nb_rows {
                            cols.accumulation.populate_real(
                                &cumulative_sum[idx..idx + 2],
                                final_digest,
                                final_sum_checker,
                            );
                        } else {
                            cols.interaction.populate_dummy();
                            cols.accumulation
                                .populate_dummy(final_digest, final_sum_checker);
                        }
                    });
            });

        RowMajorMatrix::new(values, NUM_GLOBAL_COLS)
    }

    fn is_active(&self, _: &Self::Record) -> bool {
        true
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Global
    }
}
