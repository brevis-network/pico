package poseidon2

import (
	"github.com/brevis-network/pico/gnark/koalabear"
)

// KoalaBear-Poseidon2 round constants for the MLE/WHIR backend.
//
// These are a DIFFERENT table from `rc16_koalabear` in constants.go, which the legacy FRI on-chain
// circuit uses. The two must coexist rather than one replacing the other: `rc16_koalabear` mirrors
// the hand-maintained table the FRI stack hashed with, whose Rust side is gone, while the MLE wrap
// circuit hashes with `pico_mle_core::config::koala_bear_poseidon2::KOALABEAR_POSEIDON2_RC_16_*`.
// Swapping either table under the other circuit makes its own honest witness unsatisfiable
// (measured: the FRI onchain circuit fails at `assertIsEqual` when built against this table).
//
// Pinned on the Rust side by `kb_poseidon2_permutation_vector_matches_gnark` and here by
// `TestPoseidon2KoalaBearMle`.
var rc16_koalabear_mle [30][KOALABEAR_WIDTH]koalabear.Variable

func init() {
	init_rc16_koalabear_mle()
}

func init_rc16_koalabear_mle() {
	round := 0

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("2128964168"),
		koalabear.NewFConst("288780357"),
		koalabear.NewFConst("316938561"),
		koalabear.NewFConst("2126233899"),
		koalabear.NewFConst("426817493"),
		koalabear.NewFConst("1714118888"),
		koalabear.NewFConst("1045008582"),
		koalabear.NewFConst("1738510837"),
		koalabear.NewFConst("889721787"),
		koalabear.NewFConst("8866516"),
		koalabear.NewFConst("681576474"),
		koalabear.NewFConst("419059826"),
		koalabear.NewFConst("1596305521"),
		koalabear.NewFConst("1583176088"),
		koalabear.NewFConst("1584387047"),
		koalabear.NewFConst("1529751136"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1863858111"),
		koalabear.NewFConst("1072044075"),
		koalabear.NewFConst("517831365"),
		koalabear.NewFConst("1464274176"),
		koalabear.NewFConst("1138001621"),
		koalabear.NewFConst("428001039"),
		koalabear.NewFConst("245709561"),
		koalabear.NewFConst("1641420379"),
		koalabear.NewFConst("1365482496"),
		koalabear.NewFConst("770454828"),
		koalabear.NewFConst("693167409"),
		koalabear.NewFConst("757905735"),
		koalabear.NewFConst("136670447"),
		koalabear.NewFConst("436275702"),
		koalabear.NewFConst("525466355"),
		koalabear.NewFConst("1559174242"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1030087950"),
		koalabear.NewFConst("869864998"),
		koalabear.NewFConst("322787870"),
		koalabear.NewFConst("267688717"),
		koalabear.NewFConst("948964561"),
		koalabear.NewFConst("740478015"),
		koalabear.NewFConst("679816114"),
		koalabear.NewFConst("113662466"),
		koalabear.NewFConst("2066544572"),
		koalabear.NewFConst("1744924186"),
		koalabear.NewFConst("367094720"),
		koalabear.NewFConst("1380455578"),
		koalabear.NewFConst("1842483872"),
		koalabear.NewFConst("416711434"),
		koalabear.NewFConst("1342291586"),
		koalabear.NewFConst("1692058446"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1493348999"),
		koalabear.NewFConst("1113949088"),
		koalabear.NewFConst("210900530"),
		koalabear.NewFConst("1071655077"),
		koalabear.NewFConst("610242121"),
		koalabear.NewFConst("1136339326"),
		koalabear.NewFConst("2020858841"),
		koalabear.NewFConst("1019840479"),
		koalabear.NewFConst("678147278"),
		koalabear.NewFConst("1678413261"),
		koalabear.NewFConst("1361743414"),
		koalabear.NewFConst("61132629"),
		koalabear.NewFConst("1209546658"),
		koalabear.NewFConst("64412292"),
		koalabear.NewFConst("1936878279"),
		koalabear.NewFConst("1980661727"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1423960925"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("2101391318"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1915532054"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("275400051"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1168624859"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1141248885"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("356546469"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1165250474"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1320543726"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("932505663"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1204226364"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1452576828"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1774936729"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("926808140"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1184948056"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1186493834"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("843181003"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("185193011"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("452207447"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("510054082"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1139268644"),
		koalabear.NewFConst("630873441"),
		koalabear.NewFConst("669538875"),
		koalabear.NewFConst("462500858"),
		koalabear.NewFConst("876500520"),
		koalabear.NewFConst("1214043330"),
		koalabear.NewFConst("383937013"),
		koalabear.NewFConst("375087302"),
		koalabear.NewFConst("636912601"),
		koalabear.NewFConst("307200505"),
		koalabear.NewFConst("390279673"),
		koalabear.NewFConst("1999916485"),
		koalabear.NewFConst("1518476730"),
		koalabear.NewFConst("1606686591"),
		koalabear.NewFConst("1410677749"),
		koalabear.NewFConst("1581191572"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1004269969"),
		koalabear.NewFConst("143426723"),
		koalabear.NewFConst("1747283099"),
		koalabear.NewFConst("1016118214"),
		koalabear.NewFConst("1749423722"),
		koalabear.NewFConst("66331533"),
		koalabear.NewFConst("1177761275"),
		koalabear.NewFConst("1581069649"),
		koalabear.NewFConst("1851371119"),
		koalabear.NewFConst("852520128"),
		koalabear.NewFConst("1499632627"),
		koalabear.NewFConst("1820847538"),
		koalabear.NewFConst("150757557"),
		koalabear.NewFConst("884787840"),
		koalabear.NewFConst("619710451"),
		koalabear.NewFConst("1651711087"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("505263814"),
		koalabear.NewFConst("212076987"),
		koalabear.NewFConst("1482432120"),
		koalabear.NewFConst("1458130652"),
		koalabear.NewFConst("382871348"),
		koalabear.NewFConst("417404007"),
		koalabear.NewFConst("2066495280"),
		koalabear.NewFConst("1996518884"),
		koalabear.NewFConst("902934924"),
		koalabear.NewFConst("582892981"),
		koalabear.NewFConst("1337064375"),
		koalabear.NewFConst("1199354861"),
		koalabear.NewFConst("2102596038"),
		koalabear.NewFConst("1533193853"),
		koalabear.NewFConst("1436311464"),
		koalabear.NewFConst("2012303432"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("839997195"),
		koalabear.NewFConst("1225781098"),
		koalabear.NewFConst("2011967775"),
		koalabear.NewFConst("575084315"),
		koalabear.NewFConst("1309329169"),
		koalabear.NewFConst("786393545"),
		koalabear.NewFConst("995788880"),
		koalabear.NewFConst("1702925345"),
		koalabear.NewFConst("1444525226"),
		koalabear.NewFConst("908073383"),
		koalabear.NewFConst("1811535085"),
		koalabear.NewFConst("1531002367"),
		koalabear.NewFConst("1635653662"),
		koalabear.NewFConst("1585100155"),
		koalabear.NewFConst("867006515"),
		koalabear.NewFConst("879151050"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	round += 1

	rc16_koalabear_mle[round] = [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}
}
