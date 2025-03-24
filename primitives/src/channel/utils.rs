use crate::fields::m31::M31Bar;
use bitcoin::script::read_scriptint;
use num_traits::Zero;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::basic::sha256_hash::bitcoin_num_to_bytes;
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use recursive_stwo_bitcoin_dsl::treepp::*;
use stwo_prover::core::fields::m31::M31;

pub fn reconstruct_for_channel_draw(hint: &StrBar) -> (M31Bar, StrBar) {
    let res = if hint.value == vec![0x80] {
        (M31::zero(), vec![0x00, 0x00, 0x00, 0x80])
    } else {
        let num = read_scriptint(&hint.value).unwrap();
        let abs = M31::from_u32_unchecked(num.unsigned_abs() as u32);
        let abs_str = bitcoin_num_to_bytes(num.abs());

        if abs_str.len() < 4 {
            let mut str = hint.value.clone();
            if str.len() < 2 {
                str.push(0x00);
                str.push(0x00);
            }
            if str.len() < 3 {
                str.push(0x00);
            }

            if num < 0 {
                str.push(0x80);
            } else {
                str.push(0x00);
            }

            (abs, str)
        } else {
            (abs, hint.value.clone())
        }
    };

    let cs = hint.cs();

    cs.insert_script(reconstruct_for_channel_draw_gadget, hint.variables())
        .unwrap();

    let reconstructed_str = StrBar::new_function_output(&cs, res.1).unwrap();
    let reconstructed_m31 = M31Bar::new_function_output(&cs, res.0).unwrap();

    (reconstructed_m31, reconstructed_str)
}

fn reconstruct_for_channel_draw_gadget() -> Script {
    script! {
        // handle 0x80 specially---it is the "negative zero", but most arithmetic opcodes refuse to work with it.
        OP_DUP OP_PUSHBYTES_1 OP_LEFT OP_EQUAL
        OP_IF
            OP_DROP
            OP_PUSHBYTES_4 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_LEFT
            OP_PUSHBYTES_0 OP_TOALTSTACK
        OP_ELSE
            OP_DUP OP_ABS
            OP_DUP OP_TOALTSTACK

            OP_SIZE 4 OP_LESSTHAN
            OP_IF
                OP_DUP OP_ROT
                OP_EQUAL OP_TOALTSTACK

                // stack: abs(a)
                // altstack: abs(a), is_positive

                OP_SIZE 2 OP_LESSTHAN OP_IF OP_PUSHBYTES_2 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_CAT OP_ENDIF
                OP_SIZE 3 OP_LESSTHAN OP_IF OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_CAT OP_ENDIF

                OP_FROMALTSTACK
                OP_IF
                    OP_PUSHBYTES_1 OP_PUSHBYTES_0
                OP_ELSE
                    OP_PUSHBYTES_1 OP_LEFT
                OP_ENDIF
                OP_CAT
            OP_ELSE
                OP_DROP
            OP_ENDIF
            OP_FROMALTSTACK
        OP_ENDIF

        // stack: str abs(a)
    }
}
