use crate::channel::sha256::Sha256ChannelBar;
use anyhow::Result;
use recursive_stwo_bitcoin_dsl::bar::{AllocBar, Bar};
use recursive_stwo_bitcoin_dsl::basic::str::StrBar;
use recursive_stwo_bitcoin_dsl::basic::u8::U8Bar;
use recursive_stwo_bitcoin_dsl::options::Options;
use recursive_stwo_bitcoin_dsl::stack::Stack;
use recursive_stwo_bitcoin_dsl::treepp::*;

pub fn verify_pow(channel: &Sha256ChannelBar, pow_bits: usize) -> Result<()> {
    let digest = channel.digest.value.as_ref();

    let suffix = digest[16..].to_vec();
    let prefix = digest[..16 - pow_bits.div_ceil(8)].to_vec();

    let cs = channel.digest.cs();
    let prefix_var = StrBar::new_hint(&cs, prefix)?;
    let suffix_var = StrBar::new_hint(&cs, suffix)?;

    let msb_var = if pow_bits % 8 == 0 {
        None
    } else {
        Some(U8Bar::new_hint(&cs, digest[16 - 1 - pow_bits / 8])?)
    };

    if pow_bits % 8 == 0 {
        cs.insert_script_complex(
            verify_pow_without_msb_gadget,
            [
                channel.digest.variable,
                suffix_var.variable,
                prefix_var.variable,
            ],
            &Options::new().with_u32("pow_bits", pow_bits as u32),
        )
    } else {
        cs.insert_script_complex(
            verify_pow_with_msb_gadget,
            [
                channel.digest.variable,
                suffix_var.variable,
                prefix_var.variable,
                msb_var.unwrap().variable,
            ],
            &Options::new().with_u32("pow_bits", pow_bits as u32),
        )
    }
}

fn verify_pow_without_msb_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let pow_bits = options.get_u32("pow_bits")?;
    assert_eq!(pow_bits % 8, 0);
    let zero = vec![0x0u8; (pow_bits / 8) as usize];

    Ok(script! {
        // input:
        //    digest
        //    suffix
        //    prefix
        if pow_bits >= 8 {
            { zero }
            OP_CAT
        }
        OP_SWAP
        OP_SIZE 16 OP_EQUALVERIFY
        OP_CAT
        OP_EQUALVERIFY
    })
}

fn verify_pow_with_msb_gadget(_: &mut Stack, options: &Options) -> Result<Script> {
    let pow_bits = options.get_u32("pow_bits")?;
    assert_ne!(pow_bits % 8, 0);
    let zero = vec![0x0u8; (pow_bits / 8) as usize];
    let max_msb = (1 << (pow_bits % 8)) - 1;
    Ok(script! {
        // input:
        //    digest
        //    suffix
        //    prefix
        //    msb

        // process the msb
        OP_DUP { max_msb } OP_GREATERTHANOREQUAL OP_VERIFY
        // if it is zero, replace it with 0x00 (one byte)
        OP_DUP 0 OP_EQUAL OP_IF
            OP_DROP
            OP_PUSHBYTES_1 OP_PUSHBYTES_0
        OP_ENDIF

        // connect [000] + msb
        if pow_bits >= 8 {
            { zero }
            OP_CAT
        }

        // stack:
        //    digest
        //    prefix
        //    suffix
        //    [000] + msb

        // check prefix length
        OP_SWAP
        OP_SIZE { 16 - pow_bits.div_ceil(8) } OP_EQUALVERIFY

        OP_SWAP
        OP_CAT
        OP_SWAP
        OP_CAT

        OP_EQUALVERIFY
    })
}
