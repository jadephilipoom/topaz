use clap::Parser;
use rand::prelude::*;
use std::fs;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Generate a random password and exit.
    #[arg(short, long, default_value_t = false)]
    random: bool,

    /// Path to the word list to use.
    #[arg(short, long, default_value_t = String::from("eff_large_wordlist.txt"))]
    wordlist: String,
}

// Fetch words deterministically from the word list based on a seed value.
fn get_words(wordlist: String, seed: &[u8;32]) -> Vec<String> {
    // Read the word list.
    let words_string: String = fs::read_to_string(wordlist)
        .expect("Could not open wordlist!");
    let words: Vec<&str> = words_string.lines().collect();
    if words.len() == 0 {
        panic!("Word list is empty!");
    }

    // Based on the size of the word list, determine how many words we need for
    // a minimum security threshold.
    let sec_threshold: usize = 64;
    let count = sec_threshold.div_ceil(words.len().ilog2() as usize);

    // We need to translate the seed into indices into the word list. The seed
    // is large enough relative to the security threshold that we can simply
    // split it into `count` sections. The number of bits in each section is
    // approximately (words.len())^(seed_bitlen / sec_threshold), so as long
    // as the word list is reasonably long and the seed is a few times larger
    // than the threshold, the bias should be negligible.
    let seed_bitlen = seed.len() * 8;
    if seed_bitlen.div_ceil(count) > 64 {
        panic!("Seed bit count per word must be low enough to fit in u64.");
    }
    let mut idxs: Vec<usize> = Vec::new();
    while idxs.len() < count {
        let start_bit = (seed_bitlen * idxs.len()) / count;
        let end_bit = if idxs.len() == count - 1 {
            seed_bitlen
        } else {
            (seed_bitlen * (idxs.len() + 1)) / count
        };
        let start_byte = start_bit / 8;
        let end_byte = end_bit / 8;
        let bytelen = end_byte - start_byte;
        let idx_bytes: &mut [u8] = &mut [0u8;8];
        for i in 0..bytelen {
            idx_bytes[i] = seed[start_byte + i];
        }
        let mut idx = u64::from_le_bytes(idx_bytes.try_into().unwrap());
        idx >>= start_bit % 8;
        idx &= (1 << (end_bit - start_bit)) - 1;
        idx %= words.len() as u64;
        idxs.push(idx as usize);
    }

    return idxs.into_iter()
        .map(|i| String::from(*words.get(i).unwrap()))
        .collect();
}

fn main() {
    let args = Args::parse();

    if args.random {
        let mut rng = rand::rng();
        let seed: [u8;32] = rng.random();
        let words = get_words(args.wordlist, &seed);
        println!("{}", words.join(" "));
    } else {
        // TODO
        println!("Not yet supported.")
    }
}
