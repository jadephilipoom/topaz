use clap::Parser;
use crossterm::cursor;
use crossterm::event;
use crossterm::execute;
use crossterm::style::Print;
use crossterm::terminal;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha512_256};
use std::fs;
use std::io;
use std::process;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Account name; password is random if not provided.
    #[arg(short, long)]
    account: Option<String>,

    /// Adjust for requirements like symbols
    #[arg(short, long, default_value_t = 0,
        long_help="Intended to accomodate reqirements such as uppercase letters, symbols,
and numbers (level 1) and maximum length (level 2). Overwrites the
default stupidity level of the password when it is printed next time.")]
    stupidity: usize,

    /// Increment account counter to generate a fresh password
    #[arg(short, long, default_value_t = false,
        long_help="Persistently increments the counter for an account to get a new
password. Ignored if --account is not set or if --counter is set")]
    refresh: bool,

    /// Persistently set a counter value for the account
    #[arg(short, long)]
    counter: Option<u32>,

    /// Path to alternative word list for password selection
    #[arg(short, long)]
    wordlist: Option<String>,

    // TODO: option to edit notes
}

#[derive(Debug, Deserialize, Serialize)]
struct Account {
    name: String,
    counter: u32,
    stupidity: usize,
    notes: String,
}

// Fetch words deterministically from the word list based on a seed value.
fn get_words(wordlist: Option<String>, seed: &[u8]) -> Vec<String> {
    // Read the word list.
    let words_string = match wordlist {
        Some(path) => fs::read_to_string(path).expect("Could not open wordlist!"),
        None => String::from(include_str!("eff_large_wordlist.txt")),
    };
    let words: Vec<&str> = words_string.lines().collect();
    if words.len() == 0 {
        panic!("Word list is empty!");
    }

    // Based on the size of the word list, determine how many words we need for
    // a minimum security threshold.
    let sec_threshold: usize = 70;
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
        let idx_bytes: &mut [u8] = &mut [0u8; 8];
        for i in 0..bytelen {
            idx_bytes[i] = seed[start_byte + i];
        }
        let mut idx = u64::from_le_bytes(idx_bytes.try_into().unwrap());
        idx >>= start_bit % 8;
        idx &= (1 << (end_bit - start_bit)) - 1;
        idx %= words.len() as u64;
        idxs.push(idx as usize);
    }

    return idxs
        .into_iter()
        .map(|i| String::from(*words.get(i).unwrap()))
        .collect();
}

// Read a password from standard input (without echoing to the terminal).
fn read_password(prompt: &str) -> String {
    // Using raw mode allows us to not echo the characters typed.
    terminal::enable_raw_mode().expect("Could not enable terminal raw mode.");
    execute!(io::stdout(), Print(format!("{}: ", prompt))).unwrap();
    let mut password = String::new();
    loop {
        match event::read().unwrap() {
            event::Event::Key(k) => {
                // Ignore non-press events.
                if !k.is_press() {
                    continue;
                }

                //  If the key was enter, exit the loop.
                if k.code.is_enter() {
                    execute!(io::stdout(), Print("\n"), cursor::MoveToNextLine(1)).unwrap();
                    break;
                }

                // If the key was ctrl-c, exit the program.
                if k.code == event::KeyCode::Char('c')
                    && k.modifiers == event::KeyModifiers::CONTROL
                {
                    execute!(io::stdout(), Print("\n"), cursor::MoveToNextLine(1)).unwrap();
                    terminal::disable_raw_mode().expect("Could not disable terminal raw mode.");
                    process::exit(1);
                }

                // If the key was backspace, delete some characters.
                if k.code == event::KeyCode::Backspace {
                    if password.len() == 0 {
                        continue;
                    }
                    password.pop();
                    execute!(
                        io::stdout(),
                        cursor::MoveLeft(1),
                        Print(" "),
                        cursor::MoveLeft(1)
                    )
                    .unwrap();
                }

                // Otherwise, accept the new character as part of the password
                // and echo an asterisk character.
                if let event::KeyCode::Char(c) = k.code {
                    password.push(c);
                    execute!(io::stdout(), Print("*")).unwrap();
                }
            }
            _ => (),
        }
    }
    // Disable raw mode again before exiting.
    terminal::disable_raw_mode().expect("Could not disable terminal raw mode.");
    return password;
}

fn get_domain_password() -> String {
    let password = read_password("Please type the domain password");
    let mut password_confirm = read_password("Type password again to confirm");
    if password == password_confirm {
        password_confirm.zeroize();
        return password;
    }
    println!("Passwords did not match! Please try again.");
    return get_domain_password();
}

fn account_path(account_name: &String) -> String {
    format!("_accounts/{}", account_name)
}

fn get_account_record(account_name: &String) -> Option<Account> {
    let path = account_path(account_name);
    match fs::exists(&path) {
        Ok(true) => (),
        _ => return None,
    }
    let account_str = fs::read_to_string(&path).expect("Could not read account data.");
    return serde_json::from_str(account_str.as_str()).expect("Could not read account data");
}

fn write_account_record(account: &Account) {
    let path = account_path(&account.name);
    let account_str = serde_json::to_string(account).expect("Could not serialize account data.");
    fs::write(&path, account_str).expect("Could not write account data.");
}

fn make_stupid_password(length_limit: Option<usize>, words: &Vec<String>) -> String {
    let mut password = String::new();
    for w in words {
        let mut chars = w.chars();
        password.push(chars.next().unwrap().to_ascii_uppercase());
        let mut len = 1;
        while if let Some(lim) = length_limit {
            len < lim
        } else {
            true
        } {
            match chars.next() {
                Some(c) => {
                    password.push(c);
                    len += 1;
                }
                None => {
                    break;
                }
            };
        }
    }
    password.push('1');
    password.push('!');
    return password;
}

fn print_password(stupid: usize, words: &Vec<String>) {
    match stupid {
        0 => {
            println!("{}", words.join(" "));
        }
        1 => {
            let mut password = make_stupid_password(None, words);
            println!("{}", password);
            password.zeroize();
        }
        2 => {
            let mut password = make_stupid_password(Some(3), words);
            println!("{}", password);
            password.zeroize();
        }
        _ => {
            // Panic; we should have caught this before.
            panic!("Stupidity too high!");
        }
    }
}

fn main() {
    let args = Args::parse();

    if args.stupidity > 2 {
        println!("Password formats that stupid are not supported.");
        process::exit(1);
    }

    if let Some(account_name) = args.account {
        let mut is_new = false;
        let mut overwrite = false;
        let mut account = match get_account_record(&account_name) {
            Some(x) => x,
            None => {
                println!(
                    "Creating new account {}. If you mistyped the name, exit with Ctrl-C and try again.",
                    account_name
                );
                is_new = true;
                Account {
                    name: account_name,
                    counter: 0,
                    stupidity: args.stupidity,
                    notes: String::from(""),
                }
            }
        };
        if let Some(ctr) = args.counter {
            overwrite = true;
            println!(
                "Account counter will be updated from {} to {}.",
                account.counter, ctr
            );
            account.counter = ctr;
        } else if args.refresh {
            overwrite = true;
            println!(
                "Account counter will be updated from {} to {}.",
                account.counter,
                account.counter + 1
            );
            account.counter += 1;
        }
        if args.stupidity != account.stupidity {
            overwrite = true;
            println!(
                "Stupidity level will be updated from {} to {}.",
                account.stupidity, args.stupidity
            );
            account.stupidity = args.stupidity;
        }
        if account.notes != "" {
            println!("Notes: {}", account.notes);
        }
        let mut domain_password = get_domain_password();
        let mut seed = Sha512_256::new()
            .chain_update(account.counter.to_le_bytes())
            .chain_update(account.name.as_bytes())
            .chain_update(domain_password.as_bytes())
            .finalize();
        let mut words = get_words(args.wordlist, seed.as_slice());
        domain_password.zeroize();
        seed.zeroize();
        print_password(args.stupidity, &words);
        words.zeroize();
        if is_new {
            println!("Add notes? (press enter to skip)");
            io::stdin()
                .read_line(&mut account.notes)
                .expect("Could not interpret notes.")
                .to_string();
            account.notes = account.notes.trim_end().to_string();
        }
        if overwrite || is_new {
            write_account_record(&account);
        }
    } else {
        // No account given; generate a random password.
        let mut rng = rand::rng();
        let mut seed: [u8; 32] = rng.random();
        let mut words = get_words(args.wordlist, &seed);
        seed.zeroize();
        print_password(args.stupidity, &words);
        words.zeroize();
    }
}
