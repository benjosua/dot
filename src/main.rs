fn main() {
    if let Err(err) = dot::run() {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
