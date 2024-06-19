# Sanitizer Runtime Library
Currently only the **UndefinedBehaviorSanitizer** is supported.

Cross-compile for bare-bones usage:
```sh
cargo build --target x86_64-unknown-none --no-default-features --features ubsan --release
```
