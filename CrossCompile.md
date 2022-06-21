# Cross Compile

To do cross compile, you should set the toolchains correctly, espicially the target linker, please read the [Cargo target reference](https://doc.rust-lang.org/cargo/reference/config.html#target) first.

Here are some examples for cross compile.

## Build on macOS and target Linux

1. Install the rustc toolchain for Linux

```sh
rustup target add x86_64-unknown-linux-gnu
```

2. Install a prebuilt cross compiler for Linux

```sh
brew tap SergioBenitez/osxct
brew install x86_64-unknown-linux-gnu
```

3. Do cross compile:

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-unknown-linux-gnu-gcc \
cargo build --target=x86_64-unknown-linux-gnu
```

The `CARGO_TARGET_<triple>_LINKER` environment is used to specify the linker for cross compiling.

## Build on macOS and target Android

1. Install the rustc toolchain for Android

```sh
rustup target add arm-linux-androideabi aarch64-linux-android
```

2. Install ndk for Android, you can download it in [here](https://developer.android.com/ndk/downloads)
3. Set the linker for cross compile:

```sh
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang
```

the `$NDK` is the ndk installation directory.

4. Do cross compile:

```sh
cargo build --target aarch64-linux-android
```
