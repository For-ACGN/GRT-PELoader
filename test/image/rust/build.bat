cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc

move /Y target\x86_64-pc-windows-msvc\release\rust.exe ..\x64\rust_msvc.exe
move /Y target\i686-pc-windows-msvc\release\rust.exe   ..\x86\rust_msvc.exe

rd /S /Q target
