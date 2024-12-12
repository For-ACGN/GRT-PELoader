echo =============build ucrtbase example=============
cd ucrtbase
call Build.bat
cd ..

echo ================build Go example================
cd go
call build.bat
cd ..

echo ===============build Rust example===============
cd rust
call build.bat
cd ..

echo finished
