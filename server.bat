echo off
cls

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting admin privileges^.^.^.
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b 1
)


where python3 >nul 2>nul
if %ERRORLEVEL%==0 set PYTHON=python3
where python >nul 2>nul
if %ERRORLEVEL%==0 set PYTHON=python
set OPENSSL="C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

echo Grabbing OpenSSL installer^.^.^.
curl -k https://slproweb.com/download/Win64OPENSSL_Light-3_5_1.msi -o %USERPROFILE%\Downloads\OpenSSL.msi

echo Running OpenSSL installer^.^.^.
msiexec /i %USERPROFILE%\Downloads\OpenSSL.msi /qn

echo Generating necessary certificates^.^.^.
rmdir /s /q %USERPROFILE%\Documents\hozinumcert 2>nul
mkdir %USERPROFILE%\Documents\hozinumcert 2>nul

@REM TLS config (non-CA)
echo "^[ req ^]" > %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "distinguished_name ^= dn" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "prompt ^= no" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo. >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "^[ dn ^]" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "CN ^= keyauth^.win" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo. >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "^[ v3 ^]" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "basicConstraints ^= CA^:FALSE" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "keyUsage ^= digitalSignature" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "subjectAltName ^= DNS^:keyauth^.win" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "^[ alt^_names ^]" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf
echo "DNS^.1 ^= keyauth^.win" >> %USERPROFILE%\Documents\hozinumcert\tls.cnf

@REM CA cert config
echo "^[ v3^_ca ^]" > %USERPROFILE%\Documents\hozinumcert\ca.cnf
echo "basicConstraints ^= CA^:TRUE" >> %USERPROFILE%\Documents\hozinumcert\ca.cnf

%OPENSSL% genrsa -out %USERPROFILE%\Documents\hozinumcert\root.key 4096
%OPENSSL% req -x509 -new -key %USERPROFILE%\Documents\hozinumcert\root.key -sha256 -days 825 -out %USERPROFILE%\Documents\hozinumcert\root.pem -subj "/CN=keyauth.win"
certutil -addstore root %USERPROFILE%\Documents\hozinumcert\root.pem

%OPENSSL% genrsa -out %USERPROFILE%\Documents\hozinumcert\tls.key 2048
%OPENSSL% req -new -key %USERPROFILE%\Documents\hozinumcert\tls.key -out %USERPROFILE%\Documents\hozinumcert\tls.csr -config %USERPROFILE%\Documents\hozinumcert\tls.cnf
%OPENSSL% x509 -req -in %USERPROFILE%\Documents\hozinumcert\tls.csr -CA %USERPROFILE%\Documents\hozinumcert\root.pem -CAkey %USERPROFILE%\Documents\hozinumcert\root.key -CAcreateserial -out %USERPROFILE%\Documents\hozinumcert\tls.crt -days 365 -sha256 -extfile %USERPROFILE%\Documents\hozinumcert\tls.cnf -extensions v3

%OPENSSL% genpkey -algorithm ed25519 -out %USERPROFILE%\Documents\hozinumcert\ed.key
%OPENSSL% pkey -in %USERPROFILE%\Documents\hozinumcert\ed.key -pubout -out %USERPROFILE%\Documents\hozinumcert\ed.pub

echo Prerequisites
%PYTHON% -m pip install pymem
%PYTHON% -m pip install psutil
%PYTHON% -m pip install cryptography

echo Getting server script^.^.^.
curl -k https://raw.githubusercontent.com/Ixve/keyauth-v1.3-emu/refs/heads/main/server.py -o server.py

echo Starting server^.^.^.
start %PYTHON% server.py
timeout /t 3 /nobreak
