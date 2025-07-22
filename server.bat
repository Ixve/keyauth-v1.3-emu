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
> %USERPROFILE%\Documents\hozinumcert\tls.cnf (
echo [ req ]
echo distinguished_name = dn
echo prompt = no
echo.
echo [ dn ]
echo CN = keyauth.win
echo.
echo [ v3 ]
echo basicConstraints = CA:FALSE
echo keyUsage = digitalSignature
echo subjectAltName = DNS:keyauth.win
echo [ alt_names ]
echo DNS.1 = keyauth.win
)

@REM CA cert config
> %USERPROFILE%\Documents\hozinumcert\ca.cnf (
echo [ v3_ca ]
echo basicConstraints = CA:TRUE
)

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
