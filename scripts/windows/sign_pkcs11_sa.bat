:: set all path variables
:: ======================
@if DEFINED BEID_SEARCH_PATHS_SET goto searchpaths_set
call "%~dp0.\SetPaths.bat"
@if ERRORLEVEL 1 goto paths_failed

:searchpaths_set
:: Create the version and revision number
:: ======================================
@call "%~dp0.\create_eidmw_version_files.cmd"

:: clean and build pkcs11 SA
:: =========================
@echo [INFO] Clean the pkcs11 SA dll, 32bit
@"%BEID_DIR_MSBUILD%\MSBuild.exe" /m /target:clean /property:Configuration=PKCS11_SA_Release /Property:Platform=x86 "%~dp0..\..\VS_2022\beid.sln"
@if ERRORLEVEL 1 goto msbuild_failed

@echo [INFO] Build the pkcs11 SA dll, 32bit
@"%BEID_DIR_MSBUILD%\MSBuild.exe" /m /target:build /property:Configuration=PKCS11_SA_Release /Property:Platform=x86 "%~dp0..\..\VS_2022\beid.sln"
@if ERRORLEVEL 1 goto msbuild_failed

@echo [INFO] Clean the pkcs11 SA dll, 64bit
@"%BEID_DIR_MSBUILD%\MSBuild.exe" /m /target:clean /property:Configuration=PKCS11_SA_Release /Property:Platform=x64 "%~dp0..\..\VS_2022\beid.sln"
@if ERRORLEVEL 1 goto msbuild_failed

@echo [INFO] Build the pkcs11 SA dll, 64bit
@"%BEID_DIR_MSBUILD%\MSBuild.exe" /m /target:build /property:Configuration=PKCS11_SA_Release /Property:Platform=x64 "%~dp0..\..\VS_2022\beid.sln"
@if ERRORLEVEL 1 goto msbuild_failed

:: sign pkcs11 SA
:: ==============
@echo [INFO] Sign the pkcs11 SA dll, 32bit
"%SIGNTOOL_PATH%\signtool" sign /fd SHA256 /s MY /n "Zetes SA" /sha1 "3f85e2a3538669c2a04aaeeb318497c780101872" /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 /v "%~dp0..\..\cardcomm\pkcs11\VS_2022\Binaries\Win32_PKCS11_SA_Release\beid_sa_pkcs11.dll"
@if ERRORLEVEL 1 goto signtool_failed

@echo [INFO] Sign the pkcs11 SA dll, 64bit
"%SIGNTOOL_PATH%\signtool" sign /fd SHA256 /s MY /n "Zetes SA" /sha1 "3f85e2a3538669c2a04aaeeb318497c780101872" /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 /v "%~dp0..\..\cardcomm\pkcs11\VS_2022\Binaries\x64_PKCS11_SA_Release\beid_sa_pkcs11.dll"
@if ERRORLEVEL 1 goto signtool_failed

@echo [INFO] Signing pkcs11 SA release dlls done
@goto end

:msbuild_failed
@echo [ERR ] msbuild failed
@goto err

:signtool_failed
@echo [ERR ] signtool failed
@goto err

:paths_failed
@echo [ERR ] could not set paths

:err
@exit /B 1

:end
@exit /B 0
