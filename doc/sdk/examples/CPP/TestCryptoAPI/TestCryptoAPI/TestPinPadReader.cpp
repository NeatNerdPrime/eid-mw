#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <vector>
#include <iostream>
#include <fstream>

#include <wchar.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")


void PrintErrorMessage(DWORD errorCode) {
	char* messageBuffer = nullptr;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorCode, 0, (LPSTR)&messageBuffer, 0, NULL);
	if (messageBuffer) {
		//std::cout << "Error " << "0x" << std::hex << errorCode << ": " << messageBuffer;

		wchar_t log[1024];
		swprintf(log, sizeof(log) / sizeof(log[0]), L"Error  %0x", errorCode);
		OutputDebugString(log);
		OutputDebugStringA(messageBuffer);

		LocalFree(messageBuffer);
	}
	else {
		//std::cout << "Unknown error code: " << errorCode << std::endl;
		wchar_t log[300];
		swprintf(log, sizeof(log) / sizeof(log[0]), L"Unknown error code: %s", errorCode);
		OutputDebugString(log);
	}
}


void ListKeysFromBaseCSP()
{
	NCRYPT_PROV_HANDLE hProvider = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	NCryptKeyName* pKeyName = nullptr;
	PVOID pEnumState = nullptr;
	SECURITY_STATUS status;

	// Open the Base CSP provider
	status = NCryptOpenStorageProvider(&hProvider, MS_SCARD_PROV, 0);
	if (status != ERROR_SUCCESS) {
		//d::wcout << L"Failed to open provider. Error: " << status << std::endl;
		PrintErrorMessage(status);
		return;
	}

	//std::wcout << L"Base CSP Opened Successfully!\nEnumerating Keys...\n";
	OutputDebugString(L"Base CSP Opened Successfully!\nEnumerating Keys...\n");

	// Enumerate keys
	while ((status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, 0/*NCRYPT_MACHINE_KEY_FLAG*/)) == ERROR_SUCCESS) {
		//std::wcout << std::endl;

		//std::wcout << L"Key Name: " << pKeyName->pszName << std::endl;
		wchar_t log[300];
		swprintf(log, sizeof(log) / sizeof(log[0]), L"Key Name: %s ", pKeyName->pszName);
		OutputDebugString(log);

		//std::wcout << L"  Algorithm: " << (pKeyName->pszAlgid ? pKeyName->pszAlgid : L"(Unknown)") << std::endl;
		swprintf(log, sizeof(log) / sizeof(log[0]), L"  Algorithm: %S\n", pKeyName->pszAlgid ? pKeyName->pszAlgid : L"(Unknown)");
		OutputDebugString(log);


		// Open key to check additional properties
		if (NCryptOpenKey(hProvider, &hKey, pKeyName->pszName, 0, 0) == ERROR_SUCCESS) {
			DWORD keyUsage = 0, keyUsageSize = 0;

			if (NCryptGetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY,
				(PBYTE)&keyUsage, sizeof(DWORD), &keyUsageSize, 0) == ERROR_SUCCESS) {
				if (keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) {
					//std::wcout << L"  [v] Key supports signing" << std::endl;
					OutputDebugString(L"  [v] Key supports signing\n");
				}
				else {
					//std::wcout << L"  [x] Key does NOT support signing" << std::endl;
					OutputDebugString(L"  [x] Key does NOT support signing\n");
				}
			}

			NCryptFreeObject(hKey);
		}
		else {
			//std::wcout << L"  Could not open key!" << std::endl;
			OutputDebugString(L"  Could not open key!\n");
		}

		NCryptFreeBuffer(pKeyName);
	}
	//if (status == NTE_NO_MORE_ITEMS)
	{

		PrintErrorMessage(status);
	}

	// Cleanup
	NCryptFreeObject(hProvider);
	//std::wcout << L"Key Enumeration Completed!" << std::endl;
	OutputDebugString(L"Key Enumeration Completed!\n");

}
void SignDataWithSmartCard()
{
	NCRYPT_PROV_HANDLE hProvider = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	SECURITY_STATUS status;
	BYTE hash[32] = { 0 };  // Fake hash data
	BYTE signature[256];
	DWORD signatureSize = 0;

	// Open the Smart Card CSP provider
	status = NCryptOpenStorageProvider(&hProvider, MS_SCARD_PROV, 0);
	if (status != ERROR_SUCCESS) {
		OutputDebugString(L"[BixVReader] Failed to open provider.\n");
		return;
	}

	// Open a specific key (Replace "YourKeyName" with an actual key)
	//status = NCryptOpenKey(hProvider, &hKey, L"YourKeyName", 0, 0);
	status = NCryptOpenKey(hProvider, &hKey, L"Ali Bas (Signature)", 0, 0);
	if (status != ERROR_SUCCESS) {
		OutputDebugString(L"[BixVReader] Failed to open key.\n");
		return;
	}

	// **Trigger Windows Security PIN Prompt (User Authentication)**
	status = NCryptSignHash(hKey, NULL, hash, sizeof(hash), signature, sizeof(signature), &signatureSize, 0);
	if (status == ERROR_SUCCESS) {
		OutputDebugString(L"[BixVReader] Signing successful! Windows Security PIN prompt appeared.\n");
	}
	else {
		OutputDebugString(L"[BixVReader] Signing failed.\n");
	}

	// Cleanup
	NCryptFreeObject(hKey);
	NCryptFreeObject(hProvider);
}


/*

PS C:\Users\ali.bas> echo $thumbprint
8c35d1735327c96d5f5e19a1636f2d389105e37e
PS C:\Users\ali.bas>
PS C:\Users\ali.bas>
PS C:\Users\ali.bas> certutil -sign c:\test.txt c:\test.sig $correctThumbprint -user
Load(CRL) returned ASN1 bad tag value met. 0x8009310b (ASN: 267 CRYPT_E_ASN1_BADTAG)
CertUtil: -sign command FAILED: 0x8009310b (ASN: 267 CRYPT_E_ASN1_BADTAG)
CertUtil: ASN1 bad tag value met.
PS C:\Users\ali.bas>
PS C:\Users\ali.bas>

*/
HRESULT SignDataWithSmartCardPath_orig() {
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProvider = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	PBYTE pbHash = NULL;
	DWORD cbHash = 0;
	BYTE pbSignature[512];
	DWORD cbSignature = sizeof(pbSignature);
	//WCHAR filePath[] = L"c:\\test.txt";

	OutputDebugString(L"Attempting to sign using Smart Card...\n");

	// Open Smart Card Provider
	status = NCryptOpenStorageProvider(&hProvider, MS_SCARD_PROV, 0);
	if (status != ERROR_SUCCESS) {
		OutputDebugString(L"Failed to open provider.\n");
		return status;
	}

	// Enumerate keys
	NCryptKeyName* pKeyName = NULL;
	PVOID pEnumState = NULL;
	while ((status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, 0)) == ERROR_SUCCESS) {
		OutputDebugString(L"Key Found: ");
		OutputDebugString(pKeyName->pszName);
		OutputDebugString(L"\n");

		// Open the first found key
		status = NCryptOpenKey(hProvider, &hKey, pKeyName->pszName, 0, 0);
		if (status == ERROR_SUCCESS) break;
	}

	if (hKey == NULL) {
		OutputDebugString(L"No valid signing key found.\n");
		return NTE_NO_KEY;
	}

	/*
	// Read the file and create a hash
	HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		OutputDebugString(L"Failed to open file.\n");
		return HRESULT_FROM_WIN32(GetLastError());
	}

	DWORD cbFileSize = GetFileSize(hFile, NULL);
	pbHash = (PBYTE)malloc(cbFileSize);
	ReadFile(hFile, pbHash, cbFileSize, &cbHash, NULL);
	CloseHandle(hFile);
	*/


	if (hKey == NULL) {
		OutputDebugString(L"Error: hKey is NULL, cannot sign.\n");
		return NTE_NO_KEY;
	}



	if (pbHash == NULL || cbHash == 0) {
		OutputDebugString(L"Error: Hash data is not set properly.\n");
		return NTE_FAIL;
	}


	// Debugging before signing
	OutputDebugString(L"Signing data with Smart Card...\n");

	BCRYPT_PKCS1_PADDING_INFO padding;
	unsigned char hash[32];
	status = NCryptSignHash(hKey, &padding, hash, sizeof(hash), pbSignature, sizeof(pbSignature), &cbSignature, BCRYPT_PAD_PKCS1);

	OutputDebugString(L"PIN entry accepted, proceeding to signing...\n");

	// Sign the hash
	//status = NCryptSignHash(hKey, NULL, pbHash, cbHash, pbSignature, sizeof(pbSignature), &cbSignature, 0);
	if (status != ERROR_SUCCESS) {
		wchar_t log[300];
		swprintf(log, sizeof(log) / sizeof(log[0]), L"status = %d ", status);
		OutputDebugString(log);
		OutputDebugString(L"Signing failed.\n");
		return status;
	}

	/*
	// Save the signature
	std::ofstream outFile("c:\\test.sig", std::ios::binary);
	outFile.write((char*)pbSignature, cbSignature);
	outFile.close();
	*/

	// Cleanup
	NCryptFreeObject(hKey);
	NCryptFreeObject(hProvider);
	free(pbHash);

	OutputDebugString(L"Signing completed successfully. Signature saved to c:\\test.sig\n");
	return S_OK;
}

#include <iostream>
#include <windows.h>
#include <ncrypt.h>

HRESULT _SignDataWithSmartCardPath() {
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProvider = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	BYTE pbSignature[1024];  // Increased buffer size
	DWORD cbSignature = sizeof(pbSignature);
	PBYTE pbHash = NULL;
	DWORD cbHash = 32;  // Assume SHA-256 hash

	std::wcout << L"Attempting to sign using Smart Card..." << std::endl;

	// Open Smart Card Provider
	status = NCryptOpenStorageProvider(&hProvider, MS_SCARD_PROV, 0);
	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to open provider. Error: " << status << std::endl;
		return status;
	}

	// Enumerate keys
	NCryptKeyName* pKeyName = NULL;
	PVOID pEnumState = NULL;
	while ((status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, 0)) == ERROR_SUCCESS) {
		std::wcout << L"Key Found: " << pKeyName->pszName << std::endl;

		// Open the first found key
		status = NCryptOpenKey(hProvider, &hKey, pKeyName->pszName, 0, NCRYPT_SILENT_FLAG);
		if (status == ERROR_SUCCESS) break;
	}

	if (hKey == NULL) {
		std::wcout << L"No valid signing key found. Exiting." << std::endl;
		return NTE_NO_KEY;
	}
	else {
		std::wcout << L"Valid signing key found. Proceeding..." << std::endl;
	}

	// Ensure the key supports signing
	DWORD keyUsage = 0;
	DWORD cbResult = 0;
	status = NCryptGetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(DWORD), &cbResult, 0);
	if ((keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) == 0) {
		std::wcout << L"Error: Selected key does not support signing." << std::endl;
		return NTE_NO_KEY;
	}
	else {
		std::wcout << L"Smart Card Key supports signing." << std::endl;
	}


	// Check key algorithm
	WCHAR alg[64];
	status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)&alg, sizeof(alg), &cbResult, 0);
	std::wcout << L"Key Algorithm: " << alg << std::endl;

	DWORD providerType = 0;
	status = NCryptGetProperty(hProvider, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&providerType, sizeof(DWORD), &cbResult, 0);
	std::wcout << L"Provider Type: " << providerType << std::endl;



		// If keyUsage does not include NCRYPT_ALLOW_SIGNING_FLAG (0x02), the key cannot be used for signing.
	keyUsage = 0;
	cbResult = 0;
	status = NCryptGetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(DWORD), &cbResult, 0);
	std::wcout << L"Key Usage Flags: " << keyUsage << std::endl;


	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to set authentication property. Error: " << status << std::endl;
	}

		// If key length is 0 or invalid, hKey is a public key and cannot be used for signing
	DWORD keyLength = 0;
	status = NCryptGetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(DWORD), &cbResult, 0);
	wchar_t log[100];
	swprintf(log, 100, L"Key Length: %d bits\n", keyLength);
	std::wcout << log << std::endl;  // Debug output
	//OutputDebugString(log);



	std::wcout << L"Before NCryptSignHash: Signing process started." << std::endl;

	// Perform signing
	//status = NCryptSignHash(hKey, &padding, pbHash, cbHash, pbSignature, sizeof(pbSignature), &cbSignature, BCRYPT_PAD_PKCS1);
	//status = NCryptSignHash(hKey, NULL, pbHash, cbHash, pbSignature, sizeof(pbSignature), &cbSignature, 0);

	// Initialize PKCS1 padding

	/*
	BCRYPT_PKCS1_PADDING_INFO padding;
	padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	status = NCryptSignHash(hKey, &padding, pbHash, cbHash, pbSignature, sizeof(pbSignature), &cbSignature, BCRYPT_PAD_PKCS1);
	*/


	
		// Force user authentication (PIN prompt)
	//DWORD authRequired = TRUE;
	//status = NCryptSetProperty(hKey, NCRYPT_REQUIRE_AUTH_PROPERTY, (PBYTE)&authRequired, sizeof(DWORD), 0);
	const wchar_t* pinPolicy = L"Always Prompt";
	status = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (PBYTE)pinPolicy, (DWORD)(wcslen(pinPolicy) + 1) * sizeof(wchar_t), 0);


	//pssPadding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	
	//pssPadding.pszAlgId = BCRYPT_PKCS1_PADDING_INFO;
	//pssPadding.cbSalt = 32;
	//status = NCryptSignHash(hKey, &pssPadding, pbHash, cbHash, pbSignature, sizeof(pbSignature), &cbSignature, BCRYPT_PAD_PSS);
	//BCRYPT_PKCS1_PADDING_INFO padding;
	//unsigned char hash[32];
	BCRYPT_PKCS1_PADDING_INFO padding = { BCRYPT_SHA256_ALGORITHM };
	BYTE hash[32] = { 0 };  // Ensure it's a valid SHA-256 hash
	status = NCryptSignHash(hKey, &padding, hash, sizeof(hash), pbSignature, sizeof(pbSignature), &cbSignature, BCRYPT_PAD_PKCS1);


	if (status == ERROR_SUCCESS) {
		std::wcout << L"NCryptSignHash completed successfully!" << std::endl;
	}
	else {
		std::wcout << L"NCryptSignHash failed with status = " << status << std::endl;
	}

	// Cleanup
	NCryptFreeObject(hKey);
	NCryptFreeObject(hProvider);

	return status;
}

HRESULT SignDataWithSmartCardPath() {
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProvider = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	BYTE pbSignature[1024];  // Increased buffer size
	DWORD cbSignature = sizeof(pbSignature);
	
	//PBYTE pbHash = NULL;
	//DWORD cbHash = 32;  // Default SHA-256 hash size
	BYTE pbHash[48] = { 0 };  // Default to SHA-384 for ECDSA P-384
	DWORD cbHash = 48;


	std::wcout << L"Attempting to sign using Smart Card..." << std::endl;

	// Open Smart Card Provider
	status = NCryptOpenStorageProvider(&hProvider, MS_SCARD_PROV, 0);
	if (status != ERROR_SUCCESS) {
		std::wcout << L"Failed to open provider. Error: " << status << std::endl;
		return status;
	}

	// Enumerate keys
	NCryptKeyName* pKeyName = NULL;
	PVOID pEnumState = NULL;
	while ((status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, 0)) == ERROR_SUCCESS) {
		std::wcout << L"Key Found: " << pKeyName->pszName << std::endl;

		// Open the first found key
		status = NCryptOpenKey(hProvider, &hKey, pKeyName->pszName, 0, NCRYPT_SILENT_FLAG);
		if (status == ERROR_SUCCESS) break;
	}

	if (hKey == NULL) {
		std::wcout << L"No valid signing key found. Exiting." << std::endl;
		return NTE_NO_KEY;
	}
	else {
		std::wcout << L"Valid signing key found. Proceeding..." << std::endl;
	}

	// Ensure the key supports signing
	DWORD keyUsage = 0;
	DWORD cbResult = 0;
	status = NCryptGetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(DWORD), &cbResult, 0);
	if ((keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) == 0) {
		std::wcout << L"Error: Selected key does not support signing." << std::endl;
		return NTE_NO_KEY;
	}
	else {
		std::wcout << L"Smart Card Key supports signing." << std::endl;
	}

	// Get key algorithm
	WCHAR alg[64];
	status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)&alg, sizeof(alg), &cbResult, 0);
	std::wcout << L"Key Algorithm: " << alg << std::endl;

	// Get provider type
	DWORD providerType = 0;
	status = NCryptGetProperty(hProvider, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&providerType, sizeof(DWORD), &cbResult, 0);
	std::wcout << L"Provider Type: " << providerType << std::endl;

	// Check key length
	DWORD keyLength = 0;
	status = NCryptGetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(DWORD), &cbResult, 0);
	std::wcout << L"Key Length: " << keyLength << L" bits" << std::endl;


	std::wcout << L"Before NCryptSignHash: Signing process started." << std::endl;

	// Determine signing mode based on key algorithm
	if (wcscmp(alg, BCRYPT_ECDSA_P256_ALGORITHM) == 0 ||
		wcscmp(alg, BCRYPT_ECDSA_P384_ALGORITHM) == 0 ||
		wcscmp(alg, BCRYPT_ECDSA_P521_ALGORITHM) == 0) {

		std::wcout << L"Using ECDSA signing mode..." << std::endl;

		// Use a SHA-384 hash for ECDSA P-384 (default to 48 bytes)
		BYTE hash[48] = { 0 };
		cbHash = sizeof(hash);

		status = NCryptSignHash(hKey, NULL, hash, cbHash, pbSignature, sizeof(pbSignature), &cbSignature, 0);
	}
	else if (wcscmp(alg, BCRYPT_RSA_ALGORITHM) == 0) {

		std::wcout << L"Using RSA signing mode..." << std::endl;

		// Force user authentication (PIN prompt)
		const wchar_t* pinPolicy = L"Always Prompt";
		status = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (PBYTE)pinPolicy, (DWORD)(wcslen(pinPolicy) + 1) * sizeof(wchar_t), 0);


		// Use a SHA-256 hash for RSA (default to 32 bytes)
		BYTE hash[32] = { 0 };
		cbHash = sizeof(hash);

		// Initialize PKCS1 padding for RSA
		BCRYPT_PKCS1_PADDING_INFO padding = { BCRYPT_SHA256_ALGORITHM };

		status = NCryptSignHash(hKey, &padding, hash, cbHash, pbSignature, sizeof(pbSignature), &cbSignature, BCRYPT_PAD_PKCS1);
	}
	else {
		std::wcout << L"Unsupported key algorithm. Cannot sign." << std::endl;
		status = NTE_BAD_ALGID;
	}

	// Check signing result
	if (status == ERROR_SUCCESS) {
		std::wcout << L"NCryptSignHash completed successfully!" << std::endl;
	}
	else {
		std::wcout << L"NCryptSignHash failed with status = " << status << std::endl;
	}

	// Cleanup
	NCryptFreeObject(hKey);
	NCryptFreeObject(hProvider);

	return status;
}


void SignWithCryptoAPI() {
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	BYTE pbSignature[512];
	DWORD cbSignature = sizeof(pbSignature);

	// Acquire the CSP handle
	if (!CryptAcquireContext(&hProv, NULL, MS_SCARD_PROV, PROV_RSA_FULL, 0)) {
		std::wcout << L"Failed to acquire CryptoAPI context. Error: " << GetLastError() << std::endl;
		return;
	}

	// Hash some data
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		std::wcout << L"Failed to create hash. Error: " << GetLastError() << std::endl;
		return;
	}

	BYTE data[] = "Test data to sign";
	if (!CryptHashData(hHash, data, sizeof(data) - 1, 0)) {
		std::wcout << L"Failed to hash data. Error: " << GetLastError() << std::endl;
		return;
	}

	// Sign the hash
	if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &cbSignature)) {
		std::wcout << L"CryptSignHash failed. Error: " << GetLastError() << std::endl;
	}
	else {
		std::wcout << L"Successfully signed with CryptoAPI!" << std::endl;
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
}


int main() {

	//listProviders();

	std::wcout << L"TEST 1: "<<std::endl;
	SignWithCryptoAPI();
	std::wcout << L"TEST 22: " << std::endl;
	SignDataWithSmartCardPath();




	return 0;
}
